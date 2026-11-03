#!/usr/bin/env node
// Read-only pre-open-source scan. Prints JSON findings; never writes to the repository or calls anything but git and gh.
// Usage: node scan.mjs [repo-dir] [--no-history] [--no-github]
import { execFileSync, spawn } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { createInterface } from 'node:readline'

const args = process.argv.slice(2)
const root = resolve(args.find((arg) => !arg.startsWith('--')) ?? '.')
const flags = new Set(args.filter((arg) => arg.startsWith('--')))
const MAX_EVIDENCE = 20
const MAX_FILE_BYTES = 1_000_000
const LARGE_FILE_BYTES = 5_000_000

const findings = []
/** level: block (fix before going public), warn (should fix), info (worth knowing). status: pass, fail, skip. */
function add(id, level, status, title, detail = '', evidence = []) {
  findings.push({ id, level, status, title, ...(detail ? { detail } : {}), ...(evidence.length ? { evidence: evidence.slice(0, MAX_EVIDENCE), ...(evidence.length > MAX_EVIDENCE ? { more: evidence.length - MAX_EVIDENCE } : {}) } : {}) })
}

function run(command, commandArgs, options = {}) {
  try {
    return execFileSync(command, commandArgs, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 256 * 1024 * 1024, ...options }).trim()
  } catch {
    return null
  }
}

const has = (command) => run(process.platform === 'win32' ? 'where' : 'which', [command]) !== null

// ---------- Secret and leak rules ----------

const SECRET_RULES = [
  { id: 'private-key', re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/ },
  { id: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { id: 'openai-key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/ },
  { id: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})/ },
  { id: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { id: 'stripe-live-key', re: /\b[sr]k_live_[0-9A-Za-z]{20,}/ },
  { id: 'npm-token', re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: 'url-credentials', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/'"]+:[^\s@/'"]{6,}@[^\s'"]+/i },
  { id: 'assigned-secret', re: /\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|password|passwd)\b["']?\s*[:=]\s*["']([^"'\s]{16,})["']/i },
]
// Values that look like placeholders rather than real credentials.
const PLACEHOLDER = /(your|example|placeholder|changeme|dummy|sample|fake|test|xxxx|\*\*\*\*|<|\$\{|process\.env|import\.meta)/i
const ALLOW = /oss-prep:\s*allow/

function secretIn(line) {
  if (ALLOW.test(line)) return null
  for (const rule of SECRET_RULES) {
    const match = rule.re.exec(line)
    if (!match) continue
    const value = match[1] ?? match[0]
    if ((rule.id === 'assigned-secret' || rule.id === 'url-credentials') && PLACEHOLDER.test(value)) continue
    return { rule: rule.id, preview: `${match[0].slice(0, 8)}… (${match[0].length} chars)` }
  }
  return null
}

const SENSITIVE_FILE = [
  /(^|\/)\.env(\.[^/]*)?$/,
  /\.(pem|key|p12|pfx|keystore|jks|ppk)$/i,
  /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/,
  /(^|\/)\.npmrc$/,
  /(^|\/)\.pypirc$/,
  /(^|\/)credentials(\.json)?$/i,
  /(^|\/)service[-_]?account.*\.json$/i,
  /(^|\/)\.DS_Store$/,
  /(^|\/)(secrets?|private)(\/|\.)/i,
]
const SAFE_SENSITIVE = /(^|\/)\.env\.(example|sample|template)$/
const isSensitive = (path) => !SAFE_SENSITIVE.test(path) && SENSITIVE_FILE.some((re) => re.test(path))

const PERSONAL_PATH = /(?:\/(?:Users|home)\/(?!runner\b|user\b|username\b|you\b|me\b)[a-z0-9._-]+\/|[A-Z]:\\Users\\(?!Public\b)[^\\\s<>]+\\)/i
const PRIVATE_IP = /\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/

const isText = (buffer) => !buffer.subarray(0, 8000).includes(0)
const LOCKFILES = /(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb|poetry\.lock|Cargo\.lock|uv\.lock)$/

// ---------- Repository files ----------

const LICENSES = [
  ['AGPL-3.0', /GNU AFFERO GENERAL PUBLIC LICENSE/i],
  ['LGPL-3.0', /GNU LESSER GENERAL PUBLIC LICENSE/i],
  ['GPL-3.0', /GNU GENERAL PUBLIC LICENSE\s+Version 3/i],
  ['GPL-2.0', /GNU GENERAL PUBLIC LICENSE\s+Version 2/i],
  ['Apache-2.0', /Apache License,?\s+Version 2\.0/i],
  ['MPL-2.0', /Mozilla Public License,?\s+(Version|v\.?)\s*2\.0/i],
  ['MIT', /Permission is hereby granted, free of charge/i],
  ['ISC', /Permission to use, copy, modify, and\/or distribute this software/i],
  ['BSD-3-Clause', /Neither the name of/i],
  ['BSD-2-Clause', /Redistribution and use in source and binary forms/i],
  ['Unlicense', /This is free and unencumbered software released into the public domain/i],
]

function findFile(names, dirs = ['', '.github', 'docs']) {
  for (const dir of dirs) {
    const base = join(root, dir)
    if (!existsSync(base)) continue
    const hit = readdirSync(base).find((entry) => names.some((name) => entry.toLowerCase() === name.toLowerCase() || entry.toLowerCase().startsWith(`${name.toLowerCase()}.`)))
    if (hit) return join(dir, hit)
  }
  return null
}

function licenseOf(text) {
  return LICENSES.find(([, re]) => re.test(text))?.[0] ?? 'unknown'
}

/** SPDX ids compare loosely: AGPL-3.0, AGPL-3.0-only and AGPL-3.0-or-later share a family. */
const family = (id) => (id ?? '').replace(/-(only|or-later)$/i, '').replace(/\+$/, '').toUpperCase()

// ---------- Main ----------

async function main() {
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    process.stdout.write(`${JSON.stringify({ ok: false, error: `Not a directory: ${root}` }, null, 2)}\n`)
    process.exit(1)
  }
  const isRepo = run('git', ['rev-parse', '--is-inside-work-tree']) === 'true'
  const remote = isRepo ? run('git', ['remote', 'get-url', 'origin']) : null
  const branch = isRepo ? run('git', ['branch', '--show-current']) : null
  const commits = isRepo ? Number(run('git', ['rev-list', '--all', '--count']) ?? 0) : 0
  const tracked = isRepo ? (run('git', ['ls-files', '-z']) ?? '').split('\0').filter(Boolean) : []
  if (!isRepo) add('git', 'block', 'fail', 'Not a git repository', 'History, tracked-file and secret checks need git. Run git init, or point the scan at the repository root.')
  const dirty = isRepo ? (run('git', ['status', '--porcelain']) ?? '') : ''
  if (dirty) add('git-clean', 'info', 'fail', 'Uncommitted changes', 'The scan reads the working tree; uncommitted files are checked but are not what will be published.', dirty.split('\n').slice(0, MAX_EVIDENCE))

  // License
  const licensePath = findFile(['LICENSE', 'LICENCE', 'COPYING'], [''])
  const licenseText = licensePath ? readFileSync(join(root, licensePath), 'utf8') : ''
  const licenseId = licensePath ? licenseOf(licenseText) : null
  if (!licensePath) add('license', 'block', 'fail', 'No LICENSE file', 'Without a license, nobody may legally use, change or share the code, even when the repository is public.')
  else {
    const year = /copyright\s*(\(c\)|©)?\s*(\d{4})/i.exec(licenseText)?.[2]
    add('license', 'block', 'pass', `LICENSE found: ${licenseId}`, licenseId === 'unknown' ? 'The text did not match a common license; check it is complete and unmodified.' : year ? `Copyright year ${year}.` : '', [licensePath])
  }

  // README
  const readmePath = findFile(['README'], [''])
  if (!readmePath) add('readme', 'block', 'fail', 'No README', 'The README is the landing page of the repository.')
  else {
    const text = readFileSync(join(root, readmePath), 'utf8')
    const headings = text.split('\n').filter((line) => /^#{1,3} /.test(line)).map((line) => line.trim())
    const others = readdirSync(root).filter((entry) => /^readme[.-]/i.test(entry) && entry !== readmePath)
    const brokenImages = [...text.matchAll(/(?:!\[[^\]]*\]\(|<img[^>]+src=["'])([^)"'\s]+)/g)].map((m) => m[1]).filter((src) => !/^(https?:|data:)/.test(src) && !existsSync(join(root, dirname(readmePath), src.split('#')[0])))
    add('readme', 'block', 'pass', `README found (${text.length} chars)`, others.length ? `Other READMEs: ${others.join(', ')}` : '', [readmePath, ...headings])
    if (brokenImages.length) add('readme-links', 'warn', 'fail', 'README points to files that do not exist', '', brokenImages)
    if (!/licen[cs]e|许可|协议/i.test(text)) add('readme-license', 'warn', 'fail', 'README does not mention the license')
  }

  // Community files
  const community = [
    ['security', 'warn', ['SECURITY'], 'SECURITY.md', 'Tells people how to report a vulnerability privately instead of in a public issue.'],
    ['contributing', 'warn', ['CONTRIBUTING'], 'CONTRIBUTING.md', 'How to set up, test and send changes, and under what terms contributions are accepted.'],
    ['code-of-conduct', 'info', ['CODE_OF_CONDUCT'], 'CODE_OF_CONDUCT.md', 'Optional for a small project; GitHub shows it in the community profile.'],
    ['changelog', 'info', ['CHANGELOG', 'HISTORY'], 'CHANGELOG.md', 'Optional when GitHub Releases carry the notes.'],
  ]
  for (const [id, level, names, label, why] of community) {
    const path = findFile(names)
    add(id, level, path ? 'pass' : 'fail', path ? `${label} found` : `No ${label}`, path ? '' : why, path ? [path] : [])
  }
  const templates = ['.github/ISSUE_TEMPLATE', '.github/ISSUE_TEMPLATE.md', '.github/PULL_REQUEST_TEMPLATE.md', '.github/pull_request_template.md'].filter((path) => existsSync(join(root, path)))
  add('templates', 'info', templates.length ? 'pass' : 'fail', templates.length ? 'Issue or PR templates found' : 'No issue or PR templates', templates.length ? '' : 'Templates make bug reports arrive with versions and steps to reproduce.', templates)
  const dependabot = ['.github/dependabot.yml', '.github/dependabot.yaml', 'renovate.json', '.github/renovate.json'].find((path) => existsSync(join(root, path)))
  add('dependency-updates', 'info', dependabot ? 'pass' : 'fail', dependabot ? 'Dependency updates configured' : 'No Dependabot or Renovate config', '', dependabot ? [dependabot] : [])

  // .gitignore
  if (!existsSync(join(root, '.gitignore'))) add('gitignore', 'warn', 'fail', 'No .gitignore')
  else {
    const ignored = (path) => run('git', ['check-ignore', '-q', '--no-index', path]) !== null
    const wanted = ['.env', '.DS_Store', ...(existsSync(join(root, 'package.json')) ? ['node_modules/x'] : [])]
    const missing = isRepo ? wanted.filter((path) => !ignored(path)) : []
    add('gitignore', 'warn', missing.length ? 'fail' : 'pass', missing.length ? '.gitignore misses common entries' : '.gitignore covers .env and OS files', '', missing.map((path) => path.replace('/x', '/')))
  }

  // Sensitive files: tracked now, or ever added in history.
  const trackedSensitive = tracked.filter(isSensitive)
  add('tracked-sensitive', 'block', trackedSensitive.length ? 'fail' : 'pass', trackedSensitive.length ? 'Sensitive-looking files are tracked' : 'No sensitive-looking files tracked', trackedSensitive.length ? 'Remove them from git (git rm --cached) and add them to .gitignore. If they ever held real credentials, rotate those first.' : '', trackedSensitive)
  if (isRepo && !flags.has('--no-history')) {
    const everAdded = [...new Set((run('git', ['log', '--all', '--diff-filter=A', '--name-only', '--format=']) ?? '').split('\n').filter(Boolean))]
    const historySensitive = everAdded.filter((path) => isSensitive(path) && !tracked.includes(path))
    add('history-sensitive', 'block', historySensitive.length ? 'fail' : 'pass', historySensitive.length ? 'Sensitive-looking files exist in git history' : 'No sensitive-looking files in history', historySensitive.length ? 'Deleted files stay readable in history once the repository is public. Check what they held.' : '', historySensitive)
  }

  // Secrets and personal details in tracked files.
  const worktreeSecrets = []
  const personalPaths = []
  const privateIps = []
  for (const path of tracked) {
    const full = join(root, path)
    if (!existsSync(full) || LOCKFILES.test(path)) continue
    const stats = statSync(full)
    if (!stats.isFile() || stats.size > MAX_FILE_BYTES) continue
    const buffer = readFileSync(full)
    if (!isText(buffer)) continue
    buffer.toString('utf8').split('\n').forEach((line, index) => {
      const where = `${path}:${index + 1}`
      const secret = secretIn(line)
      if (secret) worktreeSecrets.push({ where, ...secret })
      if (PERSONAL_PATH.test(line) && !ALLOW.test(line)) personalPaths.push(where)
      if (PRIVATE_IP.test(line) && !ALLOW.test(line)) privateIps.push(where)
    })
  }
  add('secrets', 'block', worktreeSecrets.length ? 'fail' : 'pass', worktreeSecrets.length ? 'Possible secrets in tracked files' : 'No secrets found in tracked files', worktreeSecrets.length ? 'Check each one. A real credential must be revoked and replaced, not just deleted.' : '', worktreeSecrets)
  add('personal-paths', 'warn', personalPaths.length ? 'fail' : 'pass', personalPaths.length ? 'Personal file paths in tracked files' : 'No personal file paths', personalPaths.length ? 'Paths like /Users/<name>/ reveal a user name and machine layout.' : '', personalPaths)
  if (privateIps.length) add('private-ips', 'info', 'fail', 'Private network addresses in tracked files', 'Usually harmless, but check none describe a real internal network.', privateIps)

  // Secrets and large files in history.
  if (isRepo && !flags.has('--no-history')) {
    const historySecrets = await scanHistory(new Set(worktreeSecrets.map((hit) => `${hit.rule}|${hit.preview}`)))
    add('history-secrets', 'block', historySecrets.length ? 'fail' : 'pass', historySecrets.length ? 'Possible secrets in git history' : `No secrets found in history (${commits} commits)`, historySecrets.length ? 'Removed lines are still public in history. Revoke real credentials first, then decide whether to rewrite history or publish a fresh one.' : '', historySecrets)
    const objects = run('sh', ['-c', 'git rev-list --objects --all | git cat-file --batch-check="%(objecttype) %(objectsize) %(rest)"']) ?? ''
    const large = objects.split('\n').map((line) => line.split(' ')).filter(([type, size]) => type === 'blob' && Number(size) > LARGE_FILE_BYTES).map(([, size, ...path]) => `${path.join(' ')} (${(Number(size) / 1e6).toFixed(1)} MB)`)
    if (large.length) add('large-files', 'warn', 'fail', 'Large files in history', 'They make every clone slower. Consider Git LFS or removing them before the first public push.', large)
    const people = [...new Set((run('git', ['log', '--all', '--format=%an <%ae>%n%cn <%ce>']) ?? '').split('\n').filter(Boolean))]
    const exposed = people.filter((person) => !/noreply\.github\.com>$|<noreply@/i.test(person))
    add('author-emails', 'info', exposed.length ? 'fail' : 'pass', exposed.length ? 'Commit emails that will become public' : 'Commit emails use noreply addresses', exposed.length ? 'Every author and committer email in history is visible once public. Use a GitHub noreply address for future commits if that matters.' : '', exposed)
  }

  scanPackages(tracked, licenseId)
  scanSkills(tracked, licenseId)
  scanWorkflows(tracked)
  const github = flags.has('--no-github') ? null : scanGitHub(remote, branch)

  const order = { block: 0, warn: 1, info: 2 }
  findings.sort((a, b) => order[a.level] - order[b.level] || (a.status === 'fail' ? -1 : 1) - (b.status === 'fail' ? -1 : 1))
  const count = (level) => findings.filter((f) => f.level === level && f.status === 'fail').length
  process.stdout.write(
    `${JSON.stringify({ ok: true, repo: root, git: { isRepo, branch, remote, commits, tracked: tracked.length }, github, summary: { block: count('block'), warn: count('warn'), info: count('info') }, findings }, null, 2)}\n`,
  )
}

function scanHistory(seen) {
  return new Promise((resolvePromise) => {
    const hits = []
    const keys = new Set()
    const git = spawn('git', ['log', '--all', '-p', '-U0', '--no-color', '--no-ext-diff', '--format=%x00%H'], { cwd: root })
    let commit = ''
    let file = ''
    const lines = createInterface({ input: git.stdout })
    lines.on('line', (line) => {
      if (line.startsWith('\0')) commit = line.slice(1, 13)
      else if (line.startsWith('+++ ')) file = line.slice(4).replace(/^b\//, '')
      else if (line.startsWith('+') && !LOCKFILES.test(file) && line.length < 5000) {
        const secret = secretIn(line.slice(1))
        if (!secret) return
        const key = `${secret.rule}|${secret.preview}`
        if (keys.has(key)) return
        keys.add(key)
        hits.push({ commit, file, ...secret, stillInWorkingTree: seen.has(key) })
      }
    })
    git.on('close', () => resolvePromise(hits))
    git.on('error', () => resolvePromise(hits))
  })
}

function scanPackages(tracked, licenseId) {
  const manifests = tracked.filter((path) => basename(path) === 'package.json' && !path.includes('node_modules/'))
  for (const path of manifests) {
    let pkg
    try {
      pkg = JSON.parse(readFileSync(join(root, path), 'utf8'))
    } catch {
      add(`package:${path}`, 'warn', 'fail', `${path} is not valid JSON`)
      continue
    }
    const isRoot = path === 'package.json'
    const fields = isRoot ? ['name', 'description', 'license', 'repository', 'homepage', 'bugs', 'author', 'keywords'] : ['name', 'license']
    const missing = fields.filter((field) => pkg[field] === undefined || pkg[field] === '')
    const evidence = missing.map((field) => `missing: ${field}`)
    if (pkg.license && licenseId && licenseId !== 'unknown' && family(pkg.license) !== family(licenseId)) evidence.push(`license "${pkg.license}" does not match LICENSE (${licenseId})`)
    if (pkg.license === 'UNLICENSED') evidence.push('license is UNLICENSED, which means "all rights reserved"')
    if (isRoot && !['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'bun.lockb', 'bun.lock'].some((lock) => tracked.includes(lock))) evidence.push('no lockfile committed')
    if (isRoot && pkg.private !== true && !pkg.files) evidence.push('publishable to npm without a "files" list; check what npm pack would include')
    add(`package:${path}`, 'warn', evidence.length ? 'fail' : 'pass', evidence.length ? `${path} metadata is incomplete` : `${path} metadata is complete`, pkg.private ? 'private: true, so it cannot be published to npm by accident.' : '', evidence)
  }
}

function frontmatter(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text)
  if (!match) return null
  const data = {}
  for (const line of match[1].split('\n')) {
    const pair = /^([A-Za-z_-]+):\s*(.*)$/.exec(line)
    if (pair) data[pair[1]] = pair[2].replace(/^["']|["']$/g, '').trim()
  }
  return data
}

function scanSkills(tracked, licenseId) {
  for (const path of tracked.filter((entry) => basename(entry) === 'SKILL.md')) {
    const meta = frontmatter(readFileSync(join(root, path), 'utf8'))
    const folder = basename(dirname(path))
    const evidence = []
    if (!meta) evidence.push('no YAML frontmatter')
    else {
      if (!meta.name) evidence.push('missing: name')
      else {
        if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(meta.name) || meta.name.length > 64) evidence.push(`name "${meta.name}" should be lowercase letters, digits and hyphens, at most 64 characters`)
        if (dirname(path) !== '.' && meta.name !== folder) evidence.push(`name "${meta.name}" differs from its folder "${folder}"`)
      }
      if (!meta.description) evidence.push('missing: description')
      else if (meta.description.length > 1024) evidence.push(`description is ${meta.description.length} characters; the limit is 1024`)
      if (!meta.license) evidence.push('missing: license (the skill folder is often copied on its own, away from the repository LICENSE)')
      else if (licenseId && licenseId !== 'unknown' && !family(meta.license).includes(family(licenseId))) evidence.push(`license "${meta.license}" does not mention ${licenseId}`)
    }
    add(`skill:${path}`, 'warn', evidence.length ? 'fail' : 'pass', evidence.length ? `${path} frontmatter needs attention` : `${path} frontmatter is complete`, '', evidence)
  }
}

function scanWorkflows(tracked) {
  const workflows = tracked.filter((path) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(path))
  if (!workflows.length) return add('ci', 'warn', 'fail', 'No GitHub Actions workflows', 'A CI run on pull requests shows contributors their change builds and passes tests.')
  add('ci', 'warn', 'pass', `${workflows.length} workflow(s)`, '', workflows)
  const risky = []
  const unpinned = []
  for (const path of workflows) {
    const text = readFileSync(join(root, path), 'utf8')
    if (!/^permissions:/m.test(text)) risky.push(`${path}: no top-level permissions; the token gets the repository default`)
    if (/pull_request_target/.test(text)) risky.push(`${path}: uses pull_request_target; never check out or run the pull request's code in it`)
    if (/\$\{\{\s*github\.event\.(issue|pull_request|comment|review)[^}]*\.(title|body|head_ref|label)/.test(text)) risky.push(`${path}: interpolates untrusted event text into the workflow; pass it through env instead`)
    for (const match of text.matchAll(/uses:\s*([^\s@]+)@([^\s#]+)/g)) if (!/^[0-9a-f]{40}$/.test(match[2]) && !match[1].startsWith('./')) unpinned.push(`${path}: ${match[1]}@${match[2]}`)
  }
  add('workflow-safety', 'warn', risky.length ? 'fail' : 'pass', risky.length ? 'Workflow settings to review' : 'Workflows set permissions and avoid risky triggers', '', risky)
  if (unpinned.length) add('workflow-pinning', 'info', 'fail', 'Actions pinned to tags, not commit SHAs', 'Fine for a small project; OpenSSF Scorecard asks for SHAs because tags can be moved.', [...new Set(unpinned)])
}

function scanGitHub(remote, branch) {
  const slug = /github\.com[:/]([^/]+\/[^/.]+?)(\.git)?$/.exec(remote ?? '')?.[1]
  if (!slug) return { checked: false, reason: remote ? 'origin is not on github.com' : 'no origin remote' }
  if (!has('gh')) {
    add('github', 'info', 'skip', 'GitHub settings not checked', 'Install and sign in to the gh CLI to check visibility, private vulnerability reporting and branch protection.')
    return { checked: false, slug, reason: 'gh is not installed' }
  }
  const json = (...ghArgs) => {
    const out = run('gh', ghArgs)
    try {
      return out ? JSON.parse(out) : null
    } catch {
      return null
    }
  }
  /** A gh api call that keeps the HTTP status, so "off" and "not available" can be told apart. */
  const api = (path) => {
    try {
      const out = execFileSync('gh', ['api', path], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
      return { ok: true, status: 200, body: out.trim() ? JSON.parse(out) : null }
    } catch (error) {
      const status = Number(/HTTP (\d{3})/.exec(String(error.stderr ?? ''))?.[1] ?? 0)
      return { ok: false, status, body: null }
    }
  }
  const repo = json('repo', 'view', slug, '--json', 'visibility,description,homepageUrl,repositoryTopics,hasIssuesEnabled,defaultBranchRef')
  if (!repo) {
    add('github', 'info', 'skip', 'GitHub settings not checked', 'gh could not read the repository; run gh auth status.')
    return { checked: false, slug, reason: 'gh could not read the repository' }
  }
  const main = repo.defaultBranchRef?.name ?? branch ?? 'main'
  const isPrivate = repo.visibility !== 'PUBLIC'
  const reporting = api(`repos/${slug}/private-vulnerability-reporting`)
  const protection = api(`repos/${slug}/branches/${main}/protection`)
  const rules = api(`repos/${slug}/rules/branches/${main}`)
  const analysis = json('api', `repos/${slug}`, '--jq', '.security_and_analysis')
  const evidence = []
  // On a private repository of a free account several features answer 403/404 or null: not off, just unavailable until public.
  const later = []
  if (!repo.description) evidence.push('About: no description')
  if (!repo.homepageUrl) evidence.push('About: no website')
  if (!repo.repositoryTopics?.length) evidence.push('About: no topics')
  if (!repo.hasIssuesEnabled) evidence.push('Issues are turned off')
  if (reporting.ok) {
    if (!reporting.body?.enabled) evidence.push('Private vulnerability reporting is off')
  } else if (isPrivate) later.push('Private vulnerability reporting')
  const hasRules = rules.ok && Array.isArray(rules.body) && rules.body.length > 0
  if (protection.ok || hasRules) {
    // protected
  } else if (protection.status === 403 && isPrivate) later.push(`Branch protection or a ruleset on ${main}`)
  else evidence.push(`No branch protection or ruleset on ${main}`)
  if (analysis) {
    if (analysis.secret_scanning?.status === 'disabled') evidence.push('Secret scanning is off (free for public repositories)')
    if (analysis.secret_scanning_push_protection?.status === 'disabled') evidence.push('Push protection for secrets is off')
    if (analysis.dependabot_security_updates?.status === 'disabled') evidence.push('Dependabot security updates are off')
  } else if (isPrivate) later.push('Secret scanning, push protection and Dependabot security updates')
  add('github', 'warn', evidence.length ? 'fail' : 'pass', evidence.length ? 'GitHub settings to change' : 'GitHub settings look ready', '', evidence)
  if (later.length) add('github-after-public', 'info', 'fail', 'Turn on right after making the repository public', 'GitHub offers these on private repositories only with a paid plan, so they cannot be set yet. Enable them as soon as it is public.', later)
  return { checked: true, slug, visibility: repo.visibility, defaultBranch: main }
}

await main()
