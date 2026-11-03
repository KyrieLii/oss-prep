// Builds throwaway repositories with planted, randomly generated fake leaks and checks what the scanner reports.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath } from 'node:url'

const scanner = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'scan.mjs')
const dirs = []
after(() => dirs.forEach((dir) => rmSync(dir, { recursive: true, force: true })))

const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const random = (length) => Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('')
// Built from parts so this file never holds a token-shaped string.
const fakeGithubToken = () => ['gh', 'p_', random(36)].join('')
const fakeAnthropicKey = () => ['sk', '-ant-', 'api03-', random(40)].join('')

function repo(files, { commits = [] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'oss-prep-'))
  dirs.push(dir)
  const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'ignore' })
  git('init', '-q', '-b', 'main')
  git('config', 'user.name', 'Test Person')
  git('config', 'user.email', 'test@example.com')
  git('config', 'commit.gpgsign', 'false')
  const write = (entries) => {
    for (const [path, content] of Object.entries(entries)) {
      mkdirSync(dirname(join(dir, path)), { recursive: true })
      if (content === null) rmSync(join(dir, path))
      else writeFileSync(join(dir, path), content)
    }
  }
  for (const step of [...commits, files]) {
    write(step)
    git('add', '-A')
    git('commit', '-q', '--allow-empty', '-m', 'step')
  }
  return dir
}

const scan = (dir, ...flags) => JSON.parse(execFileSync('node', [scanner, dir, '--no-github', ...flags], { encoding: 'utf8' }))
const finding = (result, id) => result.findings.find((entry) => entry.id === id)

test('an empty project fails the blocking file checks', () => {
  const result = scan(repo({ 'index.js': 'console.log(1)\n' }))
  assert.equal(finding(result, 'license').status, 'fail')
  assert.equal(finding(result, 'readme').status, 'fail')
  assert.equal(finding(result, 'secrets').status, 'pass')
})

test('finds a secret that was removed but stays in history, and a deleted .env', () => {
  const token = fakeGithubToken()
  const dir = repo(
    { 'config.js': 'export const token = process.env.TOKEN\n', '.env': null },
    { commits: [{ 'config.js': `export const token = '${token}'\n`, '.env': `KEY=${random(20)}\n` }] },
  )
  const result = scan(dir)
  assert.equal(finding(result, 'secrets').status, 'pass')
  const history = finding(result, 'history-secrets')
  assert.equal(history.status, 'fail')
  assert.equal(history.evidence[0].rule, 'github-token')
  assert.equal(history.evidence[0].stillInWorkingTree, false)
  assert.ok(!JSON.stringify(result).includes(token), 'the full token must not be printed')
  assert.deepEqual(finding(result, 'history-sensitive').evidence, ['.env'])
})

test('flags secrets and personal paths in the working tree, but not placeholders or allowed lines', () => {
  const result = scan(
    repo({
      'src/ai.ts': `const key = '${fakeAnthropicKey()}'\n`,
      'docs/setup.md': 'Run /Users/somebody/projects/app/run.sh\napi_key = "your-api-key-goes-here"\n', // oss-prep: allow
      'test/fixture.ts': `const sample = '${fakeGithubToken()}' // oss-prep: allow\n`,
    }),
  )
  const secrets = finding(result, 'secrets')
  assert.equal(secrets.evidence.length, 1)
  assert.equal(secrets.evidence[0].rule, 'anthropic-key')
  assert.equal(secrets.evidence[0].where, 'src/ai.ts:1')
  assert.deepEqual(finding(result, 'personal-paths').evidence, ['docs/setup.md:1'])
})

test('checks license consistency across LICENSE, package.json and SKILL.md', () => {
  const mit = 'MIT License\n\nCopyright (c) 2026 Someone\n\nPermission is hereby granted, free of charge, to any person\n'
  const result = scan(
    repo({
      LICENSE: mit,
      'README.md': '# App\n\nMIT licensed.\n',
      'package.json': JSON.stringify({ name: 'app', license: 'Apache-2.0', private: true }),
      'skills/My Skill/SKILL.md': '---\nname: my-skill\ndescription: Does a thing.\n---\n',
    }),
  )
  assert.equal(finding(result, 'license').title, 'LICENSE found: MIT')
  const pkg = finding(result, 'package:package.json')
  assert.ok(pkg.evidence.some((line) => line.includes('does not match LICENSE')))
  const skill = finding(result, 'skill:skills/My Skill/SKILL.md')
  assert.ok(skill.evidence.some((line) => line.includes('differs from its folder')))
  assert.ok(skill.evidence.some((line) => line.startsWith('missing: license')))
})

test('reviews workflow safety', () => {
  const result = scan(
    repo({
      '.github/workflows/ci.yml': 'on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v5\n      - run: echo "${{ github.event.pull_request.title }}"\n',
    }),
  )
  const safety = finding(result, 'workflow-safety')
  assert.equal(safety.status, 'fail')
  assert.equal(safety.evidence.length, 3)
  assert.equal(finding(result, 'workflow-pinning').status, 'fail')
})
