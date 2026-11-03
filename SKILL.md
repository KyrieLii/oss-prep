---
name: oss-prep
description: Check a repository before it goes open source and fill in what is missing - license, README, SECURITY.md, CONTRIBUTING, issue and PR templates, package and Agent Skill metadata, CI and workflow safety, secrets and personal details in files and in the whole git history, and GitHub settings such as private vulnerability reporting and branch protection. Use it whenever someone is about to make a repository public, publish a first release, asks "is this ready to open source", "开源前检查", "准备开源", "还缺什么", or wants the open-source boilerplate done, even if they only name one item such as a license or a security policy.
license: MIT
---

# Open-source prep

A pre-release pass for a repository that is about to become public. A script does the mechanical checks; you read the project, judge what the script cannot, report, and then fill in only what the user picks.

The order matters because one mistake cannot be undone: once a repository is public, everything in its history has been seen. Leaked credentials and personal data come first; boilerplate comes last.

## 1. Scan

Run the bundled scanner from the repository root (Node 20 or newer, no dependencies, read-only):

```bash
node <skill-dir>/scripts/scan.mjs <repo-dir>
```

It prints JSON: `summary` counts failing findings by level, and each finding has an `id`, a `level` (`block`, `warn`, `info`), a `status` (`pass`, `fail`, `skip`) and `evidence`. Add `--no-history` for a very large history only if the user agrees to skip that part, and say it was skipped. If `gitleaks` is installed, also run `gitleaks git <repo-dir> --redact --no-banner` and merge its findings; it knows many more token formats.

The scanner's secret rules are patterns, so expect false positives (test fixtures, documentation examples) and do not assume it caught everything. Look at every hit yourself before reporting it. A line can be marked intentional with an `oss-prep: allow` comment.

## 2. Read and judge

Read [references/checklist.md](references/checklist.md) for what each check means, how to tell a real problem from noise, and the checks only you can do. In short, beyond the script's findings:

- **What the history and files reveal.** Open each secret hit and each sensitive file in history (`git show <commit>:<path>`). Look for real names, emails, phone numbers, addresses, customer or financial data, internal hostnames, and screenshots with private data in docs or fixtures.
- **License consistency.** The LICENSE text, `package.json`, SKILL.md frontmatter, README and any per-file headers should agree. Note bundled third-party code, fonts or images and whether their licenses allow redistribution.
- **README for a stranger.** Someone arriving from a search should learn what it is, see it (a screenshot or demo link), install and run it, and find the license, without private context.
- **Things that only worked for the author.** Hard-coded local paths, `.env` values the project needs but does not document, scripts that assume the author's machine.

## 3. Report

Write the report in the user's language, in this shape:

```markdown
# Open-source readiness: <repo>

**Verdict:** <Ready / Ready after the blocking items / Not ready>, one sentence why.

## Blocking (fix before going public)
- ❌ <title>: <what was found, with file:line or commit> → <the fix>

## Should fix
- ⚠️ ...

## Nice to have
- 💡 ...

## Already in place
- ✅ <one line each, grouped>

## Needs you on GitHub
<settings the user changes themselves, with the exact gh command or settings path>
```

Put the most serious item first. Be specific: "`src/config.ts:12` has an OpenAI key, also in commit `a1b2c3d`" rather than "secrets found". Say what you did not check (no `gh`, history skipped, binary files).

Then ask which items to fill in. Offer the obvious set as the default ("all missing files"), and list each choice so the user can pick.

## 4. Fill in what the user picked

Use the templates in `assets/templates/` as a starting point and adapt them to this project; read [references/fixing.md](references/fixing.md) first. In short:

- **Write files, never publish.** Create or edit files in the working tree only. Do not commit, push, change repository visibility or settings, or create releases unless the user asks for that specific step.
- **Match the project.** Use its real commands, Node version, package manager, license and contact route; write in the README's language (both, if the README is bilingual). Leave out sections that do not apply rather than shipping placeholders.
- **Never choose a license for the user.** If there is none, explain the common choices in a sentence each (MIT, Apache-2.0, GPL-3.0, AGPL-3.0, dual licensing) and ask. Copy the official license text exactly; do not paraphrase or retype it from memory.
- **Secrets in history are not fixed by deleting the file.** The credential must be revoked and replaced first; that is the user's job in the provider's console. Rewriting history (`git filter-repo`) or publishing a fresh repository are their decision; explain both and do neither without a clear yes.
- **GitHub settings belong to the user.** Give the exact `gh` commands or settings paths from the reference; run them only if the user asks.

Finish by running the scanner again and showing which findings changed, plus what is still left for the user.
