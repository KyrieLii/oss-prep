# Checklist

What each scanner finding means, how to tell a real problem from noise, and the checks the scanner cannot do. Finding ids are in `code`.

## Contents

1. Leaks: secrets, sensitive files, personal details
2. License
3. README
4. Community files
5. Package and Agent Skill metadata
6. CI and workflows
7. GitHub settings
8. Judgment-only checks

## 1. Leaks

These are the only items that cannot be fixed after going public, so they are always blocking.

**`secrets`, `history-secrets`.** Pattern matches for API keys, tokens, private keys, credentials in URLs, and `password = "..."`-style assignments.
- Real or not: open the line (`git show <commit>:<path>` for history). A real key has high entropy and no placeholder words; check whether the provider's prefix is real (`sk-ant-api03-…`, `ghp_…`). Test fixtures, docs and example configs are usually fake, but confirm: people paste real keys into examples.
- `stillInWorkingTree: false` means the line was removed later but stays in history.
- A real credential, even an expired-looking one, means: revoke it at the provider, replace it, and only then clean history. Deleting the line does nothing for anyone who clones the history.

**`tracked-sensitive`, `history-sensitive`.** Files whose names suggest secrets or private data: `.env*` (not `.env.example`), keys and certificates, `.npmrc`, credential JSON, folders called `private` or `secrets`, `.DS_Store`. Open each one. `.DS_Store` leaks file names in that folder; low risk, still remove it.

**`personal-paths`.** `/Users/<name>/`, `/home/<name>/` or `C:\Users\<name>\` in tracked files reveal a user name and folder layout. Often in configs, docs, test snapshots and generated files. Replace with relative paths or `~`.

**`author-emails`.** Every author and committer email in history becomes public. Not a blocker; mention it if any address looks private (a work email, a personal address the user may not want indexed). Future commits can use `<id>+<user>@users.noreply.github.com`; rewriting old ones means rewriting history.

**`large-files`.** Blobs over 5 MB anywhere in history. They slow every clone forever; removing them later means rewriting history, so decide now.

**`private-ips`.** Addresses in 10.x, 172.16-31.x and 192.168.x. Usually examples; flag only if they look like a real internal network.

## 2. License

**`license`.** Without a license file the code is "all rights reserved": public, but nobody may legally use it. If missing, ask the user to choose; do not pick for them.

| License | One-line summary |
|---|---|
| MIT | Do anything, keep the notice. Simplest and most common. |
| Apache-2.0 | Like MIT, plus an explicit patent grant and NOTICE handling. |
| GPL-3.0 | Distributed changes must stay open under GPL. |
| AGPL-3.0 | Like GPL, and running a modified version as a network service also requires sharing source. |
| MPL-2.0 | Copyleft per file; can be combined with closed code. |
| Dual (e.g. AGPL + commercial) | Open under copyleft, with a paid license for closed use. Needs contributors to agree their work can be relicensed. |

Consistency: the same SPDX id should appear in the LICENSE text, `package.json` `license`, SKILL.md `license`, the README's license section and any file headers. The copyright line should name the right holder and a sensible year. If the project bundles third-party code, fonts, icons or images, check each one's license allows redistribution and keep their notices.

## 3. README

**`readme`** lists the headings. A stranger should find, near the top: what it is in one or two sentences, a screenshot or demo link, how to install and run it, and the license. Further down: how to develop and test, how to report problems, and limits or status (prototype, unmaintained). Check for internal jargon, private links (internal wikis, staging hosts, private boards), and instructions that only work on the author's machine.

**`readme-links`** lists relative image or link targets that do not exist. **`readme-license`**: the README never mentions the license.

## 4. Community files

- **`security`**: SECURITY.md with a private reporting route (GitHub private vulnerability reporting, or an email), what counts as in scope, and which versions get fixes. Pair it with enabling private vulnerability reporting.
- **`contributing`**: setup and test commands, branch and commit conventions if any, and the terms contributions are accepted under (important for dual-licensed projects).
- **`code-of-conduct`**, **`templates`**, **`changelog`**, **`dependency-updates`**: optional for a small personal project. Offer them; do not push them.

## 5. Package and Agent Skill metadata

**`package:<path>`.** For the root `package.json`: `name`, `description`, `license`, `repository`, `homepage`, `bugs`, `author`, `keywords`, a committed lockfile. If the package is not meant for npm, `"private": true` prevents an accidental publish. If it is meant for npm, a `files` list (or `.npmignore`) keeps tests, fixtures and private notes out of the tarball; check with `npm pack --dry-run`.

**`skill:<path>`.** SKILL.md frontmatter: `name` in lowercase-hyphen form matching its folder, a `description` of at most 1024 characters that says what it does and when to use it, and a `license` field, because skill folders are often copied without the repository LICENSE. If a skill ships built scripts, check they are rebuilt from the current source.

## 6. CI and workflows

- **`ci`**: at least one workflow that installs, type-checks or lints, tests and builds on pushes and pull requests.
- **`workflow-safety`**: a top-level `permissions:` block (start from `contents: read`); no `pull_request_target` that checks out or runs pull-request code; untrusted event text (issue titles, PR bodies, branch names) passed through `env:` instead of `${{ }}` inside `run:`.
- **`workflow-pinning`**: third-party actions pinned to a full commit SHA, with the tag in a comment. Optional; mention it as the OpenSSF Scorecard recommendation.

## 7. GitHub settings

**`github`** (needs `gh` signed in) lists settings that can be changed now. **`github-after-public`** lists features GitHub offers on private repositories only with a paid plan (private vulnerability reporting, branch protection and rulesets, secret scanning): they are not "off", they cannot be set yet. Put them in the report as the first steps right after the visibility switch.

Things to suggest, with commands the user can run:

```bash
# About section
gh repo edit OWNER/REPO --description "..." --homepage "https://..." --add-topic topic-one --add-topic topic-two
# Private vulnerability reporting
gh api -X PUT repos/OWNER/REPO/private-vulnerability-reporting
# Secret scanning and push protection (free on public repositories)
gh api -X PATCH repos/OWNER/REPO -f 'security_and_analysis[secret_scanning][status]=enabled' -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
# Dependabot security updates
gh api -X PUT repos/OWNER/REPO/automated-security-fixes
# Make it public: irreversible in practice, so last, after a final scan
gh repo edit OWNER/REPO --visibility public --accept-visibility-change-consequences
```

Branch protection is easiest in Settings → Rules → Rulesets: target the default branch, block force pushes and deletions, and require the CI check for pull requests. A solo maintainer who pushes straight to `main` may not want required reviews; say so instead of prescribing them.

## 8. Judgment-only checks

The scanner cannot see these; look for them yourself:

- Screenshots, recordings, fixtures or sample data with real people's data, account numbers or private UI. Sample data should be clearly fictional.
- Comments, TODOs, commit messages and docs that mention customers, employers, colleagues or internal systems.
- Files that are gitignored locally but that the project needs (`.env` keys, local configs): the README should say how to create them.
- Generated or vendored files committed by accident (`dist/`, coverage, `node_modules`).
- Trademarks and branding: names, logos or wording that imply an affiliation the project does not have.
- Claims in the README (performance, security, "production ready") that the project does not back up.
