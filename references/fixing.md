# Filling in what is missing

Read before writing any file. Templates are in `assets/templates/`; each is a starting point, not a form to fill.

## General

- Read the project first: `package.json` scripts, the README, CI workflows, the LICENSE. Every command you write must be one that exists and works here. Run it if in doubt.
- Write in the README's language. If the README has an English and a Chinese version, give new top-level docs both, the same way (two files, or one file with both, matching what the project already does).
- Delete template sections that do not apply. A short accurate file beats a long generic one.
- Replace every `{{placeholder}}`. If you cannot fill one (a contact email, a company name), ask instead of guessing.
- Keep the existing tone and terminology; do not add badges, emojis or marketing copy the project does not already use.
- Never invent facts: supported versions, response times, maintainers, sponsors, users.

## Files

| Missing | Template | Notes |
|---|---|---|
| LICENSE | none | Ask which license. Fetch the official text (choosealicense.com, gnu.org, apache.org, or `gh api licenses/<spdx-id> --jq .body`); fill only the year and holder fields the license defines. |
| SECURITY.md | `SECURITY.md` | Prefer GitHub private vulnerability reporting; offer an email only if the user gives one. Scope should name the project's real attack surface (where it stores data, what it sends where). |
| CONTRIBUTING.md | `CONTRIBUTING.md` | Real setup, check and build commands. For dual-licensed projects keep the contribution-terms paragraph and match the README's wording. |
| CODE_OF_CONDUCT.md | none | Link to or copy the official Contributor Covenant 2.1 text from contributor-covenant.org with the user's contact method; do not retype it. |
| Issue templates | `ISSUE_TEMPLATE/` | Copy to `.github/ISSUE_TEMPLATE/`. Ask for the environment fields that matter here (browser and OS for a web app, Node version for a CLI). Point security reports to SECURITY.md in `config.yml`. |
| PR template | `PULL_REQUEST_TEMPLATE.md` | Copy to `.github/`. The checklist should name the project's real check commands. |
| Dependabot | `dependabot.yml` | Copy to `.github/`. Keep only the ecosystems the project uses; GitHub Actions is worth including whenever there are workflows. |
| CI workflow | `ci.yml` | Copy to `.github/workflows/`. Adapt install and check steps; keep `permissions: contents: read`. |
| `package.json` fields | none | Edit in place. `repository`, `homepage` and `bugs` come from the git remote; `author` from the LICENSE holder. Ask before setting `private` or `files`, since they decide what npm would publish. |
| `.gitignore` entries | none | Append; do not reorder the existing file. |

## Leaks

- **Tracked sensitive file:** `git rm --cached <path>`, add it to `.gitignore`, and say the file still exists in history.
- **Secret in the working tree:** move it to an environment variable or an ignored local file, document the variable (for example in `.env.example`), and tell the user to revoke the old value.
- **Secret or private file in history:** the user revokes it first. Then explain the two clean-up routes and let them choose:
  1. Rewrite history with `git filter-repo` (`--path <file> --invert-paths`, or `--replace-text`), then force-push. Every existing clone and fork keeps the old history, and commit hashes change.
  2. Publish a fresh repository: a new repository with one squashed initial commit of the current tree. Simplest when the history has no value to outsiders.
  Do not run either without a clear yes.
- **Personal paths:** replace with relative paths, `~`, or a placeholder; regenerate any generated file instead of hand-editing it.

## After fixing

Run the scanner again and report what changed. List what is still open and whose move it is (revoking keys, GitHub settings, the visibility switch). Do not commit unless asked; if asked, follow the repository's commit conventions.
