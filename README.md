# oss-prep

An Agent Skill that checks a repository before it goes open source, then fills in what is missing once you say which items to do.

- **Scan.** `scripts/scan.mjs` is read-only and has no dependencies (Node 20+). It checks the license, README, community files, `.gitignore`, and package and SKILL.md metadata. It looks at workflow safety. It searches tracked files and the whole git history for secrets, sensitive files, personal paths and large files. With `gh` signed in, it also reads GitHub settings. The output is JSON.
- **Judge.** The agent reads the project for what a pattern cannot catch, such as private data in screenshots or fixtures, internal links, and a README that only makes sense to the author.
- **Report.** You get a list of blocking, should-fix and nice-to-have items, plus what is already in place and the GitHub settings you change yourself.
- **Fill in.** The agent writes only the items you pick, based on `assets/templates/` and adapted to the project. It never commits, pushes, rewrites history, changes settings or makes the repository public unless you ask.

## Install

```bash
ln -s ~/Github/oss-prep ~/.claude/skills/oss-prep
```

Then ask your agent something like "check this repo before I open source it", or "开源前检查一下".

## Run the scanner on its own

```bash
node scripts/scan.mjs path/to/repo            # everything
node scripts/scan.mjs path/to/repo --no-history --no-github
```

If [gitleaks](https://github.com/gitleaks/gitleaks) is installed, the skill also runs it, since gitleaks knows many more token formats. Add `oss-prep: allow` to a line to mark a match as intentional.

## Test

```bash
node --test tests/
```

The tests build throwaway repositories with randomly generated fake tokens, so the test files contain no token-shaped strings.

## License

[MIT](LICENSE).
