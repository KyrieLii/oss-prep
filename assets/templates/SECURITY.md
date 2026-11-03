# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through [GitHub's private vulnerability reporting]({{repo_url}}/security/advisories/new) (the **Security** tab → **Report a vulnerability**).

Include what you found, how to reproduce it, and what an attacker could do with it. You will get a reply as soon as the maintainer can look at it; this is a {{personal / small team}} project, so there is no guaranteed response time.

## Scope

{{Describe the real attack surface in two to four bullets. Examples:}}
- {{Where user data is stored and who can read it.}}
- {{What the project sends to other services, and when.}}
- {{Supply-chain parts: published packages, release archives, CI workflows.}}

Out of scope: {{e.g. problems that need an already compromised device or browser, or issues in third-party services themselves}}.

## Supported versions

Fixes go into the latest release and the `{{default_branch}}` branch.
