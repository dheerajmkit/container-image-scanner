# container-image-scanner

A lightweight Dockerfile security linter written in pure Python 3
(standard library only). It parses a Dockerfile and flags common
container security anti-patterns — running as root, `:latest` tags,
secrets baked into `ENV`/`ARG`, `ADD` instead of `COPY`, exposed
sensitive ports, missing `HEALTHCHECK`, and bloated package installs —
*before* the image gets built.

This is a **personal portfolio project** exploring shift-left container
security. It is a learning exercise, not a production tool, and it has
never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 scan.py [Dockerfile] [--format text|json] [--fail-on critical|high|medium|low|never]
```

Example:

```bash
$ python3 scan.py Dockerfile
container-image-scanner v0.1.0 — Dockerfile
============================================================
[DKS003] CRITICAL line 4
  Secret baked into image: ARG 'AWS_SECRET_ACCESS_KEY' looks like a credential. Values are stored in plaintext in image layers and build history.
  -> Use BuildKit secrets ('RUN --mount=type=secret') for build-time values and a runtime secret store (vault, cloud KMS) for the running container.

[DKS001] HIGH     Dockerfile
  Container runs as root: No USER instruction found; processes in the container will run as root (uid 0) by default.
  -> Create a non-root user (e.g. 'RUN useradd -r appuser') and add 'USER appuser' before CMD/ENTRYPOINT.

------------------------------------------------------------
8 findings (2 critical, 1 high, 3 medium, 2 low) | Grade: F (16/100)
```

JSON output for CI pipelines:

```bash
python3 scan.py Dockerfile --format json
```

The exit code is `1` when a finding at or above `--fail-on`
(default: `high`) exists, `0` when the image is clean enough, and `2`
on a usage error — so the scanner can gate a build step. Secret
*values* are never echoed; only the variable name appears in output.

## What it detects (day 1)

| Rule | Anti-pattern | Severity |
| ---- | ------------ | -------- |
| `DKS001` | No `USER` instruction (or `USER root`) — container runs as root | HIGH |
| `DKS002` | `FROM` uses `:latest` or an untagged base image | MEDIUM |
| `DKS003` | Secret-like name in `ENV` / `ARG` (password, token, api_key, …) | CRITICAL |
| `DKS004` | `ADD` used instead of `COPY` (tar auto-extract, remote URLs) | MEDIUM |
| `DKS005` | `EXPOSE` of a sensitive port (22, 3306, 5432, 6379, 27017, …) | MEDIUM |
| `DKS006` | No `HEALTHCHECK` instruction | LOW |
| `DKS007` | Package install without cleanup flags (`--no-install-recommends`, `--no-cache`) | LOW |

Every finding carries a rule ID, a severity, and a remediation hint.
Findings roll up into an image grade: **A** (≥90), **B** (≥80),
**C** (≥70), **D** (≥60), **F** (<60), starting from 100 with
per-severity penalties (critical −25, high −15, medium −5, low −2).

## Project layout

```
scan.py            # CLI entry point + parser + rules + reporters
requirements.txt   # stdlib only — nothing to install
```

## Roadmap

- **Day 2:** scan `docker inspect`-style image config JSON, SARIF output,
  pytest unit tests, sample Dockerfiles.
- **Day 3:** allowlist / suppression config, Markdown report with grade,
  sample GitHub Actions CI workflow, full usage docs.
