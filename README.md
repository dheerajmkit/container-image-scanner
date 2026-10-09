# container-image-scanner

[![CI](https://github.com/dheerajmkit/container-image-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/dheerajmkit/container-image-scanner/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight Dockerfile and container image security linter written in
pure Python 3 (standard library only). It parses a Dockerfile — and,
optionally, a `docker inspect`-style image config — and flags common
container security anti-patterns *before* the image gets built or
shipped: running as root, `:latest` tags, secrets baked into
`ENV`/`ARG`, `ADD` instead of `COPY`, exposed database ports, missing
`HEALTHCHECK`, and bloated package installs.

This is a **personal portfolio project** exploring shift-left container
security. It is a learning exercise, not a production tool, and it has
never been deployed at any employer.

## Quickstart

No dependencies to install for scanning — the standard library is all
you need:

```bash
python3 scan.py [Dockerfile] [options]
```

```bash
# Scan a Dockerfile
python3 scan.py samples/Dockerfile.vulnerable

# Scan a Dockerfile AND its built image config together
python3 scan.py samples/Dockerfile.clean --image-config samples/image-config.clean.json

# SARIF output for GitHub code scanning / CI ingestion
python3 scan.py Dockerfile --format sarif > results.sarif

# Markdown report with the A–F image grade
python3 scan.py Dockerfile --format markdown > report.md
```

## Example output

```text
$ python3 scan.py samples/Dockerfile.vulnerable
container-image-scanner v0.3.0 — samples/Dockerfile.vulnerable
============================================================
[DKS003] CRITICAL line 5
  Secret baked into image: ARG 'AWS_SECRET_ACCESS_KEY' looks like a credential. Values are stored in plaintext in image layers and build history.
  -> Use BuildKit secrets ('RUN --mount=type=secret') for build-time values and a runtime secret store (vault, cloud KMS) for the running container.

[DKS001] HIGH     dockerfile
  Container runs as root: No USER instruction found; processes in the container will run as root (uid 0) by default.
  -> Create a non-root user (e.g. 'RUN useradd -r appuser') and add 'USER appuser' before CMD/ENTRYPOINT.

[DKS002] MEDIUM   line 3
  Base image uses :latest tag: FROM 'python:latest' does not pin a specific version; rebuilds may silently pull a different base image.
  -> Pin an immutable tag (e.g. 'python:3.12-slim-bookworm') or, better, a digest ('image@sha256:...').

------------------------------------------------------------
8 findings (2 critical, 1 high, 3 medium, 2 low) | Grade: F (16/100)
```

The exit code is `1` when a finding at or above `--fail-on`
(default: `high`) exists, `0` when the image is clean enough, and `2`
on a usage error — so the scanner can gate a build step. Secret
*values* are never echoed; only the variable name appears in output.

## What it detects

### Dockerfile rules

| Rule | Anti-pattern | Severity |
| ---- | ------------ | -------- |
| `DKS001` | No `USER` instruction (or `USER root`) — container runs as root | HIGH |
| `DKS002` | `FROM` uses `:latest` or an untagged base image | MEDIUM |
| `DKS003` | Secret-like name in `ENV` / `ARG` (password, token, api_key, …) | CRITICAL |
| `DKS004` | `ADD` used instead of `COPY` (tar auto-extract, remote URLs) | MEDIUM |
| `DKS005` | `EXPOSE` of a sensitive port (22, 3306, 5432, 6379, 27017, …) | MEDIUM |
| `DKS006` | No `HEALTHCHECK` instruction | LOW |
| `DKS007` | Package install without cleanup flags (`--no-install-recommends`, `--no-cache`) | LOW |

### Image-config rules (`--image-config`)

| Rule | Anti-pattern | Severity |
| ---- | ------------ | -------- |
| `DKS101` | `Config.User` empty or root — image runs as root | HIGH |
| `DKS102` | Secret-like name in `Config.Env` | CRITICAL |
| `DKS103` | No `Config.Healthcheck` | LOW |
| `DKS104` | Sensitive port in `Config.ExposedPorts` | MEDIUM |

Every finding carries a rule ID, a severity, and a remediation hint.
Findings roll up into an image grade: **A** (≥90), **B** (≥80),
**C** (≥70), **D** (≥60), **F** (<60), starting from 100 with
per-severity penalties (critical −25, high −15, medium −5, low −2).

## Suppressing findings

Two mechanisms, for two audiences:

**Inline** — a trailing comment on the offending instruction (for the
Dockerfile author):

```dockerfile
ADD legacy-bundle.tar.gz /opt  # containerscan:ignore DKS004
```

**Config file** — `--config scan.json` (for the pipeline owner):

```json
{
  "ignore_rules": ["DKS006", "DKS007"],
  "fail_on": "high"
}
```

See `samples/scan-config.example.json` and the full reference in
[USAGE.md](USAGE.md).

## CI integration

A sample GitHub Actions workflow ships under
[.github/workflows/ci.yml](.github/workflows/ci.yml): it runs the
pytest suite, scans the sample Dockerfiles (gating on the clean one),
and uploads SARIF to GitHub code scanning.

## Project layout

```
scan.py                  # CLI entry point: parser + rules + reporters
samples/                 # vulnerable + clean Dockerfiles, image configs,
                         #   and an example suppression config
tests/                   # pytest unit tests (47 tests)
.github/workflows/ci.yml # sample CI: tests + scan + SARIF upload
USAGE.md                 # full usage reference
requirements.txt         # pytest for tests only; the scanner is stdlib-only
LICENSE                  # MIT
```

Run the test suite:

```bash
pip install -r requirements.txt
pytest -q
```

## Changelog

- **v0.3.0 (day 3):** suppression config file, Markdown report with
  grade, sample CI workflow, USAGE.md.
- **v0.2.0 (day 2):** image-config JSON scanning (DKS101–DKS104), SARIF
  output, pytest suite, sample files.
- **v0.1.0 (day 1):** Dockerfile parser, DKS001–DKS007 rules, text/JSON
  reports, A–F grading.
