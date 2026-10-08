# container-image-scanner

A lightweight Dockerfile and container image security linter written in
pure Python 3 (standard library only). It parses a Dockerfile — and,
optionally, a `docker inspect`-style image config — and flags common
container security anti-patterns *before* the image gets built or
shipped.

This is a **personal portfolio project** exploring shift-left container
security. It is a learning exercise, not a production tool, and it has
never been deployed at any employer.

## Quickstart

No dependencies to install for scanning — the standard library is all
you need:

```bash
python3 scan.py [Dockerfile] [--image-config config.json] [--format text|json|sarif] [--fail-on critical|high|medium|low|never]
```

Scan a Dockerfile:

```bash
python3 scan.py samples/Dockerfile.vulnerable
```

Scan a Dockerfile **and** its built image config together:

```bash
python3 scan.py samples/Dockerfile.clean --image-config samples/image-config.clean.json
```

Emit SARIF for GitHub code scanning / CI ingestion:

```bash
python3 scan.py Dockerfile --format sarif > results.sarif
```

The exit code is `1` when a finding at or above `--fail-on`
(default: `high`) exists, `0` when the image is clean enough, and `2`
on a usage error — so the scanner can gate a build step. Secret
*values* are never echoed; only the variable name appears in output.

## What it detects

### Dockerfile rules (day 1)

| Rule | Anti-pattern | Severity |
| ---- | ------------ | -------- |
| `DKS001` | No `USER` instruction (or `USER root`) — container runs as root | HIGH |
| `DKS002` | `FROM` uses `:latest` or an untagged base image | MEDIUM |
| `DKS003` | Secret-like name in `ENV` / `ARG` (password, token, api_key, …) | CRITICAL |
| `DKS004` | `ADD` used instead of `COPY` (tar auto-extract, remote URLs) | MEDIUM |
| `DKS005` | `EXPOSE` of a sensitive port (22, 3306, 5432, 6379, 27017, …) | MEDIUM |
| `DKS006` | No `HEALTHCHECK` instruction | LOW |
| `DKS007` | Package install without cleanup flags (`--no-install-recommends`, `--no-cache`) | LOW |

### Image-config rules (day 2)

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

## Project layout

```
scan.py            # CLI entry point: parser + rules + reporters
samples/           # vulnerable + clean Dockerfiles and image configs
tests/             # pytest unit tests (41 tests)
requirements.txt   # pytest for tests only; the scanner is stdlib-only
```

Run the test suite:

```bash
pip install -r requirements.txt
pytest -q
```

## Roadmap

- **Day 3:** allowlist / suppression config file, Markdown report with
  grade, sample GitHub Actions CI workflow, full usage docs.
