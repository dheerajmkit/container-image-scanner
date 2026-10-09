# container-image-scanner — usage reference

## Installation

Python 3.10 or newer. The scanner itself needs nothing beyond the
standard library:

```bash
git clone https://github.com/dheerajmkit/container-image-scanner.git
cd container-image-scanner
python3 scan.py --help
```

To run the test suite, install pytest:

```bash
pip install -r requirements.txt
pytest -q
```

## Scanning a Dockerfile

```bash
python3 scan.py [Dockerfile]
```

Defaults to `./Dockerfile` when no path is given. The parser
understands multi-stage builds, backslash line continuations, and both
`ENV KEY=value` and legacy `ENV KEY value` forms.

## Scanning a built image config

Point `--image-config` at a `docker inspect` JSON dump (or a bare
config object) to lint what the image *actually* contains, not just
what the Dockerfile says:

```bash
docker inspect my-image:1.2.3 > inspect.json
python3 scan.py Dockerfile --image-config inspect.json
```

This enables the DKS101–DKS104 rules (runtime user, baked-in env
secrets, healthcheck, exposed ports).

## Report formats

| `--format` | Output |
| ---------- | ------ |
| `text` (default) | Human-readable findings, severities, and grade |
| `json` | Machine-readable report (grade, score, summary, findings) |
| `sarif` | SARIF 2.1.0 for GitHub code scanning / CI ingestion |
| `markdown` | Markdown report with the A–F grade and findings table |

```bash
python3 scan.py Dockerfile --format sarif > results.sarif
python3 scan.py Dockerfile --format markdown > report.md
```

## Gating builds (`--fail-on`)

Exit `1` when any finding meets or exceeds the threshold, `0`
otherwise, `2` on usage errors:

```bash
python3 scan.py Dockerfile --fail-on high   # default
python3 scan.py Dockerfile --fail-on never  # report only, never fail
```

Typical CI gate: fail the build on high-or-worse, but only warn on
medium/low. Secret values are never printed — findings name the
variable, never its value.

## Suppressing findings

### Inline comments

Append a trailing comment to the offending instruction. Multiple rules
are comma-separated:

```dockerfile
# this tarball layout is intentional and reviewed
ADD legacy-bundle.tar.gz /opt  # containerscan:ignore DKS004
```

### Config file

For pipeline-wide suppressions, pass a JSON config:

```bash
python3 scan.py Dockerfile --config scan.json
```

```json
{
  "ignore_rules": ["DKS006", "DKS007"],
  "fail_on": "high"
}
```

- `ignore_rules`: rule IDs suppressed in every scan (case-insensitive).
- `fail_on`: overrides the `--fail-on` default for this config.

An example ships at `samples/scan-config.example.json`.

## The A–F grade

The score starts at 100. Each finding subtracts a severity penalty:
critical −25, high −15, medium −5, low −2 (floored at 0). Grades:
A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

## Rule reference

See the README's rule tables, or run with `--format json` — every
finding includes its rule ID, severity, a plain-language detail, and a
remediation hint.

## CI example

`.github/workflows/ci.yml` shows the full pattern: install pytest,
run the suite, scan the samples (expecting findings on the vulnerable
one, a clean gate on the hardened one), and upload SARIF to GitHub
code scanning.
