#!/usr/bin/env python3
"""
container-image-scanner (day 3)
================================
A lightweight Dockerfile security linter written in pure Python 3
(standard library only).

Day 3 adds:
  * suppression config file (--config scan.json) with `ignore_rules`
    and a `fail_on` default,
  * Markdown report with the A-F image grade (--format markdown),
  * sample GitHub Actions CI workflow (.github/workflows/ci.yml),
  * full usage documentation (USAGE.md).

Day 2 added image-config scanning (DKS101-DKS104) and SARIF output.
Day 1 added the Dockerfile parser and DKS001-DKS007 rules.

Dockerfile rules:

  DKS001  running as root (no USER, or USER root)            HIGH
  DKS002  base image uses :latest (or untagged)              MEDIUM
  DKS003  secrets baked into ENV / ARG                       CRITICAL
  DKS004  ADD used instead of COPY                           MEDIUM
  DKS005  sensitive port exposed via EXPOSE                  MEDIUM
  DKS006  missing HEALTHCHECK                                LOW
  DKS007  bloated package install (no cleanup flags)         LOW

Image-config rules:

  DKS101  image runs as root (Config.User empty/root)        HIGH
  DKS102  secret in image env (Config.Env)                   CRITICAL
  DKS103  image has no healthcheck                           LOW
  DKS104  sensitive port in Config.ExposedPorts               MEDIUM

This is a personal portfolio project exploring shift-left container
security. It is a learning exercise, not a production tool, and it has
never been deployed at any employer.
"""

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass

VERSION = "0.3.0"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
GRADE_PENALTY = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2}

# Ports that should (almost) never be reachable from a container image.
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    6380: "Redis (TLS)",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB (shard)",
    5601: "Kibana",
    5984: "CouchDB",
    9200: "Elasticsearch",
    9300: "Elasticsearch (cluster)",
}

SECRET_NAME_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|credential)",
    re.IGNORECASE,
)

IGNORE_COMMENT_RE = re.compile(
    r"#\s*containerscan\s*:\s*ignore\s*=?\s*([A-Za-z0-9_,\s]+)",
    re.IGNORECASE,
)


@dataclass
class Instruction:
    """A single parsed Dockerfile instruction."""

    keyword: str  # upper-cased, e.g. "FROM"
    args: str  # everything after the keyword
    line: int  # 1-based line number where the instruction starts
    raw: str  # the full (continuation-joined) source line


@dataclass
class Finding:
    """One rule violation."""

    rule_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    title: str
    detail: str
    line: int | None
    remediation: str
    source: str = "dockerfile"

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "line": self.line,
            "remediation": self.remediation,
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# Dockerfile parsing
# ---------------------------------------------------------------------------

def parse_dockerfile(text):
    """Parse Dockerfile text into a list of Instruction objects.

    Handles backslash line continuations and skips blank lines and
    full-line comments.
    """
    instructions = []
    buf = ""
    buf_start = 0
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.rstrip()
        if stripped.endswith("\\"):
            if not buf:
                buf_start = lineno
            buf += stripped[:-1] + " "
            continue
        if buf:
            logical = buf + stripped
            start_line = buf_start
            buf = ""
        else:
            logical = stripped
            start_line = lineno
        code = logical.strip()
        if not code or code.startswith("#"):
            continue
        keyword, _, args = code.partition(" ")
        instructions.append(
            Instruction(
                keyword=keyword.upper(),
                args=args.strip(),
                line=start_line,
                raw=logical.strip(),
            )
        )
    return instructions


def parse_key_values(argstr):
    """Parse `ENV`/`ARG` arguments into (name, value) pairs.

    Supports both `KEY=value` and legacy `KEY value` forms, with
    shell-like quoting.
    """
    try:
        tokens = shlex.split(argstr)
    except ValueError:
        tokens = argstr.split()
    pairs = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if "=" in token:
            name, _, value = token.partition("=")
            pairs.append((name, value))
            i += 1
        elif i + 1 < len(tokens):
            pairs.append((token, tokens[i + 1]))
            i += 2
        else:
            pairs.append((token, ""))
            i += 1
    return pairs


def inline_ignored_rules(raw):
    """Return rule IDs suppressed by a trailing containerscan comment."""
    match = IGNORE_COMMENT_RE.search(raw)
    if not match:
        return set()
    return {
        part.strip().upper()
        for part in match.group(1).split(",")
        if part.strip()
    }


def is_url(value):
    return value.startswith(("http://", "https://", "ftp://"))


# ---------------------------------------------------------------------------
# Rules (Dockerfile)
# ---------------------------------------------------------------------------

def rule_root_user(instructions):
    """DKS001 — the image runs as root unless a non-root USER is set."""
    users = [ins for ins in instructions if ins.keyword == "USER"]
    if not users:
        return [
            Finding(
                rule_id="DKS001",
                severity="HIGH",
                title="Container runs as root",
                detail=(
                    "No USER instruction found; processes in the container "
                    "will run as root (uid 0) by default."
                ),
                line=None,
                remediation=(
                    "Create a non-root user (e.g. 'RUN useradd -r appuser') "
                    "and add 'USER appuser' before CMD/ENTRYPOINT."
                ),
            )
        ]
    last = users[-1]
    user = last.args.split()[0] if last.args else ""
    if user in ("root", "0"):
        return [
            Finding(
                rule_id="DKS001",
                severity="HIGH",
                title="Container runs as root",
                detail=f"Final USER instruction sets the user to '{user}'.",
                line=last.line,
                remediation="Switch to a non-root user for runtime: 'USER appuser'.",
            )
        ]
    return []


def rule_latest_tag(instructions):
    """DKS002 — FROM pins :latest (or no tag), so builds are not reproducible."""
    findings = []
    for ins in instructions:
        if ins.keyword != "FROM":
            continue
        ref = ins.args.split()[0] if ins.args else ""
        if not ref or ref.lower() == "scratch":
            continue
        if "@" in ref:
            continue  # digest-pinned: immutable regardless of tag
        name = ref.split("@")[0]  # drop any digest pin
        slash = name.rfind("/")
        colon = name.rfind(":")
        tag = name[colon + 1:] if colon > slash else None
        if tag is None or tag.lower() == "latest":
            findings.append(
                Finding(
                    rule_id="DKS002",
                    severity="MEDIUM",
                    title="Base image uses :latest tag",
                    detail=(
                        f"FROM '{ref}' does not pin a specific version; "
                        "rebuilds may silently pull a different base image."
                    ),
                    line=ins.line,
                    remediation=(
                        "Pin an immutable tag (e.g. 'python:3.12-slim-bookworm') "
                        "or, better, a digest ('image@sha256:...')."
                    ),
                )
            )
    return findings


def rule_secrets_in_env(instructions):
    """DKS003 — credentials baked into ENV/ARG end up in image history."""
    findings = []
    for ins in instructions:
        if ins.keyword not in ("ENV", "ARG"):
            continue
        for name, _value in parse_key_values(ins.args):
            if SECRET_NAME_RE.search(name):
                findings.append(
                    Finding(
                        rule_id="DKS003",
                        severity="CRITICAL",
                        title="Secret baked into image",
                        # Never echo the value — image layers are forever.
                        detail=(
                            f"{ins.keyword} '{name}' looks like a credential. "
                            "Values are stored in plaintext in image layers "
                            "and build history."
                        ),
                        line=ins.line,
                        remediation=(
                            "Use BuildKit secrets ('RUN --mount=type=secret') "
                            "for build-time values and a runtime secret store "
                            "(vault, cloud KMS) for the running container."
                        ),
                    )
                )
    return findings


def rule_add_instead_of_copy(instructions):
    """DKS004 — ADD has surprising behaviour (tar auto-extract, remote URLs)."""
    findings = []
    for ins in instructions:
        if ins.keyword != "ADD":
            continue
        try:
            tokens = shlex.split(ins.args)
        except ValueError:
            tokens = ins.args.split()
        operands = [t for t in tokens if not t.startswith("--")]
        srcs = operands[:-1] if len(operands) >= 2 else []
        if any(is_url(s) for s in srcs):
            detail = (
                f"ADD fetches remote URL(s) ({', '.join(srcs)}); the download "
                "cannot be checksum-verified by the Dockerfile reader."
            )
            remediation = (
                "Use curl/wget with an explicit checksum in a RUN step, "
                "then COPY the verified artifact."
            )
        else:
            detail = (
                f"ADD '{' '.join(srcs) if srcs else ins.args}' copies local "
                "files; ADD also auto-extracts archives, which is a common "
                "source of surprises."
            )
            remediation = "Use COPY for local files — it does exactly one thing."
        findings.append(
            Finding(
                rule_id="DKS004",
                severity="MEDIUM",
                title="ADD used instead of COPY",
                detail=detail,
                line=ins.line,
                remediation=remediation,
            )
        )
    return findings


def rule_exposed_sensitive_ports(instructions):
    """DKS005 — EXPOSE on a database/admin port widens the attack surface."""
    findings = []
    for ins in instructions:
        if ins.keyword != "EXPOSE":
            continue
        for token in ins.args.split():
            port_part = token.split("/")[0]
            if not port_part.isdigit():
                continue
            port = int(port_part)
            if port in SENSITIVE_PORTS:
                findings.append(
                    Finding(
                        rule_id="DKS005",
                        severity="MEDIUM",
                        title="Sensitive port exposed",
                        detail=(
                            f"EXPOSE {port} ({SENSITIVE_PORTS[port]}) publishes "
                            "a service that should not be reachable from the "
                            "container network."
                        ),
                        line=ins.line,
                        remediation=(
                            "Remove the EXPOSE, or bind the service to "
                            "localhost / a private network instead."
                        ),
                    )
                )
    return findings


def rule_missing_healthcheck(instructions):
    """DKS006 — no HEALTHCHECK means orchestrators cannot detect a sick app."""
    if any(ins.keyword == "HEALTHCHECK" for ins in instructions):
        return []
    return [
        Finding(
            rule_id="DKS006",
            severity="LOW",
            title="Missing HEALTHCHECK",
            detail=(
                "No HEALTHCHECK instruction; orchestrators cannot tell a "
                "hung process from a healthy one."
            ),
            line=None,
            remediation=(
                "Add e.g. 'HEALTHCHECK --interval=30s CMD curl -f "
                "http://localhost:8080/health || exit 1'."
            ),
        )
    ]


def rule_package_install_bloat(instructions):
    """DKS007 — package installs without cleanup flags bloat the image."""
    findings = []
    for ins in instructions:
        if ins.keyword != "RUN":
            continue
        cmd = ins.args
        if re.search(r"apt-get\s+.*\binstall\b", cmd) and "--no-install-recommends" not in cmd:
            findings.append(
                Finding(
                    rule_id="DKS007",
                    severity="LOW",
                    title="apt-get install without --no-install-recommends",
                    detail="Pulls recommended (often unneeded) packages, bloating the image.",
                    line=ins.line,
                    remediation=(
                        "Use 'apt-get install -y --no-install-recommends ...' "
                        "and clean up with 'rm -rf /var/lib/apt/lists/*' in "
                        "the same RUN layer."
                    ),
                )
            )
        if re.search(r"\bapk\s+add\b", cmd) and "--no-cache" not in cmd:
            findings.append(
                Finding(
                    rule_id="DKS007",
                    severity="LOW",
                    title="apk add without --no-cache",
                    detail="Leaves the apk package cache inside the image layer.",
                    line=ins.line,
                    remediation="Use 'apk add --no-cache ...'.",
                )
            )
        if re.search(r"\b(yum|dnf)\s+install\b", cmd) and "clean all" not in cmd:
            findings.append(
                Finding(
                    rule_id="DKS007",
                    severity="LOW",
                    title="yum/dnf install without cache cleanup",
                    detail="Package manager caches remain in the image layer.",
                    line=ins.line,
                    remediation="Append '&& yum clean all' (or 'dnf clean all') to the RUN step.",
                )
            )
    return findings


DOCKERFILE_RULES = [
    rule_root_user,
    rule_latest_tag,
    rule_secrets_in_env,
    rule_add_instead_of_copy,
    rule_exposed_sensitive_ports,
    rule_missing_healthcheck,
    rule_package_install_bloat,
]


# ---------------------------------------------------------------------------
# Image-config (docker inspect) scanning
# ---------------------------------------------------------------------------

def load_image_config(path):
    """Load a `docker inspect`-style image config file.

    Accepts either the full inspect array ([{... "Config": {...}}]) or a
    bare config object ({"User": ..., "Env": [...], ...}).
    """
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        if not data:
            raise ValueError("image config list is empty")
        data = data[0]
    if isinstance(data, dict) and "Config" in data and isinstance(data["Config"], dict):
        return data["Config"]
    if isinstance(data, dict):
        return data
    raise ValueError("unrecognised image config shape")


def scan_image_config(config):
    """Run the DKS1xx rules over an image config dict."""
    findings = []
    user = str(config.get("User") or "").strip()
    if user in ("", "root", "0"):
        findings.append(
            Finding(
                rule_id="DKS101",
                severity="HIGH",
                title="Image runs as root",
                detail="Config.User is empty or root; containers start as uid 0.",
                line=None,
                remediation=(
                    "Set a non-root USER in the Dockerfile so Config.User is "
                    "populated at build time."
                ),
                source="image-config",
            )
        )
    for entry in config.get("Env") or []:
        name, _, _value = entry.partition("=")
        if SECRET_NAME_RE.search(name):
            findings.append(
                Finding(
                    rule_id="DKS102",
                    severity="CRITICAL",
                    title="Secret in image environment",
                    detail=(
                        f"Config.Env '{name}' looks like a credential baked "
                        "into the image."
                    ),
                    line=None,
                    remediation=(
                        "Inject secrets at runtime (orchestrator secrets, "
                        "vault agent) instead of baking them into the image."
                    ),
                    source="image-config",
                )
            )
    exposed = config.get("ExposedPorts") or {}
    for key in exposed:
        port_part = str(key).split("/")[0]
        if port_part.isdigit() and int(port_part) in SENSITIVE_PORTS:
            findings.append(
                Finding(
                    rule_id="DKS104",
                    severity="MEDIUM",
                    title="Sensitive port exposed",
                    detail=(
                        f"ExposedPorts includes {port_part} "
                        f"({SENSITIVE_PORTS[int(port_part)]})."
                    ),
                    line=None,
                    remediation="Do not publish database/admin ports from the image.",
                    source="image-config",
                )
            )
    healthcheck = config.get("Healthcheck")
    if not healthcheck or not healthcheck.get("Test"):
        findings.append(
            Finding(
                rule_id="DKS103",
                severity="LOW",
                title="Image has no healthcheck",
                detail="Config.Healthcheck is missing; orchestrators cannot probe liveness.",
                line=None,
                remediation="Add a HEALTHCHECK instruction to the Dockerfile.",
                source="image-config",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Suppressions
# ---------------------------------------------------------------------------

def apply_suppressions(instructions, findings):
    """Drop findings suppressed by inline `# containerscan:ignore` comments."""
    ignored = {}  # line -> set(rule_id)
    for ins in instructions:
        rules = inline_ignored_rules(ins.raw)
        if rules:
            ignored.setdefault(ins.line, set()).update(rules)
    kept = []
    for finding in findings:
        if finding.line is not None and finding.rule_id in ignored.get(finding.line, set()):
            continue
        kept.append(finding)
    return kept


def load_scan_config(path):
    """Load a JSON suppression config file.

    Supported keys:
      ignore_rules: list of rule IDs to suppress everywhere,
      fail_on:      default severity gate (critical/high/medium/low/never).
    """
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("config file must contain a JSON object")
    ignore_rules = data.get("ignore_rules", []) or []
    if not isinstance(ignore_rules, list) or not all(
        isinstance(r, str) for r in ignore_rules
    ):
        raise ValueError("'ignore_rules' must be a list of rule ID strings")
    fail_on = data.get("fail_on")
    if fail_on is not None and str(fail_on).lower() not in (
        "critical", "high", "medium", "low", "never",
    ):
        raise ValueError("'fail_on' must be critical/high/medium/low/never")
    return {
        "ignore_rules": {r.upper() for r in ignore_rules},
        "fail_on": str(fail_on).lower() if fail_on else None,
    }


def apply_config_suppressions(findings, ignore_rules):
    """Drop every finding whose rule ID is listed in the config file."""
    if not ignore_rules:
        return findings
    return [f for f in findings if f.rule_id.upper() not in ignore_rules]


def scan_dockerfile(text):
    """Run every Dockerfile rule; returns (instructions, findings)."""
    instructions = parse_dockerfile(text)
    findings = []
    for rule in DOCKERFILE_RULES:
        findings.extend(rule(instructions))
    return instructions, apply_suppressions(instructions, findings)


# ---------------------------------------------------------------------------
# Grading and reporting
# ---------------------------------------------------------------------------

def grade_findings(findings):
    """Return (grade, score): score starts at 100, penalties per severity."""
    score = 100
    for finding in findings:
        score -= GRADE_PENALTY.get(finding.severity, 0)
    score = max(0, score)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return grade, score


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.line or 0, f.rule_id),
    )


def summarize(findings):
    counts = {sev: 0 for sev in SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def format_text(findings, target):
    grade, score = grade_findings(findings)
    counts = summarize(findings)
    lines = [
        f"container-image-scanner v{VERSION} — {target}",
        "=" * 60,
    ]
    if not findings:
        lines.append("No findings. Image looks clean.")
    for finding in sort_findings(findings):
        where = f"line {finding.line}" if finding.line is not None else finding.source
        lines.append(f"[{finding.rule_id}] {finding.severity:<8} {where}")
        lines.append(f"  {finding.title}: {finding.detail}")
        lines.append(f"  -> {finding.remediation}")
        lines.append("")
    lines.append("-" * 60)
    parts = ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITIES)
    lines.append(f"{len(findings)} findings ({parts}) | Grade: {grade} ({score}/100)")
    return "\n".join(lines)


def format_json(findings, target):
    grade, score = grade_findings(findings)
    payload = {
        "tool": "container-image-scanner",
        "version": VERSION,
        "target": target,
        "grade": grade,
        "score": score,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2)


SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

RULE_HELP = {
    "DKS001": "Run containers as a non-root user.",
    "DKS002": "Pin base images to an immutable tag or digest.",
    "DKS003": "Never bake secrets into image layers.",
    "DKS004": "Prefer COPY over ADD.",
    "DKS005": "Do not expose database/admin ports.",
    "DKS006": "Define a HEALTHCHECK.",
    "DKS007": "Use package-manager cleanup flags to keep layers small.",
    "DKS101": "Set a non-root Config.User.",
    "DKS102": "Never bake secrets into image environment.",
    "DKS103": "Define a healthcheck for the image.",
    "DKS104": "Do not expose database/admin ports.",
}


def format_sarif(findings, target):
    """Render findings as SARIF 2.1.0 (for GitHub code scanning etc.)."""
    rules = []
    seen = set()
    for finding in sort_findings(findings):
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.remediation},
                    "help": {"text": RULE_HELP.get(finding.rule_id, finding.remediation)},
                    "properties": {"severity": finding.severity},
                }
            )
    results = []
    for finding in sort_findings(findings):
        region = {}
        if finding.line is not None:
            region = {"startLine": finding.line}
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": f"{finding.title}: {finding.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target},
                            "region": region,
                        }
                    }
                ],
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "container-image-scanner",
                        "version": VERSION,
                        "informationUri": "https://github.com/dheerajmkit/container-image-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def format_markdown(findings, target):
    """Render a Markdown report with the A-F image grade."""
    from datetime import datetime, timezone

    grade, score = grade_findings(findings)
    counts = summarize(findings)
    stamped = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Container Image Scan Report",
        "",
        f"**Target:** `{target}`",
        f"**Scanned:** {stamped}",
        f"**Grade:** {grade} ({score}/100)",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| -------- | ----- |",
    ]
    for severity in SEVERITIES:
        lines.append(f"| {severity} | {counts[severity]} |")
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No findings. Image looks clean.")
    else:
        lines += [
            "| Rule | Severity | Location | Finding | Remediation |",
            "| ---- | -------- | -------- | ------- | ----------- |",
        ]
        for finding in sort_findings(findings):
            where = (
                f"line {finding.line}"
                if finding.line is not None
                else finding.source
            )
            # Keep table cells on one line.
            detail = " ".join(finding.detail.split())
            remediation = " ".join(finding.remediation.split())
            lines.append(
                f"| {finding.rule_id} | {finding.severity} | {where} | "
                f"**{finding.title}** — {detail} | {remediation} |"
            )
    lines += [
        "",
        "## Grade scale",
        "",
        "Score starts at 100. Penalties: critical −25, high −15, medium −5, "
        "low −2. A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.",
        "",
        f"*Generated by container-image-scanner v{VERSION}*",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Lint a Dockerfile and/or image config for container "
        "security anti-patterns."
    )
    parser.add_argument(
        "dockerfile",
        nargs="?",
        default="Dockerfile",
        help="Path to the Dockerfile to scan (default: ./Dockerfile).",
    )
    parser.add_argument(
        "--image-config",
        metavar="PATH",
        default=None,
        help="Also scan a `docker inspect`-style image config JSON file.",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="JSON suppression config file with 'ignore_rules' and 'fail_on'.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif", "markdown"),
        default="text",
        help="Report format (default: text).",
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "never"),
        default="high",
        help=(
            "Exit 1 when a finding at or above this severity exists "
            "(default: high). 'never' always exits 0 on a clean parse."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        with open(args.dockerfile, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        print(f"error: cannot read '{args.dockerfile}': {exc.strerror}", file=sys.stderr)
        return 2

    _instructions, findings = scan_dockerfile(text)
    target = args.dockerfile

    if args.image_config:
        try:
            config = load_image_config(args.image_config)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: cannot parse image config '{args.image_config}': {exc}",
                  file=sys.stderr)
            return 2
        findings.extend(scan_image_config(config))
        target = f"{args.dockerfile} + {args.image_config}"

    fail_on = args.fail_on
    if args.config:
        try:
            scan_config = load_scan_config(args.config)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: cannot parse config '{args.config}': {exc}",
                  file=sys.stderr)
            return 2
        findings = apply_config_suppressions(findings, scan_config["ignore_rules"])
        if scan_config["fail_on"]:
            fail_on = scan_config["fail_on"]

    if args.format == "json":
        print(format_json(findings, target))
    elif args.format == "sarif":
        print(format_sarif(findings, target))
    elif args.format == "markdown":
        print(format_markdown(findings, target))
    else:
        print(format_text(findings, target))

    if fail_on == "never":
        return 0
    threshold = SEVERITY_RANK[fail_on.upper()]
    worst = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
