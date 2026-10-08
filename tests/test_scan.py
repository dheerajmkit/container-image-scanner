"""Unit tests for container-image-scanner (day 2).

Run with:  pytest -q   (or: python3 -m pytest -q)
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scan


def findings_for(dockerfile_text):
    _instructions, findings = scan.scan_dockerfile(dockerfile_text)
    return findings


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def test_parser_skips_comments_and_blanks():
    instructions = scan.parse_dockerfile("# comment\n\nFROM ubuntu:22.04\n")
    assert [(i.keyword, i.args) for i in instructions] == [("FROM", "ubuntu:22.04")]


def test_parser_joins_continuations():
    text = "RUN apt-get update \\\n    && apt-get install -y curl\n"
    instructions = scan.parse_dockerfile(text)
    assert len(instructions) == 1
    assert instructions[0].keyword == "RUN"
    assert "apt-get install -y curl" in instructions[0].args
    assert instructions[0].line == 1


def test_parser_multi_stage():
    text = "FROM golang:1.22 AS builder\nRUN go build .\nFROM debian:12-slim\nCOPY --from=builder /app /app\n"
    instructions = scan.parse_dockerfile(text)
    assert [i.keyword for i in instructions] == ["FROM", "RUN", "FROM", "COPY"]


# ---------------------------------------------------------------------------
# DKS001 — root user
# ---------------------------------------------------------------------------

def test_dks001_no_user_is_high():
    findings = findings_for("FROM ubuntu:22.04\n")
    assert "DKS001" in rule_ids(findings)
    finding = next(f for f in findings if f.rule_id == "DKS001")
    assert finding.severity == "HIGH"


def test_dks001_explicit_root_is_high():
    findings = findings_for("FROM ubuntu:22.04\nUSER root\n")
    assert "DKS001" in rule_ids(findings)


def test_dks001_non_root_is_clean():
    findings = findings_for("FROM ubuntu:22.04\nRUN useradd -r appuser\nUSER appuser\n")
    assert "DKS001" not in rule_ids(findings)


# ---------------------------------------------------------------------------
# DKS002 — latest tag
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "from_line,expected",
    [
        ("FROM ubuntu", True),
        ("FROM ubuntu:latest", True),
        ("FROM ubuntu:LATEST", True),
        ("FROM ubuntu:22.04", False),
        ("FROM scratch", False),
        ("FROM ubuntu:22.04 AS base", False),
        ("FROM ubuntu@sha256:abc123", False),
        ("FROM registry.local:5000/team/app:1.2.3", False),
        ("FROM registry.local:5000/team/app", True),
    ],
)
def test_dks002_tag_pinning(from_line, expected):
    findings = findings_for(from_line + "\n")
    assert ("DKS002" in rule_ids(findings)) == expected


# ---------------------------------------------------------------------------
# DKS003 — secrets in ENV/ARG
# ---------------------------------------------------------------------------

def test_dks003_env_secret_is_critical():
    findings = findings_for('FROM ubuntu:22.04\nENV DB_PASSWORD=hunter2\n')
    assert "DKS003" in rule_ids(findings)
    finding = next(f for f in findings if f.rule_id == "DKS003")
    assert finding.severity == "CRITICAL"
    # The value must never be echoed back.
    assert "hunter2" not in finding.detail
    assert "hunter2" not in scan.format_text(findings, "t")


def test_dks003_arg_token_is_critical():
    findings = findings_for("FROM ubuntu:22.04\nARG GITHUB_TOKEN=ghp_x\n")
    assert "DKS003" in rule_ids(findings)


def test_dks003_benign_env_is_clean():
    findings = findings_for("FROM ubuntu:22.04\nENV APP_ENV=production\nENV PORT=8080\n")
    assert "DKS003" not in rule_ids(findings)


# ---------------------------------------------------------------------------
# DKS004 — ADD instead of COPY
# ---------------------------------------------------------------------------

def test_dks004_add_local_is_medium():
    findings = findings_for("FROM ubuntu:22.04\nADD app.tar.gz /app\n")
    assert "DKS004" in rule_ids(findings)
    finding = next(f for f in findings if f.rule_id == "DKS004")
    assert finding.severity == "MEDIUM"


def test_dks004_copy_is_clean():
    findings = findings_for("FROM ubuntu:22.04\nCOPY app.tar.gz /app\n")
    assert "DKS004" not in rule_ids(findings)


# ---------------------------------------------------------------------------
# DKS005 — sensitive ports
# ---------------------------------------------------------------------------

def test_dks005_sensitive_port():
    findings = findings_for("FROM ubuntu:22.04\nEXPOSE 8080 5432\n")
    assert "DKS005" in rule_ids(findings)


def test_dks005_benign_port_is_clean():
    findings = findings_for("FROM ubuntu:22.04\nEXPOSE 8080\n")
    assert "DKS005" not in rule_ids(findings)


# ---------------------------------------------------------------------------
# DKS006 — missing HEALTHCHECK
# ---------------------------------------------------------------------------

def test_dks006_missing():
    findings = findings_for("FROM ubuntu:22.04\n")
    assert "DKS006" in rule_ids(findings)


def test_dks006_present_is_clean():
    findings = findings_for(
        "FROM ubuntu:22.04\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
    )
    assert "DKS006" not in rule_ids(findings)


# ---------------------------------------------------------------------------
# DKS007 — package install bloat
# ---------------------------------------------------------------------------

def test_dks007_apt_without_flag():
    findings = findings_for("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n")
    assert "DKS007" in rule_ids(findings)


def test_dks007_apt_with_flag_is_clean():
    findings = findings_for(
        "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y --no-install-recommends curl\n"
    )
    assert "DKS007" not in rule_ids(findings)


def test_dks007_apk_without_no_cache():
    findings = findings_for("FROM alpine:3.20\nRUN apk add curl\n")
    assert "DKS007" in rule_ids(findings)


# ---------------------------------------------------------------------------
# Image-config rules (DKS101-DKS104)
# ---------------------------------------------------------------------------

def _config(**overrides):
    base = {
        "User": "appuser",
        "Env": ["APP_ENV=production"],
        "ExposedPorts": {"8080/tcp": {}},
        "Healthcheck": {"Test": ["CMD-SHELL", "curl -f http://localhost/ || exit 1"]},
    }
    base.update(overrides)
    return base


def test_dks101_root_user():
    findings = scan.scan_image_config(_config(User=""))
    assert "DKS101" in rule_ids(findings)
    assert "DKS101" in rule_ids(scan.scan_image_config(_config(User="root")))
    assert "DKS101" not in rule_ids(scan.scan_image_config(_config()))


def test_dks102_secret_in_env():
    findings = scan.scan_image_config(_config(Env=["DB_PASSWORD=x"]))
    assert "DKS102" in rule_ids(findings)
    finding = next(f for f in findings if f.rule_id == "DKS102")
    assert finding.severity == "CRITICAL"


def test_dks103_missing_healthcheck():
    findings = scan.scan_image_config(_config(Healthcheck=None))
    assert "DKS103" in rule_ids(findings)


def test_dks104_sensitive_port():
    findings = scan.scan_image_config(_config(ExposedPorts={"6379/tcp": {}}))
    assert "DKS104" in rule_ids(findings)


def test_load_image_config_accepts_inspect_array(tmp_path):
    path = tmp_path / "inspect.json"
    path.write_text(json.dumps([{"Config": _config(), "Id": "sha256:abc"}]))
    config = scan.load_image_config(str(path))
    assert config["User"] == "appuser"


def test_load_image_config_accepts_bare_config(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(_config()))
    config = scan.load_image_config(str(path))
    assert config["User"] == "appuser"


# ---------------------------------------------------------------------------
# Grading, sorting, output formats
# ---------------------------------------------------------------------------

def test_grade_clean_is_a():
    grade, score = scan.grade_findings([])
    assert (grade, score) == ("A", 100)


def test_grade_penalties():
    critical = scan.Finding("DKS003", "CRITICAL", "t", "d", 1, "r")
    grade, score = scan.grade_findings([critical])
    assert (grade, score) == ("C", 75)
    high = scan.Finding("DKS001", "HIGH", "t", "d", 1, "r")
    grade, _score = scan.grade_findings([critical, high])
    assert grade == "D"


def test_findings_sorted_by_severity():
    low = scan.Finding("DKS006", "LOW", "t", "d", 1, "r")
    crit = scan.Finding("DKS003", "CRITICAL", "t", "d", 2, "r")
    ordered = scan.sort_findings([low, crit])
    assert [f.rule_id for f in ordered] == ["DKS003", "DKS006"]


def test_json_output_shape():
    findings = findings_for("FROM ubuntu:latest\n")
    payload = json.loads(scan.format_json(findings, "Dockerfile"))
    assert payload["tool"] == "container-image-scanner"
    assert payload["grade"] in ("A", "B", "C", "D", "F")
    assert isinstance(payload["findings"], list)
    assert all("rule_id" in f and "remediation" in f for f in payload["findings"])


def test_sarif_output_shape():
    findings = findings_for("FROM ubuntu:latest\n")
    sarif = json.loads(scan.format_sarif(findings, "Dockerfile"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "container-image-scanner"
    assert run["results"]
    assert all("ruleId" in r and "level" in r for r in run["results"])


# ---------------------------------------------------------------------------
# Suppressions
# ---------------------------------------------------------------------------

def test_inline_suppression_drops_finding():
    text = "FROM ubuntu:22.04\nADD app.tar.gz /app  # containerscan:ignore DKS004\n"
    findings = findings_for(text)
    assert "DKS004" not in rule_ids(findings)


def test_inline_suppression_only_affects_named_rule():
    text = "FROM ubuntu:latest  # containerscan:ignore DKS001\n"
    findings = findings_for(text)
    assert "DKS002" in rule_ids(findings)  # latest-tag still reported


# ---------------------------------------------------------------------------
# CLI exit codes
# ---------------------------------------------------------------------------

def test_cli_exit_codes(tmp_path, capsys):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM ubuntu:latest\nUSER appuser\n")
    assert scan.main([str(dockerfile), "--fail-on", "never"]) == 0
    assert scan.main([str(dockerfile), "--fail-on", "high"]) == 0  # only MEDIUM+LOW
    assert scan.main([str(dockerfile), "--fail-on", "low"]) == 1
    capsys.readouterr()
    assert scan.main([str(tmp_path / "missing")]) == 2
