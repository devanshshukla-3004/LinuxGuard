from __future__ import annotations
import argparse
import json
import os
import platform
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def finding(check_id: str, title: str, status: str, severity: str, evidence: str, remediation: str) -> dict[str, str]:
    return {"id": check_id, "title": title, "status": status, "severity": severity, "evidence": evidence, "remediation": remediation}

def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None

def audit_system(root: Path = Path("/"), fixture: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read-only checks. root is a filesystem prefix useful for isolated fixtures."""
    checks: list[dict[str, str]] = []
    if fixture is not None:
        os_info = fixture.get("os", {})
        ssh_text = fixture.get("ssh_config")
        ufw_active = fixture.get("ufw_active")
        firewall_tool = fixture.get("firewall_tool")
        sensitive_paths = fixture.get("sensitive_paths", {})
    else:
        os_release = read_text(root / "etc/os-release") or ""
        os_info = {"name": next((m.group(1).strip('"') for m in re.finditer(r"(?m)^PRETTY_NAME=(.+)$", os_release)), platform.system())}
        ssh_text = read_text(root / "etc/ssh/sshd_config")
        ufw_path = root / "usr/sbin/ufw"
        nft_path = root / "usr/sbin/nft"
        iptables_path = root / "usr/sbin/iptables"
        firewall_tool = next((p.name for p in (ufw_path, nft_path, iptables_path) if p.exists()), None)
        ufw_output = shutil.which("ufw")
        ufw_active = None
        if ufw_output:
            # Do not invoke commands: status is unknown unless explicitly supplied.
            ufw_active = None
        sensitive_paths = {}
        for raw in ("/etc/shadow", "/etc/ssh/sshd_config"):
            p = root / raw.lstrip("/")
            try:
                mode = stat.S_IMODE(p.stat().st_mode)
                sensitive_paths[raw] = {"exists": True, "mode": oct(mode), "world_writable": bool(mode & stat.S_IWOTH)}
            except OSError:
                sensitive_paths[raw] = {"exists": False}

    checks.append(finding("LINUX-001", "Operating system identification", "PASS" if os_info.get("name") else "WARN", "INFO",
                          str(os_info.get("name") or "Distribution information unavailable"),
                          "Review /etc/os-release if distribution identification is needed."))
    if ssh_text is None:
        checks.append(finding("LINUX-002", "SSH daemon configuration", "NOT_APPLICABLE", "INFO",
                              "sshd_config not available at the inspected path",
                              "If this host runs OpenSSH server, locate and review its effective configuration."))
    else:
        root_values = []
        for line in ssh_text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0].lower() == "permitrootlogin":
                root_values.append(parts[1].lower())
        value = root_values[-1] if root_values else "default/unspecified"
        if value in {"no"}:
            status, severity = "PASS", "INFO"
        elif value in {"yes", "prohibit-password", "without-password"}:
            status, severity = "WARN", "MEDIUM"
        else:
            status, severity = "WARN", "LOW"
        checks.append(finding("LINUX-003", "SSH root-login policy", status, severity, f"PermitRootLogin: {value}",
                              "Prefer PermitRootLogin no unless a documented operational need requires otherwise; validate effective sshd configuration before changing it."))

    if firewall_tool:
        checks.append(finding("LINUX-004", "Firewall tooling present", "PASS", "INFO", f"Detected executable: {firewall_tool}",
                              "Confirm the firewall is enabled and its rules match the host's intended exposure."))
    else:
        checks.append(finding("LINUX-004", "Firewall tooling present", "WARN", "MEDIUM", "No common firewall executable found at inspected paths.",
                              "Check the distribution's firewall stack (for example nftables, ufw, or firewalld) and verify its active rules."))

    for raw, data in sorted(sensitive_paths.items()):
        if not data.get("exists"):
            checks.append(finding("LINUX-005", f"Sensitive file permissions: {raw}", "NOT_APPLICABLE", "INFO",
                                  "File not present or not accessible.", "Verify the path if the service is expected to be installed."))
        elif data.get("world_writable"):
            checks.append(finding("LINUX-006", f"World-writable sensitive file: {raw}", "FAIL", "HIGH",
                                  f"Reported mode: {data.get('mode', 'unknown')}", "Review ownership and permissions manually; do not apply changes blindly."))
        else:
            checks.append(finding("LINUX-006", f"Sensitive file permissions: {raw}", "PASS", "INFO",
                                  f"Reported mode: {data.get('mode', 'unknown')}", "Keep permissions restricted to the minimum required access."))

    status_weights = {"FAIL": 3, "WARN": 1, "PASS": 0, "ERROR": 2, "NOT_APPLICABLE": 0}
    applicable = [c for c in checks if c["status"] != "NOT_APPLICABLE"]
    max_score = max(1, len(applicable) * 3)
    risk_points = sum(status_weights.get(c["status"], 0) for c in applicable)
    score = round(100 * (1 - risk_points / max_score))
    return {"format": "LinuxGuard report v1", "mode": "fixture" if fixture is not None else "local-read-only",
            "system": os_info, "summary": {"checks": len(checks), "pass": sum(c["status"] == "PASS" for c in checks),
            "warn": sum(c["status"] == "WARN" for c in checks), "fail": sum(c["status"] == "FAIL" for c in checks),
            "errors": sum(c["status"] == "ERROR" for c in checks), "risk_score": max(0, min(100, score))},
            "checks": checks}

def main() -> int:
    parser = argparse.ArgumentParser(description="LinuxGuard — read-only Linux security configuration auditor")
    parser.add_argument("--input", type=Path, help="Audit a JSON fixture instead of inspecting local files")
    parser.add_argument("--root", type=Path, default=Path("/"), help="Filesystem prefix for read-only checks (default: /)")
    parser.add_argument("--output", type=Path, default=Path("reports/linuxguard-report.json"), help="JSON report path")
    args = parser.parse_args()
    try:
        fixture = json.loads(args.input.read_text(encoding="utf-8")) if args.input else None
        report = audit_system(args.root, fixture)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        s = report["summary"]
        print(f"LinuxGuard | {report['mode']}")
        print(f"Checks: {s['checks']} | PASS: {s['pass']} | WARN: {s['warn']} | FAIL: {s['fail']} | Risk score: {s['risk_score']}/100")
        for item in report["checks"]:
            print(f"[{item['status']}] {item['id']} {item['title']} — {item['evidence']}")
        print(f"JSON report: {args.output}")
        return 1 if s["fail"] or s["warn"] else 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
