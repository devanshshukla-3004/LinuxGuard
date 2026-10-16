# LinuxGuard — Linux System Security Auditor

**Day 13/100 · 100 Days, 100 Cybersecurity Projects**

LinuxGuard is an offline-first, read-only Python CLI for reviewing selected Linux security configuration signals. It emits evidence-backed PASS/WARN/FAIL/NOT_APPLICABLE results and a JSON report. It is a learning tool, not a complete CIS benchmark or compliance scanner.

## Checks included
- Distribution identification from OS metadata
- SSH `PermitRootLogin` setting when a readable `sshd_config` is available
- Presence of common firewall tooling at inspected paths (presence does not prove the firewall is enabled)
- World-writable status of selected sensitive files when their metadata is accessible
- JSON output with summary, severity, evidence, and remediation guidance

## Requirements
- Python 3.10+
- Standard library only; no third-party runtime dependencies

## Run a synthetic, offline demo

    python linuxguard.py --input samples/sample_system.json --output reports/demo-report.json

The fixture is synthetic and intentionally includes warning conditions. Its results do not describe your real machine.

## Run the tests

    python -m unittest discover -s tests -v

## Inspect the local system
Run on a Linux host:

    python linuxguard.py --output reports/linuxguard-report.json

Some checks depend on permissions and distribution layout. The tool does not execute privileged commands or modify system settings. The `--root` option allows read-only checks against an alternate filesystem prefix, useful for isolated test fixtures.

## Exit codes
- `0`: no WARN or FAIL results
- `1`: at least one WARN or FAIL result
- `2`: input, parsing, or filesystem error

## Security limitations
- This tool checks a small set of signals, not all Linux hardening controls.
- Finding a firewall executable does not establish that filtering is enabled or configured correctly.
- SSH configuration parsing is intentionally simple and does not resolve all OpenSSH `Include`, `Match`, or effective-configuration rules. Confirm results with trusted system administration procedures.
- A missing or unreadable file may produce NOT_APPLICABLE or a warning; review the evidence before drawing conclusions.
- Recommendations are guidance, not automatic remediation. LinuxGuard never changes firewall, SSH, or file permissions.

## Structure

    LinuxGuard/
    ├── linuxguard.py
    ├── tests/test_linuxguard.py
    ├── samples/sample_system.json
    ├── reports/
    ├── requirements.txt
    └── LICENSE

## License
MIT
