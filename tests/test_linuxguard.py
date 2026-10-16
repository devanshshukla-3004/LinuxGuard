import json
import tempfile
import unittest
from pathlib import Path
from linuxguard import audit_system

class LinuxGuardTests(unittest.TestCase):
    def fixture(self):
        return {"os": {"name": "Test Linux"}, "ssh_config": "PermitRootLogin no\n",
                "ufw_active": True, "firewall_tool": "nft",
                "sensitive_paths": {"/etc/shadow": {"exists": True, "mode": "0o640", "world_writable": False}}}

    def test_secure_fixture_reports_pass(self):
        report = audit_system(fixture=self.fixture())
        self.assertEqual(report["mode"], "fixture")
        self.assertEqual(report["summary"]["fail"], 0)
        self.assertTrue(any(c["id"] == "LINUX-003" and c["status"] == "PASS" for c in report["checks"]))

    def test_root_login_yes_warns(self):
        data = self.fixture()
        data["ssh_config"] = "PermitRootLogin yes\n"
        report = audit_system(fixture=data)
        item = next(c for c in report["checks"] if c["id"] == "LINUX-003")
        self.assertEqual(item["status"], "WARN")
        self.assertEqual(item["severity"], "MEDIUM")

    def test_world_writable_sensitive_file_fails(self):
        data = self.fixture()
        data["sensitive_paths"]["/etc/shadow"]["world_writable"] = True
        data["sensitive_paths"]["/etc/shadow"]["mode"] = "0o666"
        report = audit_system(fixture=data)
        self.assertEqual(report["summary"]["fail"], 1)

    def test_missing_firewall_tool_warns(self):
        data = self.fixture()
        data["firewall_tool"] = None
        report = audit_system(fixture=data)
        item = next(c for c in report["checks"] if c["id"] == "LINUX-004")
        self.assertEqual(item["status"], "WARN")

    def test_missing_ssh_config_is_not_applicable(self):
        data = self.fixture()
        data["ssh_config"] = None
        report = audit_system(fixture=data)
        item = next(c for c in report["checks"] if c["id"] == "LINUX-002")
        self.assertEqual(item["status"], "NOT_APPLICABLE")

    def test_report_is_json_serializable(self):
        report = audit_system(fixture=self.fixture())
        self.assertEqual(json.loads(json.dumps(report))["format"], "LinuxGuard report v1")

if __name__ == "__main__":
    unittest.main()
