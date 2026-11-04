import os, sys, unittest, tempfile, shutil
sys.path.insert(0, "/tmp/constantine")
from core.auth.auth_manager import AuthManager
from core.engine.vault import QuarantineVault
from core.engine.phishing import PhishingShield
from core.engine.scanner import Scanner
from core.engine.dns_manager import DNSManager
from core.engine.system_whitelist import SystemWhitelist

class TestConstantine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.auth = AuthManager()
        self.vault = QuarantineVault(vault_dir=os.path.join(self.tmp, "vault"))
        self.phishing = PhishingShield()
        self.scanner = Scanner()
        self.whitelist = SystemWhitelist()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_auth_native_system(self):
        # Comprobar detección de usuario
        user = self.auth.get_current_user()
        self.assertIsNotNone(user)

        # Simular token de sesión válido
        token = "test_valid_token_123"
        self.auth.active_sessions[token] = 9999999999.0
        self.assertTrue(self.auth.is_session_valid(token))
        self.auth.revoke_session(token)
        self.assertFalse(self.auth.is_session_valid(token))

    def test_system_whitelist(self):
        self.assertTrue(self.whitelist.is_trusted_system_binary("/usr/bin/python3"))
        self.assertTrue(self.whitelist.is_trusted_system_binary("/bin/bash"))
        self.assertFalse(self.whitelist.is_trusted_system_binary("/tmp/malware.sh"))
        self.assertFalse(self.whitelist.is_trusted_system_binary("/home/user/script.py"))

    def test_vault(self):
        fpath = os.path.join(self.tmp, "bad.sh")
        with open(fpath, "wb") as f:
            f.write(b"badcontent")
        vid = self.vault.quarantine_file(fpath, "Malware.Test")
        self.assertIsNotNone(vid)
        self.assertFalse(os.path.exists(fpath))
        items = self.vault.list_items()
        self.assertEqual(len(items), 1)
        self.assertTrue(self.vault.restore_file(vid))
        self.assertTrue(os.path.exists(fpath))

    def test_phishing(self):
        self.assertFalse(self.phishing.analyze_url("https://google.com").is_phishing)
        self.assertTrue(self.phishing.analyze_url("http://g00gle-verify.xyz/account").is_phishing)
        self.assertTrue(self.phishing.analyze_url("http://192.168.1.1/confirm-banking").is_phishing)

    def test_dns_manager(self):
        dm = DNSManager(state_file=os.path.join(self.tmp, "dns_state.json"))
        profiles = dm.get_profiles()
        self.assertIn("mullvad-base", profiles)
        self.assertIn("quad9-partner", profiles)
        applied = dm.apply_profile("mullvad-adblock")
        self.assertTrue(applied)

if __name__ == "__main__":
    unittest.main()

    def test_update_guard(self):
        from core.engine.update_guard import SystemUpdateGuard
        ug = SystemUpdateGuard()
        info = ug.check_pending_updates()
        self.assertIn("has_updates", info)
        self.assertIn("current_kernel", info)

    def test_new_commercial_modules(self):
        from core.engine.audit_logger import AuditLogger
        al = AuditLogger(log_path=os.path.join(self.tmp, "audit.json"))
        al.record_incident("Trojan.Test", "/tmp/bad.sh", "FAN_DENY")
        incidents = al.get_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["threat"], "Trojan.Test")
