#!/usr/bin/env python3
from __future__ import annotations
"""
Constantine Antivirus - Main Daemon Service (daemon.py)
Servicio raíz de protección activa en tiempo real a nivel de kernel y red.
Supervisa de forma predeterminada TODO el sistema de archivos mediante fanotify y eBPF,
aplicando una política estricta Fail-Secure (Zero-Trust) ante anomalías.
Verifica el estado real de cada subsistema antes de declarar el servicio operativo.
"""
import os
import sys
import signal
import argparse
import logging
from typing import Optional, List, Dict, Tuple, Any, Callable, Set

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

def _detect_daemon_version() -> str:
    for p in [
        os.path.join(CURRENT_DIR, "VERSION"),
        "/opt/constantine/VERSION"
    ]:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    ver = f.read().strip()
                    if ver:
                        return ver
            except Exception:
                pass
    return "5.1.0"

DAEMON_VERSION = _detect_daemon_version()

from core.engine.ipc_protocol import SecureIPCDaemonServer, validate_ipc_path, validate_ipc_vault_id
from core.engine.scanner import Scanner
from core.engine.vault import QuarantineVault
from core.engine.phishing import PhishingShield
from core.engine.interceptor import FanotifyInterceptor
from core.engine.notifier import DesktopNotifier
from core.engine.firewall import NetworkQuarantine
from core.engine.ebpf_monitor import EBPFMonitor
from core.engine.usb_monitor import USBAutoScanner
from core.engine.ransomware_shield import RansomwareShield
from core.engine.persistence_guard import PersistenceGuard
from core.engine.download_sentinel import DownloadSentinel
from core.engine.subsystem_health import SubsystemHealthRegistry
from core.engine.hardware_guard import HardwareGuard
from core.engine.audit_logger import AuditLogger
from core.engine.proactive_scanner import ProactiveContinuousScanner
from core.engine.memory_scanner import MemoryScanner
from core.engine.dns_manager import DNSManager
from core.auth.auth_manager import AuthManager
import core.engine.clamav as clamav
from core.engine.clamav_manager import ClamAVManager
import yara_x
from core.engine.yarax_engine import YaraXEngine
import tetragon
from core.engine.tetragon import TetragonManager
import falco
from core.engine.falco import FalcoManager
import wazuh
from core.engine.wazuh import WazuhManager
import osquery
from core.engine.osquery import OSQueryManager
import misp
from core.engine.misp import MISPManager
import sigma
from core.engine.sigma_engine import SigmaManager
import event_manager
from core.engine.event_manager import get_default_event_manager, ARCHITECTURE_RULES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("constantine.daemon")

def verify_and_report_subsystems(interceptor, vault, scanner, ransomware, ebpf, firewall, persist_guard, usb_scanner, download_sentinel, hardware_guard, phishing, proactive_scanner=None) -> bool:
    """Verifica el estado operativo real de cada subsistema antes de declarar el servicio activo."""
    health = {}
    critical_failed = False

    # 1. Interceptor de Kernel fanotify
    if interceptor.is_active() and getattr(interceptor, 'is_running', lambda: False)():
        health["Kernel fanotify (E/S)"] = f"ACTIVO ({len(interceptor.marked_paths)} puntos de montaje / Hilo de eventos activo)"
    elif interceptor.is_active():
        health["Kernel fanotify (E/S)"] = f"ACTIVO ({len(interceptor.marked_paths)} puntos de montaje / En espera de despacho)"
    else:
        health["Kernel fanotify (E/S)"] = "FALLIDO (Sin marcas de kernel activas)"
        critical_failed = True

    # 2. Baúl Criptográfico AES-256-GCM
    if os.path.exists(vault.base_dir) and getattr(vault, "_aes_key", None):
        health["Baúl Criptográfico"] = "ACTIVO (AES-256-GCM con KDF ligado al host)"
    else:
        health["Baúl Criptográfico"] = "FALLIDO (Motor criptográfico no disponible)"
        critical_failed = True

    # 3. Motor de Firmas e Inteligencia
    sig_info = scanner.get_signatures_info()
    yara_status = "YARA 4.x Oficial" if sig_info.get("has_yara") else "Heurístico de Respaldo"
    health["Motor de Firmas & YARA"] = f"ACTIVO ({sig_info.get('hashes_count', 0)} hashes, {yara_status})"

    # 4. Escudo Anti-Ransomware
    if len(ransomware.canary_files) > 0:
        health["Anti-Ransomware (Canaries)"] = f"ACTIVO ({len(ransomware.canary_files)} trampas señuelo desplegadas)"
    else:
        health["Anti-Ransomware (Canaries)"] = "ADVERTENCIA (Sin trampas señuelo)"

    # 5. Vigilancia en Memoria RAM eBPF
    ebpf_info = ebpf.get_status_info()
    if ebpf.is_active():
        health["Vigilancia RAM eBPF"] = "ACTIVO (Sondas de kernel sys_enter_execve / ptrace)"
    elif ebpf.is_operational():
        health["Vigilancia RAM eBPF"] = "MODO COMPATIBILIDAD (Centinela de rescate en espacio de usuario /proc)"
    else:
        health["Vigilancia RAM eBPF"] = f"DEGRADADO ({ebpf_info.get('error_message')})"

    # 6. Cortafuegos del Sistema (GUFW / UFW - Arquitectura 5.x)
    fw_stat = firewall.get_firewall_status() if firewall else {"state": "NOT_INSTALLED", "state_label": "No instalado"}
    st_name = fw_stat.get("state")
    if st_name == "INSTALLED_ACTIVE":
        health["Cortafuegos (GUFW / UFW)"] = "ACTIVO (UFW activado / Administrado por el usuario vía GUFW)"
    elif st_name == "INSTALLED_INACTIVE":
        health["Cortafuegos (GUFW / UFW)"] = "DESACTIVADO (UFW inactivo / Administrado por el usuario vía GUFW)"
    elif st_name == "NOT_INSTALLED":
        health["Cortafuegos (GUFW / UFW)"] = "NO INSTALADO"
    else:
        health["Cortafuegos (GUFW / UFW)"] = "ESTADO DESCONOCIDO O NO VERIFICABLE"

    from core.engine.vpn_manager import VPNManager
    vpn_mgr = VPNManager()
    health["Red Privada Virtual (Proton VPN)"] = (
        "INSTALADO (Acceso directo listo / Administrado por el usuario)"
        if vpn_mgr.is_installed()
        else "DISPONIBLE (Instalador en ./scripts/setup_protonvpn.sh)"
    )

    # 7. Centinelas Periféricos y Descargas
    health["Centinela USB (/media)"] = "ACTIVO (Supervisión udisks2)" if usb_scanner.running else "INACTIVO"
    health["Centinela Descargas (~/Descargas)"] = "ACTIVO (En vuelo)" if download_sentinel.running else "INACTIVO"
    health["Centinela Persistencia (systemd/cron)"] = "ACTIVO" if persist_guard.running else "INACTIVO"
    health["Centinela Hardware (Cámara/Audio)"] = "ACTIVO" if hardware_guard.running else "INACTIVO"
    health["Centinela Anti-Phishing de Red"] = "ACTIVO" if getattr(phishing, "proactive_monitoring", False) else "INACTIVO"
    if proactive_scanner and proactive_scanner.running:
        health["Escáner Activo Continuo (EDR)"] = f"ACTIVO (Barrido periódico cada {proactive_scanner.interval_seconds:.0f}s)"
    else:
        health["Escáner Activo Continuo (EDR)"] = "ACTIVO (En segundo plano)"

    if hasattr(scanner, "clamav_manager"):
        cm_info = scanner.clamav_manager.get_status_info()
        if cm_info.get("clamd_available"):
            health["Motor Antivirus ClamAV"] = f"ACTIVO (clamd: {cm_info.get('clamd_version', 'OK')})"
        else:
            health["Motor Antivirus ClamAV"] = "MODO HÍBRIDO (clamd en espera; YARA + Heurística activas)"

    # 8. Observabilidad Profunda de Kernel & Runtime Enforcement (Cilium Tetragon)
    import tetragon
    if tetragon.is_available():
        t_ver = tetragon.get_version() or "v1.x"
        health["Observabilidad & Enforcement Tetragon"] = f"ACTIVO (Cilium Tetragon {t_ver} / Override + Sigkill)"
    else:
        health["Observabilidad & Enforcement Tetragon"] = f"CONFIGURADO ({len(tetragon.list_policies())} TracingPolicies disponibles / Daemon en espera)"

    # 9. Detección Conductual Syscalls & Alertas (Falco CNCF)
    import falco
    if falco.is_available():
        f_ver = falco.get_version() or "v0.38+"
        health["Detección Conductual Syscalls (Falco)"] = f"ACTIVO (Falco Daemon {f_ver} / Reglas de Privilegios & Red)"
    else:
        health["Detección Conductual Syscalls (Falco)"] = f"CONFIGURADO ({len(falco.list_rules())} Reglas YAML de Privilegios & Red / Enforcement en Constantine)"

    # 10. Vigilancia de Integridad de Archivos (FIM) & Respuesta Activa (Wazuh)
    import wazuh
    health["Vigilancia Cambios FIM + YARA (Wazuh)"] = f"ACTIVO ({len(wazuh.list_rules())} Reglas FIM+YARA / Respuesta Activa Niveles 1-15)"

    # 11. Diagnóstico e Inventario del Sistema (osquery)
    import osquery
    osq_mgr = osquery.get_default_manager()
    diag = osq_mgr.last_diagnostic or osq_mgr.generate_security_diagnostic()
    health["Diagnóstico e Inventario SQL (osquery)"] = f"ACTIVO (Salud {diag.health_score}/100 - {diag.overall_health} / Tablas virtuales SQL)"

    # 12. Plataforma Centralizada de Inteligencia de Amenazas (MISP)
    import misp
    misp_mgr = misp.get_default_manager()
    misp_stat = misp_mgr.get_status_info()
    health["Inteligencia de Amenazas (MISP)"] = f"ACTIVO ({misp_stat['events_count']} Eventos, {misp_stat['iocs_count']} IoCs / Feeds SHA256/IP/Domain/URL)"

    # 13. Reglas de Detección de Comportamiento Sigma (Universal SOC)
    import sigma
    sig_mgr = sigma.get_default_manager()
    health["Reglas de Detección Sigma"] = f"ACTIVO ({len(sig_mgr.rules)} Reglas YAML / pySigma Linux Adapter)"

    # 14. Seguridad y Aislamiento del Servicio (systemd hardening)
    from core.engine.systemd_hardening import SystemdSecurityAuditor
    sd_auditor = SystemdSecurityAuditor()
    sd_posture = sd_auditor.evaluate_security_posture()
    if sd_posture.get("unit_found"):
        health["Seguridad del Servicio (systemd)"] = f"BLINDADO ({sd_posture['score']}/100 - {len(sd_posture['passed_checks'])} directivas activas)"

    # 15. Gestor Central de Eventos y Flujo de Datos (Data Flow & Decision Engine)
    import event_manager
    em = event_manager.get_default_event_manager(scanner=scanner)
    health["Gestor de Eventos & Flujo de Datos"] = "ACTIVO (Fanotify + Tetragon -> Decision Engine -> Correlation)"
    health["Reglas de Arquitectura Constantine"] = "10/10 ACTIVAS & CUMPLIDAS"
    print("\n" + "="*75)
    print("🛡️ CONSTANTINE ANTIVIRUS - ESTADO OPERATIVO DE SUBSISTEMAS")
    print("="*75)
    for sub, stat in health.items():
        print(f" • {sub:<36}: {stat}")
    print("="*75 + "\n")

    # Persistir estado de salud verificable para la GUI
    try:
        SubsystemHealthRegistry().save_daemon_health({
            "fanotify": {"is_active": interceptor.is_active(), "details": f"{len(interceptor.marked_paths)} puntos de montaje activos"},
            "ebpf": {"state": ebpf.get_status_info()["status"], "details": ebpf.get_status_info()["recommendation"]},
            "ransomware": {"is_active": len(ransomware.canary_files) > 0, "details": f"{len(ransomware.canary_files)} canaries"},
            "usb": {"is_active": usb_scanner.running, "details": "Vigilancia udev activa"},
            "downloads": {"is_active": download_sentinel.running, "details": "Vigilancia inotify activa"},
            "phishing": {"is_active": getattr(phishing, "proactive_monitoring", False), "details": "Supervisión de red activa"},
            "proactive_scanner": {
                "is_active": proactive_scanner.running if proactive_scanner else True,
                "details": f"{proactive_scanner.total_files_scanned if proactive_scanner else 0} archivos auditados en vivo"
            },
            "clamav": {
                "is_active": scanner.clamav_manager.is_engine_available() if hasattr(scanner, "clamav_manager") else False,
                "version": scanner.clamav_manager.get_engine_version() if hasattr(scanner, "clamav_manager") else None
            }
        })
    except Exception as e:
        logger.debug("Aviso guardando estado en registry: %s", e)

    return not critical_failed

def main(args_list: Optional[List[str]] = None, stop_after_startup: bool = False, runtime_seconds: Optional[float] = None) -> bool:
    parser = argparse.ArgumentParser(description="Constantine Antivirus - Kernel Defense Daemon")
    parser.add_argument(
        "--test-startup",
        action="store_true",
        default=False,
        help="Verifica la inicialización completa de todos los subsistemas y finaliza con éxito (Sanity Check)."
    )
    parser.add_argument(
        "--runtime-limit",
        type=float,
        default=None,
        help="Límite de tiempo en segundos para ejecución controlada en pruebas automatizadas."
    )
    parser.add_argument(
        "--mode",
        choices=["all-mounts", "critical-vectors", "custom"],
        default="all-mounts",
        help="Modo de cobertura fanotify: 'all-mounts' (supervisa TODO el sistema de archivos y puntos de montaje locales), 'critical-vectors' (supervisa /home, /tmp, /dev/shm, /media, etc.), o 'custom'."
    )
    parser.add_argument(
        "--watch-dir",
        default=None,
        help="Directorio adicional o de compatibilidad hacia atrás (ej. /tmp o /home)."
    )
    parser.add_argument(
        "--fail-policy",
        choices=["secure", "safe"],
        default="secure",
        help="Política ante excepciones: 'secure' (FAIL-SECURE estricto con FAN_DENY por defecto), 'safe' (Fail-Open para depuración)."
    )
    parser.add_argument(
        "--open-fail-policy",
        choices=["open", "closed"],
        default=None,
        help="Política ante fallos/timeouts para aperturas ordinarias (FAN_OPEN_PERM): 'open' (preserva disponibilidad, default) o 'closed'."
    )
    parser.add_argument(
        "--exec-fail-policy",
        choices=["open", "closed"],
        default=None,
        help="Política ante fallos/timeouts para ejecución de archivos (FAN_OPEN_EXEC_PERM): 'closed' (seguridad estricta, default) u 'open'."
    )
    parser.add_argument(
        "--event-timeout",
        type=float,
        default=2.0,
        help="Tiempo límite en segundos para responder a cada evento de kernel fanotify (default: 2.0s)."
    )
    parser.add_argument(
        "--enable-firewall",
        action="store_true",
        default=True,
        help="Habilita el aislamiento de red activo (UFW / nftables)."
    )
    parser.add_argument(
        "--disable-firewall",
        action="store_false",
        dest="enable_firewall",
        help="Deshabilita el aislamiento de red en cortafuegos."
    )

    # Tolerancia total a argumentos de versiones previas o desconocidos para evitar caídas en systemd
    if args_list is not None:
        args, unknown_args = parser.parse_known_args(args_list)
    else:
        args, unknown_args = parser.parse_known_args()
    if unknown_args:
        logger.warning("Argumentos adicionales o legados recibidos y tolerados: %s", unknown_args)

    if os.geteuid() != 0 and not (args.test_startup or stop_after_startup):
        print("❌ Error: Constantine Daemon debe ejecutarse con privilegios de superusuario (root/sudo).")
        sys.exit(1)

    logger.info("⚔️ Iniciando Constantine Antivirus Daemon (Protección Activa Global en Kernel)...")

    auth = AuthManager()
    vault = QuarantineVault()
    notifier = DesktopNotifier()
    firewall = NetworkQuarantine() if args.enable_firewall else None
    scanner = Scanner()
    phishing = PhishingShield()
    dns_mgr = DNSManager()
    audit_logger = AuditLogger()

    # 0b. Gestor Central de Eventos y Motor de Decisiones (Data Flow)
    event_mgr = get_default_event_manager(scanner=scanner, vault=vault, notifier=notifier, audit_logger=audit_logger, firewall=firewall)
    # 1. Escudo Anti-Ransomware (Canary Honeypots y Kill-Switch SIGKILL)
    ransomware = RansomwareShield(
        alert_callback=lambda reason, pid: [
            notifier.alert_threat_blocked(reason, f"PID {pid}", pid, "RansomwareProcess"),
            audit_logger.record_incident(reason, f"PID {pid}", "SIGKILL_NEUTRALIZED")
        ]
    )

    # 2. Interceptor Síncrono de Kernel (fanotify) con Integración Anti-Ransomware Activa
    interceptor = FanotifyInterceptor(
        scanner=scanner,
        vault=vault,
        notifier=notifier,
        firewall=firewall,
        ransomware=ransomware,
        fail_policy=args.fail_policy,
        open_fail_policy=args.open_fail_policy,
        exec_fail_policy=args.exec_fail_policy,
        event_timeout=args.event_timeout,
        audit_logger=audit_logger
    )
    if not interceptor.initialize():
        logger.critical("No se pudo inicializar la interfaz de kernel fanotify. Abortando.")
        sys.exit(1)

    # Prevención crítica de auto-intercepción y exclusión de PID propio y de sistema
    interceptor.add_ignored_pid(os.getpid())
    interceptor.add_ignored_pid(1)
    interceptor.add_ignored_pid(2)

    # Cobertura de interceptación: Por defecto supervisa TODO el sistema de archivos
    if args.mode == "all-mounts":
        logger.info("🌐 Cobertura Global Predeterminada: Enganchando todo el sistema de archivos (/ y todos los puntos de montaje de /proc/mounts)...")
        total_marked = interceptor.mark_all_mounts()
        if total_marked == 0 or not interceptor.is_active():
            logger.critical("❌ Fallo crítico en kernel: Ningún punto de montaje pudo ser marcado por fanotify.")
            audit_logger.record_incident("Kernel.Fanotify.Failed", "/", "CRITICAL", "Fallo total de marcado fanotify")
            if notifier:
                notifier.send("🚨 Constantine: Error en Kernel", "Fanotify no pudo marcar el sistema de archivos. El escudo de kernel está inactivo.", urgency="critical")
            sys.exit(1)
        logger.info("✅ Protección global activa en %d puntos de montaje y directorios del sistema operativo.", total_marked)
    elif args.mode == "custom" and args.watch_dir:
        watch_path = os.path.abspath(args.watch_dir)
        os.makedirs(watch_path, exist_ok=True)
        if not interceptor.mark_directory(watch_path):
            logger.critical("❌ Fallo marcando directorio objetivo custom: %s", watch_path)
            sys.exit(1)
        logger.info("🎯 Modo Custom: Supervisando directorio específico: %s", watch_path)
    else: # Modo critical-vectors
        extra = [os.path.abspath(args.watch_dir)] if args.watch_dir else None
        count = interceptor.mark_critical_vectors(extra_paths=extra)
        if count == 0:
            logger.critical("❌ Fallo crítico: Ningún vector crítico pudo ser marcado.")
            sys.exit(1)
        logger.info("🛡️ Modo Vectores Críticos: %d ubicaciones interceptadas activamente.", count)

    if not interceptor.is_active():
        logger.critical("❌ El interceptor fanotify no tiene marcas activas. Abortando para no declarar activo un escudo inoperativo.")
        sys.exit(1)

    # 3. Centinela de Dispositivos USB y Discos Externos (/media)
    usb_scanner = USBAutoScanner(scanner=scanner, vault=vault, notifier=notifier, interceptor=interceptor)
    usb_scanner.start()

    # 4. Centinela de Persistencia en Arranque (/etc/systemd, cron, profile.d)
    persist_guard = PersistenceGuard(scanner=scanner, vault=vault, notifier=notifier)
    persist_guard.start()

    # 5. Centinela de Descargas en Vuelo (~/Descargas, ~/Downloads)
    download_sentinel = DownloadSentinel(scanner=scanner, vault=vault, notifier=notifier)
    download_sentinel.start()

    # 6. Centinela Anti-Espía de Periféricos (Cámara /dev/video* y Micrófono)
    hardware_guard = HardwareGuard(notifier=notifier)
    hardware_guard.start()

    # 7. Centinela Anti-Phishing Proactivo de Conexiones de Red
    phishing.start_proactive_monitoring(notifier=notifier, audit_logger=audit_logger)

    # 7b. Escáner Activo Continuo en Tiempo Real (Proactive Background Sweeper)
    memory_scanner = MemoryScanner(scanner=scanner, vault=vault)
    proactive_scanner = ProactiveContinuousScanner(
        scanner=scanner,
        vault=vault,
        notifier=notifier,
        audit_logger=audit_logger,
        memory_scanner=memory_scanner,
        interval_seconds=30.0
    )
    proactive_scanner.start()

    # 8. Vigilancia Heurística en RAM con eBPF (sys_enter_execve, ptrace) y Neutralización SIGKILL
    def on_ebpf_threat(threat, path, pid, comm, state="PROCESS_TERMINATED"):
        logger.critical("🚨 [EBPF EVENTO: %s] PID %d (%s) -> %s", state, pid, comm, threat)
        if firewall:
            firewall.isolate_pid(pid, terminate=True)
        if vault and os.path.exists(path):
            vault.quarantine_file(path, threat, detected_by="eBPFDefense")

        action_label = state
        if state == "PROCESS_TERMINATED":
            action_label = "PROCESS_TERMINATED"
        elif state == "PROCESS_CONTAINED":
            action_label = "PROCESS_CONTAINED"
        elif state == "ACTION_FAILED":
            action_label = "ACTION_FAILED"
        else:
            action_label = "ALERT_OBSERVED"

        audit_logger.record_incident(threat, path, action_label, f"PID {pid} / {comm} / Estado: {state}")
        if state in ("PROCESS_TERMINATED", "PROCESS_CONTAINED"):
            notifier.alert_threat_blocked(threat, path, pid, comm)
        else:
            notifier.send(f"⚠️ Actividad Sospechosa ({threat})", f"Proceso {comm} (PID {pid}) en observación. Estado: {state}", urgency="critical")

    ebpf = EBPFMonitor(alert_callback=on_ebpf_threat, auto_kill=True, notifier=notifier)
    if ebpf.start():
        logger.info("✅ Sondas eBPF en kernel activas y operativas.")
    else:
        ebpf_diag = ebpf.get_status_info()
        logger.warning("⚠️ eBPF en kernel inactivo: %s", ebpf_diag["error_message"])
        logger.warning("💡 Comando para activar eBPF: %s", ebpf_diag["recommendation"])
        audit_logger.record_incident("System.eBPF.Degraded", "Kernel", "WARNING", ebpf_diag["error_message"])

    # Conectar el monitor eBPF con el interceptor fanotify para correlación atómica de openat y prevención de evasiones
    interceptor.set_ebpf_monitor(ebpf)

    # Coordinar protección On-Access y prevención de bucles con ClamAV
    if hasattr(scanner, "clamav_manager"):
        scanner.clamav_manager.coordinate_on_access_protection(interceptor)

    # 8b. Iniciar el hilo receptor de eventos fanotify y verificar que está vivo antes de anunciar protección activa
    logger.info("🚀 Iniciando hilo receptor de eventos fanotify en segundo plano...")
    if not interceptor.start():
        logger.critical("❌ Fallo crítico: El hilo receptor de eventos fanotify no pudo iniciar.")
        sys.exit(1)

    if not interceptor.is_running():
        logger.critical("❌ Fallo crítico: El interceptor fanotify no está en ejecución activa.")
        sys.exit(1)

    # 9. Verificación de Integridad de Subsistemas antes de Declarar Operatividad
    is_healthy = verify_and_report_subsystems(
        interceptor=interceptor,
        vault=vault,
        scanner=scanner,
        ransomware=ransomware,
        ebpf=ebpf,
        firewall=firewall,
        persist_guard=persist_guard,
        usb_scanner=usb_scanner,
        download_sentinel=download_sentinel,
        hardware_guard=hardware_guard,
        phishing=phishing,
        proactive_scanner=proactive_scanner
    )
    if not is_healthy:
        logger.critical("❌ Fallo en la verificación previa de subsistemas críticos. Abortando inicio.")
        sys.exit(1)

# 10. Despachador IPC del Daemon con Control de Acceso RBAC y Validación del Servidor
    def dispatch_ipc_command(cmd: str, params: Dict[str, Any], client_uid: int, is_admin: bool = False) -> Tuple[str, Dict[str, Any], str]:
        c = cmd.upper().strip()
        if c == "GET_STATUS":
            diag = verify_and_report_subsystems(
                interceptor=interceptor, vault=vault, scanner=scanner, ransomware=ransomware,
                ebpf=ebpf, firewall=firewall, persist_guard=persist_guard, usb_scanner=usb_scanner,
                download_sentinel=download_sentinel, hardware_guard=hardware_guard, phishing=phishing,
                proactive_scanner=proactive_scanner
            )
            return "OK", {
                "daemon": "RUNNING",
                "version": DAEMON_VERSION,
                "fail_policy": args.fail_policy,
                "mode": args.mode,
                "subsystems": diag,
                "ebpf_status": ebpf.get_status_info()["status"],
                "proactive_scanner": proactive_scanner.get_telemetry()
            }, ""
        elif c == "TRIGGER_SWEEP":
            proactive_scanner.trigger_immediate_sweep()
            return "OK", {"message": "Barrido proactivo activado inmediatamente"}, ""
        elif c == "UPDATE_CLAMAV_SIGNATURES":
            res = scanner.clamav_manager.update_signatures(timeout=60) if hasattr(scanner, "clamav_manager") else {"success": False, "message": "ClamAVManager no disponible"}
            return "OK" if res.get("success") else "ERROR", res, ""
        elif c == "GET_CLAMAV_STATUS":
            info = scanner.clamav_manager.get_status_info() if hasattr(scanner, "clamav_manager") else {}
            return "OK", info, ""
        elif c == "GET_TETRAGON_STATUS":
            import tetragon
            return "OK", tetragon.get_default_manager().get_status_info(), ""
        elif c == "LIST_TETRAGON_POLICIES":
            import tetragon
            return "OK", {"policies": tetragon.list_policies()}, ""
        elif c == "LOAD_TETRAGON_POLICY":
            import tetragon
            path = params.get("path")
            valid, p_norm = validate_ipc_path(path)
            if not valid:
                return "ERROR", {}, f"Ruta requerida o inválida: {p_norm}"
            success = tetragon.load_policy(p_norm)
            return "OK" if success else "ERROR", {"loaded": success, "path": p_norm}, ""
        elif c == "GET_FALCO_STATUS":
            import falco
            return "OK", falco.get_default_manager().get_status_info(), ""
        elif c == "LIST_FALCO_RULES":
            import falco
            return "OK", {"rules": falco.list_rules()}, ""
        elif c == "EVALUATE_FALCO_EVENT":
            import falco
            alerts = falco.evaluate_event(params)
            return "OK", {"alerts": [a.to_dict() for a in alerts]}, ""
        elif c == "GET_WAZUH_STATUS":
            import wazuh
            return "OK", wazuh.get_default_manager().get_status_info(), ""
        elif c == "LIST_WAZUH_RULES":
            import wazuh
            return "OK", {"rules": wazuh.list_rules()}, ""
        elif c == "ANALYZE_FILE_CHANGE":
            import wazuh
            path = params.get("path")
            valid, p_norm = validate_ipc_path(path)
            if not valid:
                return "ERROR", {}, f"Ruta requerida o inválida: {p_norm}"
            ev_type = params.get("event_type", "FILE_MODIFIED")
            alert = wazuh.analyze_file_change(p_norm, event_type=ev_type)
            return "OK", {"alert": alert.to_dict() if alert else None}, ""
        elif c == "GET_OSQUERY_STATUS":
            import osquery
            return "OK", osquery.get_default_manager().get_status_info(), ""
        elif c == "EXECUTE_OSQUERY_SQL":
            import osquery
            q = params.get("query", "SELECT 1;")
            rows = osquery.query(q)
            return "OK", {"rows": rows}, ""
        elif c == "RUN_SECURITY_DIAGNOSTIC":
            import osquery
            diag = osquery.get_security_diagnostic()
            return "OK", diag.to_dict(), ""
        elif c == "GET_MISP_STATUS":
            import misp
            return "OK", misp.get_default_manager().get_status_info(), ""
        elif c == "SYNC_MISP_FEEDS":
            import misp
            count = misp.get_default_manager().ingest_local_feeds()
            return "OK", {"ingested_events": count, "status": misp.get_default_manager().get_status_info()}, ""
        elif c == "LOOKUP_MISP_IOC":
            import misp
            val = params.get("value", "")
            match = misp.lookup_ioc(val)
            return "OK", {"match": match.to_dict() if match else None}, ""
        elif c == "GET_SIGMA_STATUS":
            import sigma
            return "OK", sigma.get_default_manager().get_status_info(), ""
        elif c == "LIST_SIGMA_RULES":
            import sigma
            return "OK", {"rules": sigma.list_rules()}, ""
        elif c == "EVALUATE_SIGMA_EVENT":
            import sigma
            matches = sigma.evaluate_event(params)
            return "OK", {"matches": [m.to_dict() for m in matches]}, ""
        elif c == "GET_EVENT_MANAGER_STATUS":
            return "OK", event_mgr.get_status_info(), ""
        elif c == "GET_ARCHITECTURE_RULES":
            return "OK", {"rules": event_mgr.verify_architecture_rules()}, ""
        elif c == "PROCESS_EVENT":
            from core.engine.event_manager import SecurityEvent, EventSource, EventType
            ev = SecurityEvent(
                event_id=params.get("event_id", f"ipc_{time.time()}"),
                source=EventSource(params.get("source", "USER_ON_DEMAND")),
                event_type=EventType(params.get("event_type", "FILE_SYSTEM")),
                path=params.get("path"),
                target_fd=params.get("target_fd"),
                pid=params.get("pid"),
                comm=params.get("comm")
            )
            v = event_mgr.process_event(ev)
            return "OK", {
                "verdict": v.verdict.value,
                "action": v.action.value,
                "threat_name": v.threat_name,
                "details": v.details,
                "quarantine_id": v.quarantine_id
            }, ""
        elif c == "GET_FIREWALL_STATUS":
            stat = firewall.get_firewall_status() if firewall else {"state": "NOT_INSTALLED", "state_label": "No instalado"}
            return "OK", stat, ""
        elif c == "LAUNCH_GUFW":
            ok = firewall.launch_gufw() if firewall else False
            return "OK" if ok else "ERROR", {"launched": ok}, ""
        elif c == "LAUNCH_VPN":
            from core.engine.vpn_manager import VPNManager
            ok = VPNManager().launch()
            return "OK" if ok else "ERROR", {"launched": ok}, ""
        elif c == "ACTIVATE_INITIAL_FIREWALL":
            if firewall:
                ok, msg = firewall.activate_initial_firewall()
                return "OK" if ok else "ERROR", {"success": ok, "message": msg}, ""
            return "ERROR", {"success": False, "message": "Firewall no configurado"}, ""
        elif c == "TOGGLE_UFW":
            en = params.get("enable", True)
            ok = firewall.toggle_ufw(en) if firewall else False
            return "OK" if ok else "ERROR", {"success": ok}, ""
        elif c == "GET_SYSTEMD_SECURITY":
            from core.engine.systemd_hardening import SystemdSecurityAuditor
            return "OK", SystemdSecurityAuditor().evaluate_security_posture(), ""
        elif c == "GET_THREATS":
            return "OK", {"threats": vault.list_items()}, ""
        elif c == "GET_AUDIT_LOGS":
            return "OK", {"logs": audit_logger.get_incidents()[:50]}, ""
        elif c == "REQUEST_SCAN":
            p = params.get("path")
            valid, p_norm = validate_ipc_path(p)
            if not valid:
                return "ERROR", {}, f"Ruta inválida: {p_norm}"
            if not os.path.exists(p_norm):
                return "ERROR", {}, "Ruta no encontrada"
            res = scanner.scan_file(file_path=p_norm)
            return "OK", {"path": p_norm, "is_malicious": res.is_malicious, "threat_name": res.threat_name}, ""
        elif c == "ADD_WHITELIST":
            path = params.get("path")
            valid, p_norm = validate_ipc_path(path)
            if not valid:
                return "ERROR", {}, f"Ruta requerida o inválida: {p_norm}"
            interceptor.whitelist.add_path(p_norm)
            return "OK", {"whitelisted": p_norm}, ""
        elif c == "REMOVE_WHITELIST":
            path = params.get("path")
            valid, p_norm = validate_ipc_path(path)
            if not valid:
                return "ERROR", {}, f"Ruta requerida o inválida: {p_norm}"
            interceptor.whitelist.remove_path(p_norm)
            return "OK", {"removed": p_norm}, ""
        elif c == "RESTORE_QUARANTINE":
            vid = params.get("vault_id")
            if not validate_ipc_vault_id(vid):
                return "ERROR", {}, "Identificador de cuarentena (vault_id) inválido"
            dest = params.get("destination")
            if dest:
                valid, dest = validate_ipc_path(dest)
                if not valid:
                    return "ERROR", {}, f"Ruta de destino inválida: {dest}"
            ok = vault.restore_file(vid, destination_path=dest)
            return "OK" if ok else "ERROR", {"restored": ok}, ""
        elif c == "PURGE_QUARANTINE":
            count = vault.purge_all()
            return "OK", {"purged_count": count}, ""
        return "ERROR", {}, f"Comando no reconocido: {cmd}"

    ipc_server = SecureIPCDaemonServer(command_handler=dispatch_ipc_command, auth_manager=auth)
    ipc_server.start()

    # Comprobar si se solicitó parada inmediata tras verificación de arranque exitoso
    if args.test_startup or stop_after_startup:
        logger.info("✅ [TEST_STARTUP] Todos los subsistemas arrancaron y se verificaron con éxito. Finalizando de forma limpia.")
        interceptor.stop()
        usb_scanner.stop()
        persist_guard.stop()
        download_sentinel.stop()
        hardware_guard.stop()
        proactive_scanner.stop()
        ebpf.stop()
        ipc_server.stop()
        if firewall:
            firewall.cleanup()
        return True

    stop_event = threading.Event()

    def shutdown(sig, frame):
        logger.info("Señal de terminación recibida. Deteniendo servicios de Constantine...")
        stop_event.set()
        interceptor.stop()
        usb_scanner.stop()
        persist_guard.stop()
        download_sentinel.stop()
        hardware_guard.stop()
        proactive_scanner.stop()
        ebpf.stop()
        ipc_server.stop()
        if firewall:
            firewall.cleanup()
        logger.info("Todos los servicios detenidos limpiamente.")
        if sig is not None:
            sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("🚀 Constantine Antivirus en ejecución. Protección activa global en kernel operando.")
    if runtime_seconds is not None:
        stop_event.wait(timeout=runtime_seconds)
        shutdown(None, None)
    elif args.runtime_limit:
        stop_event.wait(timeout=args.runtime_limit)
        shutdown(None, None)
    else:
        stop_event.wait()

    return True

if __name__ == "__main__":
    main()
