#!/usr/bin/env python3
"""
Constantine Antivirus - Main Daemon Service (daemon.py)
"""
import os, sys, signal, argparse, logging

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
from core.engine.hardware_guard import HardwareGuard
from core.engine.audit_logger import AuditLogger
from core.engine.dns_manager import DNSManager
from core.auth.auth_manager import AuthManager

def main():
    parser = argparse.ArgumentParser(description="Constantine Antivirus Daemon")
    parser.add_argument("--watch-dir", default="/tmp/sandbox", help="Directorio objetivo fanotify")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: Constantine Daemon debe ejecutarse como root (sudo).")
        sys.exit(1)

    auth = AuthManager()
    vault = QuarantineVault()
    notifier = DesktopNotifier()
    firewall = NetworkQuarantine()
    scanner = Scanner()
    phishing = PhishingShield()
    dns_mgr = DNSManager()
    audit_logger = AuditLogger()

    ransomware = RansomwareShield(
        alert_callback=lambda reason, pid: [
            notifier.alert_threat_blocked(reason, f"PID {pid}", pid, "RansomwareProcess"),
            audit_logger.record_incident(reason, f"PID {pid}", "SIGKILL_NEUTRALIZED")
        ]
    )

    interceptor = FanotifyInterceptor(scanner=scanner, vault=vault, notifier=notifier, firewall=firewall)
    if not interceptor.initialize():
        sys.exit(1)

    watch_path = os.path.abspath(args.watch_dir)
    os.makedirs(watch_path, exist_ok=True)
    interceptor.mark_directory(watch_path)

    usb_scanner = USBAutoScanner(scanner=scanner, vault=vault, notifier=notifier, interceptor=interceptor)
    usb_scanner.start()

    persist_guard = PersistenceGuard(scanner=scanner, vault=vault, notifier=notifier)
    persist_guard.start()

    download_sentinel = DownloadSentinel(scanner=scanner, vault=vault, notifier=notifier)
    download_sentinel.start()

    hardware_guard = HardwareGuard(notifier=notifier)
    hardware_guard.start()

    phishing.start_proactive_monitoring(notifier=notifier, audit_logger=audit_logger)

    ebpf = EBPFMonitor(alert_callback=lambda threat, path, pid, comm: [
        notifier.alert_threat_blocked(threat, path, pid, comm),
        audit_logger.record_incident(threat, path, "EBPF_BLOCKED", f"PID {pid} / {comm}")
    ])
    ebpf.start()

    def shutdown(sig, frame):
        interceptor.stop()
        usb_scanner.stop()
        persist_guard.stop()
        download_sentinel.stop()
        hardware_guard.stop()
        ebpf.stop()
        firewall.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("🛡️ Constantine Daemon ACTIVO (Kernel, Anti-Ransomware, USB, Persistencia, Descargas, Periféricos)")
    interceptor.process_events()

if __name__ == "__main__":
    main()
