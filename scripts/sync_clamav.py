#!/usr/bin/env python3
"""
Constantine Antivirus - ClamAV Threat Intelligence Sync CLI (scripts/sync_clamav.py)
Herramienta de sincronización e ingesta de bases de datos de ClamAV (Cisco Talos):
- Detecta bases locales en /var/lib/clamav (daily.cvd, daily.cld, main.cvd, *.hsb).
- Extrae hashes SHA-256 e indicadores de phishing hacia la base SQLite de Constantine.
"""

import os
import sys
import argparse
import logging

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.engine.threat_intel import ThreatIntelligence
from core.engine.clamav_importer import ClamAVSignatureImporter
from core.engine.clamav_bridge import ClamAVDaemonClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("constantine.sync_clamav")


def main():
    parser = argparse.ArgumentParser(description="Sincronizador de bases de datos de ClamAV con Constantine Threat Intel")
    parser.add_argument("--db-dir", type=str, help="Directorio con archivos ClamAV (.cvd, .cld, .hsb)")
    parser.add_argument("--max-records", type=int, default=10000, help="Límite de firmas por archivo a sincronizar")
    parser.add_argument("--check-daemon", action="store_true", help="Comprueba estado y versión del demonio clamd local")
    args = parser.parse_args()

    if args.check_daemon:
        client = ClamAVDaemonClient()
        if client.is_available():
            ver = client.get_version()
            print(f"✅ Demonio ClamAV (clamd) ACTIVO: {ver}")
            sys.exit(0)
        else:
            print("⚠️ Demonio ClamAV (clamd) no encontrado o inactivo.")
            sys.exit(1)

    ti = ThreatIntelligence()
    importer = ClamAVSignatureImporter()

    dirs = [args.db_dir] if args.db_dir else None
    logger.info("Iniciando sincronización desde fuentes de ClamAV...")
    res = importer.sync_from_local_clamav(ti, db_dirs=dirs, max_records_per_file=args.max_records)
    logger.info("Sincronización completada: %d hashes importados desde %s",
                res.get("imported_hashes", 0), res.get("processed_sources", []))
    print(f"✅ Sincronizados {res.get('imported_hashes', 0)} hashes de ClamAV hacia Constantine.")


if __name__ == "__main__":
    main()
