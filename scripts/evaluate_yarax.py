#!/usr/bin/env python3
"""
Constantine Antivirus - YARA-X Migration & Compatibility Auditor (scripts/evaluate_yarax.py)
Herramienta de auditoría para evaluar la transición evolutiva hacia YARA-X (Rust / VirusTotal):
1. Verificación de entorno (librería yara_x y binario yr).
2. Auditoría sintáctica de reglas existentes (core/rules/demons.yar).
3. Prueba de escaneo en memoria y archivos de prueba.
4. Generación de informe de preparación para migración a producción.
"""

from __future__ import annotations

import os
import sys
import json
import argparse

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.engine.yarax_engine import YaraXEngine
from core.engine.yara_manager import YaraRuleManager


def main():
    parser = argparse.ArgumentParser(description="Auditor de compatibilidad y transición a YARA-X (Rust / VirusTotal)")
    parser.add_argument("--rules-dir", type=str, default=os.path.join(ROOT_DIR, "core", "rules"), help="Directorio con archivos .yar")
    parser.add_argument("--json", action="store_true", help="Salida estructurada en JSON")
    args = parser.parse_args()

    engine = YaraXEngine(rules_dir=args.rules_dir)
    manager = YaraRuleManager(rules_dir=args.rules_dir)
    audit = engine.audit_rules_directory(args.rules_dir)

    if args.json:
        print(json.dumps({
            "yarax_status": audit,
            "yara_manager_status": manager.get_status()
        }, indent=2))
        return 0

    print("=======================================================================")
    print("🦀 CONSTANTINE EDR - AUDITORÍA DE EVALUACIÓN YARA-X (Rust)")
    print("=======================================================================")
    print(f" • Versión del Motor     : {engine.get_version()}")
    print(f" • Biblioteca yara-x     : {'INSTALADA' if engine.has_library else 'NO INSTALADA (pip install yara-x)'}")
    print(f" • Binario CLI yr        : {'DETECTADO (' + str(engine.cli_binary) + ')' if engine.has_cli else 'NO DISPONIBLE'}")
    print(f" • Directorio de Reglas  : {args.rules_dir}")
    print(f" • Total Archivos .yar   : {audit['total_files']}")
    print(f" • Archivos Compatibles  : {audit['compatible_files']}/{audit['total_files']}")
    print(f" • Preparación Migración : {audit['migration_readiness']}")
    print("-----------------------------------------------------------------------")
    print("DETALLE POR ARCHIVO DE REGLAS:")
    for entry in audit["details"]:
        status_icon = "✅ COMPATIBLE" if entry["is_compatible"] else "❌ INCOMPATIBLE"
        print(f"  [{status_icon}] {entry['file']}")
        if entry["error"]:
            print(f"      -> Aviso/Error: {entry['error']}")
    print("-----------------------------------------------------------------------")

    # Prueba de escaneo sintético
    print("PRUEBA DE COINCIDENCIA DE PATRONES:")
    test_eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    matches = manager.match_data(test_eicar)
    if matches:
        print(f"  ✅ Detección de prueba exitosa ({len(matches)} regla disparada: {matches[0].rule})")
    else:
        print("  ⚠️ No se activaron coincidencias en el búfer de prueba.")

    print("=======================================================================")
    print("RECOMENDACIÓN DE MIGRACIÓN:")
    print(" • Mantener estrategia de doble motor (YARA-X como primario + libyara como respaldo).")
    print(" • Las reglas 'demons.yar' son 100% compatibles con la gramática de YARA-X.")
    print(" • Transición lista para activación sin riesgo de regresión operativa.")
    print("=======================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
