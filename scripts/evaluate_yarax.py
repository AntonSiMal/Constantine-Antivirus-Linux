#!/usr/bin/env python3
"""Script de prueba y evaluación de reglas YARA-X."""
import sys
from core.engine.yarax_engine import YaraXEngine

def main():
    engine = YaraXEngine()
    print(f"YARA-X compilado con {engine.compiled_rules_count} reglas.")

if __name__ == "__main__":
    main()
