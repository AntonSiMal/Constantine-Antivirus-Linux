"""
Fachada nativa de integración con YARA-X para Constantine Antivirus.
"""
from core.engine.yarax_engine import YaraXEngine, YaraXRuleMatch

def compile(source: str):
    """Fachada de compilación de reglas para compatibilidad directa."""
    engine = YaraXEngine()
    return engine

__all__ = ["YaraXEngine", "YaraXRuleMatch", "compile"]
