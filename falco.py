"""
Constantine Antivirus - Root Import Wrapper for Falco (falco.py)
Permite 'import falco' directamente cuando Constantine está en PYTHONPATH.
"""
from core.engine.falco import *
import core.engine.falco as _mod
import sys

if "falco" not in sys.modules:
    sys.modules["falco"] = _mod
