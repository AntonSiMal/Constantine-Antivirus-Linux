"""
Constantine Antivirus - Root Import Wrapper for MISP (misp.py)
Permite 'import misp' directamente cuando Constantine está en PYTHONPATH.
"""
from core.engine.misp import *
import core.engine.misp as _mod
import sys

if "misp" not in sys.modules:
    sys.modules["misp"] = _mod
