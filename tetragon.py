"""
Constantine Antivirus - Root Import Wrapper for Tetragon (tetragon.py)
Permite 'import tetragon' directamente cuando Constantine está en PYTHONPATH.
"""
from core.engine.tetragon import *
import core.engine.tetragon as _mod
import sys

if "tetragon" not in sys.modules:
    sys.modules["tetragon"] = _mod
