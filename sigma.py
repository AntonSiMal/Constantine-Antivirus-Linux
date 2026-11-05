"""
Constantine Antivirus - Root Import Wrapper for Sigma (sigma.py)
Permite 'import sigma' directamente cuando Constantine está en PYTHONPATH.
"""
from core.engine.sigma_engine import *
import core.engine.sigma_engine as _mod
import sys

if "sigma" not in sys.modules:
    sys.modules["sigma"] = _mod
