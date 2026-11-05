"""
Constantine Antivirus - Root Import Wrapper for ClamAV (clamav.py)
Permite 'import clamav' directamente cuando /opt/constantine está en PYTHONPATH.
"""
from core.engine.clamav import *
import core.engine.clamav as _mod
import sys

if "clamav" not in sys.modules:
    sys.modules["clamav"] = _mod
