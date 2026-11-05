"""
Constantine Antivirus - Root Import Wrapper for YARA-X (yara_x.py)
Permite 'import yara_x' directamente cuando /opt/constantine está en PYTHONPATH.
"""
from core.engine.yara_x import *
import core.engine.yara_x as _mod
import sys

if "yara_x" not in sys.modules:
    sys.modules["yara_x"] = _mod
if "yarax" not in sys.modules:
    sys.modules["yarax"] = _mod
