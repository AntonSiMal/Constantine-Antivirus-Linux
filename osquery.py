"""
Constantine Antivirus - Root Import Wrapper for osquery (osquery.py)
Permite 'import osquery' directamente cuando Constantine está en PYTHONPATH.
"""
from core.engine.osquery import *
import core.engine.osquery as _mod
import sys

if "osquery" not in sys.modules:
    sys.modules["osquery"] = _mod
