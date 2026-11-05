"""
Constantine Antivirus - Root Import Wrapper for Wazuh (wazuh.py)
Permite 'import wazuh' directamente cuando Constantine está en PYTHONPATH.
"""
from core.engine.wazuh import *
import core.engine.wazuh as _mod
import sys

if "wazuh" not in sys.modules:
    sys.modules["wazuh"] = _mod
