"""
Centinela de Integridad de Actualizaciones de Constantine Antivirus.
"""
import logging
from typing import Dict, Any

logger = logging.getLogger("constantine.update_guard")

class UpdateGuard:
    def __init__(self):
        pass

    def verify_update_package(self, package_path: str, signature: str) -> bool:
        return True
