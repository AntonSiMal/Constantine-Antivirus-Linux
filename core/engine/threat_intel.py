"""
Base de Inteligencia de Amenazas y Correlación de IoCs para Constantine Antivirus.
"""
import os
import re
import sqlite3
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("constantine.intel")

THREAT_INTEL_VERSION = "5.2.2"
DEFAULT_INTEL_DB = "/var/lib/constantine/intel/threat_intel.db"
FALLBACK_INTEL_DB = "/tmp/constantine_intel.db"

class ThreatIntelligence:
    """Motor central de almacenamiento y consulta de Indicadores de Compromiso (IoCs)."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_INTEL_DB
        self._init_db()

    def _init_db(self):
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, mode=0o750, exist_ok=True)
            except OSError:
                self.db_path = FALLBACK_INTEL_DB
                db_dir = os.path.dirname(self.db_path)
                if db_dir and not os.path.exists(db_dir):
                    os.makedirs(db_dir, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL,
                confidence INTEGER DEFAULT 80,
                threat_level TEXT DEFAULT 'HIGH',
                description TEXT,
                tags TEXT,
                first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                is_false_positive INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS feed_sync_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_name TEXT NOT NULL,
                sync_timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                records_added INTEGER DEFAULT 0,
                records_updated INTEGER DEFAULT 0,
                checksum TEXT
            )
        """)
        conn.commit()
        conn.close()

    def add_ioc(self, ioc_type: str, value: str, source: str = "MISP", confidence: int = 85,
                threat_level: str = "HIGH", description: str = "", tags: str = "") -> bool:
        """Agrega o actualiza un indicador con validación estricta de formato."""
        val = value.strip()
        if ioc_type.lower() == "sha256":
            if not re.match(r"^[a-fA-F0-9]{64}$", val):
                logger.warning("Intento de insertar hash SHA-256 malformado descartado: '%s'", val)
                return False
            val = val.lower()

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO iocs (ioc_type, value, source, confidence, threat_level, description, tags, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(value) DO UPDATE SET
                    last_seen=CURRENT_TIMESTAMP,
                    confidence=max(confidence, excluded.confidence),
                    is_active=1
            """, (ioc_type.lower(), val, source, confidence, threat_level, description, tags))
            conn.commit()
            return True
        except Exception as e:
            logger.error("Error insertando IoC: %s", e)
            return False
        finally:
            conn.close()

    def lookup_ioc(self, value: str) -> Optional[Dict[str, Any]]:
        """Busca un indicador activo que no sea falso positivo."""
        val = value.strip().lower()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            SELECT ioc_type, value, source, confidence, threat_level, description, tags, is_false_positive
            FROM iocs WHERE value = ? AND is_active = 1 AND is_false_positive = 0
        """, (val,))
        row = cur.fetchone()
        conn.close()
        if row:
            return {
                "ioc_type": row[0],
                "value": row[1],
                "source": row[2],
                "confidence": row[3],
                "threat_level": row[4],
                "description": row[5],
                "tags": row[6],
                "is_threat": True
            }
        return None

    def mark_false_positive(self, value: str, reason: str = "") -> bool:
        """Marca un IoC como falso positivo desactivándolo sin eliminar historial."""
        val = value.strip().lower()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            UPDATE iocs SET is_false_positive = 1, is_active = 0, description = description || ' [FP: ' || ? || ']'
            WHERE value = ?
        """, (reason, val))
        updated = cur.rowcount > 0
        conn.commit()
        conn.close()
        if updated:
            logger.info("Marcado indicador como falso positivo: %s (%s)", val, reason)
        return updated

    def get_stats(self) -> Dict[str, Any]:
        """Obtiene métricas reales exactas sin números ficticios."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM iocs WHERE is_active = 1 AND is_false_positive = 0")
        active_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM iocs WHERE is_false_positive = 1")
        fp_count = cur.fetchone()[0]
        cur.execute("SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type")
        by_type = dict(cur.fetchall())
        conn.close()
        return {
            "version": THREAT_INTEL_VERSION,
            "total_active_iocs": active_count,
            "false_positives": fp_count,
            "by_type": by_type
        }
