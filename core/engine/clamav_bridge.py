"""
Constantine Antivirus - ClamAV Daemon IPC Bridge (core/engine/clamav_bridge.py)
Cliente ligero, asíncrono y resiliente para el demonio local de ClamAV (clamd):
1. Comunicación Unix Domain Socket / TCP con Clamd:
   - Detecta sockets estándar: /run/clamav/clamd.ctl, /var/run/clamav/clamd.ctl, /tmp/clamd.sock.
   - Soporte opcional TCP localhost:3310.
2. Protocolo Nativo Clamd:
   - PING -> PONG (Keepalive y detección rápida de disponibilidad).
   - VERSION -> Consulta de versión oficial y firmas cargadas.
   - SCAN <path> -> Análisis bajo demanda con resolución de veredicto.
   - zINSTREAM -> Streaming binario por bloques con terminador nulo, permitiendo
     el análisis de descriptores o memoria sin exponer rutas privadas.
3. Resiliencia y Cero Bloqueos:
   - Timeout estricto por llamada (por defecto 1.5s) para garantizar que un fallo en clamd
     nunca congele la interceptación fanotify o el escáner de Constantine.
   - Modo fail-open elegante si clamd no está instalado o detenido.
"""

import os
import time
import socket
import struct
import logging
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger("constantine.clamav_bridge")

DEFAULT_CLAMD_SOCKETS = [
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.ctl",
    "/tmp/clamd.sock"
]


class ClamAVDaemonClient:
    """Cliente de comunicación IPC con el demonio local ClamAV (clamd)."""

    def __init__(self, socket_path: Optional[str] = None, host: Optional[str] = None, port: Optional[int] = None, default_timeout: float = 1.5):
        self.socket_path = socket_path
        self.host = host
        self.port = port
        self.default_timeout = default_timeout
        self._last_availability_check: float = 0.0
        self._is_available_cache: bool = False
        self._cached_version: Optional[str] = None

    def _get_connection(self, timeout: Optional[float] = None) -> Optional[socket.socket]:
        """Establece conexión con clamd a través de socket Unix o TCP."""
        t = timeout or self.default_timeout

        # 1. Probar ruta de socket Unix configurada o detectada
        candidate_paths = [self.socket_path] if self.socket_path else DEFAULT_CLAMD_SOCKETS
        for p in candidate_paths:
            if p and os.path.exists(p):
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(t)
                    s.connect(p)
                    self.socket_path = p
                    return s
                except Exception:
                    continue

        # 2. Probar TCP si está configurado
        if self.host and self.port:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(t)
                s.connect((self.host, self.port))
                return s
            except Exception:
                pass

        return None

    def ping(self, timeout: float = 1.0) -> bool:
        """Envía comando PING y espera respuesta PONG."""
        try:
            s = self._get_connection(timeout=timeout)
            if not s:
                return False
            with s:
                s.sendall(b"PING\n")
                resp = s.recv(128).decode("utf-8", errors="ignore").strip()
                return "PONG" in resp
        except Exception:
            return False

    def is_available(self, cache_ttl: float = 10.0) -> bool:
        """Comprueba disponibilidad con caché temporal para evitar latencias en llamadas repetidas."""
        now = time.time()
        if (now - self._last_availability_check) < cache_ttl:
            return self._is_available_cache

        self._last_availability_check = now
        self._is_available_cache = self.ping(timeout=0.5)
        return self._is_available_cache

    def get_version(self, timeout: float = 1.0) -> Optional[str]:
        """Obtiene la versión oficial de ClamAV y fecha de base de firmas."""
        if self._cached_version and self._is_available_cache:
            return self._cached_version
        try:
            s = self._get_connection(timeout=timeout)
            if not s:
                return None
            with s:
                s.sendall(b"VERSION\n")
                resp = s.recv(512).decode("utf-8", errors="ignore").strip()
                if resp:
                    self._cached_version = resp
                    return resp
        except Exception:
            pass
        return None

    def scan_file(self, file_path: str, timeout: Optional[float] = None) -> Tuple[bool, Optional[str]]:
        """
        Solicita a clamd analizar un archivo en disco mediante el comando SCAN.
        Retorna (is_infected, threat_name).
        """
        if not self.is_available():
            return False, None

        t = timeout or self.default_timeout
        try:
            s = self._get_connection(timeout=t)
            if not s:
                return False, None
            with s:
                cmd = f"SCAN {file_path}\n".encode("utf-8")
                s.sendall(cmd)
                raw_resp = s.recv(1024).decode("utf-8", errors="ignore").strip()
                return self._parse_scan_response(raw_resp)
        except Exception as e:
            logger.debug("Aviso de escaneo en clamd para %s: %s", file_path, e)
            return False, None

    def scan_stream(self, data_or_fd, timeout: Optional[float] = None) -> Tuple[bool, Optional[str]]:
        """
        Envía un flujo de bytes al demonio clamd mediante el comando zINSTREAM.
        Permite escanear archivos en memoria o desde descriptores sin depender de permisos de disco.
        """
        if not self.is_available():
            return False, None

        t = timeout or self.default_timeout
        try:
            s = self._get_connection(timeout=t)
            if not s:
                return False, None
            with s:
                # Iniciar protocolo zINSTREAM
                s.sendall(b"zINSTREAM\0")

                chunk_size = 32768
                if isinstance(data_or_fd, bytes):
                    for i in range(0, len(data_or_fd), chunk_size):
                        chunk = data_or_fd[i:i + chunk_size]
                        s.sendall(struct.pack("!I", len(chunk)) + chunk)
                elif hasattr(data_or_fd, "read"):
                    while chunk := data_or_fd.read(chunk_size):
                        s.sendall(struct.pack("!I", len(chunk)) + chunk)
                else:
                    return False, None

                # Terminador de flujo (chunk de 0 bytes)
                s.sendall(struct.pack("!I", 0))

                # Recibir veredicto
                raw_resp = s.recv(1024).decode("utf-8", errors="ignore").strip()
                return self._parse_scan_response(raw_resp)
        except Exception as e:
            logger.debug("Aviso en scan_stream clamd: %s", e)
            return False, None

    def _parse_scan_response(self, response: str) -> Tuple[bool, Optional[str]]:
        """
        Parsea la respuesta de clamd:
        - '/path/file: OK' -> (False, None)
        - '/path/file: Eicar-Signature FOUND' -> (True, 'Eicar-Signature')
        - '/path/file: Win.Trojan.Agent FOUND' -> (True, 'Win.Trojan.Agent')
        """
        if not response or ": OK" in response:
            return False, None

        if "FOUND" in response:
            parts = response.split(":")
            if len(parts) >= 2:
                verdict = parts[1].strip()
                threat = verdict.replace("FOUND", "").strip()
                return True, threat
            return True, "ClamAV.ThreatDetected"

        return False, None
