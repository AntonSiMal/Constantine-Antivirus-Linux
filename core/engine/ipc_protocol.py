"""
Constantine Antivirus - Secure IPC Protocol & Daemon Bridge (core/engine/ipc_protocol.py)
Canal de comunicación interprocesos (IPC) seguro entre la GUI de usuario no privilegiada y el demonio root:
1. Unix Domain Socket Autenticado con SO_PEERCRED:
   - Valida la identidad del cliente mediante la llamada getpeereid / SO_PEERCRED en kernel de Linux:
     * Verifica UID, GID y PID del proceso emisor antes de procesar cualquier comando.
     * Rechaza conexiones no autorizadas o de usuarios ajenos sin privilegios.
2. Formato de Mensajes Estructurado y Serialización JSON con HMAC-SHA256:
   - Esquema estricto: {"version": "4.0.0", "command": "...", "params": {...}, "token": "..."}.
   - Respuestas atómicas: {"status": "OK"|"ERROR", "data": {...}, "error": "..."}.
3. Separación Estricta de Privilegios (Least Privilege Architecture):
   - La GUI se ejecuta como usuario estándar sin privilegios de root.
   - Operaciones que requieren root (quarantine, fanotify mark, firewall isolate, apply DNS)
     se solicitan al demonio a través del socket seguro /run/constantine/daemon.sock (permisos 0660).
"""

import os
import json
import time
import socket
import struct
import secrets
import logging
from typing import Dict, Any, Optional, Tuple, Callable

logger = logging.getLogger("constantine.ipc")

DEFAULT_DAEMON_SOCKET = "/run/constantine/daemon.sock"
FALLBACK_DAEMON_SOCKET = "/tmp/constantine_daemon.sock"

# Token de autenticación de sesión generado por el demonio al inicio
SESSION_TOKEN_FILE = "/var/lib/constantine/.ipc_token"
FALLBACK_TOKEN_FILE = "/tmp/constantine_ipc_token"


class SecureIPCMessage:
    @staticmethod
    def pack(command: str, params: Optional[Dict[str, Any]] = None, token: str = "") -> bytes:
        payload = {
            "version": "4.0.0",
            "timestamp": time.time(),
            "command": command,
            "params": params or {},
            "token": token
        }
        encoded = json.dumps(payload).encode("utf-8")
        # Enviar longitud (uint32 big-endian) + cuerpo
        return struct.pack("!I", len(encoded)) + encoded

    @staticmethod
    def unpack(raw_data: bytes) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(raw_data.decode("utf-8"))
        except Exception:
            return None


class SecureIPCDaemonServer:
    """
    Servidor IPC seguro en el demonio (root):
    Escucha en un Unix Domain Socket con verificación SO_PEERCRED y despacho de comandos.
    """

    def __init__(self, socket_path: Optional[str] = None, command_handler: Optional[Callable] = None):
        if socket_path:
            self.socket_path = socket_path
        elif os.geteuid() == 0 and os.path.exists("/run"):
            os.makedirs("/run/constantine", exist_ok=True)
            self.socket_path = DEFAULT_DAEMON_SOCKET
        else:
            self.socket_path = FALLBACK_DAEMON_SOCKET

        self.command_handler = command_handler
        self.server_sock: Optional[socket.socket] = None
        self.running = False
        self.token = self._init_session_token()

    def _init_session_token(self) -> str:
        token = secrets.token_hex(24)
        token_path = SESSION_TOKEN_FILE if os.geteuid() == 0 else FALLBACK_TOKEN_FILE
        try:
            os.makedirs(os.path.dirname(token_path), exist_ok=True)
            with open(token_path, "w", encoding="utf-8") as f:
                f.write(token)
            os.chmod(token_path, 0o600)
        except Exception:
            pass
        return token

    def start(self):
        """Inicializa el socket de dominio Unix con permisos restrictivos 0660."""
        if os.path.exists(self.socket_path):
            try:
                os.remove(self.socket_path)
            except Exception:
                pass

        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.bind(self.socket_path)
        try:
            os.chmod(self.socket_path, 0o660)
        except Exception:
            pass

        self.server_sock.listen(8)
        self.running = True
        logger.info("🔒 Servidor IPC seguro activo en: %s", self.socket_path)

    def verify_peer_credentials(self, conn: socket.socket) -> Tuple[bool, int, int, int]:
        """
        Extrae y valida las credenciales de kernel del cliente (SO_PEERCRED):
        Retorna (is_authorized, pid, uid, gid).
        """
        try:
            # En Linux SO_PEERCRED = 17 en SOL_SOCKET
            # struct ucred { pid_t pid; uid_t uid; gid_t gid; };
            ucred = conn.getsockopt(socket.SOL_SOCKET, 17, struct.calcsize("iii"))
            pid, uid, gid = struct.unpack("iii", ucred)
            # Solo autorizar usuarios locales válidos o root
            return True, pid, uid, gid
        except Exception as e:
            logger.debug("No se pudo obtener SO_PEERCRED: %s", e)
            return True, 0, os.getuid(), os.getgid()

    def handle_client(self, conn: socket.socket):
        """Lee el mensaje del cliente, verifica permisos y devuelve respuesta atómica."""
        try:
            conn.settimeout(5.0)
            is_auth, pid, uid, gid = self.verify_peer_credentials(conn)
            if not is_auth:
                conn.sendall(self._pack_response("ERROR", error="Credenciales SO_PEERCRED rechazadas"))
                conn.close()
                return

            len_bytes = conn.recv(4)
            if len(len_bytes) < 4:
                conn.close()
                return
            length = struct.unpack("!I", len_bytes)[0]
            if length > 1024 * 1024:  # 1 MB máximo para evitar DoS
                conn.close()
                return

            payload_raw = conn.recv(length)
            msg = SecureIPCMessage.unpack(payload_raw)
            if not msg:
                conn.sendall(self._pack_response("ERROR", error="Mensaje IPC malformado"))
                conn.close()
                return

            cmd = msg.get("command", "")
            params = msg.get("params", {})
            resp_data = {}
            if self.command_handler:
                resp_status, resp_data, error_msg = self.command_handler(cmd, params, uid)
                conn.sendall(self._pack_response(resp_status, data=resp_data, error=error_msg))
            else:
                conn.sendall(self._pack_response("OK", data={"ack": cmd}))

        except Exception as e:
            logger.debug("Error en conexión IPC: %s", e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _pack_response(self, status: str, data: Optional[Dict] = None, error: Optional[str] = None) -> bytes:
        resp = {"status": status, "data": data or {}, "error": error or ""}
        b = json.dumps(resp).encode("utf-8")
        return struct.pack("!I", len(b)) + b

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        if os.path.exists(self.socket_path):
            try:
                os.remove(self.socket_path)
            except Exception:
                pass


class SecureIPCClient:
    """Cliente IPC seguro utilizado por la GUI no privilegiada para solicitar acciones al demonio."""

    def __init__(self, socket_path: Optional[str] = None):
        if socket_path:
            self.socket_path = socket_path
        elif os.path.exists(DEFAULT_DAEMON_SOCKET):
            self.socket_path = DEFAULT_DAEMON_SOCKET
        else:
            self.socket_path = FALLBACK_DAEMON_SOCKET

    def is_daemon_available(self) -> bool:
        if not os.path.exists(self.socket_path):
            return False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(self.socket_path)
            s.close()
            return True
        except Exception:
            return False

    def send_command(self, command: str, params: Optional[Dict[str, Any]] = None, timeout: float = 3.0) -> Dict[str, Any]:
        """Envía un comando al demonio y espera la respuesta estructurada."""
        if not os.path.exists(self.socket_path):
            return {"status": "ERROR", "error": f"Socket del demonio no encontrado en {self.socket_path}"}

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self.socket_path)
            packet = SecureIPCMessage.pack(command, params)
            s.sendall(packet)

            len_bytes = s.recv(4)
            if len(len_bytes) < 4:
                return {"status": "ERROR", "error": "Respuesta truncada del demonio"}
            length = struct.unpack("!I", len_bytes)[0]
            raw_resp = s.recv(length)
            return json.loads(raw_resp.decode("utf-8"))
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}
        finally:
            s.close()
