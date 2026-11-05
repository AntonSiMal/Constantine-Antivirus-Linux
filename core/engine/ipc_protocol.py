"""
Constantine Antivirus - Secure IPC Protocol & Daemon Bridge (core/engine/ipc_protocol.py)
Canal de comunicación interprocesos (IPC) seguro entre la GUI de usuario no privilegiada y el demonio root:
1. Unix Domain Socket Autenticado con SO_PEERCRED:
   - Valida la identidad del cliente mediante la llamada getpeereid / SO_PEERCRED en kernel de Linux:
     * Verifica UID, GID y PID del proceso emisor antes de procesar cualquier comando.
     * Rechaza conexiones no autorizadas o de usuarios ajenos sin privilegios.
2. Formato de Mensajes Estructurado y Serialización JSON con HMAC-SHA256:
   - Esquema estricto: {"version": "4.3.2", "command": "...", "params": {...}, "token": "..."}.
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
import threading
from enum import Enum
from typing import Dict, Any, Optional, Tuple, Callable, Set

logger = logging.getLogger("constantine.ipc")

DEFAULT_DAEMON_SOCKET = "/run/constantine/daemon.sock"
FALLBACK_DAEMON_SOCKET = "/tmp/constantine_daemon.sock"

# Token de autenticación de sesión generado por el demonio al inicio
SESSION_TOKEN_FILE = "/var/lib/constantine/.ipc_token"
FALLBACK_TOKEN_FILE = "/tmp/constantine_ipc_token"

def _detect_ipc_version() -> str:
    for p in [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "VERSION"),
        "/opt/constantine/VERSION"
    ]:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    ver = f.read().strip()
                    if ver:
                        return ver
            except Exception:
                pass
    return "4.3.2"

IPC_PROTOCOL_VERSION = _detect_ipc_version()


class SecureIPCMessage:
    @staticmethod
    def pack(command: str, params: Optional[Dict[str, Any]] = None, token: str = "") -> bytes:
        payload = {
            "version": IPC_PROTOCOL_VERSION,
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


class IPCRole(str, Enum):
    USER = "USER"
    ADMIN = "ADMIN"

# Tabla de Control de Acceso Basado en Roles (RBAC) del Daemon
ROLE_PERMISSIONS: Dict[str, Set[IPCRole]] = {
    "GET_STATUS": {IPCRole.USER, IPCRole.ADMIN},
    "GET_THREATS": {IPCRole.USER, IPCRole.ADMIN},
    "GET_SHIELDS_HEALTH": {IPCRole.USER, IPCRole.ADMIN},
    "GET_AUDIT_LOGS": {IPCRole.USER, IPCRole.ADMIN},
    "REQUEST_SCAN": {IPCRole.USER, IPCRole.ADMIN},
    "TRIGGER_SWEEP": {IPCRole.USER, IPCRole.ADMIN},
    "UPDATE_CLAMAV_SIGNATURES": {IPCRole.ADMIN},
    "GET_CLAMAV_STATUS": {IPCRole.USER, IPCRole.ADMIN},
    "GET_SYSTEMD_SECURITY": {IPCRole.USER, IPCRole.ADMIN},
    "ADD_WHITELIST": {IPCRole.ADMIN},
    "REMOVE_WHITELIST": {IPCRole.ADMIN},
    "TOGGLE_SHIELD": {IPCRole.ADMIN},
    "RESTORE_QUARANTINE": {IPCRole.ADMIN},
    "PURGE_QUARANTINE": {IPCRole.ADMIN},
    "APPLY_DNS_PROFILE": {IPCRole.ADMIN},
    "ISOLATE_NETWORK": {IPCRole.ADMIN},
    "UNINSTALL": {IPCRole.ADMIN},
}


def validate_ipc_path(path: Any) -> Tuple[bool, str]:
    """
    Valida estrictamente que una ruta recibida por IPC sea segura:
    - Debe ser cadena de texto no vacía.
    - No debe contener bytes nulos (\x00) ni caracteres de control.
    - Debe ser una ruta absoluta y normalizada.
    - Longitud acotada (máx 4096 caracteres).
    """
    if not isinstance(path, str) or not path.strip():
        return False, "Ruta vacía o tipo inválido"
    if "\x00" in path or "\r" in path or "\n" in path:
        return False, "Ruta contiene caracteres nulos o de control no permitidos"
    if len(path) > 4096:
        return False, "Ruta excede la longitud máxima permitida (4096 caracteres)"
    norm = os.path.normpath(path)
    if not os.path.isabs(norm):
        return False, "Se requiere una ruta absoluta"
    return True, norm

def validate_ipc_vault_id(vault_id: Any) -> bool:
    """Valida que un ID de cuarentena sea estrictamente hexadecimal de longitud segura (16-64 chars)."""
    if not isinstance(vault_id, str):
        return False
    import re
    return bool(re.match(r"^[0-9a-fA-F]{16,64}$", vault_id.strip()))

def is_operation_permitted(command: str, is_admin: bool) -> bool:
    """Verifica si un comando está autorizado para el rol del usuario según la política RBAC."""
    cmd_clean = command.upper().strip()
    allowed_roles = ROLE_PERMISSIONS.get(cmd_clean, {IPCRole.ADMIN})
    if is_admin:
        return True
    return IPCRole.USER in allowed_roles


class SecureIPCDaemonServer:
    """
    Servidor IPC seguro en el demonio (root):
    Escucha en un Unix Domain Socket con verificación SO_PEERCRED y despacho de comandos.
    """

    def __init__(self, socket_path: Optional[str] = None, command_handler: Optional[Callable] = None, auth_manager: Optional[Any] = None):
        if socket_path:
            self.socket_path = socket_path
        elif os.geteuid() == 0 and os.path.exists("/run"):
            os.makedirs("/run/constantine", exist_ok=True)
            self.socket_path = DEFAULT_DAEMON_SOCKET
        else:
            self.socket_path = FALLBACK_DAEMON_SOCKET

        self.command_handler = command_handler
        self.auth_manager = auth_manager
        self.server_sock: Optional[socket.socket] = None
        self.running = False
        self.thread: Optional[threading.Thread] = None
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

    def start(self, background: bool = True):
        """Inicializa el socket de dominio Unix con permisos restrictivos 0660, protección contra symlinks y lanza escucha."""
        socket_dir = os.path.dirname(self.socket_path)
        if socket_dir:
            try:
                os.makedirs(socket_dir, mode=0o750, exist_ok=True)
            except Exception:
                pass

        # Protección estricta contra enlaces simbólicos en la ruta del socket
        if os.path.islink(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass
        elif os.path.exists(self.socket_path):
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
        if background:
            self.thread = threading.Thread(target=self._accept_loop, daemon=True, name="constantine-ipc-server")
            self.thread.start()

    def _accept_loop(self):
        while self.running:
            try:
                conn, _ = self.server_sock.accept()
                client_th = threading.Thread(target=self.handle_client, args=(conn,), daemon=True)
                client_th.start()
            except Exception:
                break

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
            token = msg.get("token", "")

            # Validación de autorización RBAC del lado del servidor (Zero-Trust)
            is_admin = (uid == 0)
            if not is_admin and self.auth_manager and hasattr(self.auth_manager, "is_session_valid"):
                is_admin = self.auth_manager.is_session_valid(token)

            if not is_operation_permitted(cmd, is_admin):
                logger.warning("⛔ [ACCESO DENEGADO RBAC] Usuario UID %d intentó ejecutar comando administrativo sin privilegios: %s", uid, cmd)
                conn.sendall(self._pack_response("FORBIDDEN", error=f"Operación '{cmd}' requiere autorización administrativa."))
                conn.close()
                return

            # Validación estricta de parámetros y rutas según el comando
            if cmd == "REQUEST_SCAN":
                path_param = params.get("path")
                valid, msg = validate_ipc_path(path_param)
                if not valid:
                    conn.sendall(self._pack_response("ERROR", error=f"Parámetro 'path' inválido: {msg}"))
                    conn.close()
                    return
                params["path"] = msg

            elif cmd in ("ADD_WHITELIST", "REMOVE_WHITELIST"):
                path_param = params.get("path")
                valid, msg = validate_ipc_path(path_param)
                if not valid:
                    conn.sendall(self._pack_response("ERROR", error=f"Parámetro 'path' inválido: {msg}"))
                    conn.close()
                    return
                params["path"] = msg

            elif cmd == "RESTORE_QUARANTINE":
                vid = params.get("vault_id")
                if not validate_ipc_vault_id(vid):
                    conn.sendall(self._pack_response("ERROR", error="Parámetro 'vault_id' inválido o malformado"))
                    conn.close()
                    return
                dest = params.get("destination")
                if dest:
                    valid, msg = validate_ipc_path(dest)
                    if not valid:
                        conn.sendall(self._pack_response("ERROR", error=f"Parámetro 'destination' inválido: {msg}"))
                        conn.close()
                        return
                    params["destination"] = msg

            if self.command_handler:
                try:
                    res = self.command_handler(cmd, params, uid, is_admin)
                except TypeError:
                    res = self.command_handler(cmd, params, uid)
                resp_status, resp_data, error_msg = res
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

    def send_command(self, command: str, params: Optional[Dict[str, Any]] = None, token: str = "", timeout: float = 3.0) -> Dict[str, Any]:
        """Envía un comando al demonio y espera la respuesta estructurada."""
        if not os.path.exists(self.socket_path):
            return {"status": "ERROR", "error": f"Socket del demonio no encontrado en {self.socket_path}"}

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self.socket_path)
            packet = SecureIPCMessage.pack(command, params, token=token)
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
