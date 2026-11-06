"""
Protocolo de Comunicación IPC Seguro (Unix Domain Sockets) para Constantine Antivirus.
Esquema estricto: {"version": "5.1.8", "command": "...", "params": {...}, "token": "..."}.
Garantiza:
1. Asignación explícita del socket al grupo 'constantine-users' (root:constantine-users).
2. Permisos restrictivos 0660 para permitir conexión a usuarios legítimos de escritorio sin privilegios de root.
3. Validación estricta en servidor mediante SO_PEERCRED bajo política de Confianza Cero (Zero-Trust).
4. Matriz de Autorización Basada en Roles (RBAC) exclusiva en el servidor para comandos administrativos.
5. Lectura exacta de tramas (recv_exact) para evitar desincronización de streams Unix.
"""
import os
import sys
import grp
import json
import stat
import struct
import socket
import logging
import threading
from typing import Dict, Any, Tuple, Optional, Callable

logger = logging.getLogger("constantine.ipc")

IPC_PROTOCOL_VERSION = "5.4.7"
DEFAULT_SOCKET_PATH = "/run/constantine/constantine_daemon.sock"
FALLBACK_SOCKET_PATH = "/tmp/constantine_daemon.sock"
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB
SOCKET_GROUP_NAME = "constantine-users"

# Matriz de Comandos RBAC
USER_ALLOWED_COMMANDS = {
    "GET_STATUS",
    "PING",
    "SCAN_FILE",
    "SCAN_DIRECTORY",
    "GET_QUARANTINE_LIST",
    "RESTORE_FILE",
    "DELETE_QUARANTINE",
    "GET_AUDIT_LOGS",
    "GET_HISTORY",
    "GET_WHITELIST",
    "GET_SETTINGS",
    "GET_COMPATIBILITY_REPORT",
    "GET_INTEGRATIONS_STATUS",
    "CHECK_AIDE_INTEGRITY",
    "GET_AIDE_STATUS",
    "GET_RESILIENCE_STATUS",
    "DIAGNOSTIC_REPORT",
    "GET_SYSTEMD_POSTURE",
    "GET_THREAT_INTEL_STATS",
    "GET_CLAMAV_ONACC_STATUS",
    "GET_BLOCKING_CAPABILITIES"
}

ADMIN_ONLY_COMMANDS = {
    "ADD_WHITELIST",
    "REMOVE_WHITELIST",
    "UPDATE_SIGNATURES",
    "UPDATE_SYSTEM",
    "TOGGLE_FEATURE",
    "SET_DNS_PROFILE",
    "SET_MAINTENANCE_MODE",
    "RESET_CIRCUIT_BREAKERS",
    "RESET_MODULE_FAULT",
    "ROLLBACK_SIGNATURES",
    "INIT_AIDE_BASELINE",
    "EXPORT_KEY_RECOVERY",
    "ROTATE_VAULT_KEY",
    "SHUTDOWN",
    "SET_CLAMAV_ONACC_MODE",
    "SET_FALCO_COMPLEMENT_MODE",
    "CONFIGURE_MISP_REMOTE",
    "SET_MISP_ENABLED"
}


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """
    Lee exactamente num_bytes desde el socket Unix.
    Garantiza la recepción íntegra de la trama reensamblando fragmentos TCP-like.
    Lanza EOFError si la conexión se cierra antes de completar los bytes solicitados.
    """
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(min(num_bytes - len(buffer), 65536))
        if not chunk:
            raise EOFError("Conexión cerrada prematuramente por el extremo remoto")
        buffer.extend(chunk)
    return bytes(buffer)


def verify_peer_credentials(sock: socket.socket) -> Tuple[bool, int, int, int]:
    """
    Obtiene y valida las credenciales del peer en el kernel mediante SO_PEERCRED.
    Aplica política de CONFIANZA CERO estricta:
    - En ningún caso asigna UID 0 por defecto si falla la obtención.
    - Valida que PID > 0, UID >= 0 y GID >= 0.
    - Devuelve (is_valid, pid, uid, gid).
    """
    # En Linux, SO_PEERCRED = 17 (SOL_SOCKET = 1)
    SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", creds)
        if pid <= 0 or uid < 0 or gid < 0:
            logger.warning("⛔ [CREDENCIALES INVÁLIDAS] SO_PEERCRED fuera de rango: PID=%d, UID=%d, GID=%d", pid, uid, gid)
            return False, 0, -1, -1
        return True, pid, uid, gid
    except Exception as e:
        logger.warning("⛔ [FALLO SO_PEERCRED] Imposible verificar credenciales de peer en kernel: %s. Conexión rechazada por política Zero-Trust.", e)
        return False, 0, -1, -1


def check_user_socket_membership(uid: int, target_group: str = SOCKET_GROUP_NAME) -> bool:
    """
    Comprueba si un UID de usuario pertenece al grupo del socket o es root.
    """
    if uid == 0:
        return True
    try:
        grp_info = grp.getgrnam(target_group)
        target_gid = grp_info.gr_gid
        import pwd
        user_info = pwd.getpwuid(uid)
        username = user_info.pw_name
        # Comprobar GID primario
        if user_info.pw_gid == target_gid:
            return True
        # Comprobar grupos suplementarios
        if username in grp_info.gr_mem:
            return True
        # Consulta de grupos del usuario
        user_groups = [g.gr_gid for g in grp.getgrall() if username in g.gr_mem]
        return target_gid in user_groups
    except (KeyError, ImportError, Exception):
        return False


class SecureIPCServer:
    """Servidor IPC seguro mediante socket de dominio Unix con RBAC y aislamiento de grupos."""

    def __init__(self, socket_path: Optional[str] = None, dispatcher: Optional[Callable] = None):
        self.socket_path = socket_path or DEFAULT_SOCKET_PATH
        self.dispatcher = dispatcher
        self.server_sock: Optional[socket.socket] = None
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.active_connections = 0

    def _setup_socket_permissions(self, path: str):
        """
        Asigna el socket al grupo 'constantine-users' y configura permisos 0660.
        Permite comunicación no privilegiada de la GUI mientras protege el acceso de extraños.
        """
        target_gid = -1
        try:
            grp_info = grp.getgrnam(SOCKET_GROUP_NAME)
            target_gid = grp_info.gr_gid
        except (KeyError, Exception) as e:
            logger.debug("Grupo '%s' no encontrado en el sistema local: %s", SOCKET_GROUP_NAME, e)

        # 1. Asignación de grupo propietario (root:constantine-users)
        if target_gid != -1 and os.getuid() == 0:
            try:
                os.chown(path, 0, target_gid)
                logger.info("🔒 Socket asignado a propietario root:%s (GID %d)", SOCKET_GROUP_NAME, target_gid)
            except (PermissionError, OSError) as e:
                logger.warning("No se pudo cambiar grupo de socket a %s: %s", SOCKET_GROUP_NAME, e)

        # 2. Configurar permisos 0660 (Lectura y escritura para usuario y grupo, nada para otros)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
            logger.info("🔒 Permisos de socket configurados a 0660 (rw-rw----) en %s", path)
        except (PermissionError, OSError) as e:
            logger.error("Error estableciendo permisos 0660 en socket %s: %s", path, e)

    def start(self):
        """Inicia el servidor IPC en un hilo independiente."""
        # Asegurar directorio de runtime
        socket_dir = os.path.dirname(self.socket_path)
        if socket_dir and not os.path.exists(socket_dir):
            try:
                os.makedirs(socket_dir, mode=0o755, exist_ok=True)
            except OSError:
                self.socket_path = FALLBACK_SOCKET_PATH
                socket_dir = os.path.dirname(self.socket_path)

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.bind(self.socket_path)
        self._setup_socket_permissions(self.socket_path)
        self.server_sock.listen(16)
        self.running = True

        self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="IPCServerThread")
        self._thread.start()
        logger.info("🔒 Servidor IPC seguro activo en: %s", self.socket_path)

    def stop(self):
        """Detiene el servidor IPC y elimina el archivo de socket."""
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        logger.info("Servidor IPC detenido.")

    def _listen_loop(self):
        """Bucle principal de aceptación de conexiones."""
        while self.running:
            try:
                client_sock, _ = self.server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except (OSError, socket.error):
                break

    def _handle_client(self, client_sock: socket.socket):
        """Maneja la conexión de un cliente con validación estricta y RBAC."""
        try:
            # 1. Validación de credenciales de peer (Zero-Trust)
            valid, pid, uid, gid = verify_peer_credentials(client_sock)
            if not valid:
                logger.warning("⛔ [CONEXIÓN RECHAZADA] Conexión denegada: no se pudieron verificar credenciales de peer.")
                client_sock.close()
                return

            # 2. Lectura exacta de longitud de trama (4 bytes big-endian)
            try:
                len_bytes = recv_exact(client_sock, 4)
            except (EOFError, ConnectionResetError):
                client_sock.close()
                return

            msg_len = struct.unpack(">I", len_bytes)[0]
            if msg_len > MAX_MESSAGE_SIZE:
                logger.warning("⛔ [MENSAJE DESCARTADO] Tamaño de mensaje (%d bytes) excede el límite máximo de 1MB", msg_len)
                client_sock.close()
                return

            # 3. Lectura exacta del payload
            payload_bytes = recv_exact(client_sock, msg_len)
            try:
                request = json.loads(payload_bytes.decode("utf-8"))
            except Exception:
                logger.warning("⛔ [MENSAJE MALFORMADO] Payload corrupto o manipulación de mensaje detectada.")
                client_sock.close()
                return

            if not isinstance(request, dict):
                logger.warning("⛔ [MENSAJE INVÁLIDO] Petición IPC no es un diccionario JSON.")
                client_sock.close()
                return

            command = request.get("command", "")
            params = request.get("params", {})
            token = request.get("token", "")

            # 4. Verificación de Matriz RBAC en el Servidor
            if command in ADMIN_ONLY_COMMANDS and uid != 0:
                logger.warning("⛔ [ACCESO DENEGADO RBAC] Usuario UID %d intentó ejecutar comando administrativo sin privilegios: %s", uid, command)
                response = {
                    "status": "ERROR",
                    "code": "UNAUTHORIZED",
                    "message": f"Comando administrativo {command} denegado por política RBAC para UID {uid}",
                    "version": IPC_PROTOCOL_VERSION
                }
            else:
                # 5. Despacho seguro al controlador registrado
                if self.dispatcher:
                    status, data, msg = self.dispatcher(command, params, client_uid=uid)
                    response = {
                        "status": status,
                        "data": data,
                        "message": msg,
                        "version": IPC_PROTOCOL_VERSION
                    }
                else:
                    response = {
                        "status": "OK",
                        "data": {"command": command, "client_uid": uid, "client_gid": gid},
                        "message": "Comando procesado exitosamente",
                        "version": IPC_PROTOCOL_VERSION
                    }

            # 6. Envío de respuesta con prefijo de longitud
            resp_bytes = json.dumps(response).encode("utf-8")
            client_sock.sendall(struct.pack(">I", len(resp_bytes)) + resp_bytes)

        except Exception as e:
            logger.error("Error atendiendo cliente IPC: %s", e)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass


class SecureIPCClient:
    """Cliente IPC para la interfaz gráfica y herramientas de línea de comandos."""

    def __init__(self, socket_path: Optional[str] = None):
        self.socket_path = socket_path or DEFAULT_SOCKET_PATH
        if not os.path.exists(self.socket_path) and os.path.exists(FALLBACK_SOCKET_PATH):
            self.socket_path = FALLBACK_SOCKET_PATH

    def send_command(self, command: str, params: Optional[Dict[str, Any]] = None, timeout: float = 10.0) -> Dict[str, Any]:
        """Envía un comando al demonio y espera la respuesta estructurada."""
        if not os.path.exists(self.socket_path):
            return {
                "status": "ERROR",
                "code": "SOCKET_NOT_FOUND",
                "message": f"El socket de Constantine no existe en {self.socket_path}. ¿Está el demonio en ejecución?",
                "version": IPC_PROTOCOL_VERSION
            }

        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_sock.settimeout(timeout)
        try:
            client_sock.connect(self.socket_path)
            req = {
                "version": IPC_PROTOCOL_VERSION,
                "command": command,
                "params": params or {},
                "token": ""
            }
            payload = json.dumps(req).encode("utf-8")
            client_sock.sendall(struct.pack(">I", len(payload)) + payload)

            len_bytes = recv_exact(client_sock, 4)
            resp_len = struct.unpack(">I", len_bytes)[0]
            if resp_len > MAX_MESSAGE_SIZE:
                return {"status": "ERROR", "code": "RESPONSE_TOO_LARGE", "message": "Respuesta excede límite"}

            resp_bytes = recv_exact(client_sock, resp_len)
            return json.loads(resp_bytes.decode("utf-8"))
        except PermissionError:
            return {
                "status": "ERROR",
                "code": "PERMISSION_DENIED",
                "message": f"Permiso denegado al conectar con {self.socket_path}. Asegúrese de pertenecer al grupo '{SOCKET_GROUP_NAME}'.",
                "version": IPC_PROTOCOL_VERSION
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "code": "IPC_FAILURE",
                "message": str(e),
                "version": IPC_PROTOCOL_VERSION
            }
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
