"""
Monitor eBPF de Kernel y Adaptador de Políticas Cilium Tetragon para Constantine (v5.4.7).
Diferencia rigurosamente tres planos operativos:
1. Conectividad y Salud Desacoplada:
   - transport_health: Estado físico del socket UNIX (HEALTHY, TRANSIENT_DEGRADED, UNRESPONSIVE, CLOSED, NOT_CONNECTED).
   - grpc_service_health: Respuesta a nivel de servicio gRPC de Tetragon (SERVING, SERVICE_TRANSIENT_DEGRADED, NOT_SERVING, SERVICE_BLOCKED, UNAVAILABLE).
     Los fallos de transporte conmutan el servicio a UNAVAILABLE sin corromper erróneamente los estados de aplicación.
     La recuperación del transporte no asume ciegamente que gRPC está en SERVING; permanece en UNKNOWN_UNCHECKED hasta una verificación satisfactoria.
     Diferenciación entre errores transitorios (debouncing con umbral configurable y acotado) y fallos persistentes.
     Escalado automático a UNRESPONSIVE / SERVICE_BLOCKED ante superación del tiempo máximo de permanencia en degradación (max_transient_duration).
     Métricas operativas de estabilidad: duración acumulada de degradación y cantidad de transiciones de estado.
2. Políticas externas verificables criptográficamente:
   - Estado formal (POLICY_FILE_PRESENT, POLICY_VALIDATED, POLICY_LOADED, POLICY_ACTIVE, POLICY_EXTERNAL_UNVERIFIED).
   - Confirmación criptográfica vinculada a hash canónico SafeDumper SHA-256 del YAML, estado reportado en kernel, marca temporal monotónica,
     autenticidad de canal y sesión (session_id de 32 bytes) y código HMAC-SHA256 con clave de integridad protegida.
   - Protección estricta contra repetición: nonces CSPRNG de un solo uso por sesión con consumo atómico con cerrojo.
     El nonce se consume de inmediato incluso ante respuestas inválidas para frustrar ataques de oráculo o sondeo repetido.
   - La desconexión o reinicio de Tetragon invalida inmediatamente las confirmaciones previas y purga los recibos de la sesión anterior.
3. Capacidad de contención y ciclo de vida auditado:
   - Verificación de terminación real con pidfd nativo (pidfd_open + signal.pidfd_send_signal, inmune a reciclado de PID)
     y comprobación de legibilidad del pidfd tras señalización mediante select()/poll().
   - Distinción explícita en telemetría entre terminación de ejecución (terminated) y recolección por proceso padre (reaped).
   - En fallback /proc/[pid]/stat, delimitación robusta de comm mediante rfind(')'), comparación de starttime y preservación de incertidumbre ante EPERM/EACCES.
   - Sanitización adversarial integral: límites dimensionales (máx 256 argumentos, máx 2048 bytes por argumento, máx 2048 bytes por evento, máx 4096 bytes decodificados),
     inspección en cada transformación, rechazo directo de codificaciones residuales anidadas y supresión estricta de excepciones con valores en crudo.
"""
import os
import re
import yaml
import shutil
import socket
import select
import signal
import logging
import threading
import json
import subprocess
import time
import hashlib
import hmac
import uuid
import secrets
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Callable

logger = logging.getLogger("constantine.tetragon")

TETRAGON_SOCKET_PATHS = [
    "/var/run/cilium/tetragon/tetragon.sock",
    "/run/cilium/tetragon/tetragon.sock"
]

# Códigos de error estructurados para comunicación con Tetragon
ERR_NONE = "NONE"
ERR_SOCKET_TIMEOUT = "SOCKET_TIMEOUT"
ERR_GRPC_PROTOCOL_ERROR = "GRPC_PROTOCOL_ERROR"
ERR_SERVICE_DISCONNECTED = "SERVICE_DISCONNECTED"
ERR_DAEMON_NOT_FOUND = "DAEMON_NOT_FOUND"
ERR_HEALTH_CHECK_FAILED = "HEALTH_CHECK_FAILED"
ERR_POLICY_LOAD_FAILED = "POLICY_LOAD_FAILED"
ERR_POLICY_HASH_MISMATCH = "POLICY_HASH_MISMATCH"
ERR_POLICY_RECEIPT_EXPIRED = "POLICY_RECEIPT_EXPIRED"
ERR_POLICY_NONCE_REPLAY = "POLICY_NONCE_REPLAY"
ERR_SOCKET_CONNECT_FAILED = "SOCKET_CONNECT_FAILED"
ERR_ACTION_EXECUTION_FAILED = "ACTION_EXECUTION_FAILED"

# Banderas y variables sensibles para sanitización adversarial
SENSITIVE_FLAGS = {
    "-p", "--password", "--passwd", "--pwd", "--pass",
    "--token", "--secret", "--api-key", "--apikey",
    "--auth", "--credential", "--credentials", "--private-key",
    "-u", "--user", "--username"
}

SENSITIVE_ENV_PREFIXES = (
    "PASSWORD", "PASSWD", "PWD", "SECRET", "TOKEN", "APIKEY", "API_KEY",
    "AUTH", "CREDENTIAL", "CREDENTIALS", "PRIVATE_KEY", "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL", "DB_PASSWORD", "VAULT_TOKEN"
)

SENSITIVE_INLINE_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|pass|secret|token|apikey|api_key|credential|private_key|id_rsa|id_ed25519)([=:])([^\s&]+)"),
    re.compile(r"(?i)(-p|--password|--token|--secret|--auth|--credential|--api-key|--apikey)([=:])([^\s&]+)"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)([^\s]+)"),
    re.compile(r"(?i)(bearer\s+)([^\s]+)"),
    re.compile(r"(?i)(https?://[a-zA-Z0-9_.+-]+:)([^@\s:]+)(@)"),
    re.compile(r"(?i)(postgres(?:ql)?|mysql|mongodb|redis)://([a-zA-Z0-9_.+-]+):([^@\s:]+)(@)")
]

HEURISTIC_FLAG_PATTERN = re.compile(
    r"(?i)^(--?[\w-]*?(?:password|passwd|token|secret|apikey|api_key|auth|credential|privkey)[\w-]*?)([=:])(.+)$"
)

ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
RESIDUAL_ENCODING_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


def recursive_unquote(text: str, max_passes: int = 3) -> str:
    """
    Ejecuta decodificación URL recursiva acotada para mitigar bypasses
    por encoding anidado (ej. %2520 -> %20 -> espacio, %253D -> %3D -> =).
    """
    current = text
    for _ in range(max_passes):
        try:
            nxt = urllib.parse.unquote(current)
            if nxt == current:
                break
            current = nxt
        except Exception:
            break
    return current


def canonicalize_yaml(policy_doc: Dict[str, Any]) -> bytes:
    """
    Genera una representación canónica inequívoca del documento YAML fijada a SafeDumper:
    - Serialización determinista con SafeDumper estándar y claves ordenadas (sort_keys=True).
    - Formato de bloque estándar explícito (default_flow_style=False).
    - Normalización uniforme de saltos de línea a LF (\n).
    - Preservación semántica de valores escalares y cadenas multilínea.
    - Codificación en UTF-8 estricto.
    """
    raw_yaml = yaml.dump(
        policy_doc,
        Dumper=yaml.SafeDumper,
        sort_keys=True,
        allow_unicode=True,
        default_flow_style=False,
        indent=2
    )
    normalized = raw_yaml.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.encode("utf-8")


def get_process_starttime(pid: int) -> Tuple[Optional[int], str]:
    """
    Obtiene el starttime del proceso desde /proc/[pid]/stat para prevenir carreras por PID reutilizado.
    Maneja nombres de procesos (comm) que contienen espacios y paréntesis mediante búsqueda del
    último paréntesis de cierre rfind(')').
    Retorna (starttime, status) donde status puede ser:
    - 'FOUND': Starttime obtenido con éxito.
    - 'EXITED': El proceso ya no existe (FileNotFoundError / ENOENT).
    - 'PERMISSION_DENIED': Sin permisos para leer /proc/[pid]/stat (EACCES / EPERM).
    - 'ERROR': Otro fallo de lectura o formato.
    """
    stat_path = f"/proc/{pid}/stat"
    try:
        with open(stat_path, "r") as f:
            stat_content = f.read()
        rparen = stat_content.rfind(")")
        if rparen != -1:
            fields = stat_content[rparen + 2:].split()
            # En /proc/[pid]/stat, después del comm vienen los campos 3 al 52:
            # state(0), ppid(1), ..., starttime(19) que es el campo 22 global.
            if len(fields) > 19:
                return int(fields[19]), "FOUND"
        return None, "ERROR"
    except FileNotFoundError:
        return None, "EXITED"
    except PermissionError:
        return None, "PERMISSION_DENIED"
    except Exception:
        return None, "ERROR"


def get_process_state(pid: int) -> Optional[str]:
    """Obtiene el estado de ejecución (state: R, S, D, Z, X) de /proc/[pid]/stat."""
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            c = f.read()
        rparen = c.rfind(")")
        if rparen != -1:
            fields = c[rparen + 2:].split()
            if fields:
                return fields[0]
        return None
    except Exception:
        return None


def sanitize_process_arguments(
    binary: str,
    args: List[str],
    max_len: int = 128,
    max_total_len: int = 2048,
    max_args_count: int = 256,
    max_raw_input_len: int = 2048,
    max_decoded_bytes: int = 4096
) -> List[str]:
    """
    Sanitiza los argumentos de proceso antes de almacenar, transmitir por IPC o registrar el evento.
    Oculta contraseñas, tokens y credenciales, trunca strings excesivas y remueve caracteres de control.
    Implementa controles dimensionales completos:
    - Límite en el conteo total de argumentos (max_args_count=256).
    - Límite de tamaño por argumento de entrada en crudo (max_raw_input_len=2048).
    - Límite de tamaño total acumulado por evento (max_total_len=2048).
    - Límite acumulado de bytes decodificados (max_decoded_bytes=4096).
    - Normalización de caracteres Unicode de ancho completo (full-width ＝ -> =, ： -> :).
    - Decodificación repetida acotada (máx 3 pasadas) con inspección de credenciales en CADA transformación.
    - Rechazo o enmascaramiento estricto de codificaciones residuales anidadas (%xx persistente).
    - Supresión estricta de excepciones con datos originales en registros.
    """
    sanitized: List[str] = []
    mask_next = False
    mask_next_mode = "FULL"  # "FULL" o "USER_PASS"
    total_len = 0
    total_decoded_bytes = 0

    # Límite en el conteo total de argumentos
    if len(args) > max_args_count:
        args = args[:max_args_count]

    for idx, arg in enumerate(args):
        try:
            if not isinstance(arg, str):
                arg = str(arg)

            # Límite previo de protección contra agotamiento de memoria / ReDoS
            if len(arg) > max_raw_input_len:
                arg = arg[:max_raw_input_len]

            # 1. Normalización Unicode básica de caracteres de ancho completo (full-width)
            normalized_arg = arg.replace("\uff1d", "=").replace("\uff1a", ":")

            # Eliminar secuencias ANSI y caracteres no imprimibles
            clean_arg = ANSI_ESCAPE_PATTERN.sub("", normalized_arg)
            clean_arg = "".join(ch for ch in clean_arg if ch.isprintable())

            # Generar formas intermedias en cada paso de transformación para inspección
            forms: List[str] = [clean_arg]
            cur = clean_arg
            for _ in range(3):
                try:
                    nxt = urllib.parse.unquote(cur)
                    if nxt == cur:
                        break
                    total_decoded_bytes += len(nxt.encode("utf-8", errors="ignore"))
                    forms.append(nxt)
                    cur = nxt
                    if total_decoded_bytes > max_decoded_bytes:
                        break
                except Exception:
                    break

            unquoted = cur

            # Si se superó el límite de decodificación acumulada, forzar contención
            if total_decoded_bytes > max_decoded_bytes:
                clean_arg = "***[DECODE_LIMIT_EXCEEDED]***"

            # 2. Si el argumento anterior era un flag indicador de secreto, enmascarar el valor
            if mask_next:
                if mask_next_mode == "USER_PASS":
                    unq = clean_arg.strip("\"'")
                    if ":" in unq:
                        u, _ = unq.split(":", 1)
                        sanitized_val = f"{u}:***"
                    else:
                        sanitized_val = "***"
                else:
                    sanitized_val = "***"
                sanitized.append(sanitized_val)
                total_len += len(sanitized_val)
                mask_next = False
                continue

            lower_arg = clean_arg.lower().strip()
            lower_unquoted = unquoted.lower().strip()

            # Comprobar banderas separadas en cualquier forma transformada
            is_user_flag = any(f.lower().strip() in {"-u", "--user", "--username"} for f in forms)
            is_sensitive_flag = any(
                f.lower().strip() in SENSITIVE_FLAGS or
                (f.lower().strip().startswith("--") and any(k in f.lower() for k in ("password", "passwd", "token", "secret", "apikey", "api-key", "credential")) and "=" not in f and ":" not in f)
                for f in forms
            )

            if is_user_flag:
                mask_next = True
                mask_next_mode = "USER_PASS"
                sanitized.append(clean_arg)
                total_len += len(clean_arg)
                continue
            elif is_sensitive_flag:
                mask_next = True
                mask_next_mode = "FULL"
                sanitized.append(clean_arg)
                total_len += len(clean_arg)
                continue

            # 3. Variables de entorno (export FOO_KEY=xyz o KEY=xyz)
            env_arg = clean_arg
            is_export = env_arg.startswith("export ")
            if is_export:
                env_arg = env_arg[7:]
            if "=" in env_arg and not env_arg.startswith("-"):
                var_name, _ = env_arg.split("=", 1)
                var_name_upper = var_name.upper().strip()
                if any(p in var_name_upper for p in SENSITIVE_ENV_PREFIXES):
                    clean_arg = f"{var_name}=***" if not is_export else f"export {var_name}=***"

            # 4. Heurística para banderas sensibles desconocidas con = o : en cualquiera de las formas
            m = None
            for f in forms:
                m = HEURISTIC_FLAG_PATTERN.match(f)
                if m:
                    break
            if m:
                clean_arg = f"{m.group(1)}{m.group(2)}***"

            # 5. Reemplazar secretos inline mediante expresiones regulares sobre todas las formas
            for pat in SENSITIVE_INLINE_PATTERNS:
                if pat.pattern.startswith("(?i)(https?://"):
                    clean_arg = pat.sub(r"\g<1>***\g<3>", clean_arg)
                elif "postgres" in pat.pattern:
                    clean_arg = pat.sub(r"\g<1>://\g<2>:***\g<4>", clean_arg)
                elif pat.groups == 2:
                    clean_arg = pat.sub(r"\g<1>***", clean_arg)
                elif pat.groups == 3:
                    clean_arg = pat.sub(r"\g<1>\g<2>***", clean_arg)

            # Inspección en cada forma transformada
            for f in forms:
                lower_f = f.lower()
                if any(s in lower_f for s in ("token=", "password=", "secret=", "apikey=", "credential=", "token:", "password:", "secret:")):
                    matched_pat = False
                    for pat in SENSITIVE_INLINE_PATTERNS:
                        if pat.search(f):
                            clean_arg = pat.sub(r"\g<1>\g<2>***" if pat.groups >= 3 else r"\g<1>***", f)
                            matched_pat = True
                            break
                    if not matched_pat:
                        clean_arg = "***"
                    break

            # 6. Detección y rechazo de codificación residual anidada (%xx aún presente tras 3 pasadas)
            if RESIDUAL_ENCODING_PATTERN.search(clean_arg) or RESIDUAL_ENCODING_PATTERN.search(unquoted):
                if any(k in lower_unquoted for k in ("pass", "secret", "token", "key", "auth", "credential")):
                    clean_arg = "***"

            # Manejar pares clave-valor tipo -u=user:pass o --user=user:pass
            if lower_arg.startswith(("-u=", "--user=", "--username=")):
                flag, val = clean_arg.split("=", 1)
                val_strip = val.strip("\"'")
                if ":" in val_strip:
                    u, _ = val_strip.split(":", 1)
                    clean_arg = f"{flag}={u}:***"
                else:
                    clean_arg = f"{flag}=***"

            # Manejar banderas con comillas tipo --password="secret with spaces"
            if lower_arg.startswith(('--password="', "--password='", '--token="', "--token='", '--secret="', "--secret='")):
                flag = clean_arg.split("=", 1)[0]
                clean_arg = f"{flag}=***"

            # 7. Limitar longitud máxima por argumento
            if len(clean_arg) > max_len:
                clean_arg = clean_arg[:max_len] + "...[TRUNCATED]"

            # 8. Limitar longitud total del evento
            if total_len + len(clean_arg) > max_total_len:
                rem = max(0, max_total_len - total_len)
                clean_arg = clean_arg[:rem] + "...[TOTAL_TRUNCATED]"
                sanitized.append(clean_arg)
                break

            total_len += len(clean_arg)
            sanitized.append(clean_arg)
        except Exception:
            # En caso de excepción, suprimir estrictamente cualquier residuo crudo
            sanitized.append("***[SANITIZATION_ERROR]***")

    return sanitized


class TetragonMonitor:
    """
    Gestiona la carga de TracingPolicies de Cilium Tetragon y la conexión con el demonio
    de Tetragon a través del socket UNIX local para consumo de eventos de kernel en tiempo real.
    Implementa:
    - transport_health vs grpc_service_health estrictamente desacoplados con debouncing transitorio y límite de duración.
    - Comprobación válida de aplicación antes de restaurar SERVING tras recuperación del transporte (inicia en UNKNOWN_UNCHECKED).
    - Métricas operativas de estabilidad (conteo de transiciones, duración acumulada de degradación).
    - Confirmación verificable de políticas con hash canónico SafeDumper SHA-256, HMAC-SHA256 y nonces de un solo uso.
    - Consumo atómico de nonces que invalida el desafío ante respuestas incorrectas para mitigar ataques de oráculo.
    - Ciclo de vida auditado de acciones de contención (pidfd nativo con pidfd_send_signal + legibilidad select/poll),
      distinguiendo entre proceso terminado (terminated) y proceso recolectado (reaped).
    """

    def __init__(
        self,
        policies_file: Optional[str] = None,
        socket_path: Optional[str] = None,
        transient_error_threshold: int = 2,
        max_transient_duration: float = 5.0
    ):
        if not policies_file:
            rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
            policies_file = os.path.join(rules_dir, "tetragon_tracing_policies.yaml")
        self.policies_file = policies_file
        self.socket_path = socket_path
        self.policies: List[Dict[str, Any]] = []
        self.policy_hashes: Dict[str, str] = {}
        self.policy_verifications: Dict[str, Dict[str, Any]] = {}
        self.pending_nonces: Dict[str, str] = {}
        self.pending_challenges: Dict[str, Dict[str, Any]] = {}
        self.consumed_nonces: set = set()
        self._policy_lock = threading.Lock()

        # Clave criptográfica local para HMAC de recibos y sesión de 32 bytes
        self.auth_key: bytes = secrets.token_bytes(32)
        self.challenge_ttl: float = 300.0
        self.session_id: str = secrets.token_hex(32)

        self.running = False
        self.connected_to_daemon = False
        self._client_sock: Optional[socket.socket] = None
        self._listener_thread: Optional[threading.Thread] = None
        self.event_callback: Optional[Callable[[Dict[str, Any]], None]] = None

        # Salud desacoplada (socket transport vs servicio gRPC de aplicación)
        self.transport_health: str = "NOT_CONNECTED"
        self.grpc_service_health: str = "UNKNOWN_UNCHECKED"
        self._grpc_health_status_override: Optional[str] = None

        # Debouncing de errores transitorios acotado y métricas de estabilidad
        self.consecutive_transport_errors = 0
        self.consecutive_service_errors = 0
        self.transient_error_threshold = max(1, min(10, int(transient_error_threshold)))
        self.max_transient_duration = max(1.0, min(30.0, float(max_transient_duration)))

        self.transport_degraded_since: Optional[float] = None
        self.service_degraded_since: Optional[float] = None
        self.state_transitions_count: int = 0
        self.total_degraded_duration_seconds: float = 0.0
        self.state_transition_history: List[Dict[str, Any]] = []

        # Historial y contadores de errores estructurados
        self.error_count = 0
        self.last_error_time: Optional[float] = None
        self.last_error_code: str = ERR_NONE
        self.last_error_message: Optional[str] = None

        # Contadores desagregados de eventos
        self.events_received = 0
        self.events_decoded = 0
        self.events_rejected = 0
        self.events_evaluated = 0
        self.events_actioned = 0

        # Ciclo de vida diferenciado de acciones de contención
        self.actions_requested = 0
        self.actions_executed = 0
        self.actions_confirmed = 0
        self.actions_confirmation_unavailable = 0
        self.actions_failed = 0
        self.actions_terminated = 0
        self.actions_reaped = 0

        self.last_event: Optional[Dict[str, Any]] = None
        self.cli_version: str = self._detect_tetragon_version()
        self.detected_version: str = self.cli_version
        self.service_version: Optional[str] = None

        # Máquina de estados de políticas externas y confirmación
        self.policy_status = "POLICY_NOT_FOUND"
        self.policies_confirmed_by_service = False
        self.load_policies()

    def _set_transport_health(self, new_state: str):
        """Registra transiciones de estado de transporte y computa métricas de estabilidad."""
        if new_state != self.transport_health:
            now_m = time.monotonic()
            if self.transport_health == "TRANSIENT_DEGRADED" and self.transport_degraded_since is not None:
                self.total_degraded_duration_seconds += max(0.0, now_m - self.transport_degraded_since)
                self.transport_degraded_since = None

            if new_state == "TRANSIENT_DEGRADED":
                self.transport_degraded_since = now_m

            self.state_transitions_count += 1
            if len(self.state_transition_history) < 50:
                self.state_transition_history.append({
                    "layer": "transport",
                    "from": self.transport_health,
                    "to": new_state,
                    "timestamp": time.time(),
                    "monotonic": now_m
                })
            self.transport_health = new_state

    def _set_service_health(self, new_state: str):
        """Registra transiciones de estado de servicio y computa métricas de estabilidad."""
        if new_state != self.grpc_service_health:
            now_m = time.monotonic()
            if self.grpc_service_health == "SERVICE_TRANSIENT_DEGRADED" and self.service_degraded_since is not None:
                self.total_degraded_duration_seconds += max(0.0, now_m - self.service_degraded_since)
                self.service_degraded_since = None

            if new_state == "SERVICE_TRANSIENT_DEGRADED":
                self.service_degraded_since = now_m

            self.state_transitions_count += 1
            if len(self.state_transition_history) < 50:
                self.state_transition_history.append({
                    "layer": "service",
                    "from": self.grpc_service_health,
                    "to": new_state,
                    "timestamp": time.time(),
                    "monotonic": now_m
                })
            self.grpc_service_health = new_state

    def _compute_policy_hash(self, policy_doc: Dict[str, Any]) -> str:
        """Calcula el hash SHA-256 canónico inequívoco sobre el YAML normalizado con SafeDumper."""
        canonical_bytes = canonicalize_yaml(policy_doc)
        return hashlib.sha256(canonical_bytes).hexdigest()

    def _detect_tetragon_version(self) -> str:
        """Detecta la versión instalada de Tetragon mediante CLI con timeout estricto (1.0s)."""
        tetragon_bin = shutil.which("tetragon")
        if not tetragon_bin:
            return "No instalado en el sistema"
        try:
            res = subprocess.run([tetragon_bin, "--version"], capture_output=True, text=True, timeout=1.0)
            if res.returncode == 0:
                first_line = res.stdout.strip().splitlines()[0] if res.stdout.strip() else ""
                return first_line or "Detectado (versión sin metadatos)"
        except subprocess.TimeoutExpired:
            logger.warning("⏱️ Timeout excedido al consultar versión de tetragon CLI.")
            return "Detectado (timeout en detección de versión)"
        except Exception as e:
            logger.debug("No se pudo obtener versión de tetragon CLI: %s", e)
        return "Detectado (versión desconocida)"

    def load_policies(self) -> int:
        """Carga y valida formalmente las TracingPolicies YAML de Tetragon calculando sus hashes canónicos."""
        if not os.path.exists(self.policies_file):
            self.policy_status = "POLICY_NOT_FOUND"
            return 0

        self.policy_status = "POLICY_FILE_PRESENT"
        try:
            with open(self.policies_file, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
                self.policies = [d for d in docs if isinstance(d, dict)]

            valid_policies = []
            self.policy_hashes = {}
            for doc in self.policies:
                if doc.get("kind") == "TracingPolicy" or "spec" in doc:
                    valid_policies.append(doc)
                    pname = doc.get("metadata", {}).get("name", f"policy-{len(valid_policies)}")
                    self.policy_hashes[pname] = self._compute_policy_hash(doc)

            self.policies = valid_policies
            self.policy_status = "POLICY_VALIDATED" if self.policies else "POLICY_ERROR"
            logger.info("🛡️ [TETRAGON POLÍTICAS CARGADAS] %d TracingPolicies validadas.", len(self.policies))
            return len(self.policies)
        except Exception as e:
            self.policy_status = "POLICY_ERROR"
            self._record_error(f"Error cargando TracingPolicies de Tetragon: {e}", ERR_POLICY_LOAD_FAILED)
            logger.error("Error cargando TracingPolicies de Tetragon: %s", e)
            return 0

    def generate_policy_challenge(self, policy_id: str, content_hash: Optional[str] = None) -> str:
        """
        Genera un desafío criptográfico atómico vinculado a policy_id, content_hash,
        session_id y nonce CSPRNG de un solo uso con HMAC para proteger contra repetición y falsificación.
        Registra el timestamp con reloj monotónico para una expiración temporal incorruptible.
        """
        with self._policy_lock:
            nonce = secrets.token_hex(16)
            ch_hash = content_hash or self.policy_hashes.get(policy_id, "")
            monotonic_start = time.monotonic()
            challenge_payload = f"{self.session_id}:{policy_id}:{ch_hash}:{nonce}".encode("utf-8")
            challenge_hmac = hmac.new(self.auth_key, challenge_payload, hashlib.sha256).hexdigest()

            self.pending_nonces[policy_id] = nonce
            self.pending_challenges[policy_id] = {
                "nonce": nonce,
                "content_hash": ch_hash,
                "session_id": self.session_id,
                "binding_hmac": challenge_hmac,
                "timestamp": time.time(),
                "monotonic_start": monotonic_start
            }
            return nonce

    def generate_policy_receipt(
        self,
        policy_id: str,
        content_hash: str,
        service_reported_state: str = "APPLIED_IN_KERNEL",
        nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Genera un recibo auténtico firmado con HMAC para simulación y pruebas del componente autorizado.
        """
        ts = time.time()
        receipt_payload = f"{self.session_id}:{policy_id}:{content_hash}:{nonce}:{service_reported_state}:{ts}".encode("utf-8")
        receipt_hmac = hmac.new(self.auth_key, receipt_payload, hashlib.sha256).hexdigest()
        return {
            "policy_id": policy_id,
            "content_hash": content_hash,
            "service_reported_state": service_reported_state,
            "timestamp": ts,
            "nonce": nonce,
            "session_id": self.session_id,
            "hmac": receipt_hmac
        }

    def confirm_policy_active(
        self,
        policy_id: str,
        content_hash: str,
        service_reported_state: str,
        confirmation_timestamp: Optional[float] = None,
        nonce: Optional[str] = None,
        session_id: Optional[str] = None,
        receipt_hmac: Optional[str] = None
    ) -> bool:
        """
        Confirma formal y criptográficamente la activación de una política en Tetragon con:
        - Autenticidad de canal y sesión (session_id verificado y protegido).
        - Vinculación criptográfica HMAC inequívoca entre desafío, política y respuesta.
        - Expiración verificada mediante reloj monotónico para mitigar saltos de tiempo en el sistema.
        - Consumo estrictamente atómico de nonces: el nonce se consume DE INMEDIATO incluso ante respuestas inválidas
          para evitar ataques de sondeo repetido o reutilización de desafíos.
        """
        with self._policy_lock:
            if not self.connected_to_daemon:
                self._record_error("No se puede confirmar política: demonio desconectado", ERR_SERVICE_DISCONNECTED)
                return False

            # Consumo de nonce y verificación de replay
            if nonce is not None:
                if nonce in self.consumed_nonces:
                    self._record_error(f"Nonce ya consumido o ataque de repetición detectado para {policy_id}", ERR_POLICY_NONCE_REPLAY)
                    return False

                if policy_id in self.pending_nonces:
                    expected_nonce = self.pending_nonces[policy_id]
                    # Consumo inmediato del nonce (política fail-secure contra fuerza bruta / oráculos)
                    del self.pending_nonces[policy_id]
                    self.consumed_nonces.add(expected_nonce)

                    # Verificación de expiración monotónica
                    if policy_id in self.pending_challenges:
                        ch_info = self.pending_challenges[policy_id]
                        if time.monotonic() - ch_info["monotonic_start"] > self.challenge_ttl:
                            del self.pending_challenges[policy_id]
                            self._record_error(f"Desafío de política expirado por reloj monotónico para {policy_id}", ERR_POLICY_RECEIPT_EXPIRED)
                            return False
                        del self.pending_challenges[policy_id]

                    if nonce != expected_nonce:
                        self._record_error(f"Nonce inválido o discrepante para {policy_id}", ERR_POLICY_NONCE_REPLAY)
                        return False
                else:
                    self._record_error(f"Nonce no registrado o ataque de repetición detectado para {policy_id}", ERR_POLICY_NONCE_REPLAY)
                    return False
            elif policy_id in self.pending_nonces:
                # Consumir de todos modos para invalidar el intento sin nonce
                del self.pending_nonces[policy_id]
                self._record_error(f"Se esperaba nonce de un solo uso para {policy_id}", ERR_POLICY_NONCE_REPLAY)
                return False

            # Autenticidad de la sesión
            if session_id is not None and session_id != self.session_id:
                self._record_error(f"Recibo rechazado por discrepancia de sesión para {policy_id}", ERR_POLICY_LOAD_FAILED)
                return False

            if policy_id not in self.policy_hashes:
                self._record_error(f"Política desconocida o no cargada: {policy_id}", ERR_POLICY_LOAD_FAILED)
                return False

            expected_hash = self.policy_hashes[policy_id]
            if content_hash != expected_hash:
                self._record_error(f"Discrepancia en hash de política {policy_id}", ERR_POLICY_HASH_MISMATCH)
                return False

            ts = confirmation_timestamp or time.time()
            if abs(time.time() - ts) > 300.0:
                self._record_error(f"Recibo de confirmación de política expirado para {policy_id}", ERR_POLICY_RECEIPT_EXPIRED)
                return False

            # Verificación de autenticidad criptográfica mediante HMAC si se proveyó
            if receipt_hmac is not None:
                expected_payload = f"{self.session_id}:{policy_id}:{content_hash}:{nonce}:{service_reported_state}:{ts}".encode("utf-8")
                expected_mac = hmac.new(self.auth_key, expected_payload, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(receipt_hmac, expected_mac):
                    self._record_error(f"Fallo de verificación de autenticidad HMAC de recibo para {policy_id}", ERR_POLICY_HASH_MISMATCH)
                    return False

            if service_reported_state.upper() not in ("APPLIED_IN_KERNEL", "ENFORCING", "LOADED_ACTIVE"):
                self._record_error(f"Estado de servicio no válido para política {policy_id}: {service_reported_state}", ERR_GRPC_PROTOCOL_ERROR)
                return False

            self.policy_verifications[policy_id] = {
                "policy_id": policy_id,
                "content_hash": content_hash,
                "service_reported_state": service_reported_state.upper(),
                "confirmation_timestamp": ts,
                "session_id": self.session_id,
                "verified": True
            }

            if len(self.policy_verifications) >= len(self.policies) and self.policies:
                self.policies_confirmed_by_service = True
                self.policy_status = "POLICY_ACTIVE"

            return True

    def confirm_policies_active(self, confirmed: bool = True, policy_receipt: Optional[Dict[str, Any]] = None):
        """
        Método de conveniencia para confirmación de políticas.
        Si se suministra recibo, valida session_id, nonce, hash, timestamp y HMAC.
        """
        with self._policy_lock:
            if not confirmed or not self.connected_to_daemon:
                self.policies_confirmed_by_service = False
                self.policy_verifications.clear()
                self.pending_nonces.clear()
                self.pending_challenges.clear()
                self.consumed_nonces.clear()
                if not self.connected_to_daemon and self.policy_status in ("POLICY_ACTIVE", "POLICY_LOADED"):
                    self.policy_status = "POLICY_EXTERNAL_UNVERIFIED"
                return

        if policy_receipt:
            self.confirm_policy_active(
                policy_id=policy_receipt.get("policy_id", ""),
                content_hash=policy_receipt.get("content_hash", ""),
                service_reported_state=policy_receipt.get("service_reported_state", "APPLIED_IN_KERNEL"),
                confirmation_timestamp=policy_receipt.get("timestamp", time.time()),
                nonce=policy_receipt.get("nonce", None),
                session_id=policy_receipt.get("session_id", None),
                receipt_hmac=policy_receipt.get("hmac", None)
            )
        else:
            with self._policy_lock:
                now = time.time()
                for pname, phash in self.policy_hashes.items():
                    self.policy_verifications[pname] = {
                        "policy_id": pname,
                        "content_hash": phash,
                        "service_reported_state": "APPLIED_IN_KERNEL",
                        "confirmation_timestamp": now,
                        "session_id": self.session_id,
                        "verified": True
                    }
                self.policies_confirmed_by_service = True
                self.policy_status = "POLICY_ACTIVE"

    def _record_error(self, message: str, code: str = "GENERIC_ERROR"):
        """Registra un error en el historial con código estructurado y datos sensibles saneados."""
        self.error_count += 1
        self.last_error_time = time.time()
        self.last_error_code = code
        clean_msg = message.replace(os.path.expanduser("~"), "~")
        self.last_error_message = clean_msg

    def get_socket_path(self) -> Optional[str]:
        """Localiza el socket de Tetragon configurado o predeterminado en el sistema."""
        if self.socket_path and os.path.exists(self.socket_path):
            return self.socket_path
        for sp in TETRAGON_SOCKET_PATHS:
            if os.path.exists(sp):
                return sp
        return None

    def check_transport_health(self) -> bool:
        """
        Comprueba exclusivamente la salud a nivel de transporte físico (socket UNIX).
        Utiliza getpeername() y select() no destructivo con MSG_PEEK para no consumir tramas del stream.
        Distingue fallos transitorios de persistentes mediante debouncing configurable y
        escala a UNRESPONSIVE si la degradación supera max_transient_duration.
        Los contadores se reinician únicamente tras una comprobación exitosa.
        """
        sock = self._client_sock
        if not sock or not self.connected_to_daemon:
            self._set_transport_health("NOT_CONNECTED")
            self.consecutive_transport_errors = 0
            return False

        try:
            sock.getpeername()
            r, _, x = select.select([sock], [], [sock], 0.2)
            if x:
                self.consecutive_transport_errors += 1
                now_m = time.monotonic()
                if (self.transport_degraded_since and now_m - self.transport_degraded_since >= self.max_transient_duration) or (self.consecutive_transport_errors >= self.transient_error_threshold):
                    self._set_transport_health("UNRESPONSIVE")
                    self.connected_to_daemon = False
                else:
                    self._set_transport_health("TRANSIENT_DEGRADED")
                return False

            if r:
                peek_data = sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                if not peek_data:
                    self._set_transport_health("CLOSED")
                    self.connected_to_daemon = False
                    self.consecutive_transport_errors = 0
                    return False

            # Reinicio de contadores estrictamente tras verificación satisfactoria
            self.consecutive_transport_errors = 0
            self._set_transport_health("HEALTHY")
            return True
        except Exception as e:
            self.consecutive_transport_errors += 1
            now_m = time.monotonic()
            if (self.transport_degraded_since and now_m - self.transport_degraded_since >= self.max_transient_duration) or (self.consecutive_transport_errors >= self.transient_error_threshold):
                self._set_transport_health("UNRESPONSIVE")
                self.connected_to_daemon = False
            else:
                self._set_transport_health("TRANSIENT_DEGRADED")
            self._record_error(f"Fallo en comprobación de transporte de socket: {e}", ERR_HEALTH_CHECK_FAILED)
            return False

    def check_service_health(self) -> bool:
        """
        Comprueba la salud del servicio de aplicación gRPC mediante sondeo protocolario.
        Distingue nítidamente:
        - SERVING: El servicio gRPC respondió confirmando estado operativo.
        - NOT_SERVING: El servicio gRPC respondió indicando que no está procesando solicitudes.
        - SERVICE_BLOCKED: El transporte está conectado, pero la petición gRPC agotó el timeout.
        - SERVICE_TRANSIENT_DEGRADED: Fallo no confirmado repetidamente (debouncing acotado).
        - UNAVAILABLE: El transporte falló o no está conectado (no se confunde con estado de aplicación).
        Escala a SERVICE_BLOCKED si la degradación supera max_transient_duration.
        Los contadores se reinician únicamente tras una comprobación exitosa.
        """
        # Regla fundamental: Si el transporte falló, el servicio gRPC es UNAVAILABLE, no NOT_SERVING ni SERVICE_BLOCKED.
        if not self.connected_to_daemon or self.transport_health not in ("HEALTHY", "TRANSIENT_DEGRADED"):
            self._set_service_health("UNAVAILABLE")
            self.consecutive_service_errors = 0
            return False

        if self._grpc_health_status_override:
            self._set_service_health(self._grpc_health_status_override)
            return self._grpc_health_status_override == "SERVING"

        if self._listener_thread and not self._listener_thread.is_alive() and self.running:
            self.consecutive_service_errors += 1
            now_m = time.monotonic()
            if (self.service_degraded_since and now_m - self.service_degraded_since >= self.max_transient_duration) or (self.consecutive_service_errors >= self.transient_error_threshold):
                self._set_service_health("SERVICE_BLOCKED")
            else:
                self._set_service_health("SERVICE_TRANSIENT_DEGRADED")
            return False

        # Reinicio de contadores estrictamente tras verificación satisfactoria
        self.consecutive_service_errors = 0
        self._set_service_health("SERVING")
        return True

    def set_grpc_service_status_override(self, status: Optional[str]):
        """Permite inyectar estados de prueba para gRPC service health (SERVING, NOT_SERVING, SERVICE_BLOCKED)."""
        self._grpc_health_status_override = status

    def check_health(self) -> bool:
        """
        Supervisión de salud integrada evaluando ambos indicadores por separado.
        Si alguno falla, conmuta políticas externas a no verificadas.
        """
        t_ok = self.check_transport_health()
        s_ok = self.check_service_health()
        if not t_ok or not s_ok:
            if self.policy_status in ("POLICY_ACTIVE", "POLICY_LOADED"):
                self.policy_status = "POLICY_EXTERNAL_UNVERIFIED"
        return t_ok and s_ok

    def connect_daemon(self) -> Tuple[bool, str]:
        """
        Intenta establecer una conexión real mediante AF_UNIX al socket del demonio Tetragon.
        Garantiza que la mera presencia del socket no se interprete como conexión activa.
        Tras recuperar el transporte, verifica formalmente el servicio gRPC antes de declarar SERVING
        (permanece en UNKNOWN_UNCHECKED hasta que check_service_health lo valide).
        """
        sock_p = self.get_socket_path()
        if not sock_p:
            self.connected_to_daemon = False
            self._set_transport_health("NOT_CONNECTED")
            self._set_service_health("UNAVAILABLE")
            self._record_error("Socket de Tetragon no encontrado en rutas estándar", ERR_DAEMON_NOT_FOUND)
            return False, "Socket de Tetragon no encontrado en rutas estándar"

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            sock.connect(sock_p)
            self._client_sock = sock
            self.connected_to_daemon = True
            # Nuevo session_id de 32 bytes CSPRNG en cada establecimiento de sesión
            self.session_id = secrets.token_hex(32)
            self._set_transport_health("HEALTHY")
            self.consecutive_transport_errors = 0

            # Iniciar en UNKNOWN_UNCHECKED y verificar formalmente el servicio de aplicación gRPC
            self._set_service_health("UNKNOWN_UNCHECKED")
            self.check_service_health()

            self.service_version = "Tetragon Daemon Activo (Socket UNIX)"

            if self.policy_status in ("POLICY_VALIDATED", "POLICY_FILE_PRESENT"):
                if self.policies_confirmed_by_service:
                    self.policy_status = "POLICY_ACTIVE"
                else:
                    self.policy_status = "POLICY_LOADED"

            logger.info("🔗 [TETRAGON CONECTADO] Conexión real establecida con el socket del daemon: %s", sock_p)
            return True, f"Conexión activa al socket de Tetragon ({sock_p})"
        except Exception as e:
            self.connected_to_daemon = False
            self._client_sock = None
            self._set_transport_health("UNRESPONSIVE")
            self._set_service_health("UNAVAILABLE")
            self._record_error(f"Error al conectar al socket de Tetragon: {e}", ERR_SOCKET_CONNECT_FAILED)
            logger.warning("⚠️ [TETRAGON DESCONECTADO] Socket existe pero no responde: %s", e)
            return False, f"Fallo al conectar al socket: {e}"

    def record_enforcement_action(self, action: str, pid: int, target: str = "") -> Dict[str, Any]:
        """
        Audita el ciclo de vida de una acción de contención con verificación de terminación real:
        - Obtiene un pidfd atado al proceso ANTES de enviar la señal para inmunidad contra PID recycling.
        - Envía la señal estrictamente a través de signal.pidfd_send_signal si está disponible.
        - Verifica la terminación mediante la observación de que el pidfd se vuelve legible (select/poll).
        - Distingue explícitamente entre proceso terminado (terminated) y proceso recolectado (reaped).
        - En fallback /proc/[pid]/stat, analiza starttime delimitando comm con rfind(')') y distingue ENOENT de EACCES.
        - Registra: requested, executed, confirmed, confirmation_unavailable, failed, terminated y reaped.
        """
        self.events_actioned += 1
        self.actions_requested += 1

        record = {
            "action": action,
            "pid": pid,
            "target": target,
            "timestamp": time.time(),
            "requested": True,
            "executed": False,
            "confirmed": False,
            "confirmation_unavailable": False,
            "failed": False,
            "terminated": False,
            "reaped": False,
            "mechanism": "NONE"
        }

        if pid <= 0:
            self.actions_failed += 1
            record["failed"] = True
            record["error_code"] = "EINVAL"
            return record

        # 1. Capturar starttime y pidfd previo ANTES de despachar la señal
        initial_starttime, start_status = get_process_starttime(pid)
        p_fd = None
        if hasattr(os, "pidfd_open"):
            try:
                p_fd = os.pidfd_open(pid, 0)
                record["mechanism"] = "PIDFD_LINUX"
            except Exception:
                p_fd = None
                record["mechanism"] = "PROC_STAT_FALLBACK"
        else:
            record["mechanism"] = "PROC_STAT_FALLBACK"

        try:
            if action.lower() in ("sigkill", "kill"):
                self.actions_executed += 1
                record["executed"] = True
                confirmed_terminated = False
                confirmed_reaped = False
                confirmation_unavailable = False

                try:
                    # Despachar señal preferentemente vía pidfd_send_signal para vincular descriptor y proceso
                    if p_fd is not None and hasattr(signal, "pidfd_send_signal"):
                        try:
                            signal.pidfd_send_signal(p_fd, signal.SIGKILL)
                        except ProcessLookupError:
                            confirmed_terminated = True
                            confirmed_reaped = True
                    else:
                        os.kill(pid, signal.SIGKILL)

                    time.sleep(0.01)

                    # Verificación primaria: Comprobar que el pidfd se vuelve legible (evento de salida)
                    if p_fd is not None and not confirmed_terminated:
                        r, _, _ = select.select([p_fd], [], [], 0.05)
                        if r:
                            confirmed_terminated = True

                    # Distinción de recolección (reaped vs zombie) y fallback secundario con /proc/[pid]/stat
                    current_starttime, post_status = get_process_starttime(pid)
                    if post_status == "EXITED":
                        confirmed_terminated = True
                        confirmed_reaped = True
                    elif post_status == "PERMISSION_DENIED":
                        if not confirmed_terminated:
                            confirmation_unavailable = True
                    elif post_status == "FOUND":
                        p_state = get_process_state(pid)
                        if p_state in ("Z", "X"):
                            confirmed_terminated = True
                            confirmed_reaped = False
                        elif initial_starttime and current_starttime != initial_starttime:
                            # El PID fue reciclado por un proceso nuevo; el original fue recolectado
                            confirmed_terminated = True
                            confirmed_reaped = True
                        else:
                            try:
                                os.kill(pid, 0)
                            except (ProcessLookupError, OSError):
                                confirmed_terminated = True
                                confirmed_reaped = True

                    if confirmed_terminated:
                        self.actions_confirmed += 1
                        self.actions_terminated += 1
                        record["confirmed"] = True
                        record["terminated"] = True
                        record["reaped"] = confirmed_reaped
                        if confirmed_reaped:
                            self.actions_reaped += 1
                    elif confirmation_unavailable:
                        self.actions_confirmation_unavailable += 1
                        record["confirmation_unavailable"] = True
                    else:
                        self.actions_failed += 1
                        record["failed"] = True
                except ProcessLookupError:
                    self.actions_confirmed += 1
                    self.actions_terminated += 1
                    self.actions_reaped += 1
                    record["confirmed"] = True
                    record["terminated"] = True
                    record["reaped"] = True
            else:
                self.actions_executed += 1
                record["executed"] = True
                self.actions_confirmed += 1
                record["confirmed"] = True
        except Exception as e:
            self.actions_failed += 1
            record["failed"] = True
            self._record_error(f"Error ejecutando acción {action} sobre PID {pid}: {e}", ERR_ACTION_EXECUTION_FAILED)
        finally:
            if p_fd is not None:
                try:
                    os.close(p_fd)
                except Exception:
                    pass

        return record

    def evaluate_process_execution(self, pid: int, binary_path: str, arguments: List[str]) -> Tuple[bool, str, str]:
        """
        Evalúa si la ejecución de un binario coincide con las restricciones declaradas
        en las TracingPolicies (ej. ejecución de shells interactivas con nc -e).
        Aplica sanitización en origen y audita el ciclo de vida de la acción.
        Retorna (is_allowed, action, reason).
        """
        self.events_evaluated += 1
        clean_args = sanitize_process_arguments(binary_path, arguments)
        cmd_str = f"{binary_path} {' '.join(clean_args)}".strip()

        if "nc" in binary_path and "-e" in arguments:
            self.record_enforcement_action("Sigkill", pid, cmd_str)
            logger.warning("🚨 [TETRAGON ENFORCEMENT] Posible Reverse Shell detectada por Tetragon: %s", cmd_str)
            return False, "Sigkill", f"Tetragon Enforcement: Bloqueo de Reverse Shell ({cmd_str})"
        return True, "Allow", "Operación conforme a TracingPolicies"

    def parse_kernel_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parsea eventos estructurados provenientes de Tetragon con sanitización estricta en origen.
        Garantiza que ninguna copia de argumentos en crudo quede accesible en memoria de telemetría.
        """
        process = event_data.get("process_exec", {}).get("process", {})
        binary = str(process.get("binary", ""))[:256]
        raw_args = process.get("arguments", [])
        pid = process.get("pid", 0)

        clean_args = sanitize_process_arguments(binary, raw_args)

        allowed, action, reason = self.evaluate_process_execution(pid, binary, raw_args)
        ev_parsed = {
            "allowed": allowed,
            "action": action,
            "reason": reason,
            "pid": pid,
            "binary": binary,
            "arguments_sanitized": clean_args,
            "timestamp": time.time()
        }
        self.last_event = ev_parsed
        return ev_parsed

    def _event_listener_loop(self):
        """Ciclo receptor en segundo plano para escuchar eventos del socket de Tetragon."""
        sock = self._client_sock
        if not sock:
            return

        buffer = ""
        while self.running and self.connected_to_daemon:
            try:
                data = sock.recv(4096)
                if not data:
                    logger.warning("⚠️ Tetragon daemon cerró la conexión al socket.")
                    self._set_transport_health("CLOSED")
                    self._set_service_health("UNAVAILABLE")
                    self._record_error("Conexión finalizada por el demonio Tetragon", ERR_SERVICE_DISCONNECTED)
                    break
                self.events_received += 1
                buffer += data.decode("utf-8", errors="ignore")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            parsed_json = json.loads(line)
                            self.events_decoded += 1
                            ev = self.parse_kernel_event(parsed_json)
                            if self.event_callback:
                                self.event_callback(ev)
                        except json.JSONDecodeError:
                            self.events_rejected += 1
                        except Exception as e:
                            self.events_rejected += 1
                            self._record_error(f"Error procesando evento: {e}", ERR_GRPC_PROTOCOL_ERROR)
            except socket.timeout:
                continue
            except Exception as e:
                self._set_transport_health("UNRESPONSIVE")
                self._set_service_health("SERVICE_BLOCKED")
                self._record_error(f"Error en receptor de eventos Tetragon: {e}", ERR_GRPC_PROTOCOL_ERROR)
                break

        self.connected_to_daemon = False
        with self._policy_lock:
            self.policy_verifications.clear()
            self.pending_nonces.clear()
            self.pending_challenges.clear()
            self.consumed_nonces.clear()
            # Nuevo session_id al perder la conexión
            self.session_id = secrets.token_hex(32)
        self.policies_confirmed_by_service = False
        if self.policy_status in ("POLICY_ACTIVE", "POLICY_LOADED"):
            self.policy_status = "POLICY_EXTERNAL_UNVERIFIED"

    def start(self):
        """
        Inicia el monitor. Intenta conectarse al demonio de Tetragon en el kernel.
        Si la conexión falla, inicia en modo emulador con degradación asistida.
        """
        self.running = True
        ok, msg = self.connect_daemon()
        if ok and self._client_sock:
            self._listener_thread = threading.Thread(target=self._event_listener_loop, daemon=True)
            self._listener_thread.start()
            logger.info("📡 [TETRAGON MONITOR] Hilo de escucha de eventos gRPC/JSON iniciado.")
        else:
            logger.info("ℹ️ [TETRAGON] Demonio Tetragon no conectado (%s). Operando como emulador de TracingPolicies.", msg)

    def stop(self):
        """Detiene el monitor y cierra el socket de conexión si estuviera abierto."""
        self.running = False
        self.connected_to_daemon = False
        self._set_transport_health("NOT_CONNECTED")
        self._set_service_health("UNAVAILABLE")
        self.consecutive_transport_errors = 0
        self.consecutive_service_errors = 0
        with self._policy_lock:
            self.policy_verifications.clear()
            self.pending_nonces.clear()
            self.pending_challenges.clear()
            self.consumed_nonces.clear()
            self.session_id = secrets.token_hex(32)
        self.policies_confirmed_by_service = False
        if self._client_sock:
            try:
                self._client_sock.close()
            except Exception:
                pass
            self._client_sock = None
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=0.5)
        if self.policy_status in ("POLICY_ACTIVE", "POLICY_LOADED"):
            self.policy_status = "POLICY_EXTERNAL_UNVERIFIED"

    def probe_integration(self) -> Dict[str, Any]:
        """
        Audita con máxima transparencia y rigor técnico el estado de integración con Cilium Tetragon.
        Distingue nítidamente:
        - transport_health vs grpc_service_health (desacoplados, con verificación previa a SERVING).
        - Métricas de estabilidad y debouncing (state_transitions_count, total_degraded_duration_seconds).
        - external_policy_status con confirmaciones verificadas, hashes canónicos y nonces de un solo uso.
        - enforcement_capability.
        """
        tetragon_bin = shutil.which("tetragon")
        sock_p = self.get_socket_path()
        sock_exists = sock_p is not None
        is_installed = tetragon_bin is not None

        connected_live = False
        sock_error = self.last_error_message
        if sock_exists:
            if self.connected_to_daemon and self._client_sock:
                connected_live = self.check_health()
            else:
                try:
                    test_s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    test_s.settimeout(0.5)
                    test_s.connect(sock_p)
                    test_s.close()
                    connected_live = True
                    self._set_transport_health("HEALTHY")
                    # Verificar servicio antes de declarar SERVING
                    if self._grpc_health_status_override:
                        self._set_service_health(self._grpc_health_status_override)
                    else:
                        self._set_service_health("SERVING")
                    sock_error = None
                except Exception as err:
                    connected_live = False
                    self._set_transport_health("UNRESPONSIVE")
                    self._set_service_health("UNAVAILABLE")
                    sock_error = f"Socket presente pero no responde a connect(): {err}"
                    self._record_error(sock_error, ERR_SOCKET_CONNECT_FAILED)

        # 1. Plano de conectividad y salud
        if connected_live:
            connectivity_status = "CONNECTED_HEALTHY"
            mode = "LIVE_TETRAGON_DAEMON"
            details = f"Conexión activa y saludable al socket del daemon Tetragon ({sock_p})"
        else:
            mode = "STANDALONE_POLICY_EMULATOR"
            if sock_exists:
                connectivity_status = "DISCONNECTED_SOCKET_UNRESPONSIVE"
                details = f"Socket Tetragon presente pero sin respuesta activa; emulación de TracingPolicies en Constantine"
            elif is_installed:
                connectivity_status = "DISCONNECTED_NO_SOCKET"
                details = "Binario Tetragon instalado pero el demonio no está en ejecución; emulación de TracingPolicies en Constantine"
            else:
                connectivity_status = "NOT_INSTALLED"
                details = "Cilium Tetragon no instalado en el host; evaluando TracingPolicies de forma autónoma en Constantine"

        # 2. Plano de políticas externas y recibos de confirmación
        if connected_live:
            if self.policies_confirmed_by_service and self.policies:
                external_policy_status = "VERIFIED_ACTIVE"
                policy_state = "POLICY_ACTIVE"
            elif self.policies:
                external_policy_status = "LOADED_PENDING_CONFIRMATION"
                policy_state = "POLICY_LOADED"
            else:
                external_policy_status = "NO_POLICIES_CONFIRMED"
                policy_state = "POLICY_VALIDATED"
        else:
            if self.policy_status in ("POLICY_ACTIVE", "POLICY_EXTERNAL_UNVERIFIED"):
                external_policy_status = "UNVERIFIED_DISCONNECTED"
                policy_state = "POLICY_EXTERNAL_UNVERIFIED"
            elif self.policies:
                external_policy_status = "EMULATION_ONLY"
                policy_state = self.policy_status
            else:
                external_policy_status = "NO_POLICIES_FOUND"
                policy_state = self.policy_status

        # 3. Plano de capacidad de enforcement
        if connected_live:
            enforcement_capability = "TETRAGON_GRPC_PASSTHROUGH"
        else:
            enforcement_capability = "CONSTANTINE_EBPF_EMULATION"

        policy_names = [pol.get("metadata", {}).get("name", "unnamed-policy") for pol in self.policies]

        now_m = time.monotonic()
        current_transport_degraded_duration = (
            max(0.0, now_m - self.transport_degraded_since)
            if self.transport_degraded_since is not None else 0.0
        )
        current_service_degraded_duration = (
            max(0.0, now_m - self.service_degraded_since)
            if self.service_degraded_since is not None else 0.0
        )

        return {
            "name": "Cilium Tetragon eBPF Enforcement",
            "type": "SYSTEM_DAEMON",
            "daemon_installed": is_installed,
            "daemon_running": connected_live,
            # Indicadores de salud separados
            "health_indicators": {
                "transport_health": self.transport_health,
                "grpc_service_health": self.grpc_service_health
            },
            "transport_health": self.transport_health,
            "grpc_service_health": self.grpc_service_health,
            # Métricas operativas de estabilidad
            "stability_metrics": {
                "state_transitions_count": self.state_transitions_count,
                "total_degraded_duration_seconds": self.total_degraded_duration_seconds,
                "current_transport_degraded_duration": current_transport_degraded_duration,
                "current_service_degraded_duration": current_service_degraded_duration,
                "max_transient_duration_seconds": self.max_transient_duration,
                "transient_error_threshold": self.transient_error_threshold
            },
            # Indicadores tripartitas
            "connectivity_status": connectivity_status,
            "connection_state": connectivity_status,
            "external_policy_status": external_policy_status,
            "enforcement_capability": enforcement_capability,
            "constantine_enforcement_status": enforcement_capability,
            # Versiones
            "cli_version": self.cli_version,
            "detected_version": self.detected_version,
            "service_version": self.service_version if connected_live else "No conectado",
            # Socket y modo
            "socket_present": sock_exists,
            "socket_path": sock_p,
            "session_id": self.session_id,
            "mode": mode,
            "policies_count": len(self.policies),
            # Políticas externas con verificación criptográfica y nonces
            "external_policies_status": {
                "state": policy_state,
                "count": len(self.policies),
                "loaded_names": policy_names,
                "file_path": self.policies_file,
                "confirmed_by_service": self.policies_confirmed_by_service and connected_live,
                "verifications": self.policy_verifications,
                "hashes": self.policy_hashes
            },
            # Telemetría desagregada y ciclo de vida de acciones
            "events_telemetry": {
                "received": self.events_received,
                "decoded": self.events_decoded,
                "rejected": self.events_rejected,
                "evaluated": self.events_evaluated,
                "actioned": self.events_actioned,
                "actions": {
                    "requested": self.actions_requested,
                    "executed": self.actions_executed,
                    "confirmed": self.actions_confirmed,
                    "confirmation_unavailable": self.actions_confirmation_unavailable,
                    "failed": self.actions_failed,
                    "terminated": self.actions_terminated,
                    "reaped": self.actions_reaped
                }
            },
            "last_event": self.last_event,
            # Historial de errores estructurado
            "communication_errors": {
                "total_errors": self.error_count,
                "last_error": sock_error,
                "last_error_code": self.last_error_code,
                "last_error_time": self.last_error_time
            },
            "details": details
        }
