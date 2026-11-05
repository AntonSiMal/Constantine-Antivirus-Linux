"""
Constantine Antivirus - Multi-Layer Heuristic & 5-Layer Behavioral Engine (core/engine/heuristic_engine.py)

MOTOR HEURÍSTICO MULTICAPA DE ALTA PRECISIÓN (P1):
No confía únicamente en extensiones de archivo ni en coincidencias de firmas estáticas.
Analiza comportamientos, características estructurales, reputación e impacto del archivo
mediante una arquitectura dividida en cinco capas calibradas:

1. CAPA ESTÁTICA:
   - ELF: cabeceras, arquitectura, secciones sospechosas (.upx, .packed, falta de tabla de secciones).
   - Detección de violaciones W^X (segmentos de código con permisos de lectura, escritura y ejecución simultáneos).
   - Importaciones y llamadas a símbolos críticos (sys_call_table, ptrace, process_vm_writev, kallsyms, init_module).
   - Entropía de Shannon (0.0 - 8.0) por bloques para identificar empaquetado, compresión o cifrado.
   - Permisos inusuales del archivo en disco: bits SUID/SGID activos o permisos universales 0777 en /tmp.

2. CAPA DE FIRMAS:
   - Coincidencias de firmas de reputación criptográfica (Threat Intelligence) y reglas de patrones YARA.

3. CAPA HEURÍSTICA:
   - Scripts que descargan y ejecutan contenido sin tocar disco (curl | bash, wget | sh, python urllib | sh).
   - Técnicas evasivas de ofuscación (Base64 pipes, eval/base64_decode, ráfagas hexadecimales, memfd_create).
   - Modificaciones sospechosas de archivos de inicio de sesión (.bashrc, .profile, /etc/profile.d).
   - Persistencia en el sistema: creación/alteración de unidades systemd o tareas programadas cron.
   - Acceso anómalo a almacenes de credenciales (/etc/shadow, ~/.ssh/id_rsa, ~/.aws/credentials, gnome-keyring).

4. CAPA DE REPUTACIÓN:
   - Origen del archivo: directorios volátiles no confiables (/tmp, /dev/shm, /var/tmp) vs descargas recientes.
   - Integridad del sistema: verificación contra paquetes de la distribución oficial (SystemWhitelist / dpkg).
   - Descuento de riesgo calibrado para binarios verificados del sistema operativo para erradicar falsos positivos.

5. CAPA DE COMPORTAMIENTO (RUNTIME):
   - Modificaciones masivas de documentos (indicadores de ransomware y activación de canary tripwires).
   - Comunicación de red inusual: reverse shells activas (/dev/tcp/, nc -e), listeners en puertos efímeros.
   - Manipulación de memoria de otros procesos del sistema en tiempo de ejecución (inyección ptrace).

ESCALA DE RIESGO CALIBRADA Y POLÍTICA DE ACCIÓN (Puntuación No Aislada):
- Bajo      (0 - 29)   -> PERMIT_AND_LOG   (Permitir y registrar)
- Moderado  (30 - 59)  -> LOG_AND_REVIEW   (Registrar y revisar en auditoría)
- Alto      (60 - 84)  -> DEEP_ANALYZE     (Analizar adicionalmente / alerta preventiva)
- Crítico   (85 - 100) -> BLOCK_AND_ISOLATE (Bloquear y aislar de inmediato)

Regla de correlación anti-falsos positivos: Una característica aislada (ej. alta entropía debida a
compresión ZIP/PNG) nunca bloquea un archivo por sí sola; el aislamiento requiere correlación multicapa.
"""

import os
import stat
import math
import re
import struct
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any, Set

logger = logging.getLogger("constantine.heuristics")

try:
    from core.engine.system_whitelist import SystemWhitelist
    HAS_WHITELIST = True
except Exception:
    HAS_WHITELIST = False


class RiskLevel(str, Enum):
    LOW = "LOW"             # 0 - 29
    MODERATE = "MODERATE"   # 30 - 59
    HIGH = "HIGH"           # 60 - 84
    CRITICAL = "CRITICAL"   # 85 - 100


class RiskAction(str, Enum):
    PERMIT_AND_LOG = "PERMIT_AND_LOG"       # Permitir y registrar
    LOG_AND_REVIEW = "LOG_AND_REVIEW"       # Registrar y revisar
    DEEP_ANALYZE = "DEEP_ANALYZE"           # Analizar adicionalmente
    BLOCK_AND_ISOLATE = "BLOCK_AND_ISOLATE" # Bloquear y aislar


@dataclass
class LayerAnalysisResult:
    layer_name: str
    score: int
    reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HeuristicEvaluation:
    is_malicious: bool
    risk_score: int
    threat_category: Optional[str] = None
    reasons: List[str] = field(default_factory=list)
    entropy: float = 0.0
    is_packed: bool = False
    elf_anomalies: List[str] = field(default_factory=list)

    # Atributos de las 5 capas y gobernanza de riesgo
    risk_level: RiskLevel = RiskLevel.LOW
    action: RiskAction = RiskAction.PERMIT_AND_LOG
    layer_results: Dict[str, LayerAnalysisResult] = field(default_factory=dict)


# Patrones de detección heurística y conductual
HEURISTIC_PATTERNS = [
    # 1. Scripts que descargan y ejecutan contenido directamente a shell (Download & Execute)
    (re.compile(rb"curl\s+-[sSLfk].*\|\s*(ba)?sh", re.IGNORECASE), 45, "Descarga web y ejecución directa por tubería a shell (curl | bash)", "Downloader"),
    (re.compile(rb"wget\s+-[qO].*\|\s*(ba)?sh", re.IGNORECASE), 45, "Descarga web y ejecución directa por tubería a shell (wget | bash)", "Downloader"),
    (re.compile(rb"python(3)?\s+-c\s+.*urllib.*\|\s*(ba)?sh", re.IGNORECASE), 45, "Descarga Python y ejecución por tubería a shell", "Downloader"),

    # 2. Ofuscación y ejecución oculta en memoria (Fileless & Obfuscation)
    (re.compile(rb"base64\s+-d\s*\|\s*(ba)?sh", re.IGNORECASE), 45, "Script ejecutando carga Base64 decodificada directamente en shell", "Obfuscation"),
    (re.compile(rb"eval\s*\(\s*base64_decode\s*\(", re.IGNORECASE), 45, "PHP eval(base64_decode) ejecución oculta de payload", "Obfuscation"),
    (re.compile(rb"memfd_create\s*\(", re.IGNORECASE), 40, "Técnica de evasión 'Fileless execution' en memoria mediante memfd_create", "Fileless"),
    (re.compile(rb"/dev/shm/\.[a-zA-Z0-9_-]+", re.IGNORECASE), 35, "Ejecutable oculto en memoria compartida volátil (/dev/shm)", "Fileless"),
    (re.compile(rb"LD_PRELOAD\s*=\s*", re.IGNORECASE), 40, "Secuestro dinámico de llamadas de librería mediante LD_PRELOAD", "Rootkit"),

    # 3. Modificaciones sospechosas de archivos de inicio de sesión y perfiles de usuario
    (re.compile(rb"(\~|\$HOME|\/home\/[^\/]+|\/etc)\/(\.bashrc|\.bash_profile|\.profile|\.zshrc|profile\.d)", re.IGNORECASE), 40, "Modificación o persistencia en scripts de inicio de sesión del usuario", "Persistence"),
    (re.compile(rb"\/etc\/rc\.local", re.IGNORECASE), 35, "Modificación de script de inicialización heredado /etc/rc.local", "Persistence"),

    # 4. Mecanismos de persistencia en arranque (systemd, cron, timers)
    (re.compile(rb"\/etc\/systemd\/system\/|\/lib\/systemd\/system\/|\.config\/systemd\/user\/", re.IGNORECASE), 40, "Mecanismo de persistencia mediante servicio systemd", "Persistence"),
    (re.compile(rb"\/etc\/cron(\.d|\.daily|\.hourly|\.weekly|\.monthly)?\/|\/var\/spool\/cron\/", re.IGNORECASE), 40, "Mecanismo de persistencia mediante tareas programadas cron", "Persistence"),

    # 5. Acceso y robo anómalo de credenciales sensibles (Credential Access)
    (re.compile(rb"\/etc\/shadow|\/etc\/security\/opasswd", re.IGNORECASE), 50, "Intento de lectura o extracción del almacén de contraseñas /etc/shadow", "CredentialAccess"),
    (re.compile(rb"(\.ssh\/id_rsa|\.ssh\/id_ed25519|\.ssh\/id_ecdsa|\.ssh\/authorized_keys)", re.IGNORECASE), 45, "Acceso a claves criptográficas privadas SSH de usuario", "CredentialAccess"),
    (re.compile(rb"\.aws\/credentials|\.azure\/|\.gcloud\/", re.IGNORECASE), 45, "Extracción de credenciales de infraestructura en la nube", "CredentialAccess"),
    (re.compile(rb"(gnome-keyring|kwallet|Login\s+Data|Cookies\.sqlite)", re.IGNORECASE), 40, "Acceso a almacenes locales de credenciales de navegadores/escritorio", "CredentialAccess"),

    # 6. Canales de comunicación y shells reversas
    (re.compile(rb"exec\s+5<>\s*/dev/tcp/", re.IGNORECASE), 50, "Descriptor de archivo interactivo sobre /dev/tcp/", "ReverseShell"),
    (re.compile(rb"bash\s+-i\s*>&?\s*/dev/tcp/", re.IGNORECASE), 55, "Shell interactiva reversa sobre /dev/tcp/", "ReverseShell"),
    (re.compile(rb"nc(\.traditional|\.openbsd)?\s+-[ec]\s+(\/bin\/)?(ba)?sh", re.IGNORECASE), 50, "Shell reversa mediante netcat flag -e/-c", "ReverseShell"),
    (re.compile(rb"python(3)?\s+-c\s+.*import\s+socket.*pty\.spawn", re.IGNORECASE), 50, "Shell reversa generada mediante Python PTY", "ReverseShell"),

    # 7. Comandos destructivos del sistema
    (re.compile(rb"rm\s+-rf\s+--no-preserve-root\s+/", re.IGNORECASE), 75, "Comando destructivo masivo del sistema de archivos", "Destructive"),
    (re.compile(rb"mkfs(\.ext4|\.vfat|\.xfs)?\s+/dev/[a-z0-9]+", re.IGNORECASE), 60, "Formateo no autorizado de particiones de disco", "Destructive"),
]


class MultiLayerHeuristicEngine:
    """
    Motor Heurístico de 5 Capas de Constantine Antivirus.
    Analiza Estática, Firmas, Heurística, Reputación y Comportamiento con correlación
    ponderada para evitar falsos positivos y aplicar acciones proporcionales.
    """

    def __init__(self, score_threshold: int = 50):
        self.score_threshold = score_threshold
        self.whitelist = SystemWhitelist() if HAS_WHITELIST else None

    # =========================================================================
    # CÁLCULOS MATEMÁTICOS DE ENTROPÍA (SHANNON)
    # =========================================================================
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calcula la entropía de Shannon (0.0 a 8.0) sobre una secuencia de bytes."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    # =========================================================================
    # CAPA 1: ESTÁTICA (ELF, SECCIONES, IMPORTS, PERMISOS, ENTROPÍA)
    # =========================================================================
    def analyze_static_layer(self, data: bytes, file_path: Optional[str] = None) -> LayerAnalysisResult:
        """
        Analiza características estáticas estructurales del binario o archivo:
        - Cabecera ELF e identificación de empaquetadores (UPX, sstrip).
        - Detección de secciones anómalas y violaciones W^X (código escribible y ejecutable).
        - Importaciones y llamadas a símbolos críticos de kernel/inyección.
        - Entropía de Shannon global.
        - Permisos anómalos en el sistema de archivos (SUID/SGID, 0777).
        """
        score = 0
        reasons = []
        metadata: Dict[str, Any] = {}

        is_elf = data.startswith(b"\x7fELF")
        metadata["is_elf"] = is_elf

        # 1. Entropía de Shannon
        entropy = self.calculate_entropy(data[:1024 * 1024])
        metadata["entropy"] = entropy
        if entropy > 7.3:
            score += 30
            reasons.append(f"Alta entropía de Shannon ({entropy}/8.0): indicador de empaquetado, compresión o cifrado")

        # 2. Análisis estructural de binarios ELF
        if is_elf and len(data) >= 52:
            elf_score, elf_reasons, is_packed = self.analyze_elf(data)
            score += elf_score
            reasons.extend(elf_reasons)
            metadata["is_packed"] = is_packed

            # Detección de violaciones W^X en encabezados de programa ELF
            try:
                # Comprobar si hay segmentos PT_LOAD con flags PF_W (2) y PF_X (1) activos
                is_64bit = (data[4] == 2)
                phoff = struct.unpack_from("<Q" if is_64bit else "<I", data, 32 if is_64bit else 28)[0]
                phentsize = struct.unpack_from("<H", data, 54 if is_64bit else 42)[0]
                phnum = struct.unpack_from("<H", data, 56 if is_64bit else 44)[0]

                if phoff > 0 and phentsize > 0 and phnum > 0 and phoff + (phnum * phentsize) <= len(data):
                    has_rwx_segment = False
                    for i in range(min(phnum, 16)):
                        offset = phoff + (i * phentsize)
                        p_type = struct.unpack_from("<I", data, offset)[0]
                        p_flags = struct.unpack_from("<I", data, offset + 4)[0] if is_64bit else struct.unpack_from("<I", data, offset + 24)[0]
                        # PT_LOAD = 1
                        if p_type == 1:
                            # PF_X = 1, PF_W = 2
                            if (p_flags & 1) and (p_flags & 2):
                                has_rwx_segment = True
                                break
                    if has_rwx_segment:
                        score += 35
                        reasons.append("Violación estructural W^X en binario ELF: segmento con permisos simultáneos de escritura y ejecución (RWX)")
                        metadata["has_rwx_segment"] = True
            except Exception as elf_err:
                logger.debug("Aviso parseando program headers ELF: %s", elf_err)

        # 3. Permisos inusuales del archivo en disco
        if file_path and os.path.exists(file_path):
            try:
                st = os.stat(file_path)
                mode = st.st_mode
                metadata["mode"] = oct(mode)

                # Bit SUID activo
                if mode & stat.S_ISUID:
                    score += 35
                    reasons.append("Ejecutable con bit SUID activo (potencial vector de escalada de privilegios)")
                    metadata["is_suid"] = True

                # Bit SGID activo
                if mode & stat.S_ISGID:
                    score += 20
                    reasons.append("Ejecutable con bit SGID activo")
                    metadata["is_sgid"] = True

                # Permisos universales 0777 en directorios temporales
                norm_p = os.path.abspath(file_path)
                is_in_tmp = any(norm_p.startswith(p) for p in ("/tmp", "/dev/shm", "/var/tmp"))
                if is_in_tmp and (mode & 0o777) == 0o777:
                    score += 25
                    reasons.append("Ejecutable con permisos universales de lectura/escritura/ejecución (0777) en directorio volátil")
                    metadata["is_world_writable_exec"] = True
            except OSError as stat_err:
                logger.debug("Aviso en stat estático: %s", stat_err)

        return LayerAnalysisResult(layer_name="Estática", score=min(score, 100), reasons=reasons, metadata=metadata)

    def analyze_elf(self, data: bytes) -> Tuple[int, List[str], bool]:
        """Analiza empaquetadores y símbolos críticos en un ejecutable ELF."""
        score = 0
        anomalies = []
        is_packed = False

        if len(data) < 52 or not data.startswith(b"\x7fELF"):
            return 0, [], False

        # 1. Empaquetadores comunes
        if b"UPX!" in data:
            is_packed = True
            score += 35
            anomalies.append("Binario empaquetado con UPX (técnica de evasión de firmas)")

        # 2. Símbolos críticos de explotación/rootkit
        suspicious_symbols = [
            (b"sys_call_table", 35, "Referencia directa a sys_call_table (indicador de rootkit LKM)"),
            (b"kallsyms_lookup_name", 35, "Resolución directa de símbolos no exportados de kernel"),
            (b"process_vm_writev", 25, "Uso de process_vm_writev (inyección de memoria en otros procesos)"),
            (b"ptrace", 20, "Llamada a ptrace (potencial depuración hostil o anti-análisis)"),
            (b"/etc/ld.so.preload", 40, "Acceso a /etc/ld.so.preload (secuestro de bibliotecas compartidas)"),
            (b"init_module", 30, "Llamada directa a carga de módulos de kernel (init_module)"),
        ]

        for sym, pts, desc in suspicious_symbols:
            if sym in data:
                score += pts
                anomalies.append(desc)

        return score, anomalies, is_packed

    # =========================================================================
    # CAPA 2: FIRMAS (HASHES Y YARA)
    # =========================================================================
    def analyze_signatures_layer(
        self,
        data: bytes,
        file_hash: Optional[str] = None,
        yara_matches: Optional[List[Any]] = None
    ) -> LayerAnalysisResult:
        """
        Analiza coincidencias de Threat Intelligence y reglas de patrones YARA.
        """
        score = 0
        reasons = []
        metadata: Dict[str, Any] = {}

        if file_hash:
            metadata["sha256"] = file_hash

        if yara_matches and len(yara_matches) > 0:
            primary = yara_matches[0]
            rule_name = getattr(primary, "rule", str(primary))
            desc = getattr(primary, "description", rule_name)
            score += 90
            reasons.append(f"Coincidencia con regla YARA de malware: {rule_name} ({desc})")
            metadata["yara_rule"] = rule_name

        return LayerAnalysisResult(layer_name="Firmas", score=min(score, 100), reasons=reasons, metadata=metadata)

    # =========================================================================
    # CAPA 3: HEURÍSTICA AVANZADA (SCRIPTS, PERSISTENCIA, CREDENCIALES, DESCARGAS)
    # =========================================================================
    def analyze_heuristic_layer(self, data: bytes, file_path: Optional[str] = None) -> LayerAnalysisResult:
        """
        Analiza patrones de conducta sospechosa en código o scripts:
        - Descarga y ejecución directa (curl | bash).
        - Persistencia (systemd, cron, timers, scripts de sesión).
        - Acceso a credenciales sensibles (/etc/shadow, claves SSH, credenciales cloud).
        - Ofuscación y ejecución en memoria (memfd_create, /dev/shm).
        """
        score = 0
        reasons = []
        metadata: Dict[str, Any] = {}

        # 1. Búsqueda de patrones heurísticos predefinidos
        categories_triggered = set()
        for pattern, pts, desc, cat in HEURISTIC_PATTERNS:
            if pattern.search(data):
                score += pts
                reasons.append(desc)
                categories_triggered.add(cat)

        metadata["categories_triggered"] = list(categories_triggered)

        # 2. Análisis de ofuscación por ráfagas hexadecimales
        hex_burst = len(re.findall(rb"\\x[0-9a-fA-F]{2}", data))
        if hex_burst > 15:
            score += 30
            reasons.append(f"Ráfaga de bytes hexadecimales ofuscados ({hex_burst} instancias)")
            metadata["hex_burst_count"] = hex_burst

        return LayerAnalysisResult(layer_name="Heurística", score=min(score, 100), reasons=reasons, metadata=metadata)

    def analyze_script(self, data: bytes) -> Tuple[int, List[str]]:
        """Método de compatibilidad hacia atrás para análisis heurístico de scripts."""
        res = self.analyze_heuristic_layer(data)
        return res.score, res.reasons

    # =========================================================================
    # CAPA 4: REPUTACIÓN (ORIGEN, INTEGRIDAD Y LISTA BLANCA DE DISTRIBUCIÓN)
    # =========================================================================
    def analyze_reputation_layer(self, file_path: Optional[str] = None, data: Optional[bytes] = None) -> LayerAnalysisResult:
        """
        Evalúa el origen y la reputación del archivo:
        - Ubicaciones de alto riesgo (/tmp, /dev/shm, descargas).
        - Integridad comprobada de la distribución del sistema operativo (descuento de riesgo).
        """
        score = 0
        reasons = []
        metadata: Dict[str, Any] = {}

        if not file_path:
            return LayerAnalysisResult(layer_name="Reputación", score=0, reasons=[], metadata={})

        norm_p = os.path.abspath(file_path)
        metadata["path"] = norm_p

        # 1. Comprobación de lista blanca y legitimidad en distribución (Descuento de Riesgo)
        if self.whitelist:
            is_trusted_system = self.whitelist.is_trusted_system_binary(norm_p)
            if is_trusted_system:
                score -= 50
                reasons.append("Binario firmado e intacto correspondiente a un paquete oficial del sistema (descuento de riesgo)")
                metadata["is_system_verified"] = True
                return LayerAnalysisResult(layer_name="Reputación", score=max(score, -50), reasons=reasons, metadata=metadata)

        # 2. Archivo en directorios de drop habituales de malware
        if norm_p.startswith(("/tmp/", "/var/tmp/")):
            score += 25
            reasons.append("Archivo alojado en directorio temporal volátil (/tmp)")
            metadata["in_volatile_tmp"] = True
        elif norm_p.startswith("/dev/shm/"):
            score += 35
            reasons.append("Archivo alojado en memoria compartida volátil (/dev/shm)")
            metadata["in_shared_memory"] = True
        elif "/downloads/" in norm_p.lower() or "/descargas/" in norm_p.lower():
            score += 15
            reasons.append("Archivo alojado en carpeta de descargas de usuario")
            metadata["in_downloads"] = True

        return LayerAnalysisResult(layer_name="Reputación", score=max(0, score), reasons=reasons, metadata=metadata)

    # =========================================================================
    # CAPA 5: COMPORTAMIENTO (RUNTIME / ACCIONES DEL PROCESO)
    # =========================================================================
    def analyze_behavioral_layer(
        self,
        runtime_context: Optional[Dict[str, Any]] = None,
        data: Optional[bytes] = None
    ) -> LayerAnalysisResult:
        """
        Evalúa acciones en tiempo de ejecución correlacionadas con el proceso:
        - Modificaciones masivas de documentos (ransomware canary trips).
        - Comunicación de red hostil (reverse shells, sockets crudos).
        - Intentos de inyección o alteración de memoria en otros procesos.
        """
        score = 0
        reasons = []
        metadata: Dict[str, Any] = {}

        if not runtime_context:
            return LayerAnalysisResult(layer_name="Comportamiento", score=0, reasons=[], metadata={})

        metadata.update(runtime_context)

        # 1. Modificaciones masivas o disparador de trampas honeypot canary
        if runtime_context.get("canary_tripped"):
            score += 85
            reasons.append("Comportamiento Ransomware: alteración hostil de archivo señuelo trampa (Canary Honeypot)")

        if runtime_context.get("rapid_file_encryption"):
            score += 75
            reasons.append("Comportamiento Ransomware: ráfaga masiva de modificación y renombrado de extensiones (.locked, .crypto)")

        # 2. Comunicación de red inusual / Reverse Shell
        if runtime_context.get("reverse_shell_active"):
            score += 80
            reasons.append("Comunicación de red inusual: shell reversa activa detectada por eBPF")

        # 3. Manipulación de memoria / Inyección de procesos
        if runtime_context.get("ptrace_injection"):
            score += 70
            reasons.append("Inyección de código en proceso ajeno mediante llamada ptrace")

        return LayerAnalysisResult(layer_name="Comportamiento", score=min(score, 100), reasons=reasons, metadata=metadata)

    # =========================================================================
    # EVALUACIÓN INTEGRAL Y CORRELACIÓN MULTICAPA
    # =========================================================================
    def analyze_buffer(
        self,
        data: bytes,
        file_path: Optional[str] = None,
        runtime_context: Optional[Dict[str, Any]] = None,
        yara_matches: Optional[List[Any]] = None,
        file_hash: Optional[str] = None
    ) -> HeuristicEvaluation:
        """
        Ejecuta la evaluación integral a través de las 5 capas y aplica la política de acción:
        - Capa Estática
        - Capa de Firmas
        - Capa Heurística
        - Capa de Reputación
        - Capa de Comportamiento
        """
        if not data:
            return HeuristicEvaluation(is_malicious=False, risk_score=0, risk_level=RiskLevel.LOW, action=RiskAction.PERMIT_AND_LOG)

        # 1. Ejecutar las 5 capas de forma independiente
        layer_static = self.analyze_static_layer(data, file_path=file_path)
        layer_signatures = self.analyze_signatures_layer(data, file_hash=file_hash, yara_matches=yara_matches)
        layer_heuristic = self.analyze_heuristic_layer(data, file_path=file_path)
        layer_reputation = self.analyze_reputation_layer(file_path=file_path, data=data)
        layer_behavioral = self.analyze_behavioral_layer(runtime_context=runtime_context, data=data)

        layer_results = {
            "Estática": layer_static,
            "Firmas": layer_signatures,
            "Heurística": layer_heuristic,
            "Reputación": layer_reputation,
            "Comportamiento": layer_behavioral
        }

        # 2. Consolidación de motivos y puntuaciones
        all_reasons = []
        for l_res in layer_results.values():
            all_reasons.extend(l_res.reasons)

        raw_score = (
            layer_static.score +
            layer_signatures.score +
            layer_heuristic.score +
            layer_reputation.score +
            layer_behavioral.score
        )
        total_score = min(max(0, raw_score), 100)

        # 3. Regla de Correlación Multi-Señal (Anti-Falsos Positivos)
        # Una única característica aislada (ej. alta entropía debida a compresión) NO puede bloquear por sí sola
        significant_layers = sum(1 for l_name, l_res in layer_results.items() if l_name != "Reputación" and l_res.score >= 30)

        has_signature = (layer_signatures.score > 0)
        has_critical_behavior = (layer_behavioral.score >= 70)

        # 4. Determinación de Nivel de Riesgo y Acción de Política
        if total_score >= 85 and (has_signature or has_critical_behavior or significant_layers >= 2):
            risk_level = RiskLevel.CRITICAL
            action = RiskAction.BLOCK_AND_ISOLATE
        elif total_score >= 60:
            risk_level = RiskLevel.HIGH
            action = RiskAction.DEEP_ANALYZE
        elif total_score >= 30:
            risk_level = RiskLevel.MODERATE
            action = RiskAction.LOG_AND_REVIEW
        else:
            risk_level = RiskLevel.LOW
            action = RiskAction.PERMIT_AND_LOG

        # 5. Deducción de categoría de amenaza
        category = None
        if total_score >= self.score_threshold:
            if any("rootkit" in r.lower() or "sys_call" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.Rootkit"
            elif any("reversa" in r.lower() or "tcp" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.ReverseShell"
            elif any("ransomware" in r.lower() or "canary" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.Ransomware"
            elif any("credencial" in r.lower() or "shadow" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.CredentialAccess"
            elif any("persistencia" in r.lower() or "cron" in r.lower() or "systemd" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.Persistence"
            elif any("downloader" in r.lower() or "curl" in r.lower() or "wget" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.Downloader"
            elif any("upx" in r.lower() or "entropía" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.PackedBinary"
            elif any("destructivo" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.DestructiveCommand"
            else:
                category = "Heuristic.SuspiciousActivity"

        is_mal = (action == RiskAction.BLOCK_AND_ISOLATE) or (total_score >= self.score_threshold)

        return HeuristicEvaluation(
            is_malicious=is_mal,
            risk_score=total_score,
            threat_category=category,
            reasons=all_reasons,
            entropy=layer_static.metadata.get("entropy", 0.0),
            is_packed=layer_static.metadata.get("is_packed", False),
            elf_anomalies=layer_static.reasons,
            risk_level=risk_level,
            action=action,
            layer_results=layer_results
        )

    def analyze_file(
        self,
        file_path: str,
        max_bytes: int = 5 * 1024 * 1024,
        runtime_context: Optional[Dict[str, Any]] = None
    ) -> HeuristicEvaluation:
        """Lee hasta max_bytes (por defecto 5 MB) y ejecuta la evaluación integral de las 5 capas."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(max_bytes)
            return self.analyze_buffer(data, file_path=file_path, runtime_context=runtime_context)
        except Exception as e:
            logger.debug("Error en análisis heurístico de %s: %s", file_path, e)
            return HeuristicEvaluation(is_malicious=False, risk_score=0, reasons=[str(e)])
