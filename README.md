# ⚔️ Constantine Antivirus 5.1 (Linux Active Kernel Defense)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![License: Commercial](https://img.shields.io/badge/License-Commercial%20Available-success.svg)](LICENSE-COMMERCIAL.md)
[![CLA: Protected](https://img.shields.io/badge/CLA-Protected-purple.svg)](CONTRIBUTING.md)
[![Platform: Linux](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20Linux%20Mint-orange.svg)](https://www.debian.org)
[![Kernel: fanotify & eBPF](https://img.shields.io/badge/Kernel-fanotify%20%26%20eBPF-red.svg)](https://ebpf.io)
[![Version: v4.2.2](https://img.shields.io/badge/Version-v5.1.0-blue.svg)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)
[![GitHub Repository](https://img.shields.io/badge/GitHub-AntonSiMal%2FConstantine--Antivirus--Linux-blue?logo=github)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)

**Constantine Antivirus** es una suite de seguridad activa, preventiva y no intrusiva (*Zero-Nag*) para distribuciones Linux basadas en Debian (Ubuntu, Linux Mint, Debian) compatible con entornos gráficos **X11** y **Wayland**.

A diferencia de las herramientas antivirus tradicionales en Linux limitadas a escaneos pasivos bajo demanda, Constantine emula los **minifiltros de E/S de Windows** mediante `fanotify` a nivel de kernel (`FAN_OPEN_PERM`, `FAN_OPEN_EXEC_PERM`) y sondas **eBPF**, deteniendo y neutralizando amenazas antes de que el código toque la CPU y sin la fatiga de alertas constantes de sistemas antiguos.

---


---

## 🔄 Ciclo de Trabajo, Flujo de Datos y Reglas de Arquitectura

### 1. Constantine Data Flow (Flujo de Datos del Núcleo)
```text
============================================================
                   CONSTANTINE DATA FLOW
============================================================

                         LINUX SYSTEM
                              |
                              |
              +---------------+---------------+
              |                               |
              v                               v
       FILE SYSTEM EVENTS               SYSTEM EVENTS
              |                               |
              v                               v
          FANOTIFY                         TETRAGON
              |                               |
              |                               |
              +---------------+---------------+
                              |
                              v
                    CONSTANTINE EVENT MANAGER
                              |
                              v
                  SECURITY DECISION ENGINE
                              |
              +---------------+----------------+
              |               |                |
              v               v                v
          CLAMAV            YARA-X          THREAT INTEL
        MALWARE SCAN      RULE ANALYSIS    REPUTATION CHECK
              |               |                |
              +---------------+----------------+
                              |
                              v
                     EVENT CORRELATION
                              |
                              v
                       SECURITY VERDICT
                              |
              +---------------+----------------+
              |               |                |
              v               v                v
            CLEAN           SUSPICIOUS        MALICIOUS
              |               |                |
              v               v                v
            ALLOW           ALERT USER        BLOCK / ISOLATE
                              |                |
                              |                v
                              |          QUARANTINE MANAGER
                              |                |
                              |                v
                              |          SECURE STORAGE
                              |                |
                              +----------------+
                              |
                              v
                      SECURITY DATABASE
                              |
                  +------------+------------+
                  |                         |
                  v                         v
            AUDIT LOGGER              NOTIFICATION
                  |                         |
                  +------------+------------+
                              |
                              v
                      DESKTOP INTERFACE
                              |
              +---------------+----------------+
              |               |                |
              v               v                v
          DASHBOARD         REPORTS          ALERTS
              |
              v
        PROTECTION STATUS
============================================================
```

### 2. External Security Applications (Separación GUFW / Proton VPN)
```text
============================================================
               EXTERNAL SECURITY APPLICATIONS
============================================================

                   CONSTANTINE INSTALLER
                             |
                 +-----------+-----------+
                 |                       |
                 v                       v
               GUFW                  PROTON VPN
                 |                       |
                 v                       v
          FIREWALL ENABLED        DESKTOP SHORTCUT
             INITIALLY                   |
                 |                       v
                 v                 PROTON VPN APP
          GUFW APPLICATION               |
                 |                       v
                 v               USER CONTROLS VPN
            USER MANAGES
          FIREWALL MANUALLY
============================================================
```

### 3. Installation Data Flow (Flujo de Instalación del Sistema)
```text
============================================================
                   INSTALLATION DATA FLOW
============================================================

                    CONSTANTINE INSTALLER
                              |
                              v
                    SYSTEM COMPATIBILITY
                        VERIFICATION
                              |
                              v
                    DEPENDENCY INSTALLATION
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
        CLAMAV             YARA-X              TETRAGON
          |                   |                   |
          +-------------------+-------------------+
                              |
                              v
                    CONSTANTINE CORE
                      INSTALLATION
                              |
                              v
                    SECURITY SERVICES
                      CONFIGURATION
                              |
                              v
                    GUFW INSTALLATION
                              |
                              v
                    FIREWALL INITIAL
                       ACTIVATION
                              |
                              v
                   PROTON VPN INSTALLATION
                              |
                              v
                    DESKTOP SHORTCUTS
                              |
                              v
                    INSTALLATION CHECK
                              |
                              v
                      INSTALLATION DONE
============================================================
```

### 4. Update Data Flow (Flujo de Actualización de Firmas y Modelos)
```text
============================================================
                     UPDATE DATA FLOW
============================================================

                     UPDATE MANAGER
                          |
           +--------------+--------------+
           |              |              |
           v              v              v
       CLAMAV DB       YARA-X RULES    THREAT INTEL
           |              |              |
           +--------------+--------------+
                          |
                          v
                  SIGNATURE VALIDATION
                          |
                          v
                   UPDATE VERIFICATION
                          |
                          v
                   SECURITY DATABASE
                          |
                          v
                   PROTECTION SERVICES
============================================================
```

### 5. User Control Flow (Flujo de Control del Usuario)
```text
============================================================
                   USER CONTROL FLOW
============================================================

                      DESKTOP INTERFACE
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
      CONSTANTINE            GUFW              PROTON VPN
          |                   |                   |
          v                   v                   v
    ANTIVIRUS CONTROL    FIREWALL CONTROL      VPN CONTROL
          |                   |                   |
          v                   v                   v
    SCANS / ALERTS       USER MANAGES          USER MANAGES
    QUARANTINE           ALL RULES             CONNECTIONS
    PROTECTION
============================================================
```

### 6. Architecture Rules (1 - 10)
```text
============================================================
                     ARCHITECTURE RULES
============================================================

1. CONSTANTINE MANAGES ITS OWN ANTIVIRUS SERVICES.

2. CONSTANTINE INSTALLS GUFW AND ENABLES THE FIREWALL
   DURING INITIAL INSTALLATION.

3. THE USER HAS FULL CONTROL OVER FIREWALL SETTINGS
   THROUGH GUFW.

4. CONSTANTINE DOES NOT CREATE, MODIFY OR DELETE
   FIREWALL RULES.

5. CONSTANTINE INSTALLS PROTON VPN.

6. CONSTANTINE PROVIDES A SHORTCUT TO PROTON VPN.

7. THE USER MANAGES ALL VPN CONNECTIONS AND SETTINGS.

8. CONSTANTINE DOES NOT CONTROL VPN CONNECTIONS.

9. EXTERNAL APPLICATIONS OPERATE INDEPENDENTLY
   FROM THE ANTIVIRUS CORE.

10. CONSTANTINE MUST NOT MODIFY USER CONFIGURATIONS
    WITHOUT EXPLICIT AUTHORIZATION.

============================================================
```

## 🏛️ Arquitectura Constantine Antivirus 5.x (Separación de Responsabilidades)

En **Constantine 5.x**, el antivirus no administra el cortafuegos ni la VPN. Su responsabilidad es instalar las herramientas necesarias, facilitar su acceso directo y activar de forma segura la protección inicial del cortafuegos sin sobrescribir reglas existentes:

```text
============================================================
               CONSTANTINE ANTIVIRUS 5.x
============================================================

1. CORE ANTIVIRUS
   |-- Security Core
   |-- Security Decision Engine
   |-- Event Manager
   |-- Threat Detection
   |-- File Protection
   |-- Behavior Monitoring
   |-- Threat Intelligence
   |-- Malware Analysis
   |-- Quarantine Manager
   |-- Security Database
   |-- Update Manager
   |-- Audit Logger

2. PROTECCION DEL SISTEMA
   |-- ClamAV
   |-- YARA-X
   |-- Tetragon
   |-- fanotify
   |-- eBPF
   |-- Linux IMA / EVM (opcional)
   |-- fs-verity (opcional)

3. PROTECCION DE RED
   |-- Threat Intelligence
   |-- URLhaus
   |-- MalwareBazaar
   |-- OpenPhish
   |-- DNS Threat Detection (DoT/DoH)
   |
   |-- FIREWALL (GUFW)
   |   |-- Instalación de GUFW y UFW
   |   |-- Activación inicial segura del firewall
   |   |-- Acceso directo a GUFW en el escritorio
   |   |-- Administración exclusiva del usuario
   |   |-- Sin modificación automática de reglas
   |
   |-- VPN (Proton VPN)
       |-- Instalación de Proton VPN
       |-- Acceso directo a Proton VPN
       |-- Administración exclusiva del usuario
       |-- Sin control de conexiones VPN

4. DESKTOP INTERFACE
   |-- Dashboard & Protection Status
   |-- Malware Detection & Scan Manager
   |-- Quarantine & Security Reports
   |-- Threat Intelligence Status
   |-- System Protection Status
   |
   |-- External Applications
       |-- GUFW
       |-- Proton VPN

5. INSTALLER
   |-- Constantine Antivirus & Dependencias
   |-- ClamAV & YARA-X
   |-- GUFW & Proton VPN
   |-- Activación inicial segura del Firewall
   |-- Accesos directos de escritorio (Constantine, GUFW, Proton VPN)
   |-- Configuración de servicio y permisos
============================================================
```

### 🔒 Separación de Responsabilidades: GUFW y Proton VPN
* **Cortafuegos (GUFW):**
  - **Responsabilidad de Constantine:** Instalación de paquetes (`gufw`, `ufw`), activación inicial segura durante la instalación y provisión de accesos directos. Audita y muestra con precisión los **4 estados posibles**:
    1. *Firewall instalado y activado.*
    2. *Firewall instalado y desactivado.*
    3. *Firewall no instalado.*
    4. *Estado desconocido o no verificable.*
  - **Responsabilidad del usuario:** Administración completa y manual de reglas, permisos, puertos y excepciones desde la interfaz gráfica de GUFW.
  - **Garantía EDR 5.x:** Constantine **NUNCA** crea, modifica, elimina ni administra reglas del cortafuegos de forma automática después de la instalación.
* **Red Privada Virtual (Proton VPN):**
  - **Responsabilidad de Constantine:** Instalación del cliente oficial y acceso directo desde el Centro de Control y el menú de aplicaciones.
  - **Responsabilidad del usuario:** Inicio de sesión, selección de servidores, protocolos, perfiles y conexión/desconexión manual del túnel.
  - **Garantía EDR 5.x:** Constantine **NO** establece conexiones, no selecciona ubicaciones ni supervisa el tráfico VPN del usuario.

## 🛡️ Características Principales

### 1. Protección Activa en Kernel (fanotify & eBPF)
* **Interceptación Síncrona en Kernel:** Congela operaciones de apertura y ejecución en disco en tiempo real. Si un archivo es hostil, el kernel recibe la orden `FAN_DENY` antes de que se inicie el proceso.
* **Monitor Ticker en Vivo:** Panel en tiempo real dentro de *Escudos en Vivo* que audita operaciones de kernel, procesos en RAM y sockets de red cada 1.5 segundos.
* **Metadatos de Firmas en Tiempo Real:** Visualización detallada de versiones, fechas y horas de actualización de la Base de Hashes (Threat Intel), Firmas Heurísticas (YARA Demons) y Base Anti-Phishing/Reputación Web.
* **Cilium Tetragon (Kernel Observability & Runtime Enforcement):** Integración profunda con Cilium Tetragon (eBPF en kernel) para supervisión de procesos, operaciones de archivos (`openat`, `unlinkat`, `rename`, `truncate`), sockets y red (`tcp_connect`). Aplica la distinción crítica de seguridad: SIGKILL por sí solo no garantiza que una escritura no se haya completado en disco; por ello, Tetragon combina `Override: argError: -13` (-EACCES) con `Sigkill` y el interceptor `fanotify` (`FAN_DENY`) para anulación transaccional fail-secure en kernel y aislamiento en el Baúl Criptográfico. Opera como agente autónomo fuera de Kubernetes administrado por systemd y con políticas TracingPolicy YAML locales.
* **Falco CNCF (Syscall Behavioral Detection & Alerting Engine):** Integración nativa con Falco (proyecto graduado de CNCF) para supervisión heurística continua basada en reglas de llamadas al sistema. Detecta operaciones sospechosas relacionadas con privilegios (`pkexec`, `su`, `sudo`, EUID mismatch, setuid), conexiones de red inesperadas (balizamiento C2, puertos anómalos, sockets interactivos de reverse shell) y accesos indebidos a credenciales críticas (`/etc/shadow`, claves SSH privadas). Refleja la distinción arquitectónica fundamental: Falco detecta y notifica anomalías (no bloquea por diseño de su propia política); Constantine asume el rol de ejecutor activo traduciendo cada alerta en respuesta inmediata (bloqueo `fanotify`, corte de red con firewall, terminación `SIGKILL` y aislamiento en el Baúl Criptográfico).
* **Estrategia Wazuh FIM + YARA & Respuesta Activa:** Adopción del flujo de vigilancia de integridad de archivos (FIM / `syscheck`) correlacionado con YARA documentado por Wazuh. Evita el escaneo constante e ineficiente de todos los archivos del equipo: detecta la creación o modificación de un archivo en tiempo real, extrae su identidad forense (hash SHA-256, UID, GID, permisos, bits SUID/SGID), ejecuta el análisis YARA dirigido y aplica Respuesta Activa (Active Response) según el nivel de severidad de la regla (Niveles 1 a 15: Alerta informativa, Cuarentena transaccional en el Baúl, Aislamiento de red mediante firewall drop y Neutralización de procesos).
* **Diagnóstico e Inventario del Sistema con osquery (SQL System Telemetry):** Integración nativa de osquery para consultar la instrumentación del host mediante SQL estándar sobre tablas virtuales (`processes`, `listening_ports`, `users`, `deb_packages`, `systemd_units`, `suid_binaries`, `crontab`, `security_configurations`). Evalúa el estado de seguridad respondiendo a las preguntas clave: actualizaciones pendientes, servicios desconocidos, procesos anómalos ejecutándose desde `/tmp` o `/dev/shm`, archivos o binarios SUID alterados y directivas de kernel no endurecidas.
* **Centralización de Inteligencia de Amenazas con MISP (Threat Sharing Platform & Feeds):** Integración nativa con la plataforma MISP (Malware Information Sharing Platform & Threat Sharing) para centralizar, correlacionar y administrar indicadores de compromiso (IoCs: hashes SHA-256 de malware, IPs maliciosas de C2, dominios sospechosos y URLs de distribución). Implementa la arquitectura recomendada: en lugar de instalar la infraestructura pesada central de servidor MISP en cada endpoint, Constantine opera como un consumidor de alta velocidad de feeds curados (MISP JSON, CSV, texto libre) y APIs REST remotas, indexando y canalizando los IoCs directamente a la base de datos `threat_intel.db` y permitiendo al motor de decisiones (Scanner / Interceptor fanotify / Firewall / Baúl) actuar en tiempo real.
* **Reglas de Detección de Comportamiento Sigma (Universal SOC & pySigma Linux Adapter):** Integración nativa del estándar abierto Sigma (SigmaHQ) para reutilizar conocimiento universal de detección de amenazas. Mediante el adaptador en tiempo de ejecución de Constantine, las reglas comunitarias YAML se transforman y evalúan dinámicamente contra la telemetría del kernel (procesos, llamadas al sistema y rutas de archivos). Cubre de forma nativa: ejecución sospechosa de comandos (cradles de descarga directa a bash/sh, pipelines base64, shells reversas netcat), persistencia mediante servicios (manipulación de unidades systemd o tareas cron), modificación peligrosa de permisos (chmod +s, bits SUID/SGID, accesos 777 en /bin), actividades anómalas en SSH (authorized_keys, lectura de id_rsa, túneles remotos), ejecución desde directorios temporales (/tmp, /dev/shm, /var/tmp) y comportamientos de herramientas de ataque conocidas (LinPEAS, pspy, descubrimiento sudo).
* **Evolución y Soporte Dual YARA-X (Rust / VirusTotal):** Integración progresiva con YARA-X manteniendo compatibilidad del ~99% con las reglas existentes (demons.yar). Coexistencia segura entre YARA-X (Rust) y libyara clásica sin descarte prematuro, con auditoría automatizada (=======================================================================
🦀 CONSTANTINE EDR - AUDITORÍA DE EVALUACIÓN YARA-X (Rust)
=======================================================================
 • Versión del Motor     : YARA-X no disponible (Requerido: pip install yara-x o binario yr)
 • Biblioteca yara-x     : NO INSTALADA (pip install yara-x)
 • Binario CLI yr        : NO DISPONIBLE
 • Directorio de Reglas  : /tmp/constantine/core/rules
 • Total Archivos .yar   : 3
 • Archivos Compatibles  : 3/3
 • Preparación Migración : 100.0%
-----------------------------------------------------------------------
DETALLE POR ARCHIVO DE REGLAS:
  [✅ COMPATIBLE] demons.yar
  [✅ COMPATIBLE] linux_threats.yar
  [✅ COMPATIBLE] webshells.yar
-----------------------------------------------------------------------
PRUEBA DE COINCIDENCIA DE PATRONES:
  ✅ Detección de prueba exitosa (1 regla disparada: Demons_EICAR_Standard_Test)
=======================================================================
RECOMENDACIÓN DE MIGRACIÓN:
 • Mantener estrategia de doble motor (YARA-X como primario + libyara como respaldo).
 • Las reglas 'demons.yar' son 100% compatibles con la gramática de YARA-X.
 • Transición lista para activación sin riesgo de regresión operativa.
=======================================================================).
* **Vigilancia y Neutralización Activa en RAM con eBPF:** Supervisa llamadas al sistema `sys_enter_execve` y `sys_enter_ptrace`, detectando inyecciones de memoria, reverse shells (`nc -e`, `/dev/tcp/`) y binarios LOLBins, aplicando neutralización activa inmediata mediante terminación `SIGKILL`, corte de sockets de red en firewall y aislamiento en el baúl.
* **Lista Blanca Automática de la Distribución (Zero-Nag):** Los paquetes oficiales instalados mediante `apt`, `dpkg`, Flatpak o Snap se validan a velocidad nativa (< 0.05 ms), eliminando falsos positivos e interrupciones innecesarias.

### 2. Escudo Anti-Ransomware Activo
* **Trampas Señuelo (Canary Honeypots):** Despliega archivos trampa en directorios estratégicos del sistema.
* **Detección de Ráfagas de Cifrado:** Supervisa la creación o renombrado masivo de extensiones maliciosas (`.locked`, `.crypto`, `.lockbit`, `.enc`).
* **Neutralización Inmediata:** Congela la E/S y liquida el proceso agresor con señal `SIGKILL` en menos de 1 ms, cortando además sus sockets de red en el firewall.

### 3. Almacenamiento USB y Centinela de Descargas
* **Auto-Escaneo Silencioso de Memorias USB:** Al conectar una memoria USB o disco duro externo en `/media/$USER/` o `/run/media/` (`udisks2`), se engancha `fanotify` preventivo y se analizan archivos `autorun.inf`, scripts ofuscados y droppers. Si el dispositivo está limpio, no interrumpe la pantalla.
* **Centinela de Descargas en Vuelo:** Audita en segundo plano la carpeta `~/Descargas` (`~/Downloads`) en el milisegundo exacto en que tu navegador completa la descarga de un archivo (renombrado de `.crdownload` o `.part`).

### 4. Centinelas de Persistencia y Privacidad de Hardware
* **Centinela de Persistencia en Arranque:** Vigila en tiempo real que ningún malware intente instalarse en `/etc/systemd/system/`, cron jobs (`/etc/cron*`), `/etc/profile.d/` o `/etc/rc.local`.
* **Protección Anti-Espía de Periféricos:** Supervisa descriptores en `/dev/video*` y el subsistema de audio, alertando si un proceso no autorizado intenta encender la cámara web o el micrófono en segundo plano.

### 5. Cortafuegos (GUFW), Proton VPN & DNS Mullvad
* **Control de Cortafuegos UFW & GUFW:** Interruptor para activar/desactivar UFW y botón para abrir la interfaz gráfica avanzada **GUFW** (`pkexec gufw`).
* **Integración Opcional con Proton VPN:** Detección automática del cliente oficial de Proton VPN y botón de lanzamiento directo. Para preservar la estabilidad de la red, el antivirus no fuerza la instalación de herramientas VPN de terceros; los usuarios que deseen instalarlo disponen del script seguro `scripts/setup_protonvpn.sh` con verificación criptográfica SHA-256 previa.
* **Perfiles DNS Cifrados de Mullvad & Quad9:** Selector integrado con configuración en un clic de perfiles DoT (puerto 853) / DoH en `systemd-resolved`:
  * *Mullvad Base (`194.242.2.4`):* Malware, phishing, publicidad intrusiva y rastreadores.
  * *Mullvad Adblock (`194.242.2.3`):* Solo anuncios y telemetría.
  * *Mullvad Extended (`194.242.2.5`):* Malware, anuncios y bloqueo de redes sociales.
  * *Mullvad Family (`194.242.2.6`):* Control parental: contenido adulto, apuestas y malware.
  * *Quad9 (`9.9.9.9`):* Ciberamenazas y validación DNSSEC financiado por Mullvad.

### 6. Integración Integral del Motor Antivirus ClamAV (Cisco Talos)
* **Arquitectura Cooperativa Multicapa:**
```text
Constantine
    |
    +-- Interceptor de archivos (Kernel fanotify: FAN_OPEN_PERM, FAN_OPEN_EXEC_PERM)
    |
    +-- clamd (Demonio local ClamAV vía Unix Domain Socket)
    |     |
    |     +-- Firmas oficiales de malware (Cisco Talos / CVD)
    |     +-- Análisis profundo de ejecutables (ELF, PE, scripts)
    |     +-- Análisis de documentos (Office, PDF, OLE)
    |     +-- Archivos comprimidos (ZIP, TAR, GZ con ArchiveSentinel anti-ZipBomb)
    |
    +-- YARA (Reglas de detección conductual y patrones específicos de Linux)
    |
    +-- Decisión de seguridad (Aislamiento, Baúl Criptográfico, Fail-Secure/Fail-Open)
```
* **Prevención de Conflictos On-Access (Cero Deadlocks con clamonacc):**
  Constantine evita conscientemente la ejecución simultánea de `clamonacc` y el interceptor propio sobre los mismos puntos de montaje. Constantine asume el control del interceptor síncrono en kernel mediante `fanotify`, excluye mutuamente los procesos de ClamAV (`clamd`, `freshclam`, `clamscan`) para evitar bucles infinitos y utiliza el demonio `clamd` exclusivamente como motor de análisis de alto rendimiento vía IPC Unix Domain Socket (`/run/clamav/clamd.ctl`).
* **Ingesta y Actualización de Firmas (FreshClam & CVD Parser):**
  Sincronización desatendida mediante `freshclam` con soporte para extracción segura de contenedores CVD/CLD y carga directa de hashes (.hsb/.hdb) y listas anti-phishing (.pdb) hacia SQLite.
* **Fachada Unificada de Python (`import clamav`):**
  Módulo de conveniencia `core.engine.clamav` accesible también como `import clamav`, permitiendo escanear flujos en memoria y archivos de disco de forma transparente.

### 7. Experiencia de Usuario & Seguridad de Acceso
* **Icono en la Barra de Tareas Junto al Reloj:** Icono residente (`AppIndicator3` / `Gtk.StatusIcon`) que inicia con el sistema, muestra el estado en vivo y permite abrir el centro de seguridad, escanear memorias o lanzar la VPN.
* **Integración con Clic Derecho:** Acción en el explorador de archivos de Linux Mint (**Nemo**) y Ubuntu (**Nautilus**) para escanear cualquier archivo o carpeta con un simple clic derecho.
* **Autenticación Nativa Linux con `sudo` / PAM (Zero-Breach):** Cero contraseñas propietarias o inseguras. Los usuarios administradores autorizan acciones críticas utilizando su propia contraseña personal de Linux.
* **Despliegue Multi-Usuario Global:** Disponible para todos los usuarios actuales y futuros gracias a la configuración de `/etc/skel/`, `/usr/share/applications/` y `/etc/xdg/autostart/`.
* **Soporte Multilingüe (i18n):** Selector en la cabecera para alternar instantáneamente entre **Español (ES)** e **Inglés (EN)**.
* **Baúl de Cuarentena Cifrado con AES-256-GCM (Formato Streaming V3):** Aislamiento criptográfico con nonces independientes de 96 bits por bloque generados por CSPRNG (`secrets.token_bytes`), control de volumen por clave (límite de 100.000 operaciones bajo NIST SP 800-38D), rotación de claves (`rotate_key`) con llavero histórico persistente (`vault_keyring.json`), permisos `000` y retrocompatibilidad total con formatos V2 y V1. Muestra por defecto las **últimas 10 amenazas** para mantener una interfaz limpia y fluida, con botón para alternar a vista completa.
* **Lista Blanca con Selección Múltiple:** Exclusiones personalizadas con eliminación por lotes (`Gtk.SelectionMode.MULTIPLE`) y botones para seleccionar o desmarcar todos los elementos.
* **Desinstalación Integrada en Configuración:** Botón de desinstalación segura accesible desde la pestaña de configuración (`⚙️`), con validación de administrador (`pkexec`) y opciones para conservar o purgar el baúl de cuarentena.
* **Auditoría Forense:** Registro cronológico de incidentes con exportación de reportes en formato JSON.

---

## 🗺️ Mapeo con el Framework MITRE ATT&CK

Constantine Antivirus cubre tácticas y técnicas críticas de la matriz **MITRE ATT&CK for Enterprise (Linux)**:

| Táctica MITRE | ID Técnica | Técnica | Mecanismo de Defensa en Constantine |
| :--- | :--- | :--- | :--- |
| **Execution** | `T1059` | Command and Scripting Interpreter | Interceptación eBPF en `sys_enter_execve` contra reverse shells (`nc -e`, `/dev/tcp/`). |
| **Execution** | `T1204` | User Execution: Malicious File | Bloqueo síncrono `FAN_OPEN_EXEC_PERM` en disco antes de cargar código en CPU. |
| **Persistence** | `T1053` | Scheduled Task/Job: Cron | Centinela en tiempo real sobre `/etc/cron*` y `/var/spool/cron/`. |
| **Persistence** | `T1543.002` | Create or Modify System Process: Systemd | Detección de inyección de unidades maliciosas en `/etc/systemd/system/`. |
| **Defense Evasion** | `T1036` | Masquerading | Detección de binarios camuflados como procesos legítimos del sistema en `/proc`. |
| **Defense Evasion** | `T1070` | Indicator Removal: Clear Command History | Centinela de integridad de bitácoras y registros forenses protegidos. |
| **Credential Access** | `T1003` | OS Credential Dumping | Bloqueo preventivo de accesos indebidos a memoria y manipulación de procesos con `ptrace`. |
| **Command & Control** | `T1090` | Proxy / Reverse Shell Sockets | Monitoreo proactivo de conexiones de red y corte instantáneo de sockets en firewall (`ss -K`). |
| **Impact** | `T1486` | Data Encrypted for Impact (Ransomware) | Detección de ráfagas de cifrado y protección de *Canary Honeypots* con terminación `SIGKILL` < 1 ms. |

---

## 📁 Estructura del Repositorio

```text
Constantine-Antivirus-Linux/
├── assets/
│   ├── constantine.svg           # Icono oficial vectorial del sistema
│   └── style.css                 # Tema Apple macOS Cupertino GTK 3
├── core/
│   ├── auth/
│   │   └── auth_manager.py       # Autenticación delegada a PAM/sudo nativo
│   ├── engine/
│   │   ├── interceptor.py        # Interceptación síncrona fanotify + Whitelist
│   │   ├── clamav.py             # Fachada de integración ClamAV (import clamav)
│   │   ├── clamav_bridge.py      # Cliente IPC nativo para clamd (socket Unix)
│   │   ├── clamav_importer.py    # Parser de firmas CVD/CLD, HSB y PDB
│   │   ├── clamav_manager.py     # Gestor integral ClamAV y coordinación On-Access
│   │   ├── archive_sentinel.py   # Centinela anti-ZipBomb y contenedores anidados
│   │   ├── yarax_engine.py       # Motor evolutivo YARA-X (Rust / VirusTotal)
│   │   ├── scanner.py            # YARA + Hashes + Heurística
│   │   ├── vault.py              # Baúl de cuarentena cifrado AES-256-GCM permisos 000
│   │   ├── ransomware_shield.py  # Honeypots (canaries) y neutralización SIGKILL
│   │   ├── usb_monitor.py        # Vigilancia y auto-escaneo USB silencioso
│   │   ├── persistence_guard.py  # Centinela de arranque (systemd, cron, rc.local)
│   │   ├── download_sentinel.py  # Inspección de descargas en vuelo (~/Downloads)
│   │   ├── hardware_guard.py     # Centinela anti-espía de cámara (/dev/video*) y audio
│   │   ├── audit_logger.py       # Registro forense de incidentes exportable en JSON
│   │   ├── dns_manager.py        # Perfiles Mullvad DNS & Quad9 (DoT 853)
│   │   ├── firewall.py           # Conmutador UFW, corte ss -K y lanzador GUFW
│   │   ├── vpn_manager.py        # Integración oficial con Proton VPN
│   │   ├── update_guard.py       # Auditoría de parches del sistema
│   │   ├── phishing.py           # Escudo anti-phishing proactivo y auditoría de red
│   │   ├── ebpf_monitor.py       # Sondas eBPF (sys_enter_execve / ptrace)
│   │   ├── threat_intel.py       # Feeds de MalwareBazaar, URLhaus y OpenPhish
│   │   ├── i18n.py               # Localización dinámica Español (ES) / Inglés (EN)
│   │   ├── system_whitelist.py   # Lista blanca de paquetes oficiales APT/Flatpak
│   │   └── notifier.py           # Alertas D-Bus en escritorio (X11 y Wayland)
│   └── rules/
│       └── demons.yar            # Reglas YARA para Linux
├── gui/
│   ├── app.py                    # Suite gráfica nativa en GTK 3
│   └── tray.py                   # Icono de bandeja residente junto al reloj
├── service/
│   ├── constantine.service       # Demonio systemd con arranque temprano
│   ├── constantine-scan.nemo_action # Clic derecho para Linux Mint (Nemo)
│   └── org.constantine.antivirus.policy # Directiva Polkit para privilegios
├── scripts/
│   ├── constantine-nautilus-scan.sh # Clic derecho para Ubuntu/GNOME (Nautilus)
│   ├── sync_clamav.py            # CLI de sincronización de firmas ClamAV
│   ├── evaluate_yarax.py         # Auditor de compatibilidad y migración a YARA-X
│   └── publish_to_github.sh      # Asistente para sincronizar con GitHub
├── tests/
│   └── test_constantine.py       # Suite de pruebas unitarias
├── clamav.py                     # Wrapper de importación raíz para ClamAV
├── yara_x.py                     # Wrapper de importación raíz para YARA-X
├── tetragon.py                   # Wrapper de importación raíz para Tetragon
├── falco.py                      # Wrapper de importación raíz para Falco
├── wazuh.py                      # Wrapper de importación raíz para Wazuh
├── osquery.py                    # Wrapper de importación raíz para osquery
├── misp.py                       # Wrapper de importación raíz para MISP
├── sigma.py                      # Wrapper de importación raíz para Sigma
├── event_manager.py              # Wrapper de importación raíz para Event Manager
├── daemon.py                     # Servicio raíz en segundo plano
├── install.sh                    # Instalador desatendido del sistema
├── uninstall.sh                  # Desinstalador seguro con soporte de argumentos (-y)
├── requirements.txt              # Dependencias de Python
├── VERSION                       # Versión actual del sistema (5.1.0)
├── CONTRIBUTING.md               # Guía de contribución y acuerdo CLA
├── LICENSE-COMMERCIAL.md         # Términos de licenciamiento comercial y corporativo
├── LICENSE                       # Licencia GNU General Public License v3.0
└── README.md                     # Documentación oficial
```

---

## 🚀 Instalación Rápida

### Requisitos del Sistema
* **Distribución:** Debian 11/12+, Ubuntu 20.04/22.04/24.04+, Linux Mint 20/21/22+ (o derivadas).
* **Kernel de Linux:** Versión 5.0 o superior (con soporte nativo para `fanotify` y `eBPF`).
* **Python:** 3.10 o superior (incluido por defecto en tu distribución).

### Paso a paso

1. **Clona el repositorio oficial de GitHub:**
   ```bash
   git clone https://github.com/AntonSiMal/Constantine-Antivirus-Linux.git
   cd Constantine-Antivirus-Linux
   ```

2. **Ejecuta el instalador con privilegios de administrador:**
   ```bash
   sudo ./install.sh
   ```
   *El script se encarga automáticamente de instalar dependencias esenciales del antivirus (`yara`, `python3-yara`, `bpfcc-tools`, `gufw`, `ufw`), desplegar el demonio `constantine.service`, instalar los iconos del sistema, configurar el arranque en la barra de tareas junto al reloj y crear los accesos directos en el menú y en el escritorio de todos los usuarios.*

3. **Iniciar el Centro de Seguridad Gráfico:**
   ```bash
   python3 /opt/constantine/gui/app.py
   ```
   *(O simplemente haz doble clic sobre el acceso directo en tu **Escritorio**, búscalo en tu **Menú de Aplicaciones** o pulsa el icono del escudo **junto al reloj**).*

---

## 🧪 Ejecución de Pruebas Unitarias

Para verificar la integridad de todos los motores del sistema:
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

---

## 💼 Licenciamiento Dual & Opciones Comerciales (Enterprise / OEM)

Constantine Antivirus está disponible bajo un **esquema de licenciamiento dual**:

1. **Código Abierto (GPL v3.0):** Para usuarios individuales, desarrolladores, investigadores y entornos educativos.
2. **Licencia Comercial y Corporativa:** Para empresas, proveedores de nube, fabricantes de hardware (OEM) y proveedores de servicios de seguridad (MSSP) que deseen integrar Constantine en soluciones propietarias cerradas, desplegar en flotas corporativas sin restricciones de copyleft o contar con acuerdos de soporte dedicado (SLA).

Para consultar todos los términos y solicitar una cotización o alianza comercial, consulta el archivo [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) o contacta al mantenedor oficial a través del repositorio.

---

## 🤝 Contribuciones y Acuerdo CLA

Agradecemos las contribuciones de la comunidad técnica. Para garantizar la seguridad jurídica del proyecto y permitir tanto su continuidad abierta como su escalabilidad corporativa, todas las contribuciones están amparadas por nuestro **Contributor License Agreement (CLA)**.

Antes de abrir un Pull Request, por favor revisa [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 🗑️ Desinstalación Segura y Limpia

Constantine Antivirus incluye dos métodos de desinstalación limpia sin dejar residuos:

1. **Desde la Interfaz Gráfica:** Ve a la pestaña **Configuración (⚙️)** y pulsa en **🗑️ Desinstalar Constantine...**.
2. **Desde la Terminal:**
   ```bash
   sudo ./uninstall.sh
   ```

El desinstalador se encarga de:
1. Detener y deshabilitar el demonio `constantine.service` en systemd.
2. Eliminar las tablas y reglas de aislamiento de red en `nftables`.
3. Remover los accesos directos en el menú de aplicaciones, el inicio automático en la barra de tareas y el escritorio de todos los usuarios.
4. Eliminar los archivos binarios y librerías en `/opt/constantine/`.
5. **Gestión del Baúl de Cuarentena:** Te permite elegir si deseas conservar cifradas las muestras aisladas en `/var/lib/constantine/vault/` o destruirlas definitivamente con el parámetro `--purge-vault`.

---

## 📄 Licencia

Este proyecto está liberado para la comunidad bajo la Licencia **GNU General Public License v3.0**. Consulta el archivo `LICENSE` para más información.
