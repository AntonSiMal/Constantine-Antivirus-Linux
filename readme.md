
<h1 align="center">🛡️ CONSTANTINE ANTIVIRUS & EDR v5.5</h1>

<p align="center">
  <strong>La primera suite EDR nativa en Rust con intercepción en Kernel (eBPF + fanotify) diseñada para el escritorio Linux.</strong>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Language-Rust_1.70+-orange.svg?style=for-the-badge&logo=rust" alt="Rust"></a>
  <a href="https://gtk.org/"><img src="https://img.shields.io/badge/GUI-GTK4_Cupertino-blue.svg?style=for-the-badge&logo=gnome" alt="GTK4"></a>
  <a href="https://ebpf.io/"><img src="https://img.shields.io/badge/Kernel-eBPF_LSM_+_fanotify-red.svg?style=for-the-badge&logo=linux" alt="eBPF"></a>
  <a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPL_v3.0-green.svg?style=for-the-badge" alt="GPL-3.0"></a>
  <img src="https://img.shields.io/badge/Telemetry-0%25_Soberano-purple.svg?style=for-the-badge" alt="Zero Telemetry">
  <img src="https://img.shields.io/badge/Platform-Debian_%7C_Ubuntu_%7C_Mint-lightgrey.svg?style=for-the-badge&logo=debian" alt="Distros">
</p>

---

## ⚡ En 30 Segundos: ¿Por qué existe Constantine?

Durante décadas, la seguridad en el escritorio Linux ha estado fragmentada entre **scripts en terminal** que nadie ejecuta periódicamente o **interfaces anticuadas** sobre ClamAV que escanean el disco después de que el malware ya se ha ejecutado. Mientras tanto, en Windows y macOS, suites comerciales ofrecen protección preventiva en tiempo real, control de periféricos y defensas anti-ransomware de fábrica.

**Constantine Antivirus & EDR** cambia las reglas del juego:
1. **Intercepción Preventiva Real en Kernel**: Bloquea el malware mediante `fanotify` y políticas `eBPF LSM` en milisegundos *antes* de que el archivo toque el disco o se ejecute.
2. **Autodefensa en Kernel (*Tamper Protection*)**: Ni siquiera un atacante con permisos `root` puede detener a Constantine con `kill -9` o `systemctl stop`.
3. **Escudo Anti-Ransomware Fulminante**: Detección de ráfagas, señuelos trampa (*Canary Tripwires*) y análisis matemático de entropía de Shannon ($H > 7.55$) que neutralizan el proceso agresor en caliente.
4. **Experiencia de Usuario macOS Cupertino en GTK4**: Dashboard interactivo con KPIs de salud, modo oscuro adaptable desde pantallas de **800x600** hasta monitores 4K y operación diaria sin contraseñas de `sudo`.
5. **Privacidad Radical y Cero Telemetría**: 100% código abierto, soberano y auditable; tus datos y registros forenses jamás salen de tu máquina.

---

## 📊 Dashboard Ejecutivo en Vivo (KPIs y Telemetría)

Constantine v5.5 estrena una interfaz unificada donde cada aspecto de la seguridad de tu estación de trabajo es visible y accionable de un vistazo:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ CONSTANTINE EDR v5.5   [🛑 Apagar]  [⏸️ Pausar Escudos]  [🗑️ Desinstalar]  [● Salud: 100%] │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌────────────────────┐   │
│ │ 📦 CUARENTENA    │ │ 📋 LISTA BLANCA  │ │ 🔍 ESCUDOS       │ │ 🧬 ANTI-RANSOMWARE │   │
│ │   0 Muestras     │ │   14 Hashes      │ │   fanotify+eBPF  │ │   4/4 Intactos     │   │
│ │ Baúl AES-256-GCM │ │ Reglas SHA-256   │ │ Vigilando /home  │ │ Tripwires Activos  │   │
│ └──────────────────┘ └──────────────────┘ └──────────────────┘ └────────────────────┘   │
│                                                                                        │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 🔄 Estado de Actualizaciones del Sistema y del Kernel Linux                        │ │
│ │ Kernel activo: 6.8.0-generic | 🟢 Kernel y Sistema completamente al día             │ │
│ │ 0 parches críticos pendientes                               [🚀 Abrir Actualizador]│ │
│ └────────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                        │
│ ┌────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ 🛡️ Salud Operativa Global del EDR: 100% (10/10 Controles Activos)                  │ │
│ │ [██████████████████████████████████████████████████] [🔍 Ver Desglose para el 100%] │ │
│ └────────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                        │
│ ⚙️ Matriz de Sensores en Kernel:                                                       │
│   • 1. fanotify (ClamOnAcc): 🟢 Activo en /home      • 6. Registro Forense: 🟢 SHA-256 Chain   │
│   • 2. Canary Anti-Ransomware: 🟢 4 Señuelos         • 7. Escudo USB: 🟢 Plug & Play Activo   │
│   • 3. Sensor eBPF Tetragon: 🟢 LSM Hook Activo      • 8. DNS Sinkhole: 🟢 78,240 Dominios     │
│   • 4. Periféricos (Cámara/Mic): 🟢 V4L2 Blindado    • 9. Tamper Protection: 🟢 Anti-Kill +i   │
│   • 5. Filtros de Red (UFW): 🟢 Perímetro Activo    • 10. Modo Juego / DND: 🟢 Listo / DND    │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🏛️ Arquitectura Multicapa Fail-Secure

```text
                     ┌────────────────────────────────────────────────────────┐
                     │       Constantine GUI (GTK4 Cupertino Responsive)      │
                     │        [800x600 - 4K | Cero Contraseñas de Usuario]     │
                     └───────────────────────────┬────────────────────────────┘
                                                 │ IPC Unix Socket / D-Bus
                     ┌───────────────────────────▼────────────────────────────┐
                     │           constantine-daemon (Root Supervisor)         │
                     └──────────┬─────────────────┬─────────────────┬─────────┘
                                │                 │                 │
    ┌───────────────────────────▼──┐  ┌───────────▼────────────┐  ┌─▼──────────────────────┐
    │    Capa Kernel & eBPF        │  │  Motores & Feeds TI    │  │  Hardware y Red        │
    ├──────────────────────────────┤  ├────────────────────────┤  ├────────────────────────┤
    │ • fanotify (ClamOnAcc)       │  │ • ClamAV Socket Multihilo│ • UDisks2 (Plug & Play) │
    │ • Tetragon LSM Hooks (eBPF)  │  │ • YARA & YARA-X Rust   │  │ • V4L2 Webcam Guard    │
    │ • Falco Behavioral Engine    │  │ • AIDE & Sigma Rules   │  │ • pactl Hardware Mute  │
    │ • Tamper Protection Anti-Kill│  │ • Feeds MISP/Abuse.ch  │  │ • Sumidero DNS 0.0.0.0 │
    │ • Hash Chain SHA-256 Log     │  │ • Baúl AES-256-GCM     │  │ • Conexiones ss / UFW  │
    └──────────────────────────────┘  └────────────────────────┘  └────────────────────────┘
```

---

## 🌟 Capacidades de Seguridad de Nueva Generación

### 1. 🧬 Escudo Anti-Ransomware en 4 Fases Fulminantes
* **Canary Tripwires Invisibles:** Se siembran archivos trampa señuelo en ubicaciones estratégicas del usuario (`Escritorio`, `Documentos`, `Descargas`, `Imágenes`). Cualquier interacción no autorizada dispara una respuesta en milisegundos.
* **Supervisión de Ráfagas:** Algoritmo que detecta patrones masivos de renombrado o modificación rápida de ficheros.
* **Entropía de Shannon en Tiempo Real:** Evalúa el nivel de aleatoriedad criptográfica ($H > 7.55$) para diferenciar compresión normal de cifrado hostil.
* **Terminación Atómica Fulminante:** Envía `kill -STOP` (congelamiento instantáneo de memoria para preservar el binario agresor) seguido de `kill -KILL` y aislamiento de red perimetral mediante UFW.

### 2. 🛡️ Autodefensa del EDR en Kernel (*Tamper Protection*)
* **Anti-Kill eBPF (Cilium Tetragon):** Intercepta llamadas `sys_kill` en el kernel. Un malware con privilegios `root` no puede matar los procesos de Constantine ni sus sensores.
* **Inmutabilidad Criptográfica de Archivos:** Las claves maestras (`.vault.key`), la lista blanca y el historial forense están protegidos con atributos inmutables (`chattr +i` y `chattr +a`).

### 3. 📥 Cuarentena Preventiva de Descargas (*Mark-of-the-Web*)
* **Inspección Automática en Entrada:** Vigilancia asíncrona sobre las carpetas de descargas (`~/Downloads` y `~/Descargas`).
* **Marcado de Metadatos Extendidos (`xattr`):** Aplica la marca de procedencia `user.constantine.quarantine`.
* **Retiro Preventivo de Ejecución:** Si se descarga un binario ELF, script Shell o instalador, retira preventivamente el permiso de ejecución (`chmod a-x`) para impedir la infección por doble clic accidental antes de que los motores lo verifiquen.

### 4. 👥 Arquitectura Multiusuario Nativa (*Zero-Touch*)
* **Protección Universal Simultánea:** Detecta dinámicamente a todos los usuarios humanos del sistema (`UID >= 1000`) y los integra en el grupo `constantine`.
* **Nacimiento Protegido para Nuevos Usuarios:** Mediante la plantilla maestra `/etc/skel` y `/etc/adduser.conf`, **todo nuevo usuario que se cree en la máquina nace protegido de forma transparente**: con sus señuelos sembrados, autostart y acceso directo listos.

### 5. 🌐 Sumidero DNS Anti-Phishing & Protección Web
* **Bloqueo Local a 0.0.0.0:** Bloquea más de 78,000 dominios de phishing, malware y servidores C2 directamente en `/etc/hosts`, transparente para cualquier navegador web (Firefox, Chrome, Brave) sin consumir CPU.
* **Purga Automática de Caché:** Limpieza automática de cachés en `systemd-resolved`, `resolvectl`, `nscd` y `dnsmasq`.

### 6. 🔒 Privacidad y Control de Hardware
* **Kill-Switch V4L2 de Cámara:** Bloqueo de dispositivos de vídeo (`chmod 000 /dev/video*` y `fuser -k`) contra spyware y troyanos de acceso remoto (RAT).
* **Silenciamiento de Micrófono:** Control por hardware del subsistema de audio para evitar grabaciones clandestinas.
* **Escudo USB Reactivo (UDisks2):** Detección e inspección inmediata de unidades extraíbles al insertarse.

### 7. 📜 Auditoría Forense Inmutable (*Blockchain Ledger*)
* **Encadenamiento Criptográfico SHA-256:** Cada evento registrado contiene el hash del evento anterior:
  $$\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} \parallel \text{Timestamp} \parallel \text{Evento} \parallel \text{Detalles})$$
  Cualquier intento de alteración rompe la cadena matemática y genera una alarma pericial crítica.
* **Exportación de Informes:** Generación de informes forenses completos en HTML listos para imprimir o convertir a PDF.

---

## 💎 Comparativa: Constantine vs Otras Soluciones

| Característica | Antivirus Tradicionales en Linux (ClamTk, Chkrootkit) | Suites Propietarias en Windows/Mac (Defender, Bitdefender) | Constantine Antivirus & EDR v5.5 |
| :--- | :--- | :--- | :--- |
| **Enfoque de Operación** | Escaneos estáticos bajo demanda | Protección interactiva de escritorio | **Protección EDR interactiva en Kernel nativa para Linux** |
| **Autodefensa en Kernel** | ❌ Inexistente (`root` lo detiene) | ✔️ Controladores propietarios ELAM | **✔️ Políticas eBPF LSM (Tetragon Anti-Kill)** |
| **Defensa Anti-Ransomware** | ❌ Ninguna (detecta firmas tarde) | ✔️ Detección heurística en nube | **✔️ 4 Capas: Señuelos, Entropía $H > 7.55$, SIGKILL** |
| **Filtrado Web y Phishing** | ❌ Requiere extensiones de navegador | ✔️ Proxy local propietario | **✔️ Sumidero DNS local (0.0.0.0) transparente y sin plugins** |
| **Rendimiento e Impacto** | ⚠️ Escaneos lentos que congelan CPU | ⚠️ Alto uso de RAM y telemetría | **✔️ Rust nativo, ligero, responsivo (800x600 - 4K)** |
| **Custodia de Periféricos** | ❌ No disponible | ✔️ Notificaciones simples | **✔️ Kill-Switch V4L2 de cámara web y silenciamiento de micrófono** |
| **Registro de Eventos** | ❌ Texto plano manipulable por root | ⚠️ Envío forzado a servidores externos | **✔️ Cadena criptográfica SHA-256 inmutable (`chattr +i/+a`)** |
| **Soberanía y Privacidad** | Abierto pero desintegrado | Propietario con cobro recurrente | **100% Código Abierto (GPL-3.0), Soberano y Sin Telemetría** |

---

## 📋 Requisitos del Sistema

* **Distribuciones Oficiales:** Debian 12 (Bookworm) o superior, Ubuntu 22.04 / 24.04 LTS, Linux Mint 21 o superior.
* **Kernel de Linux:** v5.8+ con `CONFIG_FANOTIFY=y`, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` y `CONFIG_BPF=y`.
* **Entorno de Compilación:** Rust 1.70+ con Cargo (`rustup`).
* **Resolución Soportada:** Totalmente fluido desde pantallas compactas de **800 x 600** hasta monitores de alta resolución 4K.

---

## 🚀 Instalación en 1 Comando

1. Clona el repositorio oficial:
   ```bash
   git clone https://github.com/tonsimaltine-Antivirus-Linux
   cd tonsimaltine-Antivirus-Linux
   ```

2. Lanza el instalador inteligente automatizado:
   ```bash
   sudo ./install.sh
   ```

El asistente gráfico (o CLI en terminales puras) se encargará de todo:
- ✅ Aceptación transparente de la licencia y exención de riesgos operativos.
- ✅ Verificación y configuración del compilador Rust.
- ✅ Descarga de dependencias del sistema y librerías GTK4.
- ✅ Carga de sondas eBPF (Tetragon, Falco) y configuración de ClamOnAcc (`fanotify`).
- ✅ Siembra de señuelos *Canary Tripwires* para todos los usuarios actuales y futuros.
- ✅ Verificación estricta de 10 módulos en vivo con política *Fail-Secure* (si un componente falla, revierte todo limpiamente).
- ✅ Compilación optimizada del ejecutable y apertura automática del EDR en tu pantalla.

---

## 💻 Uso y Operación

### Apertura de la Interfaz
Abre Constantine desde el menú de aplicaciones de tu escritorio (GNOME, Cinnamon, XFCE), mediante el icono en el Escritorio, o simplemente ejecutando:
```bash
constantine
```

### Controles de Servicio y Escudos en la Interfaz
* **⏸️ Pausar Escudos / ▶️ Activar Escudos**: Pausa en caliente todos los sensores en kernel (`ClamOnAcc`, `Tetragon`, `Falco`, `Wazuh`, filtrado DNS) solicitando contraseña de administrador, permitiéndote reanudarlos con un solo clic.
* **🛑 Apagar**: Cierre y detención definitiva autorizada con contraseña de root.
* **🗑️ Desinstalar (Flujo en 3 Clics con Disuasión)**: Sistema deliberado de advertencia contra desinstalaciones impulsivas que requiere 3 pasos conscientes para purgar la suite.

### Operación por Línea de Comandos (CLI / Headless)
```bash
# Ejecutar en modo demonio de fondo sin interfaz gráfica
constantine --daemon

# Analizar un archivo o directorio específico bajo demanda
constantine --scan-file "/ruta/al/archivo_o_carpeta"

# Ejecutar análisis rápido programado
constantine --scan-quick

# Ejecutar análisis exhaustivo de todo el sistema
constantine --scan-full

# Diálogo interactivo de amenaza en el escritorio
constantine --threat-dialog "Malware.Name" "/ruta/al/archivo" 1234 "MotorClamAV"
```

---

## 🛑 Desinstalación Limpia con Cero Huella Residual

Si alguna vez decides desinstalar Constantine, el desinstalador oficial garantiza la reversión total y absoluta de cada cambio en el sistema operativo:
```bash
sudo ./uninstall.sh
```
* **Libera ganchos en el kernel**: Detiene y desvincula `fanotify`, `eBPF LSM` y sensores de comportamiento.
* **Restaura archivos base**: Recupera la configuración original de `clamd.conf`, retira el bloque de `/etc/hosts` y limpia reglas de UFW.
* **Elimina señuelos en todos los idiomas**: Pasa una búsqueda profunda en `/home` y `/etc/skel` eliminando señuelos Canary en cualquier idioma (`Desktop`, `Escritorio`, `Downloads`, `Descargas`, etc.).
* **Elimina el grupo y las carpetas**: Borra el grupo del sistema `constantine`, binarios en `/usr/local/bin/`, políticas Polkit, reglas Sudoers y cualquier carpeta vacía residual.

---

## 🤝 Reconocimiento a la Comunidad de Código Abierto

Constantine Antivirus & EDR se construye sobre los hombros de gigantes. Reconocemos y agradecemos el trabajo de los proyectos fundamentales que hacen posible este ecosistema:

* [**Cilium Tetragon**](https://tetragon.io/) – Sensor principal de observabilidad y seguridad en kernel con eBPF LSM.
* [**Falco Security**](https://falco.org/) – Motor de detección de anomalías y comportamiento en tiempo de ejecución (CNCF).
* [**ClamAV & ClamOnAcc**](https://www.clamav.net/) – Motor de firmas antivirus y prevención en acceso mediante `fanotify`.
* [**VirusTotal YARA & YARA-X**](https://github.com/VirusTotal/yara-x) – El estándar para la identificación de patrones de malware en Rust.
* [**Wazuh**](https://wazuh.com/) – Monitorización de integridad de ficheros (FIM) y telemetría SIEM.
* [**AIDE**](https://aide.github.io/) – Verificador de línea base criptográfica del sistema.
* [**StevenBlack Hosts**](https://github.com/StevenBlack/hosts) – Base comunitaria consolidada contra malware y phishing.
* [**Abuse.ch (MalwareBazaar, ThreatFox, URLhaus)**](https://abuse.ch/) – Inteligencia comunitaria de amenazas e IoCs en tiempo real.
* [**GTK4 & GNOME Foundation**](https://gtk.org/) – Toolkit gráfico moderno, fluido y responsivo.

---

## 📄 Licencia y Exención de Responsabilidad

Distribuido bajo la licencia **GNU General Public License v3.0 (GPL-3.0)**. Consulta el archivo `LICENSE` para el texto completo.

> **Aviso de responsabilidad**: Constantine interactúa a bajo nivel con el kernel Linux mediante controladores de seguridad (`fanotify`, `eBPF`, `chattr`). El software se proporciona "TAL CUAL" (*AS IS*), sin garantías de ningún tipo. Al instalarlo, el usuario asume los riesgos técnicos inherentes a la administración de bajo nivel del sistema operativo.
```

### 💡 Consejos adicionales:
- Si vas a subir esto a GitHub, asegúrate de que el archivo se llame exactamente `README.md`.
- El bloque de arte ASCII está envuelto en ````text` para evitar que los motores de Markdown intenten interpretarlo como código de programación y alteren su alineación.
- Las fórmulas matemáticas usan sintaxis LaTeX estándar (`$$...$$`), que GitHub y GitLab renderizan nativamente de forma correcta.
