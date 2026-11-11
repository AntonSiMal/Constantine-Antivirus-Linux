# 🛡️ Constantine Antivirus & EDR v5.5

[Version](https://www.google.com/search?q=https://github.com/constantine-edr/constantine)




**Constantine Antivirus & EDR** es una suite integral de seguridad de punto final (*Endpoint Detection & Response*) y orquestador centralizado de ciberseguridad diseñado específicamente para estaciones de trabajo y escritorios Linux (Debian, Ubuntu y Linux Mint).

Une la potencia de los motores de código abierto más avanzados con la intercepción en tiempo real en el kernel mediante **fanotify** y sondas **eBPF ([Cilium Tetragon](https://tetragon.io/) y [Falco](https://falco.org/))**, ofreciendo una experiencia interactiva y fluida comparable a los antivirus comerciales líderes en Windows y macOS, pero con total transparencia, cero telemetría invasiva y rendimiento nativo en Rust.

## 🏛️ Arquitectura General del Sistema

```
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
              │ • fanotify (ClamOnAcc)       │  │ • ClamAV Socket Multihilo│  │ • UDisks2 (Plug & Play)│
              │ • Tetragon LSM Hooks (eBPF)  │  │ • YARA & YARA-X Rust   │  │ • V4L2 Webcam Guard    │
              │ • Falco Behavioral Engine    │  │ • AIDE & Sigma Rules   │  │ • pactl Hardware Mute  │
              │ • Tamper Protection Anti-Kill│  │ • Feeds MISP/Abuse.ch  │  │ • Sumidero DNS 0.0.0.0 │
              │ • Hash Chain SHA-256 Log     │  │ • Baúl Criptográfico   │  │ • Conexiones ss / UFW  │
              └──────────────────────────────┘  └────────────────────────┘  └────────────────────────┘

```

## 🌟 ¿Qué se ha desarrollado en Constantine v5.5?

Constantine no es una simple interfaz gráfica sobre herramientas existentes; es un **orquestador centralizado y motor EDR autónomo** desarrollado en Rust nativo que integra 19 módulos funcionales de defensa:

### 1. Escudo Anti-Ransomware en 4 Capas Fulminantes

* **Canary Tripwires (Señuelos Estratégicos):** Siembra 4 archivos señuelo señuelo en ubicaciones críticas del usuario (`Desktop`, `Documents`, `Downloads`, `Pictures`). Cualquier intento de cifrado o borrado sobre ellos dispara una alarma fulminante.

* **Supervisión de Ráfagas y Frecuencia:** Algoritmo de correlación temporal que detecta procesos modificando múltiples archivos en ventanas de milisegundos.

* **Análisis de Entropía de Shannon:** Cálculo matemático de aleatoriedad criptográfica ($H > 7.55$) para distinguir entre compresión legítima y cifrado hostil de ransomware.

* **Neutralización Atómica Fulminante:** Emisión inmediata de `kill -STOP` (congelamiento de memoria) seguido de `kill -KILL`, complementado con corte de red perimetral mediante UFW.

### 2. Autodefensa del Antivirus en Kernel (*Tamper Protection*)

* **Anti-Kill eBPF (Tetragon):** Política en kernel que intercepta las llamadas `sys_kill` (`SIGKILL`, `SIGTERM`, `SIGSTOP`). Impide que malware con privilegios de administrador (`root`) termine el demonio o los sensores de seguridad, reservando el control exclusivamente a `systemd` y a la rutina autorizada de apagado.

* **Inmutabilidad Criptográfica de Archivos:** Las claves maestras del baúl (`.vault.key`), la lista blanca y el registro forense están protegidos con atributos de sistema de archivos inmutables (`chattr +i` / `chattr +a`).

### 3. Prevención en Acceso en Kernel (*On-Access Shield*)

* **Intercepción fanotify:** Supervisa la apertura y modificación de archivos en tiempo real mediante `clamonacc` y `clamd`.

* **Modo No Bloqueante en Sesión:** Configurado con exclusiones inteligentes sobre archivos de sesión X11/Cinnamon (`.Xauthority`, `.cache`, sockets locales), eliminando al 100% los congelamientos de escritorio típicos de las configuraciones tradicionales de ClamAV en Linux.

### 4. Detección de Comportamiento Anómalo en Tiempo Real

* **Falco Behavioral Engine:** Sensor eBPF moderno (`modern_ebpf`) cargado en el kernel que detecta ejecuciones sospechosas, inyecciones de código y accesos indebidos a credenciales en `/etc/shadow` o `/etc/sudoers`.

* **Reglas Sigma para Linux:** Detección de ejecuciones anómalas originadas en directorios temporales de escritura abierta (`/tmp`, `/var/tmp`, `/dev/shm`).

### 5. Protección Web y Filtrado DNS Anti-Phishing (0.0.0.0)

* **Sumidero DNS Local:** Intercepta y redirige miles de dominios hostiles de phishing, malware y servidores de comando y control (C2) hacia `0.0.0.0` en `/etc/hosts` con purga automática de cachés DNS (`resolvectl`, `systemd-resolved`, `nscd`, `dnsmasq`).

* **Protección Activa Offline y Semilla Local:** Cuenta con una lista semilla de alta confianza de más de 25 dominios críticos que garantiza protección inmediata incluso sin conexión a internet, complementada con miles de dominios sincronizados desde [URLhaus](https://urlhaus.abuse.ch/) y [OpenPhish](https://openphish.com/).

* **Supervisión Pasiva de Conexiones por Proceso:** Supervisión interactiva de qué programas y ejecutables establecen conexiones salientes hacia la red.

### 6. Custodia de Hardware y Privacidad de Periféricos

* **Webcam Guard (V4L2):** Supervisión y bloqueo por hardware de dispositivos de vídeo (`/dev/video*`) contra software espía y troyanos de acceso remoto (RAT).

* **Silenciamiento Atómico del Micrófono:** Control por hardware del subsistema de audio (`/dev/snd/*` y `pactl`) para impedir grabaciones clandestinas.

* **Sensor USB Plug & Play Reactivo (UDisks2):** Intercepción automática de memorias USB en cuanto se conectan mediante eventos D-Bus sin sondeos ineficientes de CPU.

### 7. Baúl Criptográfico de Cuarentena (AES-256-GCM)

* **Aislamiento Seguro con Metadatos:** Encriptación de archivos sospechosos en AES-256-GCM dentro de `/var/lib/constantine/quarantine`, almacenando cabeceras JSON con la ruta original, amenaza detectada, motor y suma de verificación SHA-256.

* **Restauración Inteligente a Lista Blanca:** Posibilidad de enviar archivos legítimos a la lista blanca o restaurarlos directamente al Escritorio con un solo clic.

### 8. Apartado de Auditoría Forense Universal e Inmutable (*Blockchain Ledger*)

* **Centralización Total de Eventos (100% de Cobertura):** Absolutamente todas las advertencias, notificaciones de escritorio, historial de fallas y errores, eventos de conexión/desconexión de red, perfiles DNS aplicados, bloqueos de hardware (cámara/micrófono/USB) y acciones de los 16 módulos de seguridad (orquestados o instalados por Constantine) quedan permanentemente almacenados en `/var/log/constantine/immutable_audit.log`.

* **Encadenamiento Criptográfico SHA-256 (*Hash Chaining*):** Cada evento registrado contiene el hash SHA-256 del evento cronológico previo:
  

  $$
  \text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} \parallel \text{Timestamp} \parallel \text{Evento} \parallel \text{Detalles})
  $$

  
  Cualquier intento de alteración, eliminación o manipulación rompe la cadena matemática y dispara una alerta forense crítica en la interfaz.

* **Agregador en Vivo de Sensores y Demonios (*Log Forwarder Engine*):** Hilo de supervisión pasiva que recolecta en tiempo real eventos de ClamOnAcc, Tetragon, Falco, Wazuh Agent, AIDE y reglas Sigma, ingiriéndolos al registro forense inmutable.

* **Interfaz de Auditoría Interactiva con Filtrado Multivariable:**

  * **Indicadores KPI en Tiempo Real:** Contador de eventos verificados, alertas, errores/fallas registradas, eventos de red y estado de integridad.

  * **Filtros Rápidos por Categoría:** *Todo el Historial*, *Alertas y Notificaciones*, *Errores y Fallas*, *Red y Conexiones*, *Servicios y Módulos*, *Hardware y Periféricos*.

  * **Buscador Dinámico Instantáneo:** Localización rápida por palabra clave, IP, PID, dominio o hash SHA-256.

  * **Generador de Informes Ejecutivos:** Exportación de informes periciales completos en HTML y listos para conversión a PDF o impresión.

### 9. Arquitectura Cliente-Servidor, Controles de Escudo y Desinstalación Protegida

* **Operación Fluida sin Sudo:** La interfaz opera bajo tu usuario estándar sin solicitar contraseñas para análisis, revisiones o actualizaciones, comunicándose con el demonio privilegiado mediante un socket UNIX `/run/constantine.sock` y reglas Polkit / Sudoers dedicadas.

* **Control de Escudos en Caliente (`⏸️ Pausar` / `▶️ Activar`):** Posibilidad de pausar todos los sensores y ganchos de kernel (`ClamOnAcc`, `Tetragon`, `Falco`, `Wazuh` y filtrado DNS) solicitando contraseña de administrador, manteniendo la interfaz de Constantine abierta para reanudarlos en cualquier momento con un solo clic.

* **Apagado Total Autorizado:** Exige obligatoriamente autenticación de administrador (`pkexec`) para detener de forma definitiva los módulos de protección y el servicio.

* **Desinstalación Deliberada en 3 Clics con Disuasión:** Flujo protegido contra desinstalaciones accidentales o impulsivas:
  1. **Clic 1:** Inicio del proceso desde la interfaz (`🗑️ Desinstalar`).
  2. **Clic 2:** Ventana modal de advertencias críticas sobre los riesgos de desproteger el sistema y pérdida de cobertura EDR (*"Entiendo los riesgos y deseo continuar"*).
  3. **Clic 3:** Diálogo de confirmación final con opción de cancelación recomendada y botón definitivo que invoca la desinstalación limpia previa autenticación de contraseña de administrador (`pkexec`).

* **Acuerdo de Licencia y Exención Total de Responsabilidad en el Instalador:** Obligatoriedad de revisar y aceptar expresamente los términos legales, licencias de código abierto, riesgos operativos de bajo nivel (eBPF/kernel) e incluso de posible pérdida de datos antes de habilitar la instalación (con casilla de verificación en GUI y confirmación explícita `ACEPTO` en terminal).

### 10. Interfaz Gráfica Cupertino GTK4 Adaptativa (800 x 600)

* **Diseño Nativo y Responsivo:** Desarrollada puramente en GTK4 con tema oscuro estilo macOS Cupertino.

* **Ajuste Dinámico Completo:** Optimizada para encajar fluidamente desde pantallas compactas de **800 x 600** (portátiles, pantallas táctiles y máquinas virtuales) hasta monitores 4K de alta densidad.

### 11. Novedades Oficiales de la Versión 5.5: Cuarentena Preventiva de Descargas (*Mark-of-the-Web*)

* **Vigilancia Continua de Descargas (`DownloadQuarantineGuard`):** Supervisor pasivo y asíncrono que monitoriza en tiempo real las carpetas de entrada de Internet (`~/Downloads` y `~/Descargas`).

* **Atributos Extendidos Criptográficos (*xattr*):** Estampa automáticamente sobre cada archivo nuevo el atributo `user.constantine.quarantine` con marca de tiempo UTC de origen.

* **Bloqueo Preventivo de Ejecución (*Gatekeeper-Style*):** Si se detecta un binario ELF, script o instalador recién descargado, retira preventivamente el bit de ejecución (`+x`, `chmod a-x`) para impedir que se ejecute por accidente con un simple doble clic antes de su validación formal.

* **Inspección Automática Multi-Motor Inmediata:** Todo archivo descargado pasa de forma instantánea por el pipeline Fail-Secure (ClamAV, YARA, YARA-X, entropía y cotejo de IoCs). Si resulta malicioso, se neutraliza y aísla de inmediato en el Baúl Criptográfico (`AES-256-GCM`), notificando al usuario mediante `SystemNotifier` y registrando el evento en la cadena de auditoría forense SHA-256.

### 12. Arquitectura Multiusuario Nativa (Zero-Touch Provisioning)

* **Protección Simultánea de Todos los Usuarios:** Al instalarse, Constantine detecta dinámicamente a todos los usuarios humanos del sistema (`UID >= 1000`), integrándolos en el grupo del sistema `constantine`, configurando permisos de auditoría sin `sudo` y sembrando señuelos *Canary Tripwires* en cada uno de sus escritorios y carpetas personales.

* **Garantía de Nacimiento Protegido para Nuevos Usuarios:** Gracias a la plantilla maestra `/etc/skel` y a la directiva persistente `EXTRA_GROUPS="constantine"` en `/etc/adduser.conf`, cualquier usuario que se cree en el futuro (desde la terminal o desde el panel gráfico de configuración de usuarios de Ubuntu/Linux Mint) **nace automáticamente con Constantine**: con sus señuelos Canary sembrados, acceso directo en el Escritorio y bandeja del sistema lista.

* **Vigilancia de Descargas Multiusuario Activa:** El demonio `DownloadQuarantineGuard` vigila dinámicamente `/home/*/Downloads` y `/home/*/Descargas`, detectando automáticamente la creación de nuevas cuentas de usuario en `/home/` para estampar atributos *Mark-of-the-Web* y analizar descargas de forma transparente.

* **Autostart y Sesión Global:** El inicio automático de la bandeja se despliega en `/etc/xdg/autostart/constantine-tray.desktop` y se respalda con un gancho global en `/etc/profile.d/constantine-session.sh` que verifica y repara automáticamente señuelos y accesos en cada inicio de sesión.

## 💎 ¿Por qué Constantine es Único en Linux?

| Característica | Antivirus Tradicionales en Linux (ClamTk, Chkrootkit, Sophos CLI) | Suites Comerciales en Windows/Mac (Defender, Bitdefender, CrowdStrike) | Constantine Antivirus & EDR v5.5 | 
| ----- | ----- | ----- | ----- | 
| **Enfoque de Operación** | Escaneo estático bajo demanda en terminal o servidores | Protección interactiva de escritorio en tiempo real | **Protección interactiva de escritorio en tiempo real optimizada para Linux** | 
| **Autodefensa en Kernel** | ❌ Inexistente (un malware root hace `systemctl stop`) | ✔️ Mediante controladores ELAM / Kernel Extensions | **✔️ Mediante políticas eBPF LSM (Tetragon Anti-Kill)** | 
| **Prevención Anti-Ransomware** | ❌ Nula (solo detecta firmas tras el cifrado) | ✔️ Detección de comportamiento y carpetas protegidas | **✔️ 4 Capas: Señuelos Canary, Entropía** $H > 7.55$ **y SIGKILL fulminante** | 
| **Filtrado Web y DNS** | ❌ Requiere configurar proxies o plugins de navegador | ✔️ Filtrado web y DNS local integrado | **✔️ Sumidero DNS local (0.0.0.0 en `/etc/hosts`) transparente a todo navegador** | 
| **Uso de Recursos** | ⚠️ Escaneos síncronos que congelan el disco | ⚠️ Alto consumo de RAM y telemetría propietaria | **✔️ Escrito en Rust nativo, ligero, responsivo (800x600) y sin telemetría** | 
| **Control de Periféricos** | ❌ No disponible | ✔️ Avisos de cámara y micrófono | **✔️ Kill-Switch V4L2 de cámara web y silenciamiento pactl de micrófono** | 
| **Integridad Forense** | ❌ Logs planos de texto manipulables por root | ⚠️ Envío forzado de telemetría a la nube del fabricante | **✔️ Cadena criptográfica SHA-256 local inmutable (`chattr +i/+a`)** | 
| **Filosofía de Código** | Mixto / Parcialmente abandonado | Propietario y de pago mensual | **100% Código Abierto, Transparente y Soberano** | 

## 🙏 Agradecimientos y Reconocimiento a Proyectos de Código Abierto

Constantine Antivirus & EDR es posible gracias a la labor extraordinaria de las comunidades globales de seguridad y código abierto. Expresamos nuestro sincero agradecimiento a cada uno de los siguientes proyectos fundamentales:

* [**ClamAV & ClamOnAcc**](https://www.clamav.net/): Motor de detección de firmas antivirus multihilo y escudo de intercepción en tiempo real mediante `fanotify`.

* [**Cilium Tetragon**](https://tetragon.io/) ([GitHub](https://github.com/cilium/tetragon)): Sensor principal EDR eBPF para observabilidad de seguridad y aplicación de políticas de seguridad en el kernel (LSM).

* [**Falco Security**](https://falco.org/) ([GitHub](https://github.com/falcosecurity/falco)): Motor de detección de amenazas y anomalías de comportamiento en tiempo de ejecución para Linux, incubado por la CNCF.

* [**YARA**](https://virustotal.github.io/yara/) ([GitHub](https://github.com/VirusTotal/yara)): La herramienta estándar de la industria desarrollada por VirusTotal para identificación y clasificación de patrones de malware.

* [**YARA-X**](https://github.com/VirusTotal/yara-x): La nueva generación del motor YARA reescrita completamente en Rust por VirusTotal para máximo rendimiento y seguridad de memoria.

* [**AIDE (Advanced Intrusion Detection Environment)**](https://aide.github.io/) ([GitHub](https://github.com/aide/aide)): Verificador de integridad de archivos y línea base criptográfica para supervisión de binarios de sistema.

* [**osquery**](https://osquery.io/) ([GitHub](https://github.com/osquery/osquery)): Marco de análisis de endpoints que expone el sistema operativo como una base de datos relacional de alto rendimiento.

* [**Wazuh**](https://wazuh.com/) ([GitHub](https://github.com/wazuh/wazuh)): Plataforma de ciberseguridad unificada para monitoreo de integridad de archivos (FIM) y telemetría SIEM.

* [**OpenSnitch**](https://github.com/evilsocket/opensnitch): Cortafuegos interactivo por aplicación para Linux basado en eBPF, creado por Simone Margaritelli (evilsocket).

* [**SigmaHQ**](https://github.com/SigmaHQ/sigma): Formato genérico y abierto de firmas de detección de comportamiento de adversarios para sistemas Linux.

* [**MISP (Malware Information Sharing Platform)**](https://www.misp-project.org/) ([GitHub](https://github.com/MISP/MISP)): Plataforma de código abierto para intercambio de inteligencia de amenazas e indicadores de compromiso (IoCs).

* [**MalwareBazaar (abuse.ch)**](https://bazaar.abuse.ch/): Proyecto colaborativo para la recolección, análisis y compartición de muestras y hashes de malware reciente.

* [**ThreatFox (abuse.ch)**](https://threatfox.abuse.ch/): Plataforma comunitaria de indicadores de compromiso (IoCs) asociados a infraestructura de malware y C2.

* [**StevenBlack Hosts**](https://github.com/StevenBlack/hosts): Base comunitaria consolidada de más de 50,000 dominios de malware, phishing y estafas en tiempo real.\\n\* [**Quad9**](https://www.quad9.net/): Fundación suiza sin fines de lucro para resolución DNS segura con bloqueo activo de amenazas.\\n\* [**Mullvad DNS**](https://mullvad.net/): Suite completa de perfiles de resolución DNS privada sueca sin registros:

  * *Anuncios + Malware + Rastreadores* (`194.242.2.5` / `194.242.2.3`).

  * *Solo Malware y Phishing* (`194.242.2.4` / `194.242.2.2`).

  * *Protección Total All-Inclusive* (`194.242.2.9` / `194.242.2.5`): bloquea malware, anuncios, rastreadores, redes sociales y contenido adulto.

  * *Control Familiar* (`194.242.2.7`): bloqueo de contenido para adultos y malware.

  * *Bloqueo de Redes Sociales* (`194.242.2.6`): enfocado en concentración y productividad.

  * *Privacidad Pura* (`194.242.2.2`): resolución sin filtros y cero registros.\\n\* [**URLhaus (abuse.ch)**](https://urlhaus.abuse.ch/): Base de datos comunitaria dedicada a compartir dominios y URLs utilizados para la distribución de malware.

* [**OpenPhish**](https://openphish.com/): Servicio de inteligencia de amenazas especializado en la detección global de páginas de phishing en tiempo real.

* [**Emerging Threats**](https://rules.emergingthreats.net/): Repositorio abierto de reglas e inteligencia de direcciones IP comprometidas y botnets.

* [**UFW (Uncomplicated Firewall) & GUFW**](https://launchpad.net/ufw): Cortafuegos estándar de filtrado perimetral mantenido por Canonical y la comunidad de Ubuntu.

* [**ProtonVPN**](https://protonvpn.com/): Infraestructura de red privada virtual con enfoque riguroso en privacidad y cifrado de tráfico.

* [**GTK4 & GNOME Foundation**](https://gtk.org/): El conjunto de herramientas multiplataforma moderno para la creación de interfaces gráficas elegantes y responsivas en Linux.

* [**Rust Language & Cargo**](https://www.rust-lang.org/): El lenguaje de programación que garantiza rendimiento sin concesiones y seguridad de memoria garantizada en tiempo de compilación.

* [**systemd & freedesktop.org (UDisks2 / D-Bus)**](https://systemd.io/): El ecosistema base de Linux que proporciona gestión de servicios, temporizadores inteligentes y buses de comunicación entre procesos.

## 📋 Requisitos del Sistema

* **Distribuciones Soportadas:** Debian 12 (Bookworm) o superior, Ubuntu 22.04 / 24.04 LTS, Linux Mint 21 o superior.

* **Kernel de Linux:** v5.8 o superior con soporte habilitado para `CONFIG_FANOTIFY=y`, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` y `CONFIG_BPF=y`.

* **Entorno de Compilación:** Rust 1.70+ con Cargo (`rustup`).

* **Resolución de Pantalla:** Desde **800 x 600** (totalmente responsivo) hasta resoluciones 4K.

## 🛠️ Instalación Rápida

1. Clona el repositorio oficial o accede al directorio del proyecto:

   ```
   git clone https://github.com/constantine-edr/constantine.git
   cd constantine
   
   ```

2. Ejecuta el asistente de instalación automatizado con privilegios de administrador:

   ```
   sudo ./install.sh
   
   ```

El instalador ejecutará de forma desatendida:

* Verificación y actualización de la cadena de herramientas de Rust.

* Descarga e instalación de dependencias del sistema y bibliotecas GTK4.

* Configuración de servicios de kernel (Tetragon eBPF, Falco, ClamOnAcc, OpenSnitch).

* Siembra de señuelos estratégicos (*Canary Tripwires*).

* Activación del sumidero DNS Anti-Phishing en `/etc/hosts`.

* Configuración de temporizadores periódicos inteligentes (`systemd.timer`).

* Auditoría estricta de ejecución de módulos en vivo con política Fail-Secure (si un módulo obligatorio falla, revierte todo limpiamente).

* Compilación en Rust del binario optimizado y apertura automática de la interfaz gráfica.

## 💻 Uso y Operación

### Lanzamiento de la Interfaz Gráfica

Abre Constantine desde el menú de aplicaciones, mediante el acceso directo en el Escritorio, o ejecutando en tu terminal:

```
constantine

```

### Opciones de Línea de Comandos (CLI)

Constantine soporta ejecución modular y headless para scripts, servidores o tareas automatizadas:

```
# Modo servicio de fondo sin interfaz gráfica (Daemon)
constantine --daemon

# Analizar un archivo o directorio específico bajo demanda
constantine --scan-file "/ruta/al/archivo_o_carpeta"

# Ejecutar análisis rápido diario de fondo
constantine --scan-quick

# Ejecutar inspección exhaustiva completa del sistema
constantine --scan-full

# Desplegar diálogo interactivo de decisión de amenaza (Threat Dialog)
constantine --threat-dialog "NombreAmenaza" "/ruta/al/archivo" 1234 "MotorDetector"

```

## 🛑 Desinstalación Limpia y Reversión Total

Si deseas desinstalar Constantine y restaurar el sistema operativo a su estado original previo a la instalación (liberando sondas del kernel, retirando reglas de firewall, restaurando `/etc/hosts`, eliminando señuelos canary y borrando temporizadores de systemd):

```
sudo ./uninstall.sh

```

## 📄 Licencia

Distribuido bajo la licencia **GNU General Public License v3.0 (GPL-3.0)**. Consulta el archivo `LICENSE` para más detalles.
