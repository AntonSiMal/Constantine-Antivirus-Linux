# ⚔️ Constantine Antivirus (Linux Active Kernel Defense)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platform: Linux](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20Linux%20Mint-orange.svg)](https://www.debian.org)
[![Kernel: fanotify & eBPF](https://img.shields.io/badge/Kernel-fanotify%20%26%20eBPF-red.svg)](https://ebpf.io)
[![GitHub Repository](https://img.shields.io/badge/GitHub-AntonSiMal%2FConstantine--Antivirus--Linux-blue?logo=github)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)

**Constantine Antivirus** es una suite de seguridad activa, preventiva y no intrusiva (*Zero-Nag*) para distribuciones Linux basadas en Debian (Ubuntu, Linux Mint, Debian) compatible con entornos gráficos **X11** y **Wayland**.

A diferencia de las herramientas antivirus tradicionales en Linux limitadas a escaneos pasivos bajo demanda, Constantine emula los **minifiltros de E/S de Windows** mediante `fanotify` a nivel de kernel (`FAN_OPEN_PERM`, `FAN_EXEC_PERM`) y sondas **eBPF**, deteniendo y neutralizando amenazas antes de que el código toque la CPU y sin la fatiga de alertas constantes de sistemas antiguos.

---

## 🛡️ Características Principales

### 1. Protección Activa en Kernel (fanotify & eBPF)
* **Interceptación Síncrona en Kernel:** Congela operaciones de apertura y ejecución en disco en tiempo real. Si un archivo es hostil, el kernel recibe la orden `FAN_DENY` antes de que se inicie el proceso.
* **Vigilancia Heurística en RAM con eBPF:** Supervisa las llamadas al sistema `sys_enter_execve` y `sys_enter_ptrace`, detectando inyecciones de código en memoria, reverse shells (`nc -e`, `/dev/tcp/`) y binarios *Living-Off-The-Land* (LOLBins).
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
* **Integración Oficial con Proton VPN:** Botón directo para conectar y lanzar el cliente de Proton VPN con protección NetShield.
* **Perfiles DNS Cifrados de Mullvad & Quad9:** Selector integrado con configuración en un clic de perfiles DoT (puerto 853) / DoH en `systemd-resolved`:
  * *Mullvad Base (`194.242.2.4`):* Malware, phishing, publicidad intrusiva y rastreadores.
  * *Mullvad Adblock (`194.242.2.3`):* Solo anuncios y telemetría.
  * *Mullvad Extended (`194.242.2.5`):* Malware, anuncios y bloqueo de redes sociales.
  * *Mullvad Family (`194.242.2.6`):* Control parental: contenido adulto, apuestas y malware.
  * *Quad9 (`9.9.9.9`):* Ciberamenazas y validación DNSSEC financiado por Mullvad.

### 6. Experiencia de Usuario & Seguridad de Acceso
* **Icono en la Barra de Tareas Junto al Reloj:** Icono residente (`AppIndicator3` / `Gtk.StatusIcon`) que inicia con el sistema, muestra el estado en vivo y permite abrir el centro de seguridad, escanear memorias o lanzar la VPN.
* **Integración con Clic Derecho:** Acción en el explorador de archivos de Linux Mint (**Nemo**) y Ubuntu (**Nautilus**) para escanear cualquier archivo o carpeta con un simple clic derecho.
* **Autenticación Nativa Linux con `sudo` / PAM (Zero-Breach):** Cero contraseñas propietarias o inseguras. Los usuarios administradores autorizan acciones críticas utilizando su propia contraseña personal de Linux.
* **Despliegue Multi-Usuario Global:** Disponible para todos los usuarios actuales y futuros gracias a la configuración de `/etc/skel/`, `/usr/share/applications/` y `/etc/xdg/autostart/`.
* **Soporte Multilingüe (i18n):** Selector en la cabecera para alternar instantáneamente entre **Español (ES)** e **Inglés (EN)**.
* **Baúl de Cuarentena Cifrado:** Archivos neutralizados con cifrado XOR y permisos `000` en `/var/lib/constantine/vault/`.
* **Auditoría Forense:** Registro cronológico de eventos con exportación de reportes en formato JSON.

---

## 📁 Estructura del Repositorio

```text
Constantine-Antivirus-Linux/
├── assets/
│   └── constantine.svg           # Icono oficial vectorial del sistema
├── core/
│   ├── auth/
│   │   └── auth_manager.py       # Autenticación delegada a PAM/sudo nativo
│   ├── engine/
│   │   ├── interceptor.py        # Interceptación síncrona fanotify + Whitelist
│   │   ├── scanner.py            # YARA + Hashes + Heurística
│   │   ├── vault.py              # Baúl de cuarentena cifrado XOR permisos 000
│   │   ├── ransomware_shield.py  # Honeypots (canaries) y neutralización SIGKILL
│   │   ├── usb_monitor.py        # Vigilancia y auto-escaneo USB silencioso
│   │   ├── persistence_guard.py  # Centinela de arranque (systemd, cron, rc.local)
│   │   ├── download_sentinel.py  # Inspección de descargas en vuelo (~/Downloads)
│   │   ├── hardware_guard.py     # Centinela anti-espía de cámara (/dev/video*) y audio
│   │   ├── audit_logger.py       # Registro forense de incidentes exportable en JSON
│   │   ├── dns_manager.py        # Perfiles Mullvad DNS & Quad9 (DoT 853)
│   │   ├── firewall.py           # Conmutador UFW, corte ss -K y lanzador GUFW
│   │   ├── vpn_manager.py        # Integración oficial con Proton VPN
│   │   ├── update_guard.py       # Auditoría de parches y llamada a mintupdate/update-manager
│   │   ├── phishing.py           # Escudo anti-phishing y auditoría /etc/hosts
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
│   └── publish_to_github.sh      # Asistente para sincronizar con GitHub
├── tests/
│   └── test_constantine.py       # Suite de pruebas unitarias
├── daemon.py                     # Servicio raíz en segundo plano
├── install.sh                    # Instalador desatendido del sistema
├── requirements.txt              # Dependencias de Python
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
   *El script se encarga automáticamente de instalar dependencias de sistema (`yara`, `bpfcc-tools`, `gufw`, `ufw`), desplegar el demonio `constantine.service`, instalar los iconos del sistema, configurar el arranque en la barra de tareas junto al reloj y crear los accesos directos en el menú y en el escritorio de todos los usuarios.*

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

## 🔄 Sincronizar Cambios con GitHub

Si realizas modificaciones locales y deseas subirlas a tu repositorio en GitHub:
```bash
git add .
git commit -m "docs: Actualizar documentación y enlaces oficiales del repositorio"
git push origin main
```

---

## 📄 Licencia

Este proyecto está liberado bajo la Licencia **GNU General Public License v3.0**. Consulta el archivo `LICENSE` para más información.
