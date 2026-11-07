# 🛡️ Constantine Antivirus & EDR v3.2.7

[![Version](https://img.shields.io/badge/version-3.2.7-blue.svg)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)
[![OS](https://img.shields.io/badge/OS-Ubuntu%2024.04%2B%20%7C%20Debian%2013%2B%20%7C%20Mint%2022%2B-orange.svg)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)
[![Rust](https://img.shields.io/badge/Rust-%E2%89%A51.70-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)

**Constantine** es un sistema de Detección y Respuesta en Puntos Finales (EDR) nativo para distribuciones Linux basadas en Debian. Diseñado con una arquitectura multi-motor y un enfoque **Fail-Secure**, combina telemetría eBPF, análisis heurístico, inteligencia de amenazas y criptografía autenticada.

🔗 **Repositorio Oficial**: [github.com/AntonSiMal/Constantine-Antivirus-Linux](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)

---

## 🌟 Características Principales

### 1. Escudo Anti-Ransomware (estado actual v3.2.7)

| Capa | Estado | Implementación |
|---|---|---|
| **1. Canary Tripwires (Señuelos)** | 🟡 Sembrado activo · Monitoreo vía Tetragon (pendiente de `notify` directo) | Archivos trampa en `~/Desktop`, `~/Documents`, `~/Downloads`, `~/Pictures`. La `TracingPolicy` de Tetragon vigila escrituras sobre las rutas `!000_canary_*`. |
| **2. Detección de ráfagas + entropía** | 🟡 Lógica presente · Pendiente de conectar al watcher de eventos | `AntiRansomwareShield::track_process_burst` implementa la correlación (frecuencia + entropía > 7.55 + extensión sospechosa), pero solo se invoca desde Tetragon cuando una escritura llega a un canary. La integración con `notify::Watcher` está en el roadmap. |
| **3. Neutralización atómica** | ✅ Activo | `SIGSTOP` → resolución de `/proc/PID/exe` → `SIGKILL`, más aislamiento del binario ejecutor en el baúl AES-256-GCM. Sujeto al gate de 5 pruebas (`DestructiveActionSafetyGate`). |
| **4. Forense inmutable** | ✅ Activo | Registro encadenado SHA-256 con verificación criptográfica completa en `verify_integrity()`. |

> **Nota de honestidad técnica**: las capas 1 y 2 se describen como "activas" porque la telemetría eBPF de Tetragon ya las dispara. La integración con el watcher inotify (`notify`) que detectaría modificaciones en los canarys **sin** depender de Tetragon está en el roadmap. Hasta entonces, la eficacia real de las capas 1–2 está supeditada a que Tetragon esté corriendo.

### 2. Pipeline Multi-Motor Fail-Secure

- **Prevención en Acceso (Kernel)**: `ClamOnAcc` con `fanotify` para bloqueo síncrono a nivel de kernel.
- **Análisis Estático**: motores obligatorios **ClamAV** (socket UNIX) y **YARA**, con soporte opcional para **YARA-X** (Rust). Cualquier fallo de motor → veredicto `Indeterminate` (nunca `Clean` por omisión).
- **Telemetría Comportamental**: sensor principal **Tetragon (Cilium eBPF)** con correlación de 4 pilares (Identidad, Ejecutable, Comportamiento, Contexto) y reglas **Sigma** para Linux.
- **Integridad del Sistema**: **AIDE** (Advanced Intrusion Detection Environment) y **Wazuh Agent** (FIM/SIEM).
- **Threat Intelligence**: sincronización local de IoCs de **MISP**, **MalwareBazaar**, **ThreatFox**, **URLhaus** y **OpenPhish**.
- **Firewall y VPN**: integración con **UFW/GUFW** y **ProtonVPN** (auditoría de estado, sin modificar políticas preexistentes).

### 3. Criptografía y Forense Inmutable

- **Baúl de Cuarentena (AES-256-GCM)**: aislamiento transaccional con clave CSPRNG del kernel, nonce de 96 bits y AAD vinculado al hash SHA-256 original. La escritura se sincroniza a disco (`sync_all`) antes de borrar el original.
- **Registro Forense Encadenado (Hash Chaining)**: cada evento se sella con `SHA-256(prev_hash | timestamp | event_type | details)`. `verify_integrity()` recalcula cada payload para detectar alteraciones o borrados selectivos.

### 4. Interfaz Gráfica Nativa (GTK4 Cupertino Theme)

- Aplicación escrita en **Rust** con `gtk4`, con estética inspirada en macOS.
- Panel de salud EDR que evalúa **8 controles operativos** en tiempo real (socket clamd, ClamOnAcc, YARA, canarys, forense, AIDE, Falco, Tetragon).
- Vista de auditoría con **20 componentes** de seguridad: 18 motores + UFW + ProtonVPN.

---

## 📋 Requisitos del Sistema

| Componente | Versión mínima | Notas |
|---|---|---|
| **SO** | Ubuntu 24.04+, Debian 13+, Linux Mint 22+ | Requiere **GTK ≥ 4.10** |
| **Rust** | ≥ 1.70 | El instalador usa `rustup` si `rustc` de apt es más antiguo |
| **Kernel** | `CONFIG_FANOTIFY=y` + `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` | Para prevención en acceso completa |
| **Privilegios** | `root`/`sudo` | Para instalar servicios y ejecutar acciones privilegiadas |

> ⚠️ **Ubuntu 22.04, Debian 12 y Linux Mint 21 no son compatibles** con esta versión porque su GTK4 (< 4.10) es anterior al mínimo exigido por `gtk4-rs 0.8`. Si necesitas soporte para esas distros, compila con `gtk4 = "0.7"` y `rust-version = "1.63"` (ver `Cargo.toml`).

Las dependencias de compilación (`build-essential`, `libgtk-4-dev`, `pkg-config`, `yara`, `libyara-dev`, `aide`, `clamav`, etc.) las instala automáticamente `install.sh`.

---

## 🚀 Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/AntonSiMal/Constantine-Antivirus-Linux.git
   cd Constantine-Antivirus-Linux
   ```
2. Otorga permisos de ejecución al instalador:
   ```bash
   chmod +x install.sh
   ```
3. Ejecuta el script con privilegios de superusuario:
   ```bash
   sudo ./install.sh
   ```

   > **Nota**: si estás en un entorno gráfico (Wayland/X11) con Python 3 + GTK, se abrirá un asistente visual con terminal en vivo. En caso contrario, se ejecuta en modo consola.

El instalador:
- Comprueba **Rust ≥ 1.70** e instala `rustup` si es necesario.
- Verifica **GTK ≥ 4.10** con `pkg-config` antes de compilar.
- **Compila el binario en el paso 7/20**, antes de instalar Tetragon/Falco/Wazuh/osquery/ProtonVPN. Si la compilación falla, el sistema no queda a medio configurar.
- Aplica **ACLs** para que tu usuario acceda al `.vault.key`, `immutable_audit.log` y `whitelist.txt` **sin necesidad de cerrar sesión**.
- Restringe la `TracingPolicy` de Tetragon a las rutas canary y a `/etc/shadow` + `/etc/sudoers` (no a todo `/home/`).
- Configura el `constantine-boot-update.timer` con `OnCalendar=*-*-* 03:00:00` (persistente entre reinicios).

---

## 💻 Uso

- **Menú de aplicaciones**: busca "Constantine Antivirus & EDR".
- **Terminal**:
  ```bash
  constantine
  ```
- **Gestión de servicios**:
  ```bash
  sudo systemctl status clamonacc tetragon falco wazuh-agent clamav-daemon
  ```

> 💡 **Importante**: para que tu usuario reciba el grupo `constantine` de forma permanente, cierra sesión y vuelve a entrar. Mientras tanto, las ACL aplicadas por el instalador ya permiten operar.

---

## 🗑️ Desinstalación Limpia

```bash
sudo ./uninstall.sh
```

Restaura `clamd.conf` desde `${CLAMD_CONF}.bak`, elimina las reglas UFW añadidas por Constantine, retira los canarys, purga el baúl, y borra servicios y lanzadores.

> ⚠️ **No** desinstala paquetes externos (`wazuh-agent`, `falco`, `osquery`, `protonvpn`, `gufw`) para no romper dependencias de otros usuarios del sistema. Si quieres eliminarlos, hazlo manualmente con `apt remove`.

---

## 📂 Estructura del Proyecto

```text
Constantine-Antivirus-Linux/
├── install.sh              # Instalador (compilación temprana + ACLs + hardening)
├── uninstall.sh            # Desinstalador (restauración de configuraciones)
├── Cargo.toml              # Manifiesto de dependencias (Rust ≥ 1.70, GTK ≥ 4.10)
├── Cargo.lock              # Lockfile (builds reproducibles con --locked)
├── constantine.rs          # Código fuente principal (Rust + GTK4)
└── README.md               # Este archivo
```

---

## 🗺️ Roadmap y Limitaciones Conocidas

La versión v3.2.7 es funcional, pero queremos ser transparentes sobre lo que **todavía no** hace:

- [ ] **Watcher inotify directo sobre los canarys** (`notify::Watcher`). Actualmente los canarys se siembran y se validan por existencia, pero su vigilancia en tiempo real depende de Tetragon. El crate `notify` ya está en `Cargo.toml` pero aún no se instancia.
- [ ] **Cacheo de feeds TI en memoria** (`HashSet` en `OnceLock`). Hoy `is_known_malware_hash` itera línea por línea en 3 archivos de hasta 5000 entradas por cada archivo escaneado.
- [ ] **Cache de `dpkg -S` por `(pid, exe_inode)`** en lugar de por evento de Tetragon (mejora de CPU esperada: 10-50× en escrituras sobre `/home/`).
- [ ] **Sustitución de `pkexec kill`** por un helper `setuid` con `CAP_KILL` restringido para respuesta inmediata sin prompt de polkit.
- [ ] **Soporte explícito para distros con GTK 4.6–4.8** vía feature flag (`gtk4 = "0.7"`).
- [ ] **Integración del health score** con los 20 módulos (hoy cuenta 8 controles representativos).

---

## ⚠️ Aviso Legal y de Responsabilidad

Este software es una herramienta de **seguridad defensiva** diseñada para proteger sistemas contra amenazas avanzadas.

- El uso de este software en sistemas que no son de tu propiedad o sin el consentimiento explícito del propietario está estrictamente prohibido.
- El autor no se hace responsable de daños indirectos, pérdida de datos o interrupciones del servicio derivados del uso de este software. Úsalo bajo tu propia responsabilidad.
- Constantine **no sustituye** a un antivirus comercial ni a un SOC profesional. Es una capa adicional de defensa en profundidad.

---

## 🤝 Contribuciones

Las contribuciones, reportes de bugs y solicitudes de características son bienvenidas. Abre un [Issue](https://github.com/AntonSiMal/Constantine-Antivirus-Linux/issues) o un [Pull Request](https://github.com/AntonSiMal/Constantine-Antivirus-Linux/pulls).

---

**Desarrollado con ❤️ y Rust por el Constantine Security Team.**
*Versión: 3.2.7 (Debian Edition)*
*Repositorio: [AntonSiMal/Constantine-Antivirus-Linux](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)*
