
<p align="center">
  <h1 align="center">Constantine EDR</h1>
  <p align="center" style="font-size: 1.2em; color: #666;">
    La suite de seguridad más avanzada para Linux.<br>
    Diseñada en Rust. Integrada en el Kernel. Invisible para ti, impenetrable para ellos.
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.70+-black?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/GPL_3.0-Open_Source-black?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Linux-Debian_%7C_Ubuntu_%7C_Mint-black?style=flat-square&logo=linux" alt="Linux">
  <img src="https://img.shields.io/badge/GTK4-Cupertino-black?style=flat-square&logo=gnome" alt="GTK4">
  <img src="https://img.shields.io/badge/Kernel-eBPF_%7C_fanotify-black?style=flat-square" alt="Kernel">
</p>

<p align="center">
  <em>0% Telemetría. 100% Soberanía. 16 Motores. 1 Suite.</em>
</p>

---

## Seguridad. Redefinida.

Durante años, la seguridad en el escritorio Linux ha exigido compromisos. O sacrificas rendimiento con escaneos lentos, o sacrificas protección con herramientas reactivas. Constantine elimina esa elección.

Ofrecemos protección preventiva en tiempo real con **16 motores integrados**, control de periféricos, defensa anti-ransomware de 4 capas y un dashboard ejecutivo que se siente como en casa.

---

## Potente. Elegante. Invisible.

### 🛡️ Intercepción preventiva en el Kernel
Constantine no espera a que el malware se ejecute. Mediante `eBPF LSM` (Cilium Tetragon) y `fanotify` (ClamOnAcc), interceptamos y neutralizamos las amenazas en milisegundos, antes de que toquen el disco o la memoria.

### 🧬 Escudo Anti-Ransomware en 4 Capas
Una defensa matemática y conductual contra el cifrado hostil:
1. **Canary Tripwires:** Archivos trampa invisibles sembrados en `~/Desktop`, `~/Documents`, `~/Downloads` y `~/Pictures` para todos los usuarios del sistema.
2. **Detección de Ráfagas:** Análisis de patrones masivos de renombrado en ventanas de 3 segundos.
3. **Entropía de Shannon ($H > 7.55$):** Diferenciación matemática entre compresión legítima y cifrado hostil.
4. **Aislamiento Atómico:** Congelación instantánea (`SIGSTOP`), terminación (`SIGKILL`) y cuarentena en baúl AES-256-GCM.

### 🔒 Privacidad por diseño
Tu privacidad es un derecho fundamental. Constantine no recoge datos, no envía telemetría y no depende de la nube. Tu código, tus reglas, tu máquina. Los registros forenses se almacenan localmente con una **cadena criptográfica SHA-256 inmutable** que hace imposible la alteración sin ser detectada.

### 🎯 Pipeline Multi-Motor Fail-Secure
Cada archivo pasa por una evaluación rigurosa donde el fallo de un motor se cataloga como `INDETERMINADO` —jamás se asume limpio sin análisis completo—:
- **ClamAV** (socket multihilo)
- **YARA** (reglas verificadas)
- **YARA-X** (VirusTotal en Rust)
- **Heurística** (entropía + extensiones)
- **Inteligencia de Amenazas** (MISP, MalwareBazaar, ThreatFox, URLhaus, OpenPhish, StevenBlack)

### ✨ Una interfaz que se siente como en casa
Un dashboard unificado en **GTK4 con estética Cupertino**. Desde portátiles compactos (800x600) hasta monitores 4K, la operación es fluida, intuitiva y no requiere contraseñas de `sudo` para el uso diario gracias a políticas Polkit y Sudoers finamente ajustadas.

---

## Tu seguridad, de un vistazo.

El dashboard de Constantine está diseñado para que un solo vistazo te diga todo lo que necesitas saber. Sin ruido, solo información accionable.

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│  Constantine EDR v5.5                            ● Salud: 100% (10/10)       │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  📦 MUESTRAS      📋 LISTA BLANCA   🔍 ESCUDOS        🧬 ANTI-RANSOMWARE    │
│  0 Muestras       14 Hashes         fanotify + eBPF   4/4 Canary Intactos  │
│  Baúl AES-256     Firmas SHA-256    Vigilando /home   Tripwires + Ráfagas  │
│                                                                              │
│  🔄 SISTEMA Y KERNEL                                                         │
│  Kernel activo: 6.8.0-generic | 🟢 Kernel y Sistema completamente al día    │
│  0 parches críticos pendientes                      [🚀 Abrir Actualizador] │
│                                                                              │
│  ⚙️ MATRIZ DE SENSORES                                                       │
│  1. fanotify (ClamOnAcc)     ● Activo    6. Registro Forense   ● SHA-256   │
│  2. Canary Anti-Ransomware   ● 4/4       7. Escudo USB         ● P&P       │
│  3. Tetragon eBPF (LSM)      ● Activo    8. DNS Sinkhole       ● 78k dom.  │
│  4. Periféricos V4L2         ● Blindado  9. Tamper Protection  ● Anti-Kill │
│  5. UFW Firewall             ● Activo    10. Modo Juego / DND  ● Listo     │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Arquitectura Multicapa Fail-Secure.

Constantine no es un simple script. Es una arquitectura cliente-servidor empresarial donde el demonio con privilegios root (`constantine-daemon`) expone un socket IPC seguro (`/run/constantine.sock`) a la interfaz gráfica.

```text
                     ┌────────────────────────────────────────────┐
                     │   Constantine GUI (GTK4 Cupertino)         │
                     │   [800x600 → 4K | Polkit | Cero sudo]      │
                     └────────────────────┬───────────────────────┘
                                          │ Unix Socket IPC
                     ┌────────────────────▼───────────────────────┐
                     │   constantine-daemon (Root Supervisor)     │
                     └──┬─────────────┬─────────────┬─────────────┘
                        │             │             │
   ┌────────────────────▼──┐  ┌───────▼─────────┐  ┌▼────────────────────┐
   │  Kernel & eBPF        │  │  Motores & TI   │  │  Hardware & Red     │
   │  • fanotify           │  │  • ClamAV       │  │  • UDisks2 (USB)    │
   │  • Tetragon LSM       │  │  • YARA / YARA-X│  │  • V4L2 (Cámara)    │
   │  • Falco Behavioral   │  │  • MISP / Sigma │  │  • pactl (Mic)      │
   │  • Anti-Kill          │  │  • AES-256-GCM  │  │  • DNS Sinkhole     │
   │  • Hash Chain SHA-256 │  │  • StevenBlack  │  │  • UFW / iptables   │
   └───────────────────────┘  └─────────────────┘  └─────────────────────┘
```

**Política Fail-Secure estricta:** Si durante la instalación o ejecución un módulo crítico falla, el sistema revierte limpiamente todos los cambios para no dejar residuos ni un estado de falsa seguridad.

---

## Los 16 Motores. Sincronizados.

| # | Módulo | Función |
| :--- | :--- | :--- |
| 1 | **ClamOnAcc (fanotify)** | Intercepción síncrona en kernel al abrir archivos |
| 2 | **Tetragon (Cilium eBPF)** | Sensor EDR principal con LSM Hooks y Anti-Kill |
| 3 | **Falco** | Detección de comportamiento anómalo (CNCF) |
| 4 | **Wazuh Agent** | SIEM, FIM (syscheck) y telemetría |
| 5 | **ClamAV (clamd)** | Motor de firmas multihilo vía socket UNIX |
| 6 | **YARA** | Análisis estático con reglas verificadas |
| 7 | **YARA-X** | Motor de VirusTotal reescrito en Rust |
| 8 | **osquery** | Consultas SQL del sistema en tiempo real |
| 9 | **AIDE** | Verificación criptográfica de integridad (FIM) |
| 10 | **StevenBlack Hosts** | Base comunitaria anti-phishing y malware |
| 11-14 | **Feeds TI (MISP, Bazaar, Fox, URLhaus)** | IoCs en tiempo real de Abuse.ch y CERTs |
| 15 | **Sigma Rules** | Detección genérica de amenazas para Linux |
| 16 | **YARA-Rules Comunitarias** | Repositorio oficial de reglas abiertas |

---

## Constantine vs. El resto.

| Característica | Soluciones Linux Tradicionales | Suites Propietarias | **Constantine EDR** |
| :--- | :--- | :--- | :--- |
| **Protección** | Reactiva (bajo demanda) | Preventiva, pero cerrada | **Preventiva, nativa y abierta** |
| **Autoprotección** | Inexistente (`root` la anula) | Controladores propietarios | **Políticas eBPF LSM + `chattr +i`** |
| **Anti-Ransomware** | Ninguna | Heurística en nube | **4 Capas: Canary + Ráfagas + Entropía + SIGKILL** |
| **Filtrado Web** | Requiere extensiones | Proxy local propietario | **Sumidero DNS local (0.0.0.0) transparente** |
| **Rendimiento** | Escaneos que congelan CPU | Alto uso de RAM y telemetría | **Rust nativo, ligero, responsivo** |
| **Periféricos** | No disponible | Notificaciones simples | **Kill-Switch V4L2 + Silenciamiento de Mic** |
| **Registro** | Texto plano manipulable | Envío a servidores externos | **Hash-chaining SHA-256 inmutable** |
| **Privacidad** | Variable | Propietario con cobro | **100% local. Cero telemetría.** |

---

## Capacidades de Nueva Generación.

### 📥 Cuarentena Preventiva de Descargas (Mark-of-the-Web)
Vigilancia asíncrona sobre `~/Downloads` y `~/Descargas`. Aplica metadatos extendidos (`xattr`) y retira preventivamente el permiso de ejecución (`chmod a-x`) a binarios recién descargados, impidiendo infecciones por doble clic accidental.

### 👥 Arquitectura Multiusuario Nativa
Detecta dinámicamente a todos los usuarios humanos (`UID >= 1000`) y los integra en el grupo `constantine`. Mediante `/etc/skel`, **todo nuevo usuario nace protegido**: con señuelos sembrados, autostart y accesos directos listos.

### 🌐 Sumidero DNS y Perfiles Seguros
Bloquea más de 78,000 dominios de phishing y C2 directamente en `/etc/hosts`. Incluye perfiles DNS preconfigurados de **Quad9, Mullvad (7 variantes) y Cloudflare** aplicables con un clic a la interfaz activa vía `resolvectl` y `nmcli`.

### 🔒 Custodia de Periféricos
- **Kill-Switch V4L2:** Bloqueo por hardware de cámaras (`chmod 000 /dev/video*`).
- **Silenciamiento de Micrófono:** Control vía `pactl` y `amixer` sin afectar la salida de audio.
- **Escudo USB Reactivo:** Análisis automático Plug & Play al insertar unidades (vía D-Bus UDisks2).

### 🚨 Aislamiento de Red (Kill-Switch EDR)
Contención de emergencia que corta todo el tráfico exterior mediante `iptables`, manteniendo solo el bucle local (`lo`). Ideal para neutralizar exfiltraciones o ransomware en curso.

### 📜 Auditoría Forense Inmutable
Cada evento se encadena criptográficamente:
$$\text{Hash}_n = \text{SHA-256}(\text{Hash}_{n-1} \parallel \text{Timestamp} \parallel \text{Evento} \parallel \text{Detalles})$$
Cualquier alteración rompe la cadena y genera una alarma pericial crítica. Exportable a informes HTML ejecutivos.

---

## Requisitos del Sistema.

- **Sistema Operativo:** Debian 12+, Ubuntu 22.04/24.04 LTS, o Linux Mint 21+.
- **Kernel:** Linux 5.8+ (con `CONFIG_FANOTIFY=y`, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` y `CONFIG_BPF=y`).
- **Entorno:** Rust 1.70+ (Cargo) y librerías GTK4.
- **Hardware:** Fluido desde 800x600 hasta 4K.

---

## Instalación en un solo paso.<p align="center">

```text
1. Clona el repositorio:
   ```bash
   git clone https://github.com/tonsimaltine-Antivirus-Linux
   cd tonsimaltine-Antivirus-Linux
   ```

2. Ejecuta el instalador:
   ```bash
   sudo ./install.sh
   ```

El asistente gráfico (o CLI en servidores) se encargará de todo:
- ✅ Verificación y actualización automática de la toolchain de Rust.
- ✅ Aceptación transparente de licencia y exención de riesgos.
- ✅ Instalación de los 16 motores, dependencias y feeds de inteligencia.
- ✅ Siembra de señuelos Canary para todos los usuarios (presentes y futuros).
- ✅ Configuración de Polkit, Sudoers, D-Bus y temporizadores systemd.
- ✅ Compilación optimizada y apertura automática del EDR.
- ✅ **Política Fail-Secure:** Si un módulo falla, revierte todo limpiamente.

---

## Uso Diario. Simplemente funciona.

### Interfaz Gráfica
Abre Constantine desde el menú de aplicaciones o ejecuta `constantine` en tu terminal.

### Operación por Línea de Comandos (Headless)
```bash
constantine --daemon          # Modo demonio en segundo plano
constantine --scan-quick      # Análisis rápido de zonas críticas
constantine --scan-full       # Análisis exhaustivo del sistema
constantine --scan-file /ruta # Análisis bajo demanda
```

### Integración Nativa
- **Menú Contextual:** Clic derecho en Nautilus, Nemo, Thunar o Dolphin para "Analizar con Constantine".
- **Bandeja del Sistema:** Icono de estado junto al reloj con accesos rápidos.
- **Temporizadores:** Análisis diario (02:00 AM) y semanal (Domingos 03:00 AM) con prioridad I/O baja y guardia de batería (`ConditionACPower=true`).

---

## Desinstalación Limpia. Sin dejar rastro.

Si decides que Constantine ya no es para ti, respetamos tu elección. Nuestro desinstalador garantiza una reversión total y absoluta del sistema operativo a su estado original.

```bash
sudo ./uninstall.sh
```

O desde la interfaz gráfica mediante el **flujo deliberado de 3 clics** con disuasión y autenticación obligatoria. Esto elimina sondas del kernel, restaura archivos de configuración, limpia reglas de red, retira señuelos en todos los idiomas y borra cada rastro de la aplicación.

---

## Reconocimientos.

Constantine se construye sobre los hombros de gigantes. Agradecemos profundamente a las comunidades de código abierto que hacen esto posible:

[Cilium Tetragon](https://tetragon.io/) · [Falco](https://falco.org/) · [ClamAV](https://www.clamav.net/) · [VirusTotal YARA-X](https://github.com/VirusTotal/yara-x) · [Wazuh](https://wazuh.com/) · [osquery](https://osquery.io/) · [AIDE](https://aide.github.io/) · [SigmaHQ](https://github.com/SigmaHQ/sigma) · [StevenBlack Hosts](https://github.com/StevenBlack/hosts) · [Abuse.ch](https://abuse.ch/) · [GTK](https://gtk.org/)

---

## Licencia y Exención de Responsabilidad.

Distribuido bajo la licencia **GNU General Public License v3.0 (GPL-3.0)**.

> **Aviso:** Constantine interactúa a bajo nivel con el kernel Linux mediante `fanotify`, `eBPF`, `chattr` y `iptables`. El software se proporciona "TAL CUAL" (*AS IS*), sin garantías de ningún tipo. Al instalarlo, el usuario asume los riesgos técnicos inherentes a la administración avanzada del sistema operativo.
