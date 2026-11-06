# Constantine Antivirus & EDR for Linux

[![Version: v5.4.7](https://img.shields.io/badge/Version-v5.4.7-blue.svg)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security: Hardened](https://img.shields.io/badge/Security-Hardened%20100%2F100-emerald.svg)](service/constantine.service)
[![Kernel: 5.15+](https://img.shields.io/badge/Kernel-5.15%2B%20LSM-purple.svg)](https://kernel.org)
[![Zero Trust: IPC](https://img.shields.io/badge/Zero--Trust-IPC%20RBAC-blueviolet.svg)](#comunicación-ipc-y-seguridad-zero-trust)

Constantine Antivirus es una solución integral de ciberseguridad, detección y respuesta en endpoints (EDR) y observabilidad de kernel diseñada específicamente para entornos Linux de escritorio y servidores. Combina supervisión preventiva on-access en kernel mediante `fanotify`, observabilidad y bloqueo preventivo con `eBPF` / `BPF LSM`, análisis con motores líderes (YARA-X, Sigma, Falco, Wazuh, MISP, osquery) y una arquitectura de resiliencia diseñada para garantizar que el usuario nunca vea bloqueado su equipo.

---

## 📋 Matriz Oficial de Compatibilidad de Sistemas Operativos y Kernels

No asumimos compatibilidad general basándonos únicamente en la presencia aislada de llamadas fanotify o eBPF. Constantine define una **matriz oficial de compatibilidad de 3 niveles (Tiers)** evaluada automáticamente por el módulo `CompatibilityMatrix`:

| Nivel (Tier) | Requisitos de Kernel | Distribuciones Homologadas | Capacidades Operativas | Modo de Seguridad |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Full Support** *(Óptimo)* | **Linux Kernel >= 5.15 LTS**<br>*(Recomendado >= 6.1 LTS)*<br>`CONFIG_BPF_LSM=y`<br>`CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`<br>`LSM="...,bpf"` | • **Ubuntu** 22.04 LTS, 24.04 LTS<br>• **Debian** 12 (Bookworm)<br>• **Fedora** 38, 39, 40<br>• **RHEL / Rocky / AlmaLinux** 9.0+<br>• **Arch Linux** (Rolling)<br>• **openSUSE** Tumbleweed / Leap 15.5+ | • Bloqueo preventivo en kernel antes de ejecución vía `BPF LSM` (`-EPERM`).<br>• Intercepción preventiva on-access en tiempo real (`FAN_DENY`).<br>• Baúl criptográfico AES-256-GCM y análisis multimodular 100% activo. | **Prevención Total en Kernel** |
| **Tier 2: Degraded Fallback** *(Asistido)* | **Linux Kernel 5.4 a 5.14**<br>*(O kernel >= 5.15 sin BPF LSM activo)*<br>`CONFIG_FANOTIFY=y`<br>`CONFIG_BPF=y` | • **Ubuntu** 20.04 LTS (Focal)<br>• **Debian** 11 (Bullseye)<br>• **RHEL / Rocky / AlmaLinux** 8.6+ | • Intercepción on-access `fanotify` activa con aislamiento en baúl.<br>• eBPF opera en modo de **observabilidad pasiva** con **contención reactiva** post-lanzamiento (`SIGKILL` + corte de red).<br>• Motores YARA-X, Sigma, Falco y Wazuh plenamente funcionales. | **Intercepción Fanotify + Fallback Reactivo** |
| **Tier 3: Unsupported** *(Incompatible)* | **Linux Kernel < 5.4**<br>O sistemas sin `CONFIG_FANOTIFY` | • Distribuciones obsoletas (Ubuntu 18.04, Debian 10)<br>• Entornos WSL1 (Windows Subsystem for Linux v1)<br>• Contenedores Docker/LXC no privilegiados | • El instalador y el demonio deniegan la ejecución para proteger la integridad del sistema.<br>• Requiere actualización de kernel. | **Bloqueado por Incompatibilidad** |

### Opciones de Kernel Requeridas
* `CONFIG_FANOTIFY=y` y `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` (Supervisión y control on-access de ficheros).
* `CONFIG_BPF=y` y `CONFIG_BPF_SYSCALL=y` (Ejecución de programas eBPF en kernel).
* `CONFIG_SECURITY=y` y `CONFIG_BPF_LSM=y` (Ganchos de seguridad LSM para bloqueo inline preventivo).
* Parámetro de arranque en GRUB: `lsm=lockdown,yama,apparmor,bpf` (garantiza que BPF esté en la lista activa de `/sys/kernel/security/lsm`).

---

## 🛠️ Arquitectura de Resiliencia y Recuperación ante Fallos

El principio rector de Constantine es que **el usuario debe poder utilizar su computadora con total normalidad incluso ante fallos internos**. Para lograrlo, implementa un sistema multicapa de tolerancia a fallos gestionado por `ResilienceManager`:

1. **Protección contra Bloqueos de Archivos (Anti-Lock Circuit Breaker):**
   * El interceptor fanotify opera con un timeout estricto (0.5s) y bypass anti-deadlock en rutas del sistema.
   * Si el motor de escaneo experimenta demoras o timeouts reiterados (3 fallos consecutivos), se dispara automáticamente el **Disyuntor de Emergencia**, conmutando a bypass de paso libre (`FAN_ALLOW`) para garantizar que el explorador de archivos, editores o aplicaciones del usuario **nunca se congelen**.
2. **Modo de Mantenimiento:**
   * Accesible desde la interfaz gráfica o CLI (`SET_MAINTENANCE_MODE`).
   * Suspende temporalmente todas las intercepciones activas y bloqueos de archivos sin necesidad de detener el demonio ni desinstalar el antivirus. Permite resolver conflictos, instalar software de desarrollo o depurar el sistema con total fluidez.
3. **Desactivación Segura de Módulos Defectuosos (Safe Module Quarantine):**
   * Cada subsistema (eBPF, Falco, Wazuh, Descargas, USB, etc.) es supervisado independientemente.
   * Si un módulo específico arroja excepciones consecutivas repetidas (umbral de 3 fallos), es aislado y desactivado en cuarentena operativa de forma dinámica, manteniendo al demonio y al resto de los escudos en funcionamiento.
4. **Recuperación tras Actualización Fallida (Auto-Rollback de Firmas):**
   * Antes de aplicar nuevas reglas o compendios (YARA, Sigma, etc.), el sistema genera un snapshot atómico en `/var/lib/constantine/backups/signatures_snapshot.json`.
   * Si la compilación o validación de las nuevas reglas falla, se ejecuta un **Rollback automático e instantáneo** al snapshot anterior, evitando estados inconsistentes o desprotección.
5. **Recuperación Automática del Demonio (systemd Endurecido):**
   * Configurado con directivas `Restart=always`, `RestartSec=3s`, `StartLimitIntervalSec=60s` y `StartLimitBurst=5` para levantamiento automático tras caídas imprevistas.
   * Aislamiento estricto de privilegios: `ProtectHome=read-only`, `ReadWritePaths` limitado exclusivamente a `/var/lib/constantine`, `/var/log/constantine`, `/run/constantine` y `/etc/constantine`, sin `CAP_DAC_OVERRIDE`.

---

## 🖥️ Interfaz Gráfica de Usuario (GUI v5.4.7)

La interfaz gráfica opera en espacio de usuario no privilegiado conectándose al socket Unix seguro. Muestra **información real, dinámica y verificable**, estructurada en 8 secciones:

* **🏠 1. Inicio:**
  * **Invariante estricto de protección:** La interfaz **NUNCA** indica que el equipo está protegido si el demonio está detenido o si el interceptor fanotify no está operativo en kernel. En tales casos, se muestra de inmediato un banner crítico de `SISTEMA DESPROTEGIDO`.
  * Indica con precisión el estado: `PROTEGIDO`, `PROTECCIÓN ACTIVA (DEGRADADA)` o `MODO DE MANTENIMIENTO ACTIVO`.
  * Métricas en tiempo real: amenazas neutralizadas, estado del firewall GUFW, perfil DNS activo y versión de kernel.
* **🛡️ 2. Protección:**
  * Inventario dinámico de los 14 subsistemas de seguridad de Constantine clasificados en **Activos**, **Degradados** e **Inactivos**, con explicación explícita de cualquier causa de degradación.
* **🔍 3. Análisis:**
  * **Análisis Rápido:** Zonas críticas de aterrizaje (`/tmp`, `/var/tmp`, `/dev/shm`, descargas de usuario y persistencia).
  * **Análisis Completo:** Puntos de montaje del sistema de archivos (`/home`, `/var`, `/opt`, etc.).
  * **Análisis Personalizado:** Selección de archivo o carpeta arbitraria bajo demanda.
* **🔒 4. Cuarentena:**
  * Gestión integral del Baúl Criptográfico AES-256-GCM. Visualización de metadatos (ID, ruta original, amenaza, SHA-256, fecha) con acciones de **Restaurar** o **Eliminar permanentemente**.
* **📜 5. Historial:**
  * Registro de auditoría cronológico en tiempo real (bloqueos fanotify, detecciones eBPF, alertas de comportamiento, cambios de configuración) con filtrado por severidad (`CRITICAL`, `WARNING`, `INFO`).
* **⚡ 6. Actualizaciones:**
  * Versión del sistema (v5.4.7) y estadísticas verificadas de firmas activas: reglas YARA / YARA-X, reglas Sigma, reglas Falco, reglas Wazuh FIM e IoCs indexados en MISP. Botón para comprobación y aplicación de actualizaciones con auto-rollback.
* **⚙️ 7. Configuración:**
  * **Exclusiones (Whitelist):** Gestión de rutas autorizadas con verificación de integridad de inodo y hash SHA-256. Bloqueo estricto que prohíbe excluir directorios críticos (`/`, `/etc`, `/usr/bin`, etc.).
  * **Privacidad:** Selector de perfiles DNS seguros (Mullvad Adblock, Mullvad Base, Cloudflare Security) y escudo de periféricos (cámara web y micrófono).
  * **Comportamiento:** Ajuste de políticas de fallo y sensibilidad anti-ransomware.
* **📊 8. Diagnóstico:**
  * Postura de seguridad verificada mediante consultas SQL de `osquery` y auditoría de `systemd`.
  * Informe oficial de compatibilidad de kernel/SO (Tier 1 vs Tier 2).
  * Controles de resiliencia: activación de modo de mantenimiento, restablecimiento de disyuntores y recuperación de módulos aislados.

---

## 🔒 Comunicación IPC y Seguridad Zero-Trust

La comunicación entre el demonio root y las herramientas de usuario (GUI y CLI) se realiza mediante sockets de dominio Unix bajo un esquema de **Confianza Cero**:
* **Aislamiento de Grupo:** Socket asignado a `root:constantine-users` con permisos `0660`.
* **Identidad de Kernel (SO_PEERCRED):** Validación forzosa del UID, GID y PID en el kernel. Nunca se asigna UID 0 por defecto.
* **RBAC Exclusivo en el Servidor:** Comandos divididos entre `USER_ALLOWED_COMMANDS` (consultas, escaneo, lista de cuarentena, diagnóstico) y `ADMIN_ONLY_COMMANDS` (modificación de lista blanca, DNS, firmas, mantenimiento), exigiendo privilegios elevados verificados por Polkit o root.
* **Protocolo Robusto:** Lectura exacta de tramas (`recv_exact`) con prefijos de longitud de 4 bytes para evitar desincronización de streams Unix.

---

## 📂 Árbol de Archivos del Proyecto

```text
constantine/
├── VERSION                                 # Versión canónica del sistema (5.4.7)
├── daemon.py                               # Demonio principal de seguridad y observabilidad
├── install.sh                              # Script oficial de instalación y verificación
├── service/
│   └── constantine.service                 # Unidad de servicio systemd endurecida
├── gui/
│   ├── __init__.py
│   └── app.py                             # Interfaz gráfica GTK 3.0 y controlador de 8 secciones
├── core/
│   ├── auth/                               # Gestor de autenticación y Polkit
│   │   └── auth_manager.py
│   └── engine/                             # Motores de seguridad y observabilidad
│       ├── compatibility_matrix.py         # Matriz oficial de compatibilidad de SO y kernel
│       ├── resilience_manager.py           # Resiliencia, modo de mantenimiento y circuit breakers
│       ├── ebpf_monitor.py                 # Motor eBPF (Observación, Detección, BPF LSM)
│       ├── tetragon_monitor.py             # Adaptador de políticas Cilium Tetragon y socket gRPC stream
│       ├── interceptor.py                  # Interceptor nativo Fanotify (fanotify_init, fanotify_mark, receptor multihilo y respuestas de permiso)
│       ├── vault.py                        # Baúl criptográfico AES-256-GCM
│       ├── scanner.py                      # Motor de análisis YARA-X y heurístico
│       ├── yara_manager.py                 # Compilador y gestor de reglas YARA
│       ├── yarax_engine.py                 # Motor compilado YARA-X
│       ├── sigma_engine.py                 # Adaptador y evaluador de reglas Sigma
│       ├── falco_monitor.py                # Reglas conductuales de syscalls (CNCF Falco)
│       ├── wazuh_detector.py               # Monitoreo FIM y correlación YARA (Wazuh)
│       ├── misp_feed_manager.py            # Feeds e inteligencia de amenazas MISP
│       ├── osquery_diagnostics.py          # Auditoría e inventario SQL con tablas virtuales
│       ├── download_sentinel.py            # Centinela de descargas inotify
│       ├── usb_sentinel.py                 # Centinela de medios extraíbles USB
│       ├── persistence_guard.py            # Guardián de 574 puntos de persistencia
│       ├── hardware_guard.py               # Escudo de cámara web y micrófono
│       ├── ransomware_shield.py            # Centinela de canarios y ráfagas anti-ransomware
│       ├── proactive_scanner.py            # Escáner continuo de aterrizaje en segundo plano
│       ├── auto_updater.py                 # Actualizador con snapshot y auto-rollback
│       ├── whitelist.py                    # Lista blanca con verificación de inodo y SHA-256
│       ├── dns_manager.py                  # Gestor de resolvedores DNS seguros
│       ├── firewall_manager.py             # Integración con cortafuegos GUFW/UFW
│       ├── systemd_hardening.py            # Auditor de seguridad de servicios systemd
│       ├── audit_logger.py                 # Registro inmutable de eventos de seguridad
│       └── ipc_protocol.py                 # Protocolo seguro IPC Unix con RBAC
└── tests/
    ├── test_constantine.py                 # Suite exhaustiva de pruebas unitarias
    └── test_integration.py                # Suite de pruebas de integración end-to-end
```

---

## 🚀 Instalación y Verificación

### Instalación Automática
```bash
sudo ./install.sh
```

### Gestión del Servicio systemd
```bash
# Iniciar el servicio
sudo systemctl start constantine

# Verificar estado y postura de seguridad
sudo systemctl status constantine

# Detener el servicio
sudo systemctl stop constantine
```

### Ejecución de la Interfaz Gráfica
```bash
# En entorno de escritorio (abre ventana nativa GTK 3.0)
python3 -m gui.app

# En servidores o terminal (imprime el panel de diagnóstico de 8 secciones)
python3 gui/app.py
```

### Ejecución de la Suite de Pruebas
```bash
python3 -m unittest discover tests -v
```
Todas las 119+ pruebas unitarias y de integración end-to-end se ejecutan en espacio aislado garantizando el cumplimiento de la matriz de compatibilidad, los invariantes de seguridad y la resiliencia del sistema.
