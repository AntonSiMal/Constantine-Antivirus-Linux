# 🛡️ Seguridad y Sandboxing del Servicio con systemd

Este documento describe la arquitectura de contención, aislamiento y reducción de privilegios implementada para el servicio `constantine.service` aprovechando los mecanismos de seguridad nativos de [systemd](https://github.com/systemd/systemd) y las especificaciones oficiales de [`systemd.exec(5)`](https://www.freedesktop.org/software/systemd/man/systemd.exec.html).

---

## 🎯 Objetivo de Seguridad y Modelo de Amenazas

Un software antivirus procesa activamente datos hostiles no confiables (código binario, scripts ofuscados, macros de documentos y contenedores comprimidos). Si un atacante intentara explotar una vulnerabilidad en un parser de archivos o en un motor de descompresión para lograr ejecución remota de código (RCE), las directivas de seguridad de `systemd` aseguran que **el impacto permanezca confinado en un sandbox estricto**:
* El proceso no puede escalar privilegios a root completo ni adquirir nuevas capacidades.
* El sistema operativo (`/usr`, `/boot`, `/etc`) permanece montado en modo de solo lectura.
* No se pueden modificar binarios del sistema, ni cargar módulos en el kernel, ni alterar la configuración de red.
* El espacio de nombres temporal (`/tmp`, `/var/tmp`) está completamente aislado del resto de procesos.

---

## 🔒 Matriz de Directivas de Hardening en `constantine.service`

| Directiva systemd | Configuración en Constantine | Protección que Otorga |
| :--- | :--- | :--- |
| **`NoNewPrivileges=`** | `true` | Bloquea la obtención de nuevos privilegios mediante binarios SUID/SGID para el daemon y todos sus procesos hijos (`execve`). |
| **`ProtectSystem=`** | `strict` | Monta toda la jerarquía de archivos del sistema operativo en modo de solo lectura estricto, excepto las rutas declaradas en `ReadWritePaths=`. |
| **`ProtectHome=`** | `read-only` | Protege los directorios personales (`/home`, `/root`, `/run/user`) contra modificaciones no autorizadas. |
| **`PrivateTmp=`** | `true` | Genera un espacio de nombres privado para `/tmp` y `/var/tmp`, impidiendo el robo o inyección de archivos temporales entre servicios. |
| **`CapabilityBoundingSet=`** | Delimitado | Reduce las capacidades del kernel al mínimo estricto (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_KILL`, `CAP_DAC_READ_SEARCH`, `CAP_BPF`, `CAP_PERFMON`). Elimina `CAP_SYS_BOOT`, `CAP_SYS_MODULE`, etc. |
| **`DevicePolicy=`** | `closed` | Niega el acceso a dispositivos físicos no autorizados. Solo permite dispositivos declarados explícitamente (`/dev/null`, `/dev/urandom`, `/dev/net/tun`, cámaras/micrófono para hardware guard). |
| **`SystemCallFilter=`** | `@system-service` + bpf/fanotify | Bloquea grupos de llamadas al sistema innecesarias o peligrosas (`@clock`, `@cpu-emulation`, `@module`, `@reboot`). |
| **`SystemCallArchitectures=`** | `native` | Bloquea llamadas al sistema de arquitecturas de 32 bits no nativas, mitigando ataques de evasión por emulación. |
| **`ProtectKernelTunables=`** | `true` | Niega la modificación de variables en `/proc/sys`, `/sys` y configuraciones dinámicas del kernel. |
| **`ProtectKernelModules=`** | `true` | Bloquea la carga y descarga de módulos en el kernel (`init_module`, `delete_module`). |
| **`ProtectControlGroups=`** | `true` | Bloquea la modificación de las jerarquías de cgroups del sistema. |
| **`RestrictRealtime=`** | `true` | Impide que el proceso configure políticas de planificación en tiempo real para evitar ataques de denegación de servicio. |
| **`RestrictSUIDSGID=`** | `true` | Niega la creación de archivos con bits SUID o SGID. |
| **`LockPersonality=`** | `true` | Bloquea cambios de personalidad de ejecución de Linux (`personality(2)`). |
| **`RestrictAddressFamilies=`** | `AF_UNIX AF_INET AF_INET6 AF_NETLINK` | Restringe los tipos de sockets de red autorizados. |
| **`UMask=`** | `0027` | Garantiza que cualquier archivo creado por el daemon tenga permisos restrictivos por defecto (0750 en directorios / 0640 en archivos). |

---

## 📁 Rutas de Escritura y Directorios Estandarizados

Systemd gestiona automáticamente el ciclo de vida y los permisos de los directorios del antivirus mediante:
* **`StateDirectory=constantine`:** `/var/lib/constantine` (Baúl criptográfico, trampas señuelo y metadatos) con permisos `0700`.
* **`LogsDirectory=constantine`:** `/var/log/constantine` (Registro inmutable forense de auditoría) con permisos `0750`.
* **`RuntimeDirectory=constantine`:** `/run/constantine` (Socket seguro IPC de dominio Unix) con permisos `0755`.
* **`ConfigurationDirectory=constantine`:** `/etc/constantine` (Claves de cifrado del host) con permisos `0750`.

---

## 🧪 Verificación y Auditoría con `systemd-analyze`

Para auditar la postura de seguridad del servicio en cualquier distribución Linux con systemd:

```bash
systemd-analyze security constantine.service
```

El auditor integrado `core/engine/systemd_hardening.py` valida programáticamente en tiempo de ejecución que el archivo de unidad cumpla al 100% con estas directivas antes de declarar operativo el servicio.
