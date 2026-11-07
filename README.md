# 🛡️ Constantine Antivirus & EDR v3.2.7

[![Version](https://img.shields.io/badge/version-3.2.7-blue.svg)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)
[![OS](https://img.shields.io/badge/OS-Debian%20%7C%20Ubuntu%20%7C%20Mint-orange.svg)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)

**Constantine** es un sistema avanzado de Detección y Respuesta en Puntos Finales (EDR) nativo para distribuciones Linux basadas en Debian. Diseñado con una arquitectura multi-motor y un enfoque **Fail-Secure**, ofrece un escudo proactivo de 4 capas contra ransomware, combinando telemetría eBPF, análisis heurístico, inteligencia de amenazas y criptografía de grado militar.

🔗 **Repositorio Oficial**: [github.com/AntonSiMal/Constantine-Antivirus-Linux](https://github.com/AntonSiMal/Constantine-Antivirus-Linux)

---

## 🌟 Características Principales

### 1. Escudo Anti-Ransomware de 4 Capas
- **Canary Tripwires (Señuelos)**: Archivos trampa estratégicos en `Desktop`, `Documents`, `Downloads` y `Pictures`. Cualquier intento de modificación, cifrado o borrado dispara una contención instantánea.
- **Detección de Ráfagas Anómalas**: Monitoreo de frecuencia de operaciones de escritura/renombrado en ventanas de 2 segundos, combinado con detección de extensiones sospechosas (`.locked`, `.crypto`, `.enc`, etc.).
- **Análisis de Entropía de Shannon**: Detección heurística de datos sobrescritos con alta entropía ($H > 7.55$), indicativo de cifrado malicioso.
- **Neutralización Atómica**: Terminación fulminante del proceso agresor (`SIGKILL`), aislamiento de red dinámico vía UFW y cuarentena criptográfica del binario ejecutor.

### 2. Pipeline Multi-Motor Fail-Secure
- **Prevención en Acceso (Kernel)**: `ClamOnAcc` con `fanotify` para bloqueo síncrono a nivel de kernel.
- **Análisis Estático**: Motores obligatorios **ClamAV** (vía socket UNIX) y **YARA**, con soporte opcional para **YARA-X** (Rust).
- **Telemetría Comportamental**: Sensor principal **Tetragon (Cilium eBPF)** con correlación de 4 pilares (Identidad, Ejecutable, Comportamiento, Contexto) y reglas **Sigma** para Linux.
- **Integridad del Sistema**: **AIDE** (Advanced Intrusion Detection Environment) y **Wazuh Agent** (FIM/SIEM).
- **Threat Intelligence**: Sincronización local de IoCs de **MISP**, **MalwareBazaar**, **ThreatFox**, **URLhaus** y **OpenPhish**.

### 3. Criptografía y Forense Inmutable
- **Baúl de Cuarentena (AES-256-GCM)**: Aislamiento transaccional de amenazas con clave CSPRNG del kernel, nonce de 96 bits y AAD vinculado al hash SHA-256 original.
- **Registro Forense Encadenado (Hash Chaining)**: Cada evento se registra con un hash SHA-256 que incluye el hash del evento anterior, haciendo imposible la alteración o borrado selectivo de logs sin romper la cadena.

### 4. Interfaz Gráfica Nativa (GTK4 Cupertino Theme)
- Aplicación escrita en **Rust** con `gtk4`, ofreciendo una experiencia de usuario fluida, moderna y con estética inspirada en macOS, incluyendo monitoreo de salud en tiempo real de los 16 módulos.

---

## 📋 Requisitos del Sistema

- **Sistema Operativo**: Debian 12+, Ubuntu 22.04+, Linux Mint 21+
- **Privilegios**: Acceso `root` o `sudo` para la instalación y ejecución de acciones privilegiadas.
- **Dependencias de Compilación**: `build-essential`, `cargo`, `rustc`, `libgtk-4-dev`, `pkg-config` (el instalador las gestiona automáticamente).
- **Kernel**: Se recomienda un kernel con `CONFIG_FANOTIFY=y` y `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` para la prevención en acceso completa.

---

## 🚀 Instalación

El instalador automatizado gestiona dependencias, configura servicios, descarga reglas comunitarias y compila el binario de Rust de forma segura.

1. Clona el repositorio oficial:
   ```bash
   git clone https://github.com/AntonSiMal/Constantine-Antivirus-Linux.git
   cd Constantine-Antivirus-Linux
