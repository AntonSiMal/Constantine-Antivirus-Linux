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
</p>

<p align="center">
  <em>0% Telemetría. 100% Soberanía.</em>
</p>

---

## Seguridad. Redefinida.

Durante años, la seguridad en el escritorio Linux ha exigido compromisos. O sacrificas rendimiento con escaneos lentos, o sacrificas protección con herramientas reactivas. Constantine elimina esa elección.

Ofrecemos protección preventiva en tiempo real, control de periféricos y defensa anti-ransomware de nivel empresarial, con la elegancia y simplicidad que esperas de tu escritorio.

---

## Potente. Elegante. Invisible.

### 🛡️ Protección preventiva en el Kernel
Constantine no espera a que el malware se ejecute. Mediante `eBPF LSM` y `fanotify`, interceptamos y neutralizamos las amenazas en milisegundos, antes de que toquen el disco o la memoria.

### 🧠 Prevención inteligente de Ransomware
No solo detectamos firmas. Analizamos el comportamiento en tiempo real:
- **Señuelos invisibles (Canary Tripwires):** Archivos trampa estratégicamente ubicados.
- **Análisis de entropía de Shannon:** Diferencia matemáticamente entre una compresión legítima y un cifrado hostil ($H > 7.55$).
- **Aislamiento atómico:** Congelación instantánea del proceso y corte de red perimetral.

### 🔒 Privacidad por diseño
Tu privacidad es un derecho fundamental. Constantine no recoge datos, no envía telemetría y no depende de la nube. Tu código, tus reglas, tu máquina. Los registros forenses se almacenan localmente con una cadena criptográfica SHA-256 inmutable.

### ✨ Una interfaz que se siente como en casa
Un dashboard unificado en GTK4 con una estética limpia y adaptable. Desde portátiles compactos hasta monitores 4K, la operación es fluida, intuitiva y no requiere contraseñas de `sudo` para el uso diario.

---

## Tu seguridad, de un vistazo.

El dashboard de Constantine está diseñado para que un solo vistazo te diga todo lo que necesitas saber. Sin ruido, solo información accionable.


---

## Ingenieria de vanguardia.

Constantine no es un simple script. Es una arquitectura multicapa diseñada para ser *fail-secure* (segura ante fallos).

```text
                         ┌────────────────────────────────────┐
                         │  Constantine GUI (GTK4 Responsive) │
                         │  Interfaz fluida, sin fricción     │
                         └────────────────┬───────────────────┘
                                          │ IPC / D-Bus Seguro
                         ┌────────────────▼───────────────────┐
                         │    constantine-daemon (Supervisor) │
                         └───────┬────────────┬───────────────┘
                                 │            │
          ┌──────────────────────▼─┐  ┌──────▼──────────────────────┐
          │  Kernel & eBPF         │  │  Motores de Análisis        │
          │  • fanotify (ClamOnAcc)│  │  • ClamAV Multihilo         │
          │  • Tetragon LSM Hooks  │  │  • YARA / YARA-X (Rust)     │
          │  • Autoprotección      │  │  • Reglas Sigma & AIDE      │
          └────────────────────────┘  └─────────────────────────────┘
```

---

## Constantine vs. El resto.

| Característica | Soluciones Tradicionales de Linux | Suites Propietarias (Windows/macOS) | Constantine EDR |
| :--- | :--- | :--- | :--- |
| **Protección** | Reactiva (bajo demanda) | Preventiva, pero cerrada | **Preventiva, nativa y abierta** |
| **Autoprotección** | Inexistente (`root` la anula) | Controladores propietarios | **Políticas eBPF LSM inmutables** |
| **Rendimiento** | Escaneos que consumen CPU | Alto uso de RAM y telemetría | **Nativo en Rust, ligero y eficiente** |
| **Privacidad** | Variable | Envío de datos a servidores externos | **100% local. Cero telemetría.** |
| **Interfaz** | Obsoleta o inexistente | Pulida, pero limitada a su SO | **Moderna, adaptable y multiusuario** |

---

## Requisitos del sistema

- **Sistema Operativo:** Debian 12+, Ubuntu 22.04/24.04 LTS, o Linux Mint 21+.
- **Kernel:** Linux 5.8 o superior (con soporte para `fanotify` y `eBPF`).
- **Entorno:** Rust 1.70+ (para compilación) y librerías GTK4.
- **Hardware:** Funciona con fluidez desde resoluciones de 800x600 hasta 4K.

---

## Configuración en un solo paso.

Creemos que la seguridad de nivel empresarial no debería requerir un manual de instrucciones.

1. Clona el repositorio:
   ```bash
   git clone https://github.com/tonsimaltine-Antivirus-Linux
   cd tonsimaltine-Antivirus-Linux
   ```

2. Ejecuta el instalador:
   ```bash
   sudo ./install.sh
   ```

El asistente se encargará de todo de forma transparente: configurará Rust, cargará las sondas eBPF, sembrará los señuelos de protección para todos los usuarios (presentes y futuros) y verificará que los 10 módulos críticos estén operativos. Si algo falla, el sistema revierte los cambios limpiamente.

---

## Uso diario. Simplemente funciona.

Abre Constantine desde el menú de aplicaciones o ejecuta `constantine` en tu terminal. 

- **Pausar/Reanudar:** Detén los escudos temporalmente desde la interfaz con un solo clic (requiere autenticación).
- **Modo Terminal:** Para servidores o usuarios avanzados, opera sin interfaz gráfica:
  ```bash
  constantine --daemon          # Ejecutar en segundo plano
  constantine --scan-quick      # Análisis rápido de zonas críticas
  constantine --scan-full       # Análisis exhaustivo del sistema
  ```

---

## Desinstalación limpia. Sin dejar rastro.

Si decides que Constantine ya no es para ti, respetamos tu elección. Nuestro desinstalador garantiza una reversión total y absoluta del sistema operativo a su estado original.

```bash
sudo ./uninstall.sh
```
Esto elimina sondas del kernel, restaura archivos de configuración, limpia reglas de red y borra cada rastro de la aplicación, sin dejar archivos huérfanos.

---

## Reconocimientos

Constantine se construye sobre los hombros de gigantes. Agradecemos profundamente a las comunidades de código abierto que hacen esto posible:

[Cilium Tetragon](https://tetragon.io/) · [Falco](https://falco.org/) · [ClamAV](https://www.clamav.net/) · [YARA-X](https://github.com/VirusTotal/yara-x) · [Wazuh](https://wazuh.com/) · [StevenBlack Hosts](https://github.com/StevenBlack/hosts) · [GTK](https://gtk.org/)

---

> **Licencia:** Distribuido bajo la licencia GNU General Public License v3.0 (GPL-3.0).  
> **Aviso:** Constantine interactúa a bajo nivel con el kernel Linux. El software se proporciona "TAL CUAL" (*AS IS*). Al instalarlo, asumes la responsabilidad inherente a la administración avanzada del sistema.
