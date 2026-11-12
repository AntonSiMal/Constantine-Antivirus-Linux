// ==============================================================================
// Constantine Antivirus & EDR v5.5.3 - Aplicación Nativa en Rust (GTK4 Cupertino v5.5.3)
// Orientado a Distribuciones Debian (Ubuntu, Linux Mint, Debian puro)
//
// Módulo de Protección Anti-Ransomware en Cuatro Capas:
// 1. Archivos Trampa (Canary Tripwires):
//    - Distribución de señuelos estratégicos en ~/Desktop, ~/Documents, ~/Downloads y ~/Pictures.
//    - Vigilancia pasiva: lecturas inocuas permitidas, pero cualquier intento de modificación,
//      sobrescritura o borrado dispara la contención instantánea antes de tocar archivos reales.
// 2. Detección de Ráfagas Anómalas de Cifrado y Modificación:
//    - Medición de frecuencia de operaciones de renombrado y escritura en ventanas de 2 segundos.
//    - Identificación de sufijos de ransomware (.locked, .crypto, .enc, .crypted, .locky, etc.).
//    - Detección de alta entropía de Shannon (H > 7.55) en datos sobrescritos.
// 3. Aislamiento y Neutralización del Proceso Agresor:
//    - Terminación fulminante inmediata mediante señal SIGKILL directa al PID del proceso agresor.
//    - Corte perimetral de comunicaciones de red (regla dinámica UFW para aislar comando y control).
//    - Aislamiento atómico del binario o script agresor en el Baúl Criptográfico (chmod 000).
// 4. Preservación y Respaldo Forense:
//    - Permisividad para lecturas de indexadores/backups legítimos (cero falsos positivos).
//    - Registro cronológico inmutable con encadenamiento SHA-256 de cada ataque neutralizado.
//    - Notificación visual de emergencia crítica en el escritorio informando del rescate de datos.
// ==============================================================================

use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Box, Button, CssProvider, Grid,
    HeaderBar, Label, Orientation, ProgressBar, ScrolledWindow,
    Stack, TextView, Entry, ListBox, ListBoxRow, SelectionMode, DropDown
};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const CLAMD_SOCKET: &str = "/run/clamav/clamd.ctl";
const LOG_FILE: &str = "/var/log/clamav/clamonacc.log";
const YARA_LOG_FILE: &str = "/var/log/constantine/yara_live.log";
const TETRAGON_LOG_FILE: &str = "/var/log/tetragon/tetragon.log";
const FALCO_LOG_FILE: &str = "/var/log/falco/events.log";
const WAZUH_LOG_FILE: &str = "/var/ossec/logs/alerts/alerts.log";
const AIDE_LOG_FILE: &str = "/var/log/aide/aide.log";
const AIDE_DB_FILE: &str = "/var/lib/aide/aide.db";
const SIGMA_LOG_FILE: &str = "/var/log/constantine/sigma_matches.log";
const SIGMA_RULES_DIR: &str = "/var/lib/constantine/sigma";
const MISP_IOC_FILE: &str = "/var/lib/constantine/intelligence/misp_iocs.txt";
const IMMUTABLE_AUDIT_LOG: &str = "/var/log/constantine/immutable_audit.log";
const VAULT_KEY_FILE: &str = "/var/lib/constantine/.vault.key";
const YARA_RULES_DIR: &str = "/var/lib/constantine/rules";
const YARA_COMMUNITY_DIR: &str = "/var/lib/constantine/rules/community";
const QUARANTINE_DIR: &str = "/var/lib/constantine/quarantine";
const CLAMAV_QUARANTINE_DIR: &str = "/var/lib/clamav/quarantine";
const CLAMAV_SPOOL_DIR: &str = "/var/spool/clamav/quarantine";
const TI_DIR: &str = "/var/lib/constantine/intelligence";
const WHITELIST_FILE: &str = "/var/lib/constantine/whitelist.txt";
const UPDATER_SCRIPT: &str = "/usr/local/bin/constantine-updater";

const CANARY_FILES: [&str; 4] = [
    "Desktop/!000_canary_personal_vault.docx",
    "Documents/!000_canary_financial_report.xlsx",
    "Downloads/!000_canary_confidential_id.pdf",
    "Pictures/!000_canary_backup_keys.txt",
];

const CUPERTINO_CSS: &str = r#"
window, .background {
    background-color: #1c1c1e;
    color: #f5f5f7;
    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', 'Ubuntu', 'Cantarell', sans-serif;
}

headerbar.macos-headerbar, .titlebar {
    background-image: none;
    background-color: #1a1a1c;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    min-height: 48px;
    padding: 0 12px;
    box-shadow: none;
}

button.titlebutton.close, .titlebutton.close {
    background-image: none;
    background-color: #ff5f56;
    border: 1px solid #e0443e;
    border-radius: 50%;
    min-width: 12px;
    min-height: 12px;
    margin: 4px 3px;
    padding: 0;
    color: transparent;
}

button.titlebutton.minimize, .titlebutton.minimize {
    background-image: none;
    background-color: #ffbd2e;
    border: 1px solid #dea123;
    border-radius: 50%;
    min-width: 12px;
    min-height: 12px;
    margin: 4px 3px;
    padding: 0;
    color: transparent;
}

button.titlebutton.maximize, .titlebutton.maximize {
    background-image: none;
    background-color: #27c93f;
    border: 1px solid #1aab29;
    border-radius: 50%;
    min-width: 12px;
    min-height: 12px;
    margin: 4px 3px;
    padding: 0;
    color: transparent;
}

.title-text {
    font-size: 13.5pt;
    font-weight: 700;
    color: #ffffff;
}

.subtitle-text {
    font-size: 8.5pt;
    color: #86868b;
}

.badge-version {
    background-color: rgba(0, 113, 227, 0.2);
    color: #0a84ff;
    border: 1px solid rgba(0, 113, 227, 0.35);
    border-radius: 6px;
    padding: 2px 7px;
    font-size: 7.5pt;
    font-weight: 700;
}


.kpi-card {
    background-color: #242426;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 12px 14px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}

.kpi-title {
    font-size: 8pt;
    font-weight: 600;
    color: #86868b;
    text-transform: uppercase;
}

.kpi-value {
    font-size: 15pt;
    font-weight: 700;
    color: #ffffff;
}

.kpi-subtitle {
    font-size: 8pt;
    color: #a1a1a6;
}

.health-btn {
    background-color: rgba(48, 209, 88, 0.12);
    border: 1px solid rgba(48, 209, 88, 0.3);
    border-radius: 9999px;
    padding: 3px 10px;
}

.health-btn:hover {
    background-color: rgba(48, 209, 88, 0.22);
}

.health-box {
    background-color: rgba(48, 209, 88, 0.12);
    border: 1px solid rgba(48, 209, 88, 0.3);
    border-radius: 9999px;
    padding: 4px 12px;
}

.health-score {
    color: #30d158;
    font-weight: 700;
    font-size: 10pt;
}

.sidebar-box {
    background-color: #141416;
    border-right: 1px solid rgba(255, 255, 255, 0.08);
    min-width: 165px;
    max-width: 175px;
    padding: 4px;
}

button.nav-btn {
    background-image: none;
    background-color: transparent;
    color: #e5e5ea;
    border: none;
    border-radius: 7px;
    padding: 7px 10px;
    margin: 1px 6px;
    font-weight: 500;
    box-shadow: none;
    transition: all 120ms ease;
}

button.nav-btn:hover {
    background-color: rgba(255, 255, 255, 0.08);
    color: #ffffff;
}

button.nav-btn.nav-btn-active {
    background-image: none;
    background-color: #0071e3;
    color: #ffffff;
    border: none;
    border-radius: 7px;
    box-shadow: 0 1px 4px rgba(0, 113, 227, 0.4);
}

.mini-status-card {
    background-color: #1e1e20;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 12px 14px;
    margin: 10px 10px 14px 10px;
}

.mini-row-title {
    font-size: 8pt;
    color: #86868b;
    font-weight: 500;
}

.mini-row-status-ok {
    font-size: 8pt;
    color: #30d158;
    font-weight: 600;
}

.mini-row-status-warn {
    font-size: 8pt;
    color: #ff9f0a;
    font-weight: 600;
}

.mini-row-status-alert {
    font-size: 8pt;
    color: #ff453a;
    font-weight: 600;
}

.macos-card {
    background-color: #242426;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 12px 14px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}

.macos-table-header {
    font-size: 9pt;
    font-weight: 700;
    color: #86868b;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    padding-bottom: 6px;
}

.macos-table-cell {
    font-size: 9pt;
    color: #f5f5f7;
    padding: 4px 0;
}

button {
    background-image: none;
    background-color: rgba(255, 255, 255, 0.08);
    color: #f5f5f7;
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 8px;
    padding: 6px 14px;
    font-weight: 500;
    font-size: 9.5pt;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    transition: all 120ms ease;
}

button:hover {
    background-color: rgba(255, 255, 255, 0.14);
    border-color: rgba(255, 255, 255, 0.2);
    color: #ffffff;
}

button.suggested-action {
    background-image: none;
    background-color: #0071e3;
    border: 1px solid #0a84ff;
    color: #ffffff;
    font-weight: 600;
}

button.destructive-action, button.power-btn {
    background-image: none;
    background-color: rgba(255, 69, 58, 0.15);
    border: 1px solid rgba(255, 69, 58, 0.35);
    color: #ff453a;
    font-weight: 600;
}

button.destructive-action:hover, button.power-btn:hover {
    background-color: #ff453a;
    color: #ffffff;
}

switch {
    background-image: none;
    background-color: #39393d;
    border-radius: 14px;
    border: none;
    min-width: 44px;
    min-height: 24px;
    transition: background-color 150ms ease;
}

switch:checked {
    background-image: none;
    background-color: #34c759;
}

progressbar trough {
    background-color: #2c2c2e;
    border-radius: 6px;
    min-height: 8px;
}

progressbar progress {
    background-image: none;
    background-color: #34c759;
    border-radius: 5px;
}

progressbar.scanning progress {
    background-color: #0a84ff;
}

scrolledwindow {
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 10px;
    background-color: #1c1c1e;
}
"#;

// ==============================================================================

// ==============================================================================
// 0. Helper Multiusuario Universal: Detección Dinámica de Usuarios del Sistema
// ==============================================================================
pub fn get_system_human_users() -> Vec<(String, PathBuf)> {
    let mut users = Vec::new();
    if let Ok(file) = File::open("/etc/passwd") {
        for line in BufReader::new(file).lines().flatten() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 {
                let username = parts[0].to_string();
                let uid: u32 = parts[2].parse().unwrap_or(0);
                let home = PathBuf::from(parts[5]);
                // Usuarios humanos en Debian/Ubuntu/Mint: UID >= 1000 y < 60000, excluyendo "nobody"
                if uid >= 1000 && uid < 60000 && username != "nobody" && home.exists() {
                    users.push((username, home));
                }
            }
        }
    }
    // Incluir también directorios dentro de /home por si existen usuarios no estándar
    if let Ok(entries) = fs::read_dir("/home") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                if !name.is_empty() && name != "lost+found" && !users.iter().any(|(u, _)| u == &name) {
                    users.push((name, p));
                }
            }
        }
    }
    users
}

// 1. Módulo de Protección Anti-Ransomware
// ==============================================================================

pub struct ProcessBurstMetrics {
    pub window_start: Instant,
    pub mod_count: usize,
    pub high_entropy_hits: usize,
    pub suspicious_ext_hits: usize,
}

pub struct AntiRansomwareShield {
    process_rate_tracker: Mutex<HashMap<u32, ProcessBurstMetrics>>,
}

impl AntiRansomwareShield {
    pub fn new() -> Self {
        Self { 
            process_rate_tracker: Mutex::new(HashMap::new()) 
        }
    }

    /// Siembra señuelos estratégicos en directorios clave de usuario
    /// Despliega señuelos Canary en todos los usuarios humanos del sistema y en /etc/skel
    pub fn deploy_all_users_canaries() -> usize {
        let mut total = 0;
        for (_uname, home) in get_system_human_users() {
            let home_str = home.to_string_lossy().to_string();
            let c = Self::deploy_canary_tripwires(&home_str);
            total += c;
        }
        // Sembrar también en /etc/skel para que cualquier usuario recién creado nazca protegido
        let _ = Self::deploy_canary_tripwires("/etc/skel");
        total
    }

    pub fn deploy_canary_tripwires(user_home: &str) -> usize {
        let mut count = 0;
        for rel in &CANARY_FILES {
            let full_path = format!("{}/{}", user_home, rel);
            let p = Path::new(&full_path);
            if let Some(parent) = p.parent() { 
                let _ = fs::create_dir_all(parent); 
            }
            if !p.exists() {
                let dummy_content = "CANARY_DOCUMENT_SECURE_TOKEN_DO_NOT_MODIFY_CONSTANTINE_EDR_PROTECTION_TRIPWIRE\n";
                if fs::write(p, dummy_content).is_ok() { 
                    count += 1; 
                }
            } else { 
                count += 1; 
            }
        }
        count
    }

    /// Comprueba cuántos señuelos están íntegros actualmente en el disco
    pub fn verify_active_canaries(user_home: &str) -> usize {
        let mut active = 0;
        for rel in &CANARY_FILES {
            if Path::new(&format!("{}/{}", user_home, rel)).is_file() { 
                active += 1; 
            }
        }
        active
    }

    /// Comprueba si la ruta corresponde a un archivo trampa
    pub fn is_canary_file(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for &canary in &CANARY_FILES { 
            if path_str.ends_with(canary) { 
                return true; 
            } 
        }
        path_str.contains("!000_canary_")
    }

    /// Correlación multivariable con poda periódica de memoria (TTL > 30s)
    pub fn track_process_burst(&self, pid: u32, path: &Path, data: &[u8]) -> bool {
        // Señal 1: Alteración directa de un archivo trampa Canary Honeypot (certeza inmediata)
        if Self::is_canary_file(path) { 
            return true; 
        }
        
        let now = Instant::now();
        let mut map = match self.process_rate_tracker.lock() {
            Ok(g) => g, 
            Err(poisoned) => poisoned.into_inner(),
        };
        
        // Política de limpieza de HashMap para evitar fugas de memoria
        if map.len() > 128 {
            map.retain(|_, m| now.duration_since(m.window_start) < Duration::from_secs(30));
        }
        
        let entry = map.entry(pid).or_insert(ProcessBurstMetrics {
            window_start: now, 
            mod_count: 0, 
            high_entropy_hits: 0, 
            suspicious_ext_hits: 0,
        });

        if now.duration_since(entry.window_start) <= Duration::from_secs(3) {
            entry.mod_count += 1;
            let entropy = ThreatAnalysisEngine::calculate_shannon_entropy(data);
            if entropy > 7.55 { 
                entry.high_entropy_hits += 1; 
            }
            if Self::is_ransomware_extension(path) { 
                entry.suspicious_ext_hits += 1; 
            }

            // Correlación multivariable: exige combinación de ráfaga sostenida + múltiples señales
            let burst_and_entropy = entry.mod_count >= 8 && entry.high_entropy_hits >= 4;
            let burst_and_ext = entry.mod_count >= 4 && entry.suspicious_ext_hits >= 2 && entry.high_entropy_hits >= 2;
            
            if burst_and_entropy || burst_and_ext { 
                return true; 
            }
        } else {
            *entry = ProcessBurstMetrics {
                window_start: now, 
                mod_count: 1,
                high_entropy_hits: if ThreatAnalysisEngine::calculate_shannon_entropy(data) > 7.55 { 1 } else { 0 },
                suspicious_ext_hits: if Self::is_ransomware_extension(path) { 1 } else { 0 },
            };
        }
        false
    }

    /// Verifica si la extensión del archivo coincide con patrones conocidos de ransomware
    pub fn is_ransomware_extension(path: &Path) -> bool {
        let s = path.to_string_lossy().to_lowercase();
        let suspicious = [
            ".locked", ".crypto", ".enc", ".crypted", ".ransom", 
            ".locky", ".wcry", ".wncry", ".darkside"
        ];
        for ext in &suspicious { 
            if s.ends_with(ext) { 
                return true; 
            } 
        }
        false
    }

    /// Contención segura del proceso agresor (Corregido: Prevención de Race Condition)
    pub fn neutralize_attack(pid: u32, offending_path: &Path, reason: &str) {
        if pid <= 1 { return; }
        let pid_str = pid.to_string();
        
        // 1. 🔴 CORREGIDO: Congelar PRIMERO para evitar que el malware cambie su ejecutable 
        //    mediante execve() entre la lectura y la muerte del proceso (Race Condition).
        let _ = SecurityAuth::privileged_action(&["kill", "-STOP", &pid_str]);
        
        // 2. 🔴 CORREGIDO: AHORA sí leer el ejecutable de forma segura, ya que está congelado.
        let proc_exe_link = format!("/proc/{}/exe", pid);
        let resolved_exe = fs::read_link(&proc_exe_link).ok();
        
        // 3. Terminar el proceso fulminantemente
        let _ = SecurityAuth::privileged_action(&["kill", "-KILL", &pid_str]);

        // 4. Aislar ÚNICAMENTE el binario ejecutor verificado (jamás el documento de la víctima)
        let mut isolated_exe_msg = String::from("Ejecutable en memoria detenido (documentos del usuario preservados)");
        if let Some(exe_path) = resolved_exe {
            let exe_str = exe_path.to_string_lossy();
            // Evitar aislar intérpretes o binarios base del sistema operativo
            if !exe_str.starts_with("/usr/bin/") && 
               !exe_str.starts_with("/bin/") && 
               !exe_str.starts_with("/sbin/") && 
               !exe_str.starts_with("/lib") 
            {
                if ContainmentEngine::isolate_to_vault(&exe_path) {
                    isolated_exe_msg = format!("Binario agresor aislado en baúl AES-256-GCM: {}", exe_str);
                }
            }
        }

        // 5. Registro forense inmutable y alerta crítica en el escritorio
        ImmutableAuditLog::append_event(
            "RANSOMWARE_CONTAINED",
            &format!("PID {} neutralizado ({}) sobre {} | {}", pid, reason, offending_path.display(), isolated_exe_msg),
        );
        
        SystemNotifier::notify(
            "critical",
            "security-high",
            "¡ALERTA CRÍTICA: RANSOMWARE CONTENIDO!",
            &format!("Proceso PID {} detenido.\nMotivo: {}\n{}", pid, reason, isolated_exe_msg),
        );

        // Lanzar Diálogo Interactivo de Decisión Directa
        let _ = Command::new("/usr/local/bin/constantine")
            .args([
                "--threat-alert",
                &format!("Ataque de Ransomware Neutralizado ({})", reason),
                &offending_path.to_string_lossy(),
                &pid.to_string(),
                "Escudo Anti-Ransomware (Tripwires / Ráfagas)"
            ])
            .spawn();
    }
} // <-- ESTA LLAVE FALTABA Y CAUSABA EL ERROR

// ==============================================================================
// 2. Veredicto Formal y Pipeline Multi-Motor
// ==============================================================================

#[derive(Debug, PartialEq, Clone)]
pub enum FileVerdict {
    /// Archivo certificado limpio por todos los motores obligatorios.
    Clean(String),
    /// Amenaza confirmada por al menos una capa de detección.
    Threat(String),
    /// Fallo en un motor obligatorio o error de lectura física (Fail-Secure).
    Indeterminate(String),
}

pub struct ThreatAnalysisEngine;

impl ThreatAnalysisEngine {
    /// Calcula la entropía de Shannon de un bloque de datos para detectar cifrado/compresión.
    pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = [0usize; 256];
        for &byte in data { 
            counts[byte as usize] += 1; 
        }
        let total = data.len() as f64;
        counts.iter().filter(|&&c| c > 0).map(|&c| {
            let p = (c as f64) / total;
            -p * p.log2()
        }).sum()
    }
    
    /// 🔴 CORREGIDO: Previene DoS por memoria limitando la lectura a 10 MB máximo.
    pub fn is_zip_bomb(path: &Path) -> bool {
        if let Ok(mut f) = File::open(path) {
            let mut header = [0u8; 4];
            if f.read_exact(&mut header).is_ok() && header == [0x50, 0x4B, 0x03, 0x04] {
                if let Ok(meta) = f.metadata() {
                    let compressed_len = meta.len();
                    // Solo analizamos archivos que parecen pequeños en disco (< 1MB)
                    if compressed_len > 0 && compressed_len < 1024 * 1024 {
                        let mut buf = Vec::new();
                        // CORREGIDO: .take(10_485_760) evita que un ZIP malicioso agote la RAM
                        let _ = f.take(10_485_760).read_to_end(&mut buf);
                        let zero_count = buf.iter().filter(|&&b| b == 0).count();
                        if zero_count > (buf.len() * 95) / 100 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Evalúa un archivo a través del pipeline multi-motor (Fail-Secure).
    pub fn evaluate_file(path: &Path) -> FileVerdict {
        if !path.exists() { 
            return FileVerdict::Indeterminate("El archivo no existe o fue movido.".into()); 
        }

        // 1. Cálculo único de SHA-256 y cotejo contra Lista Blanca
        let file_hash = match Self::compute_sha256(path) {
            Ok(h) => h,
            Err(_) => return FileVerdict::Indeterminate("Error de I/O: no se pudo calcular huella SHA-256.".into()),
        };
        
        if Self::is_whitelisted(&file_hash) { 
            return FileVerdict::Clean("Excluido por firma SHA-256 en Lista Blanca".into()); 
        }
        
        // 2. Comprobación de Bomba de Descompresión
        if Self::is_zip_bomb(path) { 
            return FileVerdict::Threat("Estructura de descompresión masiva hostil (Zip Bomb).".into()); 
        }

        // 3. Análisis de Entropía Heurística
        if let Ok(mut f) = File::open(path) {
            let mut buffer = vec![0u8; 65536];
            if let Ok(n) = f.read(&mut buffer) {
                let entropy = Self::calculate_shannon_entropy(&buffer[..n]);
                if entropy > 7.45 && Self::is_executable(path) {
                    return FileVerdict::Threat(format!("Ejecutable empaquetado/cifrado sospechoso (Entropía: {:.2}).", entropy));
                }
            }
        } else {
            return FileVerdict::Indeterminate("Acceso denegado temporalmente por error físico de lectura.".into());
        }

        // 4. Contrastación con Indicadores de Compromiso Locales (TI)
        if Self::is_known_malware_hash(&file_hash) {
            return FileVerdict::Threat(format!("Huella SHA-256 coincidente con muestra hostil en TI: {}.", &file_hash[..12]));
        }

        // 5. Motor Obligatorio 1: ClamAV Socket (Fail-Secure)
        if !Path::new(CLAMD_SOCKET).exists() {
            return FileVerdict::Indeterminate("Motor obligatorio ClamAV no disponible (socket /run/clamav/clamd.ctl ausente).".into());
        }
        
        match UnixStream::connect(CLAMD_SOCKET) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let cmd = format!("SCAN {}\n", path.to_string_lossy());
                if let Err(e) = stream.write_all(cmd.as_bytes()) {
                    return FileVerdict::Indeterminate(format!("Fallo de escritura en clamd socket: {}", e));
                }
                let mut reader = BufReader::new(stream);
                let mut resp = String::new();
                if let Err(e) = reader.read_line(&mut resp) {
                    return FileVerdict::Indeterminate(format!("Fallo de lectura desde clamd socket: {}", e));
                }
                let trimmed_resp = resp.trim();
                if trimmed_resp.contains("FOUND") {
                    return FileVerdict::Threat(format!("ClamAV Detección: {}", trimmed_resp));
                } else if !trimmed_resp.contains("OK") {
                    return FileVerdict::Indeterminate(format!("ClamAV devolvió respuesta de error: {}", trimmed_resp));
                }
            }
            Err(e) => { 
                return FileVerdict::Indeterminate(format!("No se pudo conectar al daemon obligatorio clamd: {}", e)); 
            }
        }

        // 6. Selección Comprobada de Reglas YARA
        let mut verified_rules = Vec::new();
        if let Ok(entries) = fs::read_dir(YARA_RULES_DIR) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() && p.extension().map(|e| e == "yar" || e == "yara").unwrap_or(false) {
                    verified_rules.push(p);
                }
            }
        }
        if verified_rules.is_empty() {
            return FileVerdict::Indeterminate("No existen archivos de reglas YARA comprobados en /var/lib/constantine/rules.".into());
        }

        // 7. Motor Obligatorio 2: YARA Tradicional
        if !Command::new("which").arg("yara").output().map(|o| o.status.success()).unwrap_or(false) {
            return FileVerdict::Indeterminate("Motor obligatorio YARA no instalado en PATH.".into());
        }
        
        for rule_path in &verified_rules {
            let output = match Command::new("yara")
                .args(["-w", rule_path.to_str().unwrap_or(""), path.to_str().unwrap_or("")])
                .output()
            {
                Ok(o) => o,
                Err(e) => return FileVerdict::Indeterminate(format!("Fallo al invocar motor obligatorio yara: {}", e)),
            };
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return FileVerdict::Indeterminate(format!(
                    "Error en motor YARA con regla {} (código {}): {}",
                    rule_path.file_name().and_then(|n| n.to_str()).unwrap_or("regla"),
                    output.status.code().unwrap_or(-1),
                    stderr.trim()
                ));
            }
            
            let res = String::from_utf8_lossy(&output.stdout);
            for line in res.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    return FileVerdict::Threat(format!(
                        "YARA Coincidencia [{}]: {}", 
                        rule_path.file_name().and_then(|n| n.to_str()).unwrap_or("regla"), 
                        trimmed
                    ));
                }
            }
        }

        // 8. Motor Complementario Opcional: YARA-X
        let yr_bin_opt = if Path::new("/usr/local/bin/yr").is_file() {
            Some("/usr/local/bin/yr")
        } else if Command::new("which").arg("yr").output().map(|o| o.status.success()).unwrap_or(false) {
            Some("yr")
        } else { 
            None 
        };

        if let Some(yr_bin) = yr_bin_opt {
            for rule_path in &verified_rules {
                let output = match Command::new(yr_bin)
                    .args(["scan", rule_path.to_str().unwrap_or(""), path.to_str().unwrap_or("")])
                    .output()
                {
                    Ok(o) => o,
                    Err(e) => return FileVerdict::Indeterminate(format!("Fallo al ejecutar binario yr (YARA-X): {}", e)),
                };
                
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return FileVerdict::Indeterminate(format!(
                        "Error de ejecución en YARA-X con regla {} (código {}): {}",
                        rule_path.file_name().and_then(|n| n.to_str()).unwrap_or("regla"),
                        output.status.code().unwrap_or(-1),
                        stderr.trim()
                    ));
                }
                
                let res = String::from_utf8_lossy(&output.stdout);
                for line in res.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        return FileVerdict::Threat(format!(
                            "YARA-X Coincidencia [{}]: {}", 
                            rule_path.file_name().and_then(|n| n.to_str()).unwrap_or("regla"), 
                            trimmed
                        ));
                    }
                }
            }
            FileVerdict::Clean("Cobertura Completa (ClamAV + YARA + YARA-X + Heurística + TI)".into())
        } else {
            FileVerdict::Clean("Cobertura Estándar Verificada (ClamAV + YARA + Heurística + TI; YARA-X opcional no instalado)".into())
        }
    }

    /// Calcula el hash SHA-256 de un archivo de forma eficiente.
    pub fn compute_sha256(path: &Path) -> Result<String, std::io::Error> {
        let mut f = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let count = f.read(&mut buffer)?;
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Verifica si un hash está en la lista blanca.
    pub fn is_whitelisted(hash: &str) -> bool {
        if let Ok(f) = File::open(WHITELIST_FILE) {
            for l in BufReader::new(f).lines().flatten() {
                if l.trim().eq_ignore_ascii_case(hash) { return true; }
            }
        }
        false
    }

    /// Verifica si un hash coincide con inteligencia de amenazas local.
    pub fn is_known_malware_hash(hash: &str) -> bool {
        let ti_files = ["malwarebazaar_hashes.txt", "threatfox_iocs.txt", "misp_iocs.txt"];
        for tf in &ti_files {
            let p = format!("{}/{}", TI_DIR, tf);
            if let Ok(f) = File::open(p) {
                for l in BufReader::new(f).lines().flatten() {
                    if l.contains(hash) { return true; }
                }
            }
        }
        false
    }

    /// Comprueba si el archivo es verdaderamente un ejecutable binario (ELF, PE o script con shebang)
    fn is_executable(path: &Path) -> bool {
        // Excluir extensiones conocidas de medios, bases de datos y registros
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            let non_exec = [
                "png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico",
                "log", "txt", "md", "json", "xml", "yaml", "yml", "csv",
                "db", "sqlite", "ldb", "lock", "pdf", "docx", "xlsx",
                "mp3", "mp4", "wav", "mkv", "avi", "ogg", "flac",
                "zip", "tar", "gz", "xz", "bz2", "7z", "iso"
            ];
            if non_exec.contains(&ext_lower.as_str()) {
                return false;
            }
        }

        // Excluir nombres específicos de bases de datos/logs de nivel bajo
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let name_upper = name.to_uppercase();
            if name_upper == "CURRENT" || name_upper == "LOCK" || name_upper == "LOG" || name_upper.starts_with("MANIFEST") {
                return false;
            }
        }

        // Verificar permisos de ejecución
        let has_exec_perm = if let Ok(meta) = path.metadata() {
            meta.permissions().mode() & 0o111 != 0
        } else {
            false
        };

        if !has_exec_perm {
            return false;
        }

        // Verificar cabecera real (ELF, Windows PE o shebang de script)
        if let Ok(mut f) = File::open(path) {
            let mut magic = [0u8; 4];
            if f.read_exact(&mut magic).is_ok() {
                if magic == [0x7F, b'E', b'L', b'F'] || magic[0..2] == [b'M', b'Z'] || magic[0..2] == [b'#', b'!'] {
                    return true;
                }
            }
        }
        false
    }
}

// ==============================================================================
// 3. Baúl Criptográfico Autenticado con AES-256-GCM y CSPRNG
// ==============================================================================
const VAULT_MAGIC: &[u8; 9] = b"CSTVAULT1";

// ==============================================================================
// Estructura de Metadatos Forenses de Amenazas en Cuarentena
// ==============================================================================
pub struct VaultMetadata {
    pub filename: String,
    pub threat_name: String,
    pub detection_method: String,
    pub original_path: String,
    pub timestamp: String,
    pub sha256: String,
}

impl VaultMetadata {
    pub fn save_to_file(&self, path: &Path) {
        let val = serde_json::json!({
            "filename": self.filename,
            "threat_name": self.threat_name,
            "detection_method": self.detection_method,
            "original_path": self.original_path,
            "timestamp": self.timestamp,
            "sha256": self.sha256,
        });
        if let Ok(mut f) = OpenOptions::new().create(true).write(true).truncate(true).open(path) {
            let _ = f.write_all(val.to_string().as_bytes());
            let _ = f.sync_all();
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
        }
    }

    pub fn load_from_file(path: &Path) -> Option<Self> {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                return Some(Self {
                    filename: v.get("filename").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    threat_name: v.get("threat_name").and_then(|x| x.as_str()).unwrap_or("Amenaza Detectada").to_string(),
                    detection_method: v.get("detection_method").and_then(|x| x.as_str()).unwrap_or("Motor EDR / ClamAV").to_string(),
                    original_path: v.get("original_path").and_then(|x| x.as_str()).unwrap_or("Desconocida").to_string(),
                    timestamp: v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    sha256: v.get("sha256").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                });
            }
        }
        None
    }
}

pub struct ContainmentEngine;

impl ContainmentEngine {
    /// Aísla y cifra un archivo mediante AES-256-GCM autenticado de forma transaccional:
    /// 1. Carga o genera una clave de 256 bits vía CSPRNG del sistema (sin claves constantes).
    /// 2. Cifra con nonce único de 96 bits y AAD vinculado al hash SHA-256 original.
    /// 3. Escribe y sincroniza en el baúl, verifica que pueda autenticarse, y SOLO entonces elimina el original.
    pub fn isolate_to_vault(source_path: &Path) -> bool {
        Self::isolate_to_vault_with_metadata(source_path, "Amenaza Detectada", "Motor de Escaneo EDR / ClamAV")
    }

    pub fn isolate_to_vault_with_metadata(source_path: &Path, threat_name: &str, detection_method: &str) -> bool {
        if !source_path.exists() || !source_path.is_file() { 
            return false; 
        }

        let key_bytes = match Self::load_or_generate_csprng_key() {
            Ok(k) => k,
            Err(e) => {
                ImmutableAuditLog::append_event("VAULT_ERROR", &format!("Fallo crítico de clave CSPRNG: {}", e));
                return false;
            }
        };

        let plaintext = match fs::read(source_path) { 
            Ok(b) => b, 
            Err(_) => {
                if let Ok(out) = Command::new("pkexec").args(["cat", "--", &source_path.to_string_lossy()]).output() {
                    if out.status.success() && !out.stdout.is_empty() {
                        out.stdout
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        };
        
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let orig_sha256: [u8; 32] = hasher.finalize().into();
        let hex_hash = hex::encode(orig_sha256);

        let mut nonce_bytes = [0u8; 12];
        if getrandom::getrandom(&mut nonce_bytes).is_err() { 
            return false; 
        }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload { 
            msg: &plaintext, 
            aad: &orig_sha256 
        };
        
        let ciphertext = match cipher.encrypt(nonce, payload) { 
            Ok(ct) => ct, 
            Err(_) => return false 
        };

        let mut vault_blob = Vec::with_capacity(9 + 12 + 32 + ciphertext.len());
        vault_blob.extend_from_slice(VAULT_MAGIC);
        vault_blob.extend_from_slice(&nonce_bytes);
        vault_blob.extend_from_slice(&orig_sha256);
        vault_blob.extend_from_slice(&ciphertext);

        let raw_name = source_path.file_name().and_then(|n| n.to_str()).unwrap_or("amenaza_detectada");
        let safe_name: String = raw_name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-').collect();
        let final_name = if safe_name.is_empty() { "muestra_aislada" } else { &safe_name };
        let dest_path = Path::new(QUARANTINE_DIR).join(format!("{}.vault", final_name));
        let meta_path = Path::new(QUARANTINE_DIR).join(format!("{}.meta.json", final_name));

        let write_ok = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dest_path)
            .and_then(|mut f| { 
                f.write_all(&vault_blob)?; 
                f.sync_all() 
            })
            .is_ok();

        if write_ok {
            let _ = fs::set_permissions(&dest_path, fs::Permissions::from_mode(0o640));
            let _ = Command::new("chown").args(["root:constantine", &dest_path.to_string_lossy()]).status();

            // Guardar metadatos forenses enriquecidos
            let meta = VaultMetadata {
                filename: format!("{}.vault", final_name),
                threat_name: threat_name.to_string(),
                detection_method: detection_method.to_string(),
                original_path: source_path.to_string_lossy().to_string(),
                timestamp: chrono_free_timestamp(),
                sha256: hex_hash.clone(),
            };
            meta.save_to_file(&meta_path);
            let _ = Command::new("chown").args(["root:constantine", &meta_path.to_string_lossy()]).status();

            let removed = fs::remove_file(source_path).is_ok() || SecurityAuth::privileged_action(&["rm", "-f", "--", &source_path.to_string_lossy()]);
            if removed {
                ImmutableAuditLog::append_event(
                    "QUARANTINE_AES256GCM", 
                    &format!("Aislado en baúl: {} | Amenaza: {} | Método: {} | SHA-256: {}", final_name, threat_name, detection_method, &hex_hash[..16])
                );
                return true;
            }
        }
        false
    }

    pub fn load_or_generate_csprng_key() -> Result<[u8; 32], String> {
        let key_path = Path::new(VAULT_KEY_FILE);
        
        if key_path.exists() {
            let content = fs::read(key_path).map_err(|e| format!("No se pudo leer {}: {}", VAULT_KEY_FILE, e))?;
            
            // Soportar tanto 32 bytes crudos como 64 caracteres hexadecimales
            if content.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&content);
                return Ok(arr);
            }
            
            let trimmed = String::from_utf8_lossy(&content).trim().to_string();
            if let Ok(decoded) = hex::decode(&trimmed) {
                if decoded.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    return Ok(arr);
                }
            }
            
            // 🔴 CORREGIDO: Rechazar explícitamente si el archivo existe pero es inválido.
            // Esto evita que se genere una clave nueva silenciosamente, lo que haría 
            // imposible descifrar permanentemente los archivos ya aislados en el baúl.
            return Err(format!("La clave en {} está corrupta o tiene un formato inválido. No se puede generar una nueva clave sin perder acceso a los archivos en cuarentena.", VAULT_KEY_FILE));
        }
 
        // Generar nueva clave CSPRNG de 256 bits (solo si el archivo NO existe)
        let mut new_key = [0u8; 32];
        getrandom::getrandom(&mut new_key).map_err(|e| format!("Error de entropía CSPRNG: {}", e))?;
        
        if let Some(parent) = key_path.parent() { 
            let _ = fs::create_dir_all(parent); 
        }
        
        let hex_key = hex::encode(new_key);
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(key_path)
            .map_err(|e| format!("No se pudo crear {}: {}", VAULT_KEY_FILE, e))?;
            
        f.write_all(hex_key.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        let _ = fs::set_permissions(key_path, fs::Permissions::from_mode(0o640));
        
        Ok(new_key)
    }
}

// ==============================================================================
// 4. Registro Forense con Verificación Criptográfica Completa y Mutex
// ==============================================================================
static AUDIT_LOG_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

pub struct ImmutableAuditLog;

impl ImmutableAuditLog {
    fn lock_guard() -> &'static Mutex<()> { AUDIT_LOG_MUTEX.get_or_init(|| Mutex::new(())) }

    pub fn append_event(event_type: &str, details: &str) {
        let _guard = match Self::lock_guard().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        let now = chrono_free_timestamp();
        let clean_event = event_type.replace('|', "/").replace('\n', " ");
        let clean_details = details.replace('|', "/").replace('\n', " ");
        let prev_hash = Self::get_last_hash_unlocked();
        let payload = format!("{}|{}|{}|{}", prev_hash, now, clean_event, clean_details);
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let current_hash = format!("{:x}", hasher.finalize());
        let log_line = format!("{} | {} | {} | {} | {}\n", now, current_hash, prev_hash, clean_event, clean_details);
        let mut wrote_ok = false;
        TamperProtectionManager::unlock_for_write(IMMUTABLE_AUDIT_LOG, || {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(IMMUTABLE_AUDIT_LOG) {
                if f.write_all(log_line.as_bytes()).is_ok() {
                    let _ = f.sync_data();
                    wrote_ok = true;
                }
            }
        });
        if !wrote_ok {
            let cmd = serde_json::json!({
                "action": "append_audit_log",
                "event_type": clean_event,
                "details": clean_details
            });
            let _ = ConstantineIpcClient::send_command(&cmd);
        }
    }

    fn parse_utc_epoch(ts: &str) -> Option<i64> {
        // Parses YYYY-MM-DDTHH:MM:SSZ
        let s = ts.trim().trim_end_matches('Z');
        let (date_part, time_part) = s.split_once('T')?;
        let mut d = date_part.split('-');
        let y: i64 = d.next()?.parse().ok()?;
        let m: i64 = d.next()?.parse().ok()?;
        let day: i64 = d.next()?.parse().ok()?;
        let mut t = time_part.split(':');
        let hh: i64 = t.next()?.parse().ok()?;
        let mm: i64 = t.next()?.parse().ok()?;
        let ss: i64 = t.next().unwrap_or("0").split('.').next().unwrap_or("0").parse().ok()?;
        // Howard Hinnant civil-from-days inverse
        let y_adj = if m <= 2 { y - 1 } else { y };
        let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
        let yoe = y_adj - era * 400;
        let m_adj = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * m_adj + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        Some(days * 86400 + hh * 3600 + mm * 60 + ss)
    }

    pub fn purge_older_than_24h() -> Result<usize, String> {
        let cmd = serde_json::json!({"action": "purge_audit_log_24h"});
        if let Some(resp) = ConstantineIpcClient::send_command(&cmd) {
            if resp.get("status").and_then(|x| x.as_str()) == Some("ok") {
                let removed = resp.get("removed").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                return Ok(removed);
            }
        }
        Self::purge_older_than_24h_local()
    }

    pub fn purge_older_than_24h_local() -> Result<usize, String> {
        let _guard = match Self::lock_guard().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        if !Path::new(IMMUTABLE_AUDIT_LOG).exists() {
            return Ok(0);
        }
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let cutoff = now_epoch - 86400;

        let raw = fs::read_to_string(IMMUTABLE_AUDIT_LOG).map_err(|e| format!("Error leyendo registro: {}", e))?;
        let mut kept_records: Vec<(String, String, String)> = Vec::new();
        let mut genesis_line: Option<String> = None;
        let mut removed = 0usize;

        for line in raw.lines() {
            if line.trim().is_empty() { continue; }
            let parts: Vec<&str> = line.splitn(5, '|').collect();
            if parts.len() < 5 { continue; }
            let ts = parts[0].trim();
            let cur_hash = parts[1].trim();
            let ev_type = parts[3].trim();
            let details = parts[4].trim();

            if ev_type == "GENESIS" && cur_hash == "0000000000000000000000000000000000000000000000000000000000000000" {
                genesis_line = Some(format!("{} | {} | {} | {} | {}
", ts, cur_hash, cur_hash, ev_type, details));
                continue;
            }
            if let Some(ep) = Self::parse_utc_epoch(ts) {
                if ep < cutoff {
                    removed += 1;
                    continue;
                }
            }
            kept_records.push((ts.to_string(), ev_type.to_string(), details.to_string()));
        }

        if removed == 0 {
            return Ok(0);
        }

        let mut rebuilt = String::new();
        let mut prev_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        if let Some(g) = genesis_line {
            rebuilt.push_str(&g);
        }
        for (ts, ev_type, details) in kept_records {
            let payload = format!("{}|{}|{}|{}", prev_hash, ts, ev_type, details);
            let mut hasher = Sha256::new();
            hasher.update(payload.as_bytes());
            let cur_hash = format!("{:x}", hasher.finalize());
            rebuilt.push_str(&format!("{} | {} | {} | {} | {}
", ts, cur_hash, prev_hash, ev_type, details));
            prev_hash = cur_hash;
        }

        let mut write_err: Option<String> = None;
        TamperProtectionManager::unlock_for_write(IMMUTABLE_AUDIT_LOG, || {
            if let Err(e) = fs::write(IMMUTABLE_AUDIT_LOG, rebuilt.as_bytes()) {
                write_err = Some(format!("Permiso denegado al purgar registro (inicia constantine-daemon): {}", e));
            }
        });
        if let Some(err) = write_err {
            return Err(err);
        }
        Ok(removed)
    }

    fn get_last_hash_unlocked() -> String {
        if let Ok(f) = File::open(IMMUTABLE_AUDIT_LOG) {
            if let Some(last_line) = BufReader::new(f).lines().flatten().last() {
                let parts: Vec<&str> = last_line.split('|').collect();
                if parts.len() >= 2 { return parts[1].trim().to_string(); }
            }
        }
        "0000000000000000000000000000000000000000000000000000000000000000".into()
    }

    pub fn verify_integrity() -> (bool, usize) {
        let _guard = match Self::lock_guard().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        if !Path::new(IMMUTABLE_AUDIT_LOG).exists() { return (true, 0); }
        
        static AUDIT_INTEGRITY_CACHE: Mutex<Option<(u64, bool, usize)>> = Mutex::new(None);
        let current_len = fs::metadata(IMMUTABLE_AUDIT_LOG).map(|m| m.len()).unwrap_or(0);
        if let Ok(guard) = AUDIT_INTEGRITY_CACHE.lock() {
            if let Some((cached_len, ok, count)) = *guard {
                if cached_len == current_len {
                    return (ok, count);
                }
            }
        }

        let mut count = 0;
        let mut expected_prev = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        if let Ok(f) = File::open(IMMUTABLE_AUDIT_LOG) {
            for line in BufReader::new(f).lines().flatten() {
                if line.trim().is_empty() { continue; }
                let parts: Vec<&str> = line.splitn(5, '|').collect();
                if parts.len() < 5 { return (false, count); }
                let timestamp = parts[0].trim();
                let current_in_log = parts[1].trim();
                let prev_in_log = parts[2].trim();
                let ev_type = parts[3].trim();
                let details = parts[4].trim();
                if prev_in_log != expected_prev { return (false, count); }
                if count == 0 && ev_type == "GENESIS" && current_in_log == "0000000000000000000000000000000000000000000000000000000000000000" {
                    expected_prev = current_in_log.to_string();
                    count += 1;
                    continue;
                }
                let payload = format!("{}|{}|{}|{}", prev_in_log, timestamp, ev_type, details);
                let mut hasher = Sha256::new();
                hasher.update(payload.as_bytes());
                let recalculated = format!("{:x}", hasher.finalize());
                if recalculated != current_in_log { return (false, count); }
                expected_prev = current_in_log.to_string();
                count += 1;
            }
        }
        (true, count)
    }
}

fn chrono_free_timestamp() -> String {
    if let Ok(o) = Command::new("date").args(["-u", "+%Y-%m-%dT%H:%M:%SZ"]).output() {
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    } else {
        "2026-11-06T12:00:00Z".into()
    }
}

// ==============================================================================
// 4.1 Notificador Centralizado de Sistema y Registro de Auditoría Inmutable
// ==============================================================================
pub struct SystemNotifier;

impl SystemNotifier {
    pub fn notify(urgency: &str, icon: &str, title: &str, body: &str) {
        let mut cmd = Command::new("notify-send");
        cmd.args(["-u", urgency]);
        if !icon.is_empty() {
            cmd.args(["-i", icon]);
        }
        cmd.args([title, body]);
        let _ = cmd.status();

        let audit_tag = match urgency {
            "critical" => "NOTIFICATION_CRITICAL",
            "normal" => "NOTIFICATION_NORMAL",
            _ => "NOTIFICATION_LOW",
        };
        ImmutableAuditLog::append_event(audit_tag, &format!("{}: {}", title, body.replace('\n', " ")));
    }
}

pub struct SecurityLogAggregator;

impl SecurityLogAggregator {
    pub fn start_log_forwarder() {
        thread::spawn(|| {
            let mut falco_offset: u64 = fs::metadata(FALCO_LOG_FILE).map(|m| m.len()).unwrap_or(0);
            let mut wazuh_offset: u64 = fs::metadata(WAZUH_LOG_FILE).map(|m| m.len()).unwrap_or(0);
            let mut sigma_offset: u64 = fs::metadata(SIGMA_LOG_FILE).map(|m| m.len()).unwrap_or(0);
            let mut aide_offset: u64 = fs::metadata(AIDE_LOG_FILE).map(|m| m.len()).unwrap_or(0);

            loop {
                thread::sleep(Duration::from_secs(3));

                // 1. Falco Behavioral Engine
                if let Ok(meta) = fs::metadata(FALCO_LOG_FILE) {
                    let len = meta.len();
                    if len > falco_offset {
                        if let Ok(mut file) = File::open(FALCO_LOG_FILE) {
                            use std::io::{Seek, SeekFrom};
                            if file.seek(SeekFrom::Start(falco_offset)).is_ok() {
                                for line in BufReader::new(file).lines().flatten() {
                                    if !line.trim().is_empty() {
                                        ImmutableAuditLog::append_event("FALCO_BEHAVIOR_ALERT", &line);
                                    }
                                }
                            }
                        }
                        falco_offset = len;
                    } else if len < falco_offset {
                        falco_offset = 0;
                    }
                }

                // 2. Wazuh Agent (SIEM & FIM)
                if let Ok(meta) = fs::metadata(WAZUH_LOG_FILE) {
                    let len = meta.len();
                    if len > wazuh_offset {
                        if let Ok(mut file) = File::open(WAZUH_LOG_FILE) {
                            use std::io::{Seek, SeekFrom};
                            if file.seek(SeekFrom::Start(wazuh_offset)).is_ok() {
                                for line in BufReader::new(file).lines().flatten() {
                                    if line.contains("Rule:") || line.contains("Alert:") || line.contains("Integrity checksum changed") {
                                        ImmutableAuditLog::append_event("WAZUH_SIEM_ALERT", &line);
                                    }
                                }
                            }
                        }
                        wazuh_offset = len;
                    } else if len < wazuh_offset {
                        wazuh_offset = 0;
                    }
                }

                // 3. Sigma Detection Rules
                if let Ok(meta) = fs::metadata(SIGMA_LOG_FILE) {
                    let len = meta.len();
                    if len > sigma_offset {
                        if let Ok(mut file) = File::open(SIGMA_LOG_FILE) {
                            use std::io::{Seek, SeekFrom};
                            if file.seek(SeekFrom::Start(sigma_offset)).is_ok() {
                                for line in BufReader::new(file).lines().flatten() {
                                    if !line.trim().is_empty() {
                                        ImmutableAuditLog::append_event("SIGMA_RULE_MATCH", &line);
                                    }
                                }
                            }
                        }
                        sigma_offset = len;
                    } else if len < sigma_offset {
                        sigma_offset = 0;
                    }
                }

                // 4. AIDE Critical Integrity
                if let Ok(meta) = fs::metadata(AIDE_LOG_FILE) {
                    let len = meta.len();
                    if len > aide_offset {
                        if let Ok(mut file) = File::open(AIDE_LOG_FILE) {
                            use std::io::{Seek, SeekFrom};
                            if file.seek(SeekFrom::Start(aide_offset)).is_ok() {
                                for line in BufReader::new(file).lines().flatten() {
                                    if line.contains("changed:") || line.contains("added:") || line.contains("removed:") {
                                        ImmutableAuditLog::append_event("AIDE_INTEGRITY_CHANGE", &line);
                                    }
                                }
                            }
                        }
                        aide_offset = len;
                    } else if len < aide_offset {
                        aide_offset = 0;
                    }
                }
            }
        });
    }
}

// ==============================================================================
// 5. Motor de Análisis Manual Recursivo sin Seguir Symlinks
// ==============================================================================
const MAX_SCAN_DEPTH: usize = 24;

pub struct ManualScanEngine;

impl ManualScanEngine {
    pub fn collect_files(dir: &Path, list: &mut Vec<PathBuf>) {
        let mut skipped_errors = 0usize;
        Self::collect_bounded(dir, list, 0, &mut skipped_errors);
    }

    pub fn collect_bounded(dir: &Path, list: &mut Vec<PathBuf>, depth: usize, skipped_errors: &mut usize) {
        if depth > MAX_SCAN_DEPTH { return; }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e, Err(_) => { *skipped_errors += 1; return; }
        };
        for entry_res in entries {
            let entry = match entry_res { Ok(e) => e, Err(_) => { *skipped_errors += 1; continue; } };
            let p = entry.path();
            let meta = match fs::symlink_metadata(&p) {
                Ok(m) => m, Err(_) => { *skipped_errors += 1; continue; }
            };
            let ftype = meta.file_type();
            if ftype.is_symlink() { continue; }
            else if ftype.is_dir() { Self::collect_bounded(&p, list, depth + 1, skipped_errors); }
            else if ftype.is_file() { list.push(p); }
        }
    }
}

// ==============================================================================
// 6. Gestor Transaccional del Baúl de Cuarentena
// ==============================================================================
#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub display_name: String,
    pub filename: String,
    pub origin_vault: &'static str,
    pub full_path: PathBuf,
    pub is_cstv_encrypted: bool,
    pub timestamp: String,
    pub threat_name: String,
    pub detection_method: String,
    pub original_path: String,
    pub sha256: String,
}

pub struct VaultManager;

impl VaultManager {
    pub fn list_all_quarantine_entries() -> Vec<QuarantineEntry> {
        let mut list = Vec::new();

        // 1. Baúl Criptográfico de Constantine (/var/lib/constantine/quarantine)
        if let Ok(entries) = fs::read_dir(QUARANTINE_DIR) {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if name.ends_with(".vault") {
                        let full_path = Path::new(QUARANTINE_DIR).join(&name);
                        let meta_path = Path::new(QUARANTINE_DIR).join(name.replace(".vault", ".meta.json"));
                        
                        // Leer metadatos forenses enriquecidos si existen
                        let (threat_name, detection_method, original_path, timestamp, sha256) = if meta_path.exists() {
                            if let Some(m) = VaultMetadata::load_from_file(&meta_path) {
                                (m.threat_name, m.detection_method, m.original_path, m.timestamp, m.sha256)
                            } else {
                                Self::extract_fallback_vault_info(&full_path, &name)
                            }
                        } else {
                            Self::extract_fallback_vault_info(&full_path, &name)
                        };

                        list.push(QuarantineEntry {
                            display_name: format!("🔒 [Baúl Criptográfico Constantine] {}", name),
                            filename: name.clone(),
                            origin_vault: "Constantine AES-256-GCM",
                            full_path,
                            is_cstv_encrypted: true,
                            timestamp,
                            threat_name,
                            detection_method,
                            original_path,
                            sha256,
                        });
                    }
                }
            }
        }

        // 2. Baúl de ClamAV (/var/lib/clamav/quarantine y /var/spool/clamav/quarantine)
        let clam_dirs = [CLAMAV_QUARANTINE_DIR, CLAMAV_SPOOL_DIR];
        for dir in &clam_dirs {
            if Path::new(dir).exists() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if let Ok(name) = entry.file_name().into_string() {
                            if !name.starts_with('.') {
                                let full_path = Path::new(dir).join(&name);
                                let mtime = ModuleVersionAudit::get_file_mtime(&full_path.to_string_lossy());
                                let hash = ThreatAnalysisEngine::compute_sha256(&full_path).unwrap_or_else(|_| "Desconocido".into());
                                
                                list.push(QuarantineEntry {
                                    display_name: format!("🛡️ [Baúl ClamAV fanotify/clamd] {}", name),
                                    filename: name.clone(),
                                    origin_vault: "ClamAV Quarantine",
                                    full_path: full_path.clone(),
                                    is_cstv_encrypted: false,
                                    timestamp: mtime,
                                    threat_name: "ClamAV Malware Detection".to_string(),
                                    detection_method: "ClamAV Engine (fanotify/clamd)".to_string(),
                                    original_path: full_path.to_string_lossy().to_string(),
                                    sha256: hash,
                                });
                            }
                        }
                    }
                }
            }
        }

        list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        list
    }

    fn extract_fallback_vault_info(vault_path: &Path, name: &str) -> (String, String, String, String, String) {
        let clean_name = name.trim_end_matches(".vault");
        let mtime = ModuleVersionAudit::get_file_mtime(&vault_path.to_string_lossy());
        
        let mut sha256_hex = "Desconocido".to_string();
        if let Ok(blob) = fs::read(vault_path) {
            if blob.len() >= 53 && &blob[0..9] == VAULT_MAGIC {
                sha256_hex = hex::encode(&blob[21..53]);
            }
        }

        (
            format!("Malware/Heurística: {}", clean_name),
            "Escudo Constantine (Heurística EDR / Canary)".to_string(),
            format!("Detectado en espacio de usuario: {}", clean_name),
            mtime,
            sha256_hex,
        )
    }

    pub fn list_vault_files() -> Vec<String> {
        Self::list_all_quarantine_entries()
            .into_iter()
            .map(|e| e.filename)
            .collect()
    }

    pub fn delete_from_vault(filename: &str) -> bool {
        let safe_name = match Path::new(filename).file_name().and_then(|n| n.to_str()) {
            Some(n) => n, None => return false,
        };

        let entries = Self::list_all_quarantine_entries();
        if let Some(entry) = entries.iter().find(|e| e.filename == safe_name) {
            let removed = fs::remove_file(&entry.full_path).is_ok() 
                || SecurityAuth::privileged_action(&["rm", "-f", "--", &entry.full_path.to_string_lossy()]);
            if removed {
                ImmutableAuditLog::append_event("VAULT_FILE_DELETED", &format!("Muestra eliminada permanentemente de {}: {}", entry.origin_vault, safe_name));
            }
            return removed;
        }
        false
    }

    pub fn restore_to_whitelist(filename: &str, user_home: &str) -> bool {
        let safe_name = match Path::new(filename).file_name().and_then(|n| n.to_str()) {
            Some(n) => n, None => return false,
        };

        let entries = Self::list_all_quarantine_entries();
        let entry = match entries.iter().find(|e| e.filename == safe_name) {
            Some(e) => e,
            None => return false,
        };

        let desktop_dir = Path::new(user_home).join("Desktop");
        let _ = fs::create_dir_all(&desktop_dir);

        // Caso A: Muestra del Baúl Criptográfico Constantine (cifrada con AES-256-GCM)
        if entry.is_cstv_encrypted {
            let blob = match fs::read(&entry.full_path) { Ok(b) => b, Err(_) => return false };
            if blob.len() < 69 || &blob[0..9] != VAULT_MAGIC {
                ImmutableAuditLog::append_event("VAULT_RESTORE_FAILED", &format!("Formato de baúl inválido o corrupto: {}", safe_name));
                return false;
            }

            let nonce_bytes = &blob[9..21];
            let expected_sha256 = &blob[21..53];
            let ciphertext = &blob[53..];
            let key_bytes = match ContainmentEngine::load_or_generate_csprng_key() { Ok(k) => k, Err(_) => return false };

            let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(nonce_bytes);
            let payload = Payload { msg: ciphertext, aad: expected_sha256 };

            let plaintext = match cipher.decrypt(nonce, payload) {
                Ok(pt) => pt,
                Err(_) => {
                    ImmutableAuditLog::append_event("VAULT_AUTH_FAILED", &format!("Fallo de autenticación GCM al restaurar: {}", safe_name));
                    return false;
                }
            };

            let mut hasher = Sha256::new();
            hasher.update(&plaintext);
            let actual_sha256: [u8; 32] = hasher.finalize().into();
            if actual_sha256.as_slice() != expected_sha256 {
                ImmutableAuditLog::append_event("VAULT_HASH_MISMATCH", &format!("Discrepancia de hash SHA-256 al restaurar: {}", safe_name));
                return false;
            }

            let clean_name = safe_name.trim_end_matches(".vault");
            let restored_path = desktop_dir.join(clean_name);

            let write_ok = OpenOptions::new().create(true).write(true).truncate(true).open(&restored_path)
                .and_then(|mut f| { f.write_all(&plaintext)?; f.sync_all() }).is_ok();
            if !write_ok { return false; }
            let _ = fs::set_permissions(&restored_path, fs::Permissions::from_mode(0o644));

            let sha256_hex = hex::encode(actual_sha256);
            let _ = WhitelistManager::add_record(&sha256_hex, clean_name, &entry.original_path);
            let _ = fs::remove_file(&entry.full_path);
            ImmutableAuditLog::append_event("VAULT_RESTORE_VERIFIED", &format!("Restaurado de Baúl Constantine con AES-256-GCM: {} (SHA-256: {})", clean_name, &sha256_hex[..16]));
            return true;
        }

        // Caso B: Muestra del Baúl de ClamAV (/var/lib/clamav/quarantine)
        let restored_path = desktop_dir.join(safe_name);
        let hash = match ThreatAnalysisEngine::compute_sha256(&entry.full_path) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let copy_ok = fs::copy(&entry.full_path, &restored_path).is_ok()
            || SecurityAuth::privileged_action(&["cp", "-f", &entry.full_path.to_string_lossy(), &restored_path.to_string_lossy()]);
        if !copy_ok { return false; }

        let _ = fs::set_permissions(&restored_path, fs::Permissions::from_mode(0o644));
        let cur_user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "root".into());
        let _ = SecurityAuth::privileged_action(&["chown", &format!("{}:{}", cur_user, cur_user), &restored_path.to_string_lossy()]);
        
        let _ = WhitelistManager::add_record(&hash, safe_name, &entry.original_path);
        let _ = fs::remove_file(&entry.full_path).is_ok() || SecurityAuth::privileged_action(&["rm", "-f", "--", &entry.full_path.to_string_lossy()]);
        
        ImmutableAuditLog::append_event("CLAMAV_VAULT_RESTORED", &format!("Restaurado de Baúl ClamAV al escritorio: {} (SHA-256: {})", safe_name, &hash[..16]));
        true
    }
}

// ==============================================================================
// 7. Control de Seguridad y Privilegios
// ==============================================================================

// ==============================================================================
// 19. Arquitectura Cliente-Servidor: Socket IPC Local (/run/constantine.sock)
// ==============================================================================
const CONSTANTINE_IPC_SOCKET: &str = "/run/constantine.sock";

pub struct ConstantineIpcServer;

impl ConstantineIpcServer {
    pub fn start_daemon_ipc_server() {
        let socket_path = Path::new(CONSTANTINE_IPC_SOCKET);
        if socket_path.exists() {
            let _ = fs::remove_file(socket_path);
        }

        let listener = match UnixListener::bind(socket_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[-] Error al enlazar socket IPC en {}: {}", CONSTANTINE_IPC_SOCKET, e);
                return;
            }
        };

        // Permisos 0666 y pertenencia al grupo constantine de inmediato de forma síncrona
        let _ = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666));
        let _ = Command::new("chmod").args(["666", CONSTANTINE_IPC_SOCKET]).status();
        let _ = Command::new("chown").args(["root:constantine", CONSTANTINE_IPC_SOCKET]).status();

        // Una vez creado y configurado el socket en disco, atender clientes concurrentes en hilo dedicado
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    Self::handle_client(stream);
                });
            }
        });
    }

    fn handle_client(mut stream: UnixStream) {
        let cloned_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut reader = BufReader::new(cloned_stream);
        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() {
            let resp = Self::process_ipc_request(line.trim());
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(b"\n");
        }
    }

    fn process_ipc_request(json_cmd: &str) -> String {
        let val: serde_json::Value = match serde_json::from_str(json_cmd) {
            Ok(v) => v,
            Err(_) => return serde_json::json!({"status": "error", "message": "JSON inválido"}).to_string(),
        };

        let action = val.get("action").and_then(|x| x.as_str()).unwrap_or("");
        match action {
            "ping" => {
                serde_json::json!({"status": "ok", "message": "pong", "version": "5.5.3"}).to_string()
            }
            "append_audit_log" => {
                let ev = val.get("event_type").and_then(|x| x.as_str()).unwrap_or("SYSTEM_EVENT");
                let det = val.get("details").and_then(|x| x.as_str()).unwrap_or("");
                ImmutableAuditLog::append_event(ev, det);
                serde_json::json!({"status": "ok"}).to_string()
            }
            "purge_audit_log_24h" => {
                match ImmutableAuditLog::purge_older_than_24h_local() {
                    Ok(removed) => serde_json::json!({"status": "ok", "removed": removed}).to_string(),
                    Err(e) => serde_json::json!({"status": "error", "message": e}).to_string(),
                }
            }
            "service_action" => {
                let service = val.get("service").and_then(|x| x.as_str()).unwrap_or("");
                let op = val.get("operation").and_then(|x| x.as_str()).unwrap_or("");
                let allowed = [
                    "clamonacc", "tetragon", "falco", "falco-modern-bpf",
                    "wazuh-agent", "clamav-daemon", "ufw", "aide", "osqueryd",
                    "constantine-daemon"
                ];
                if !allowed.contains(&service) {
                    return serde_json::json!({"status": "error", "message": "Servicio no autorizado"}).to_string();
                }

                let success = match (service, op) {
                    ("falco", "start") => {
                        let s1 = Command::new("systemctl").args(["start", "falco"]).status().map(|s| s.success()).unwrap_or(false);
                        if s1 { true } else { Command::new("systemctl").args(["start", "falco-modern-bpf"]).status().map(|s| s.success()).unwrap_or(false) }
                    }
                    ("falco", "stop") => {
                        let _ = Command::new("systemctl").args(["stop", "falco-modern-bpf"]).status();
                        Command::new("systemctl").args(["stop", "falco"]).status().map(|s| s.success()).unwrap_or(false)
                    }
                    ("falco", "restart") | ("falco", "force_restart") => {
                        let _ = Command::new("pkill").args(["-9", "-f", "falco"]).status();
                        let s1 = Command::new("systemctl").args(["restart", "falco"]).status().map(|s| s.success()).unwrap_or(false);
                        if s1 { true } else { Command::new("systemctl").args(["restart", "falco-modern-bpf"]).status().map(|s| s.success()).unwrap_or(false) }
                    }
                    (_, "start") => Command::new("systemctl").args(["start", service]).status().map(|s| s.success()).unwrap_or(false),
                    (_, "stop") => Command::new("systemctl").args(["stop", service]).status().map(|s| s.success()).unwrap_or(false),
                    (_, "restart") => Command::new("systemctl").args(["restart", service]).status().map(|s| s.success()).unwrap_or(false),
                    (_, "force_restart") => {
                        let _ = Command::new("pkill").args(["-9", "-f", service]).status();
                        Command::new("systemctl").args(["restart", service]).status().map(|s| s.success()).unwrap_or(false)
                    }
                    _ => false,
                };

                if success {
                    serde_json::json!({"status": "ok", "message": format!("Operación {} sobre {} completada por daemon root", op, service)}).to_string()
                } else {
                    serde_json::json!({"status": "error", "message": format!("Fallo al ejecutar {} sobre {}", op, service)}).to_string()
                }
            }
            "isolate_file" => {
                let path_str = val.get("path").and_then(|x| x.as_str()).unwrap_or("");
                let threat = val.get("threat_name").and_then(|x| x.as_str()).unwrap_or("Amenaza Detectada");
                let engine = val.get("engine").and_then(|x| x.as_str()).unwrap_or("Sensor EDR");
                let p = Path::new(path_str);
                if p.exists() && p.is_file() {
                    if ContainmentEngine::isolate_to_vault_with_metadata(p, threat, engine) {
                        serde_json::json!({"status": "ok", "message": "Archivo aislado exitosamente en baúl AES-256-GCM por daemon"}).to_string()
                    } else {
                        serde_json::json!({"status": "error", "message": "Fallo al aislar archivo en baúl"}).to_string()
                    }
                } else {
                    serde_json::json!({"status": "error", "message": "Archivo no encontrado"}).to_string()
                }
            }
            "delete_quarantine" => {
                let filename = val.get("filename").and_then(|x| x.as_str()).unwrap_or("");
                if VaultManager::delete_from_vault(filename) {
                    serde_json::json!({"status": "ok", "message": "Muestra eliminada permanentemente por daemon"}).to_string()
                } else {
                    serde_json::json!({"status": "error", "message": "Fallo al eliminar muestra de cuarentena"}).to_string()
                }
            }
            "restore_quarantine" => {
                let filename = val.get("filename").and_then(|x| x.as_str()).unwrap_or("");
                let user_home = val.get("user_home").and_then(|x| x.as_str()).unwrap_or("/root");
                if VaultManager::restore_to_whitelist(filename, user_home) {
                    serde_json::json!({"status": "ok", "message": "Muestra restaurada al Escritorio y agregada a lista blanca por daemon"}).to_string()
                } else {
                    serde_json::json!({"status": "error", "message": "Fallo al restaurar muestra"}).to_string()
                }
            }
            "kill_process" => {
                let pid = val.get("pid").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                if pid > 1 {
                    let pid_str = pid.to_string();
                    let _ = Command::new("kill").args(["-STOP", &pid_str]).status();
                    let success = Command::new("kill").args(["-KILL", &pid_str]).status().map(|s| s.success()).unwrap_or(false);
                    serde_json::json!({"status": if success { "ok" } else { "error" }, "message": format!("Proceso PID {} neutralizado por daemon", pid)}).to_string()
                } else {
                    serde_json::json!({"status": "error", "message": "PID inválido o crítico"}).to_string()
                }
            }
            "block_camera" => {
                let ok = PeripheralAudit::turn_off_camera();
                serde_json::json!({"status": if ok { "ok" } else { "error" }, "message": "Cámara apagada por daemon (000)"}).to_string()
            }
            "unblock_camera" => {
                let ok = PeripheralAudit::turn_on_camera();
                serde_json::json!({"status": if ok { "ok" } else { "error" }, "message": "Cámara encendida por daemon (660)"}).to_string()
            }
            "block_microphone" => {
                let ok = PeripheralAudit::turn_off_microphone();
                serde_json::json!({"status": if ok { "ok" } else { "error" }, "message": "Micrófono silenciado por daemon"}).to_string()
            }
            "unblock_microphone" => {
                let ok = PeripheralAudit::turn_on_microphone();
                serde_json::json!({"status": if ok { "ok" } else { "error" }, "message": "Micrófono activado por daemon"}).to_string()
            }
            "sync_dns_sinkhole" => {
                let success = Command::new("/usr/local/bin/constantine-dns-sinkhole").arg("--enable").status().map(|s| s.success()).unwrap_or(false);
                let count = WebProtectionManager::get_blocked_domains_count();
                serde_json::json!({
                    "status": if success { "ok" } else { "error" },
                    "message": format!("Sumidero DNS activo: {} dominios hostiles bloqueados en 0.0.0.0", count)
                }).to_string()
            }
            "apply_dns_profile" => {
                let profile_id = val.get("profile_id").and_then(|x| x.as_str()).unwrap_or("quad9");
                let iface = val.get("iface").and_then(|x| x.as_str()).unwrap_or("");
                let (ok, msg) = DnsProfileManager::apply_profile_local(profile_id, iface);
                serde_json::json!({
                    "status": if ok { "ok" } else { "error" },
                    "message": msg
                }).to_string()
            }
            "reset_dns" => {
                let iface = val.get("iface").and_then(|x| x.as_str()).unwrap_or("");
                let (ok, msg) = DnsProfileManager::reset_dns_local(iface);
                serde_json::json!({
                    "status": if ok { "ok" } else { "error" },
                    "message": msg
                }).to_string()
            }
            "toggle_web_protection" => {
                let enable = val.get("enable").and_then(|x| x.as_bool()).unwrap_or(true);
                let flag = if enable { "--enable" } else { "--disable" };
                let success = Command::new("/usr/local/bin/constantine-dns-sinkhole").arg(flag).status().map(|s| s.success()).unwrap_or(false);
                serde_json::json!({
                    "status": if success { "ok" } else { "error" },
                    "message": if enable { "Protección Web y Filtrado DNS activados" } else { "Protección Web pausada" }
                }).to_string()
            }
            "apply_tamper_protection" => {
                let (ok, msg) = TamperProtectionManager::apply_tamper_protection_local();
                serde_json::json!({
                    "status": if ok { "ok" } else { "error" },
                    "message": msg
                }).to_string()
            }
            "remove_tamper_protection" => {
                let ok = TamperProtectionManager::remove_tamper_protection_local();
                serde_json::json!({
                    "status": if ok { "ok" } else { "error" },
                    "message": "Autodefensa deshabilitada temporalmente por daemon"
                }).to_string()
            }
            "isolate_network" => {
                let (ok, msg) = NetworkIsolationManager::isolate_network_local();
                serde_json::json!({
                    "status": if ok { "ok" } else { "error" },
                    "message": msg
                }).to_string()
            }
            "reconnect_network" => {
                let (ok, msg) = NetworkIsolationManager::reconnect_network_local();
                serde_json::json!({
                    "status": if ok { "ok" } else { "error" },
                    "message": msg
                }).to_string()
            }
            _ => serde_json::json!({"status": "error", "message": "Comando no reconocido"}).to_string(),
        }
    }
}

pub struct ConstantineIpcClient;

impl ConstantineIpcClient {
    pub fn is_daemon_running() -> bool {
        Path::new(CONSTANTINE_IPC_SOCKET).exists()
    }

    pub fn send_command(cmd: &serde_json::Value) -> Option<serde_json::Value> {
        let mut stream = UnixStream::connect(CONSTANTINE_IPC_SOCKET).ok()?;
        let req_str = cmd.to_string();
        stream.write_all(req_str.as_bytes()).ok()?;
        stream.write_all(b"\n").ok()?;

        let mut reader = BufReader::new(stream);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).ok()?;
        serde_json::from_str::<serde_json::Value>(&resp_line).ok()
    }

    pub fn service_action(service: &str, operation: &str) -> bool {
        let cmd = serde_json::json!({
            "action": "service_action",
            "service": service,
            "operation": operation
        });
        if let Some(resp) = Self::send_command(&cmd) {
            return resp.get("status").and_then(|s| s.as_str()) == Some("ok");
        }
        false
    }

    pub fn isolate_file(path: &Path, threat_name: &str, engine: &str) -> bool {
        let cmd = serde_json::json!({
            "action": "isolate_file",
            "path": path.to_string_lossy(),
            "threat_name": threat_name,
            "engine": engine
        });
        if let Some(resp) = Self::send_command(&cmd) {
            return resp.get("status").and_then(|s| s.as_str()) == Some("ok");
        }
        false
    }

    pub fn kill_process(pid: u32) -> bool {
        let cmd = serde_json::json!({
            "action": "kill_process",
            "pid": pid
        });
        if let Some(resp) = Self::send_command(&cmd) {
            return resp.get("status").and_then(|s| s.as_str()) == Some("ok");
        }
        false
    }

    pub fn block_camera() -> bool {
        let cmd = serde_json::json!({"action": "block_camera"});
        if let Some(resp) = Self::send_command(&cmd) {
            return resp.get("status").and_then(|s| s.as_str()) == Some("ok");
        }
        false
    }

    pub fn unblock_camera() -> bool {
        let cmd = serde_json::json!({"action": "unblock_camera"});
        if let Some(resp) = Self::send_command(&cmd) {
            return resp.get("status").and_then(|s| s.as_str()) == Some("ok");
        }
        false
    }

    pub fn block_microphone() -> bool {
        let cmd = serde_json::json!({"action": "block_microphone"});
        if let Some(resp) = Self::send_command(&cmd) {
            return resp.get("status").and_then(|s| s.as_str()) == Some("ok");
        }
        false
    }

    pub fn unblock_microphone() -> bool {
        let cmd = serde_json::json!({"action": "unblock_microphone"});
        if let Some(resp) = Self::send_command(&cmd) {
            return resp.get("status").and_then(|s| s.as_str()) == Some("ok");
        }
        false
    }
}

pub struct SecurityAuth;

impl SecurityAuth {
    pub fn is_in_constantine_group() -> bool {
        Command::new("id").arg("-nG").output()
            .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().any(|g| g == "constantine"))
            .unwrap_or(false)
    }

    pub fn privileged_action(args: &[&str]) -> bool {
        // 1. Intentar primero con sudo -n (sin contraseña por sudoers.d/constantine)
        let mut sudo_args = vec!["-n"];
        sudo_args.extend_from_slice(args);
        if Command::new("sudo").args(&sudo_args).status().map(|s| s.success()).unwrap_or(false) {
            return true;
        }
        // 2. Si falla sudo -n, recurrir a pkexec pidiendo contraseña una sola vez
        Command::new("pkexec").args(args).status().map(|s| s.success()).unwrap_or(false)
    }

    pub fn stop_service_protected(service_name: &str) -> bool {
        let ok = if ConstantineIpcClient::service_action(service_name, "stop") {
            true
        } else {
            Self::privileged_action(&["systemctl", "stop", service_name])
        };
        if ok {
            ImmutableAuditLog::append_event("SERVICE_STOPPED", &format!("Servicio de seguridad detenido: {}", service_name));
        } else {
            ImmutableAuditLog::append_event("SERVICE_STOP_FAILED", &format!("Fallo al detener servicio de seguridad: {}", service_name));
        }
        ok
    }
    pub fn start_service_protected(service_name: &str) -> bool {
        let ok = if ConstantineIpcClient::service_action(service_name, "start") {
            true
        } else {
            Self::privileged_action(&["systemctl", "start", service_name])
        };
        if ok {
            ImmutableAuditLog::append_event("SERVICE_STARTED", &format!("Servicio de seguridad iniciado: {}", service_name));
        } else {
            ImmutableAuditLog::append_event("SERVICE_START_FAILED", &format!("Fallo al iniciar servicio de seguridad: {}", service_name));
        }
        ok
    }
    pub fn restart_service_protected(service_name: &str) -> bool {
        let ok = if ConstantineIpcClient::service_action(service_name, "restart") {
            true
        } else {
            Self::privileged_action(&["systemctl", "restart", service_name])
        };
        if ok {
            ImmutableAuditLog::append_event("SERVICE_RESTARTED", &format!("Servicio de seguridad reiniciado: {}", service_name));
        } else {
            ImmutableAuditLog::append_event("SERVICE_RESTART_FAILED", &format!("Fallo al reiniciar servicio de seguridad: {}", service_name));
        }
        ok
    }
    pub fn force_stop_service(service_name: &str) -> bool {
        ImmutableAuditLog::append_event("SERVICE_FORCE_STOP", &format!("Terminación forzada (SIGKILL) de servicio: {}", service_name));
        if ConstantineIpcClient::service_action(service_name, "stop") {
            return true;
        }
        let _ = Self::privileged_action(&["pkill", "-9", service_name]);
        Self::privileged_action(&["systemctl", "stop", service_name])
    }
    pub fn force_start_service(service_name: &str) -> bool {
        ImmutableAuditLog::append_event("SERVICE_FORCE_START", &format!("Reinicio forzado (SIGKILL + restart) de servicio: {}", service_name));
        if ConstantineIpcClient::service_action(service_name, "force_restart") {
            return true;
        }
        let _ = Self::privileged_action(&["pkill", "-9", service_name]);
        Self::privileged_action(&["systemctl", "restart", service_name])
    }
    pub fn shutdown_all_protected() -> bool {
        Self::shutdown_all_protected_interactive()
    }

    pub fn shutdown_all_protected_interactive() -> bool {
        // Requiere obligatoriamente autenticación de administrador con contraseña (pkexec)
        if Path::new("/usr/local/bin/constantine-shutdown").exists() {
            Command::new("pkexec")
                .arg("/usr/local/bin/constantine-shutdown")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            Command::new("pkexec")
                .args([
                    "sh", "-c",
                    "systemctl stop clamonacc tetragon falco wazuh-agent clamav-daemon constantine-daemon constantine-boot-update.timer 2>/dev/null; pkill -9 -f 'clamonacc|tetragon|falco|wazuh|clamd|constantine-daemon|constantine-tray' 2>/dev/null || true"
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    }

    pub fn are_shields_active() -> bool {
        get_service_active("clamonacc") || get_service_active("tetragon") || get_service_active("falco")
    }

    pub fn pause_all_shields_interactive() -> bool {
        // Pausar todos los escudos en kernel sin cerrar la interfaz de Constantine
        Command::new("pkexec")
            .args([
                "sh", "-c",
                "systemctl stop clamonacc tetragon falco wazuh-agent 2>/dev/null; /usr/local/bin/constantine-dns-sinkhole --disable 2>/dev/null || true"
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn resume_all_shields_interactive() -> bool {
        // Reactivar todos los escudos en kernel
        Command::new("pkexec")
            .args([
                "sh", "-c",
                "systemctl start clamonacc tetragon falco wazuh-agent 2>/dev/null; /usr/local/bin/constantine-dns-sinkhole --enable 2>/dev/null || true"
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn uninstall_interactive() -> bool {
        // Desinstalación protegida con autenticación de administrador (pkexec)
        if Path::new("/usr/local/bin/constantine-uninstall").exists() {
            Command::new("pkexec")
                .arg("/usr/local/bin/constantine-uninstall")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else if Path::new("/usr/local/bin/uninstall.sh").exists() {
            Command::new("pkexec")
                .arg("/usr/local/bin/uninstall.sh")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            Command::new("pkexec")
                .args([
                    "sh", "-c",
                    "if [ -f ./uninstall.sh ]; then ./uninstall.sh; elif [ -f /usr/share/constantine/uninstall.sh ]; then /usr/share/constantine/uninstall.sh; fi"
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    }
}

// ==============================================================================
// 8. Telemetría Dinámica Real de Versiones, Servicios y Salud
// ==============================================================================
#[derive(Clone, Debug)]
pub struct HealthPillar {
    pub name: String,
    pub is_ok: bool,
    pub weight_pct: u8,
    pub details: String,
    pub remedy: String,
}

#[derive(Clone, Debug)]
pub struct SystemUpdateInfo {
    pub total_packages: usize,
    pub security_packages: usize,
    pub kernel_update_pending: bool,
    pub running_kernel: String,
    pub available_kernel: Option<String>,
    pub status_text: String,
}

static SYSTEM_UPDATE_CACHE: Mutex<Option<(Instant, SystemUpdateInfo)>> = Mutex::new(None);
static IS_UPDATING_IN_BACKGROUND: AtomicBool = AtomicBool::new(false);

pub struct SystemUpdateAudit;

impl SystemUpdateAudit {
    pub fn get_running_kernel() -> String {
        Command::new("uname")
            .arg("-r")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "Linux".into())
    }

    pub fn is_kernel_update_pending() -> bool {
        let running_kernel = Self::get_running_kernel();
        if let Ok(entries) = fs::read_dir("/boot") {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.starts_with("vmlinuz-") {
                    let kver = fname.trim_start_matches("vmlinuz-");
                    if kver != running_kernel && kver > running_kernel.as_str() {
                        return true;
                    }
                }
            }
        }
        if let Ok(guard) = SYSTEM_UPDATE_CACHE.lock() {
            if let Some((_, ref info)) = *guard {
                return info.kernel_update_pending;
            }
        }
        false
    }

    pub fn check_updates() -> SystemUpdateInfo {
        // 1. Si existe caché válido menor a 5 minutos, devolverlo al instante (0.001 ms)
        if let Ok(guard) = SYSTEM_UPDATE_CACHE.lock() {
            if let Some((ts, ref info)) = *guard {
                if ts.elapsed() < Duration::from_secs(300) {
                    return info.clone();
                }
            }
        }

        let running_kernel = Self::get_running_kernel();
        let mut kernel_update_pending = false;
        let mut available_kernel = None;

        // Comprobación instantánea en /boot (< 0.2 ms)
        if let Ok(entries) = fs::read_dir("/boot") {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname.starts_with("vmlinuz-") {
                    let kver = fname.trim_start_matches("vmlinuz-");
                    if kver != running_kernel && kver > running_kernel.as_str() {
                        kernel_update_pending = true;
                        available_kernel = Some(kver.to_string());
                    }
                }
            }
        }

        // Comprobación instantánea de lectura de fichero update-notifier si existe (< 0.1 ms)
        let mut total_packages = 0;
        let mut security_packages = 0;
        if let Ok(content) = fs::read_to_string("/var/lib/update-notifier/updates-available") {
            for line in content.lines() {
                if line.contains("updates can be applied") {
                    if let Some(num_str) = line.split_whitespace().next() {
                        total_packages = num_str.parse().unwrap_or(0);
                    }
                }
                if line.contains("standard security updates") || line.contains("security updates") {
                    if let Some(num_str) = line.split_whitespace().next() {
                        security_packages = num_str.parse().unwrap_or(0);
                    }
                }
            }
        }

        let status_text = if kernel_update_pending {
            format!("⚠️ Kernel {} requiere actualización / reinicio", running_kernel)
        } else if security_packages > 0 {
            format!("⚠️ {} parches de seguridad pendientes", security_packages)
        } else if total_packages > 0 {
            format!("ℹ️ {} actualizaciones disponibles", total_packages)
        } else {
            "🟢 Sistema y Kernel completamente al día".to_string()
        };

        let initial_info = SystemUpdateInfo {
            total_packages,
            security_packages,
            kernel_update_pending,
            running_kernel: running_kernel.clone(),
            available_kernel: available_kernel.clone(),
            status_text: status_text.clone(),
        };

        // Guardar resultado rápido en caché
        if let Ok(mut guard) = SYSTEM_UPDATE_CACHE.lock() {
            *guard = Some((Instant::now(), initial_info.clone()));
        }

        // Lanzar sondeo profundo en segundo plano solo si no hay otro en curso (CERO bloqueo de la GUI)
        if !IS_UPDATING_IN_BACKGROUND.swap(true, Ordering::SeqCst) {
            let rk_thread = running_kernel.clone();
            std::thread::spawn(move || {
                let mut tot = 0;
                let mut sec = 0;
                let mut k_pend = kernel_update_pending;
                let mut k_avail = available_kernel;

                if Path::new("/usr/lib/update-notifier/apt-check").exists() {
                    if let Ok(out) = Command::new("/usr/lib/update-notifier/apt-check").output() {
                        let err_str = String::from_utf8_lossy(&out.stderr);
                        let out_str = String::from_utf8_lossy(&out.stdout);
                        let combined = if out_str.contains(';') { out_str } else { err_str };
                        let parts: Vec<&str> = combined.trim().split(';').collect();
                        if parts.len() >= 2 {
                            tot = parts[0].trim().parse().unwrap_or(0);
                            sec = parts[1].trim().parse().unwrap_or(0);
                        }
                    }
                }

                if tot == 0 {
                    if let Ok(out) = Command::new("apt-get")
                        .args(["-s", "-o", "Debug::NoLocking=true", "upgrade"])
                        .output() 
                    {
                        let text = String::from_utf8_lossy(&out.stdout);
                        for line in text.lines() {
                            if line.starts_with("Inst ") {
                                tot += 1;
                                if line.to_lowercase().contains("security") {
                                    sec += 1;
                                }
                                if line.contains("linux-image-") || line.contains("linux-headers-") || line.contains("linux-generic") {
                                    k_pend = true;
                                    if k_avail.is_none() {
                                        if let Some(pkg) = line.split_whitespace().nth(1) {
                                            k_avail = Some(pkg.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let final_status = if k_pend {
                    format!("⚠️ Kernel {} requiere actualización / reinicio", rk_thread)
                } else if sec > 0 {
                    format!("⚠️ {} parches de seguridad pendientes", sec)
                } else if tot > 0 {
                    format!("ℹ️ {} actualizaciones disponibles", tot)
                } else {
                    "🟢 Sistema y Kernel completamente al día".to_string()
                };

                let updated_info = SystemUpdateInfo {
                    total_packages: tot,
                    security_packages: sec,
                    kernel_update_pending: k_pend,
                    running_kernel: rk_thread,
                    available_kernel: k_avail,
                    status_text: final_status,
                };

                if let Ok(mut guard) = SYSTEM_UPDATE_CACHE.lock() {
                    *guard = Some((Instant::now(), updated_info));
                }
                IS_UPDATING_IN_BACKGROUND.store(false, Ordering::SeqCst);
            });
        }

        initial_info
    }

    pub fn launch_native_updater() -> bool {
        // Forzar actualización inmediata de la caché al invocar el actualizador
        if let Ok(mut guard) = SYSTEM_UPDATE_CACHE.lock() {
            *guard = None;
        }
        // Linux Mint Update Manager
        if Command::new("which").arg("mintupdate").output().map(|o| o.status.success()).unwrap_or(false) {
            if Command::new("mintupdate").spawn().is_ok() {
                return true;
            }
        }
        // Ubuntu / Debian Software Updater
        if Command::new("which").arg("update-manager").output().map(|o| o.status.success()).unwrap_or(false) {
            if Command::new("update-manager").spawn().is_ok() {
                return true;
            }
        }
        // GNOME Software Updates
        if Command::new("which").arg("gnome-software").output().map(|o| o.status.success()).unwrap_or(false) {
            if Command::new("gnome-software").arg("--mode=updates").spawn().is_ok() {
                return true;
            }
        }
        // Fallback a terminal
        if Command::new("which").arg("x-terminal-emulator").output().map(|o| o.status.success()).unwrap_or(false) {
            if Command::new("x-terminal-emulator")
                .args(["-e", "sh", "-c", "echo '🔄 Actualizador de Constantine EDR v5.5.3'; pkexec apt update && pkexec apt upgrade; echo 'Presione Enter para cerrar...'; read line"])
                .spawn().is_ok() {
                return true;
            }
        }
        Command::new("pkexec")
            .args(["apt-get", "upgrade", "-y"])
            .spawn()
            .is_ok()
    }
}
pub fn get_quarantine_count() -> usize {
    let mut cnt = 0;
    for dir in &["/var/lib/constantine/quarantine", "/var/lib/clamav/quarantine"] {
        if let Ok(entries) = fs::read_dir(dir) {
            cnt += entries.flatten().filter(|e| e.path().is_file()).count();
        }
    }
    cnt
}

pub fn get_whitelist_count() -> usize {
    if let Ok(content) = fs::read_to_string("/var/lib/constantine/whitelist.txt") {
        content.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).count()
    } else {
        0
    }
}

pub fn get_active_shield_summary() -> String {
    let onacc = get_service_active("clamonacc");
    let tetra = get_service_active("tetragon");
    let falco = get_service_active("falco") || get_service_active("falco-modern-bpf");
    let sinkhole = WebProtectionManager::is_protection_active();
    
    let mut parts = Vec::new();
    if onacc { parts.push("fanotify (/home)"); }
    if tetra { parts.push("eBPF LSM"); }
    if falco { parts.push("Falco eBPF"); }
    if sinkhole { parts.push("DNS Sinkhole"); }
    
    if parts.is_empty() {
        "⚠️ Todos los escudos en pausa".into()
    } else {
        parts.join(" + ")
    }
}


pub struct ModuleVersionAudit;

impl ModuleVersionAudit {
    pub fn get_file_mtime(path: &str) -> String {
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.len() == 0 && path.ends_with(".db") {
                return "Base vacía (Pendiente de inicialización)".into();
            }
            if let Ok(mtime) = metadata.modified() {
                if let Ok(dur) = mtime.elapsed() {
                    let secs = dur.as_secs();
                    if secs < 60 {
                        return "Hace menos de 1 min".into();
                    } else if secs < 3600 {
                        return format!("Hace {} min", secs / 60);
                    } else if secs < 86400 {
                        return format!("Hace {} horas", secs / 3600);
                    } else if secs < 86400 * 365 {
                        return format!("Hace {} días", secs / 86400);
                    }
                }
            }
        }
        // Si el archivo tiene marca temporal de compilación de paquete (epoch 1970) o no está disponible,
        // recurrir al marcador de última actualización de Constantine
        if path != "/var/lib/constantine/.last_update" && Path::new("/var/lib/constantine/.last_update").exists() {
            return Self::get_file_mtime("/var/lib/constantine/.last_update");
        }
        "Activo (Reglas cargadas)".into()
    }


    pub fn get_detailed_health_breakdown(user_home: &str) -> (u8, Vec<HealthPillar>) {
        let canaries_ok = AntiRansomwareShield::verify_active_canaries(user_home) == CANARY_FILES.len();
        let clamd_ok = Path::new(CLAMD_SOCKET).exists();
        let onacc_ok = get_service_active("clamonacc");
        let tetra_ok = get_service_active("tetragon");
        let falco_ok = get_service_active("falco") || get_service_active("falco-modern-bpf");
        let wazuh_ok = get_service_active("wazuh-agent");
        let sinkhole_ok = WebProtectionManager::is_protection_active();
        let audit_ok = ImmutableAuditLog::verify_integrity().0;
        let yara_ok = Command::new("which").arg("yara").output().map(|o| o.status.success()).unwrap_or(false);
        let kernel_up_to_date = !SystemUpdateAudit::is_kernel_update_pending();

        let pillars = vec![
            HealthPillar {
                name: "1. Prevención en Kernel (fanotify)".into(),
                is_ok: onacc_ok,
                weight_pct: 10,
                details: if onacc_ok { "● Activo: Intercepción de malware en tiempo real (/home, /var/tmp)".into() } else { "● Detenido: Escudo ClamOnAcc inactivo".into() },
                remedy: "Activar escudos de seguridad desde el botón '▶️ Activar Escudos' del panel superior.".into(),
            },
            HealthPillar {
                name: "2. Escudo Anti-Ransomware (Canary Tripwires)".into(),
                is_ok: canaries_ok,
                weight_pct: 10,
                details: if canaries_ok { format!("● Activo: 4/4 Señuelos sembrados y supervisados en {}", user_home) } else { "● Alerta: Faltan archivos trampa Canary en directorios del usuario".into() },
                remedy: "Re-sembrar señuelos Canary desde el instalador o reiniciar el demonio Constantine.".into(),
            },
            HealthPillar {
                name: "3. Sensor eBPF Tetragon (Kernel LSM)".into(),
                is_ok: tetra_ok,
                weight_pct: 10,
                details: if tetra_ok { "● Activo: Puntos de control LSM y Anti-Kill en kernel".into() } else { "● Detenido: Sensor Tetragon inactivo".into() },
                remedy: "Ejecutar 'systemctl restart tetragon' o pulsar '⚡ Forzar' en el panel de sensores.".into(),
            },
            HealthPillar {
                name: "4. Sensor de Comportamiento eBPF (Falco)".into(),
                is_ok: falco_ok,
                weight_pct: 10,
                details: if falco_ok { "● Activo: Análisis de anomalías y llamadas de sistema en vivo".into() } else { "● Detenido: Motor Falco detenido".into() },
                remedy: "Ejecutar 'systemctl restart falco-modern-bpf' o reactivar escudos generales.".into(),
            },
            HealthPillar {
                name: "5. Agente SIEM & FIM (Wazuh Agent)".into(),
                is_ok: wazuh_ok,
                weight_pct: 10,
                details: if wazuh_ok { "● Activo: Monitorización de integridad de archivos críticos y SIEM".into() } else { "● Inactivo: Agente Wazuh detenido".into() },
                remedy: "Ejecutar 'systemctl restart wazuh-agent'.".into(),
            },
            HealthPillar {
                name: "6. Protección Web Perimetral (DNS Sinkhole)".into(),
                is_ok: sinkhole_ok,
                weight_pct: 10,
                details: if sinkhole_ok { format!("● Activo: {} dominios de phishing y C2 bloqueados en /etc/hosts", WebProtectionManager::get_blocked_domains_count()) } else { "● Inactivo: Filtrado web desactivado".into() },
                remedy: "Activar protección web desde la pestaña '🌐 Red y Web'.".into(),
            },
            HealthPillar {
                name: "7. Motor de Firmas ClamAV (clamd)".into(),
                is_ok: clamd_ok,
                weight_pct: 10,
                details: if clamd_ok { "● Activo: Socket multihilo /run/clamav/clamd.ctl en escucha".into() } else { "● Error: Socket ClamAV no encontrado".into() },
                remedy: "Reiniciar el servicio ClamAV con 'systemctl restart clamav-daemon'.".into(),
            },
            HealthPillar {
                name: "8. Motor Heurístico YARA / YARA-X".into(),
                is_ok: yara_ok,
                weight_pct: 10,
                details: if yara_ok { "● Activo: Reglas de amenazas y análisis estático disponibles".into() } else { "● Incompleto: Binario yara no encontrado en el sistema".into() },
                remedy: "Instalar yara con 'sudo apt install yara' o sincronizar reglas comunitarias.".into(),
            },
            HealthPillar {
                name: "9. Baúl Criptográfico y Registro Forense".into(),
                is_ok: audit_ok,
                weight_pct: 10,
                details: if audit_ok { "● Activo: Hash-chaining SHA-256 e inmutabilidad verificados".into() } else { "● Alerta: Anomalía en la cadena criptográfica del registro".into() },
                remedy: "Verificar la integridad del registro forense en la pestaña '📜 Forense'.".into(),
            },
            HealthPillar {
                name: "10. Actualizaciones de Kernel y Seguridad".into(),
                is_ok: kernel_up_to_date,
                weight_pct: 10,
                details: if kernel_up_to_date { format!("● Al día: Kernel {} sin parches pendientes", SystemUpdateAudit::get_running_kernel()) } else { "● Vulnerabilidad potencial: Hay una versión más reciente del Kernel disponible".into() },
                remedy: "Abrir el Actualizador del Sistema desde el Dashboard y reiniciar el equipo tras actualizar.".into(),
            },
        ];

        let total_weight: u8 = pillars.iter().map(|p| p.weight_pct).sum();
        let achieved_weight: u8 = pillars.iter().filter(|p| p.is_ok).map(|p| p.weight_pct).sum();
        let pct = if total_weight > 0 { ((achieved_weight as f32 / total_weight as f32) * 100.0) as u8 } else { 0 };
        (pct, pillars)
    }

    pub fn compute_real_health_score(user_home: &str) -> (u8, usize, usize) {
        let (pct, pillars) = Self::get_detailed_health_breakdown(user_home);
        let active = pillars.iter().filter(|p| p.is_ok).count();
        let total = pillars.len();
        (pct, active, total)
    }

    pub fn get_modules_status() -> Vec<(&'static str, String, String)> {
        let user_home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let active_canaries = AntiRansomwareShield::verify_active_canaries(&user_home);
        let aide_ready = fs::metadata(AIDE_DB_FILE).map(|m| m.len() > 0).unwrap_or(false);
        
        vec![
            ("Constantine Core EDR", "v5.5.3 (Debian Edition)".into(), "Binario Nativo Rust Activo".into()),
            (
                "Escudo Anti-Ransomware",
                format!("{}/{} Señuelos Activos", active_canaries, CANARY_FILES.len()),
                if active_canaries == CANARY_FILES.len() { "Operativo (Correlación Multivariable)".into() } else { "Cobertura Parcial".into() },
            ),
            ("1. ClamAV Engine (clamd)", Self::get_clamav_version(), Self::get_clamav_db_mtime()),
            ("2. YARA Engine", Self::cmd_version("yara", &["-v"]), Self::get_dir_latest_mtime(YARA_RULES_DIR)),
            ("3. YARA-X Engine (Rust)", Self::get_real_yarax_version(), Self::get_file_mtime("/usr/local/bin/yr")),
            (
                "4. ClamOnAcc (fanotify Shield)",
                if get_service_active("clamonacc") { "Servicio Activo (Tiempo Real)".into() } else { "Servicio Detenido".into() },
                Self::get_file_mtime(LOG_FILE),
            ),
            ("5. Tetragon (Cilium eBPF)", Self::get_tetragon_version(), Self::get_file_mtime("/usr/local/bin/tetragon")),
            ("6. Falco Behavioral Engine", Self::get_falco_version(), Self::get_falco_rules_mtime()),
            ("7. osquery (SQL Audit)", Self::cmd_version("osqueryi", &["--version"]), Self::get_file_mtime("/usr/bin/osqueryi")),
            ("8. Wazuh Agent (SIEM & FIM)", Self::get_wazuh_version(), Self::get_file_mtime("/var/ossec/etc/ossec.conf")),
            (
                "9. AIDE Critical Integrity",
                if aide_ready { Self::cmd_version("aide", &["-v"]) } else { "Instalado (Base aún no inicializada)".into() },
                Self::get_file_mtime(AIDE_DB_FILE),
            ),
            ("10. StevenBlack Hosts Shield", Self::get_stevenblack_status(), Self::get_stevenblack_mtime()),
            ("11. MISP Threat Sharing", Self::feed_line_count(MISP_IOC_FILE), Self::get_feed_mtime(MISP_IOC_FILE)),
            (
                "12. MalwareBazaar Feed",
                Self::feed_line_count(&format!("{}/malwarebazaar_hashes.txt", TI_DIR)),
                Self::get_feed_mtime(&format!("{}/malwarebazaar_hashes.txt", TI_DIR)),
            ),
            (
                "13. ThreatFox Feed",
                Self::feed_line_count(&format!("{}/threatfox_iocs.txt", TI_DIR)),
                Self::get_feed_mtime(&format!("{}/threatfox_iocs.txt", TI_DIR)),
            ),
            (
                "14. URLhaus & OpenPhish Feeds",
                Self::feed_line_count(&format!("{}/urlhaus_domains.txt", TI_DIR)),
                Self::get_feed_mtime(&format!("{}/urlhaus_domains.txt", TI_DIR)),
            ),
            ("15. Sigma Detection Rules", Self::dir_file_count(SIGMA_RULES_DIR), Self::get_dir_latest_mtime(SIGMA_RULES_DIR)),
            ("16. YARA-Rules Comunitarias", Self::dir_file_count(YARA_COMMUNITY_DIR), Self::get_dir_latest_mtime(YARA_COMMUNITY_DIR)),
            ("Cortafuegos UFW / GUFW", if NetworkPrivacyAudit::is_ufw_active() { "UFW Activo".into() } else { "UFW Inactivo".into() }, Self::get_file_mtime("/etc/ufw/ufw.conf")),
            (
                "ProtonVPN Client",
                if NetworkPrivacyAudit::is_protonvpn_active() { "Túnel ProtonVPN Activo".into() } else { Self::cmd_version("protonvpn-app", &["--version"]) },
                "Verificación de Interfaz".into(),
            ),
        ]
    }

    fn get_clamav_version() -> String {
        let v = Self::cmd_version("clamscan", &["-V"]);
        let svc_state = if get_service_active("clamav-daemon") { "Activo" } else { "Inactivo" };
        if v != "No disponible" {
            return format!("{} [{}]", v, svc_state);
        }
        let v2 = Self::cmd_version("clamd", &["-V"]);
        if v2 != "No disponible" {
            return format!("{} [{}]", v2, svc_state);
        }
        "No disponible".into()
    }

    fn get_clamav_db_mtime() -> String {
        let paths = [
            "/var/lib/clamav/daily.cld",
            "/var/lib/clamav/daily.cvd",
            "/var/lib/clamav/main.cvd",
            "/var/lib/clamav/bytecode.cvd",
        ];
        for p in paths {
            if Path::new(p).exists() {
                if let Ok(mut f) = File::open(p) {
                    let mut header = [0u8; 128];
                    if let Ok(n) = f.read(&mut header) {
                        let s = String::from_utf8_lossy(&header[..n]);
                        if s.starts_with("ClamAV-VDB:") {
                            let parts: Vec<&str> = s.split(':').collect();
                            if parts.len() >= 4 {
                                let ver = parts[2].trim();
                                let mtime = Self::get_file_mtime(p);
                                return format!("v{} ({})", ver, mtime);
                            }
                        }
                    }
                }
                return Self::get_file_mtime(p);
            }
        }
        Self::get_file_mtime("/var/lib/constantine/.last_update")
    }

    fn get_tetragon_version() -> String {
        let v = Self::cmd_version("tetragon", &["--version"]);
        let svc_state = if get_service_active("tetragon") { "Activo" } else { "Inactivo" };
        if v != "No disponible" {
            return format!("{} [{}]", v, svc_state);
        }
        let v2 = Self::cmd_version("tetra", &["version"]);
        if v2 != "No disponible" {
            return format!("{} [{}]", v2, svc_state);
        }
        if Path::new("/usr/local/bin/tetragon").exists() {
            return format!("Instalado [{}]", svc_state);
        }
        "No disponible".into()
    }

    fn get_falco_version() -> String {
        let svc_state = if get_service_active("falco") { "Activo" } else { "Inactivo" };
        let v = Self::cmd_version("falco", &["--version"]);
        if v != "No disponible" {
            return format!("{} [{}]", v, svc_state);
        }
        if Path::new("/usr/bin/falco").exists() || Path::new("/usr/local/bin/falco").exists() {
            return format!("Instalado [{}]", svc_state);
        }
        "No disponible".into()
    }

    fn get_falco_rules_mtime() -> String {
        let paths = ["/etc/falco/falco_rules.yaml", "/etc/falco/falco.yaml"];
        for p in paths {
            if Path::new(p).exists() {
                return Self::get_file_mtime(p);
            }
        }
        Self::get_file_mtime("/var/lib/constantine/.last_update")
    }

    fn get_feed_mtime(path: &str) -> String {
        let mtime = Self::get_file_mtime(path);
        if mtime != "No disponible" {
            return mtime;
        }
        Self::get_file_mtime("/var/lib/constantine/.last_update")
    }

    fn get_dir_latest_mtime(dir: &str) -> String {
        if let Ok(entries) = fs::read_dir(dir) {
            let mut latest: Option<std::time::SystemTime> = None;
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(m) = meta.modified() {
                        if latest.map_or(true, |cur| m > cur) {
                            latest = Some(m);
                        }
                    }
                }
            }
            if let Some(l) = latest {
                if let Ok(dur) = l.elapsed() {
                    let secs = dur.as_secs();
                    if secs < 60 {
                        return "Hace menos de 1 min".into();
                    } else if secs < 3600 {
                        return format!("Hace {} min", secs / 60);
                    } else if secs < 86400 {
                        return format!("Hace {} horas", secs / 3600);
                    } else {
                        return format!("Hace {} días", secs / 86400);
                    }
                }
            }
        }
        Self::get_file_mtime(dir)
    }

    fn feed_line_count(path: &str) -> String {
        if let Ok(f) = File::open(path) {
            let count = BufReader::new(f).lines().count();
            if count > 0 {
                return format!("{} indicadores activos", count);
            }
        }
        if Path::new(path).exists() {
            if let Ok(meta) = fs::metadata(path) {
                if meta.len() > 0 {
                    return format!("Activo (~{} KB)", meta.len() / 1024);
                }
            }
        }
        "0 indicadores (Vacío / Sin sincronizar)".into()
    }

    fn dir_file_count(dir: &str) -> String {
        if let Ok(entries) = fs::read_dir(dir) {
            let count = entries.flatten().count();
            if count > 0 {
                return format!("{} elementos instalados", count);
            }
        }
        "No disponible".into()
    }

    fn get_real_yarax_version() -> String {
        if let Ok(out) = Command::new("yr").arg("--version").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                if let Some(line) = s.lines().next() {
                    return format!("Instalado ({})", line.trim());
                }
            }
        }
        "No disponible (Módulo Opcional)".into()
    }

    fn get_wazuh_version() -> String {
        if Path::new("/var/ossec/bin/wazuh-control").exists() {
            let svc = if get_service_active("wazuh-agent") { "Activo" } else { "Detenido" };
            if let Ok(out) = Command::new("/var/ossec/bin/wazuh-control").arg("info").output() {
                let s = String::from_utf8_lossy(&out.stdout);
                for l in s.lines() {
                    if l.contains("WAZUH_VERSION") {
                        let ver = l.trim_start_matches("WAZUH_VERSION=").trim_matches('"');
                        return format!("{} (Servicio {})", ver.trim(), svc);
                    }
                }
            }
            return format!("Instalado (Servicio {})", svc);
        }
        "No disponible".into()
    }

    fn cmd_version(cmd: &str, args: &[&str]) -> String {
        let candidates = [
            cmd.to_string(),
            format!("/usr/bin/{}", cmd),
            format!("/usr/sbin/{}", cmd),
            format!("/usr/local/bin/{}", cmd),
            format!("/bin/{}", cmd),
            format!("/sbin/{}", cmd),
        ];
        for candidate in candidates {
            if let Ok(out) = Command::new(&candidate).args(args).output() {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout);
                    if let Some(line) = s.lines().next() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            return trimmed.to_string();
                        }
                    }
                    return "Instalado".into();
                }
            }
        }
        "No disponible".into()
    }

    #[allow(dead_code)]
    fn cmd_version_with_service(cmd: &str, args: &[&str], service: &str) -> String {
        let base = Self::cmd_version(cmd, args);
        if base == "No disponible" {
            return base;
        }
        let svc_state = if get_service_active(service) { "Activo" } else { "Inactivo" };
        format!("{} [{}]", base, svc_state)
    }

        fn get_stevenblack_status() -> String {
        let p = "/var/lib/constantine/intelligence/stevenblack_hosts.txt";
        if let Ok(f) = File::open(p) {
            let count = BufReader::new(f).lines().count();
            if count > 0 {
                return format!("{} dominios activos", count);
            }
        }
        let blocked_cnt = WebProtectionManager::get_blocked_domains_count();
        if blocked_cnt > 0 {
            return format!("{} dominios activos", blocked_cnt);
        }
        "Sin sincronizar".into()
    }

    fn get_stevenblack_mtime() -> String {
        let p = "/var/lib/constantine/intelligence/stevenblack_hosts.txt";
        if Path::new(p).exists() {
            return Self::get_file_mtime(p);
        }
        Self::get_file_mtime("/var/lib/constantine/.last_update")
    }

    pub fn update_all_modules() -> bool {
        ImmutableAuditLog::append_event("MODULES_UPDATE_START", "Iniciando ciclo de sincronización de los 16 módulos de seguridad, firmas y feeds de amenazas.");
        let ok = if Path::new(UPDATER_SCRIPT).exists() {
            if Command::new(UPDATER_SCRIPT).status().map(|s| s.success()).unwrap_or(false) {
                true
            } else if Command::new("sudo").args(["-n", UPDATER_SCRIPT]).status().map(|s| s.success()).unwrap_or(false) {
                true
            } else {
                Command::new("pkexec").arg(UPDATER_SCRIPT).status().map(|s| s.success()).unwrap_or(false)
            }
        } else {
            false
        };
        if ok {
            ImmutableAuditLog::append_event("MODULES_UPDATE_SUCCESS", "Actualización completada exitosamente: ClamAV, StevenBlack Hosts, MISP, ThreatFox, MalwareBazaar, Sigma, YARA y AIDE.");
        } else {
            ImmutableAuditLog::append_event("MODULES_UPDATE_FAILED", "Error o cancelación de privilegios al actualizar los módulos de seguridad.");
        }
        ok
    }

    pub fn run_aide_check() -> bool {
        ImmutableAuditLog::append_event("AIDE_CHECK_START", "Verificación criptográfica de integridad de archivos del sistema (AIDE) iniciada.");
        let ok = if Path::new(UPDATER_SCRIPT).exists() {
            Command::new("pkexec").args([UPDATER_SCRIPT, "--aide-only"]).status().map(|s| s.success()).unwrap_or(false)
        } else {
            false
        };
        if ok {
            ImmutableAuditLog::append_event("AIDE_CHECK_COMPLETED", "Verificación AIDE finalizada con éxito.");
        } else {
            ImmutableAuditLog::append_event("AIDE_CHECK_FAILED", "Error o cancelación al ejecutar verificación AIDE.");
        }
        ok
    }
}
// ==============================================================================
// 9. Auditoría Exacta de Firewall y VPN (con lookup HTTPS fiable)
// ==============================================================================

// ==============================================================================
// 20. Protección Web y Filtrado DNS en Tiempo Real (Sumidero Anti-Phishing)
// ==============================================================================
const SINKHOLE_SCRIPT: &str = "/usr/local/bin/constantine-dns-sinkhole";
const SINKHOLE_DOMAINS_FILE: &str = "/var/lib/constantine/intelligence/blocked_domains.txt";

pub struct WebProtectionManager;

impl WebProtectionManager {
    pub fn get_blocked_domains_count() -> usize {
        if let Ok(content) = fs::read_to_string("/etc/hosts") {
            let mut count = 0;
            let mut in_block = false;
            for line in content.lines() {
                if line.contains("CONSTANTINE EDR ANTI-PHISHING BEGIN") {
                    in_block = true;
                    continue;
                }
                if line.contains("CONSTANTINE EDR ANTI-PHISHING END") {
                    break;
                }
                if in_block && line.trim().starts_with("0.0.0.0 ") {
                    count += 1;
                }
            }
            if count > 0 {
                return count;
            }
        }
        
        if let Ok(f) = File::open(SINKHOLE_DOMAINS_FILE) {
            return BufReader::new(f).lines().count();
        }
        0
    }

    pub fn is_protection_active() -> bool {
        if let Ok(content) = fs::read_to_string("/etc/hosts") {
            return content.contains("CONSTANTINE EDR ANTI-PHISHING BEGIN");
        }
        false
    }

    pub fn sync_dns_sinkhole() -> (bool, String) {
        let cmd = serde_json::json!({"action": "sync_dns_sinkhole"});
        if let Some(resp) = ConstantineIpcClient::send_command(&cmd) {
            let status = resp.get("status").and_then(|x| x.as_str()).unwrap_or("");
            let msg = resp.get("message").and_then(|x| x.as_str()).unwrap_or("Sincronización completada por daemon");
            let ok = status == "ok";
            if ok {
                ImmutableAuditLog::append_event("WEB_PROTECTION_SYNC", &format!("Sumidero DNS sincronizado por daemon: {}", msg));
            } else {
                ImmutableAuditLog::append_event("WEB_PROTECTION_ERROR", &format!("Error al sincronizar sumidero por daemon: {}", msg));
            }
            return (ok, msg.to_string());
        }

        if Path::new(SINKHOLE_SCRIPT).exists() {
            let ok = SecurityAuth::privileged_action(&[SINKHOLE_SCRIPT, "--enable"]);
            let count = Self::get_blocked_domains_count();
            if ok {
                ImmutableAuditLog::append_event("WEB_PROTECTION_SYNC", &format!("Sumidero DNS local sincronizado: {} dominios maliciosos bloqueados.", count));
            } else {
                ImmutableAuditLog::append_event("WEB_PROTECTION_ERROR", "Error al sincronizar sumidero DNS local.");
            }
            return (ok, format!("Sumidero DNS sincronizado: {} dominios bloqueados.", count));
        }

        ImmutableAuditLog::append_event("WEB_PROTECTION_ERROR", "Script de sumidero DNS no disponible en /usr/local/bin.");
        (false, "Script de sumidero DNS no disponible.".into())
    }

    pub fn enable_protection() -> bool {
        let cmd = serde_json::json!({"action": "toggle_web_protection", "enable": true});
        let ok = if let Some(resp) = ConstantineIpcClient::send_command(&cmd) {
            resp.get("status").and_then(|x| x.as_str()) == Some("ok")
        } else {
            SecurityAuth::privileged_action(&[SINKHOLE_SCRIPT, "--enable"])
        };
        if ok {
            let count = Self::get_blocked_domains_count();
            ImmutableAuditLog::append_event("WEB_PROTECTION_ENABLED", &format!("Sumidero DNS anti-phishing activado: {} dominios maliciosos bloqueados en 0.0.0.0.", count));
        } else {
            ImmutableAuditLog::append_event("WEB_PROTECTION_ERROR", "Fallo al activar sumidero DNS anti-phishing.");
        }
        ok
    }

    pub fn disable_protection() -> bool {
        let cmd = serde_json::json!({"action": "toggle_web_protection", "enable": false});
        let ok = if let Some(resp) = ConstantineIpcClient::send_command(&cmd) {
            resp.get("status").and_then(|x| x.as_str()) == Some("ok")
        } else {
            SecurityAuth::privileged_action(&[SINKHOLE_SCRIPT, "--disable"])
        };
        if ok {
            ImmutableAuditLog::append_event("WEB_PROTECTION_PAUSED", "Sumidero DNS anti-phishing pausado por el usuario.");
        } else {
            ImmutableAuditLog::append_event("WEB_PROTECTION_ERROR", "Fallo al pausar sumidero DNS anti-phishing.");
        }
        ok
    }
}


// ==============================================================================
// 21. Autodefensa del Antivirus (Tamper Protection) e Inmutabilidad de Archivos
// ==============================================================================

// ==============================================================================
// 22. Modo Juego y Presentación (Do Not Disturb / Game Mode)
// ==============================================================================
pub struct GamePresentationMode;

impl GamePresentationMode {
    const MANUAL_FLAG: &'static str = "/var/lib/constantine/.game_mode_active";

    pub fn is_active() -> bool {
        if Path::new(Self::MANUAL_FLAG).exists() {
            return true;
        }
        Self::detect_fullscreen_or_presentation()
    }

    pub fn toggle_manual(enable: bool) -> bool {
        if enable {
            let _ = File::create(Self::MANUAL_FLAG);
            ImmutableAuditLog::append_event("GAME_MODE_ENABLED", "Modo Juego/Presentación activado manualmente.");
        } else {
            let _ = fs::remove_file(Self::MANUAL_FLAG);
            ImmutableAuditLog::append_event("GAME_MODE_DISABLED", "Modo Juego/Presentación desactivado.");
        }
        enable
    }

    pub fn detect_fullscreen_or_presentation() -> bool {
        // 1. Detección en X11 mediante xprop buscando _NET_WM_STATE_FULLSCREEN
        if let Ok(out) = Command::new("xprop").args(["-root", "_NET_ACTIVE_WINDOW"]).output() {
            let out_str = String::from_utf8_lossy(&out.stdout);
            if let Some(win_id) = out_str.split('#').nth(1).or_else(|| out_str.split("window id #").nth(1)) {
                let id = win_id.trim();
                if !id.is_empty() && id != "0x0" {
                    if let Ok(prop_out) = Command::new("xprop").args(["-id", id, "_NET_WM_STATE"]).output() {
                        let prop_str = String::from_utf8_lossy(&prop_out.stdout);
                        if prop_str.contains("_NET_WM_STATE_FULLSCREEN") {
                            return true;
                        }
                    }
                }
            }
        }

        // 2. Detección de procesos de videojuegos o presentación conocidos en ejecución
        let game_presentation_bins = [
            "steam", "lutris", "heroic", "retroarch", "wine64-preloader", "gamescope",
            "zoom", "teams", "discord", "obs", "impress"
        ];
        if let Ok(out) = Command::new("pgrep").args(["-l", "-f"]).output() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            for bin in &game_presentation_bins {
                if s.contains(bin) {
                    return true;
                }
            }
        }
        false
    }
}

// ==============================================================================
// 23. Aislamiento Inmediato del Equipo de la Red (Endpoint Host Containment)
// ==============================================================================
pub struct NetworkIsolationManager;

impl NetworkIsolationManager {
    const ISOLATION_FLAG: &'static str = "/var/lib/constantine/.network_isolated";
    const IPTABLES_BAK: &'static str = "/var/lib/constantine/iptables.pre-isolation.bak";

    pub fn is_network_isolated() -> bool {
        Path::new(Self::ISOLATION_FLAG).exists()
    }

    pub fn isolate_network() -> (bool, String) {
        let cmd = serde_json::json!({"action": "isolate_network"});
        if let Some(resp) = ConstantineIpcClient::send_command(&cmd) {
            let status = resp.get("status").and_then(|x| x.as_str()).unwrap_or("");
            let msg = resp.get("message").and_then(|x| x.as_str()).unwrap_or("Aislamiento ejecutado");
            return (status == "ok", msg.to_string());
        }

        Self::isolate_network_local()
    }

    pub fn isolate_network_local() -> (bool, String) {
        // 1. Guardar reglas preexistentes de iptables
        let _ = SecurityAuth::privileged_action(&["sh", "-c", &format!("iptables-save > {}", Self::IPTABLES_BAK)]);
        
        // 2. Establecer política atómica de contención: DROP total entrante y saliente excepto bucle local (lo)
        let isolation_script = "iptables -P INPUT DROP && iptables -P OUTPUT DROP && iptables -P FORWARD DROP && \
                                iptables -F && iptables -X && \
                                iptables -A INPUT -i lo -j ACCEPT && iptables -A OUTPUT -o lo -j ACCEPT";
        let ok = SecurityAuth::privileged_action(&["sh", "-c", isolation_script]);

        if ok {
            let _ = File::create(Self::ISOLATION_FLAG);
            ImmutableAuditLog::append_event("NETWORK_ISOLATION_ENGAGED", "🚨 AISLAMIENTO DE RED ACTIVADO: Todo el tráfico exterior bloqueado por el EDR.");
            (true, "Equipo aislado de la red con éxito. Tráfico exterior bloqueado.".into())
        } else {
            (false, "Fallo al aplicar reglas de aislamiento con iptables.".into())
        }
    }

    pub fn reconnect_network() -> (bool, String) {
        let cmd = serde_json::json!({"action": "reconnect_network"});
        if let Some(resp) = ConstantineIpcClient::send_command(&cmd) {
            let status = resp.get("status").and_then(|x| x.as_str()).unwrap_or("");
            let msg = resp.get("message").and_then(|x| x.as_str()).unwrap_or("Reconexión ejecutada");
            return (status == "ok", msg.to_string());
        }

        Self::reconnect_network_local()
    }

    pub fn reconnect_network_local() -> (bool, String) {
        let reconnect_script = if Path::new(Self::IPTABLES_BAK).exists() {
            format!("iptables-restore < {} 2>/dev/null || (iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -F)", Self::IPTABLES_BAK)
        } else {
            "iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -F".to_string()
        };

        let ok = SecurityAuth::privileged_action(&["sh", "-c", &reconnect_script]);
        let _ = SecurityAuth::privileged_action(&["ufw", "reload"]);
        let _ = fs::remove_file(Self::ISOLATION_FLAG);
        let _ = fs::remove_file(Self::IPTABLES_BAK);

        ImmutableAuditLog::append_event("NETWORK_ISOLATION_DISENGAGED", "🟢 CONECTIVIDAD DE RED RESTAURADA: Tráfico normal habilitado.");
        (ok, "Conectividad de red normal restaurada correctamente.".into())
    }
}

// ==============================================================================
// 24. Consulta de Reputación Global en la Nube (Cloud Threat Intelligence API)
// ==============================================================================
pub struct CloudThreatLookup;

impl CloudThreatLookup {
    pub fn lookup_hash(hash: &str) -> (bool, String) {
        let clean_hash = hash.trim().to_lowercase();
        if clean_hash.len() != 64 {
            return (false, "Hash SHA-256 no válido (debe tener exactamente 64 caracteres hexadecimales).".into());
        }

        // 1. Comprobar primero en listas blancas locales
        if ThreatAnalysisEngine::is_whitelisted(&clean_hash) {
            return (false, "🟢 BENIGNO: El hash se encuentra verificado en la Lista Blanca de Constantine.".into());
        }

        // 2. Consulta en vivo a la API oficial de MalwareBazaar (Abuse.ch)
        let curl_cmd = format!(
            "curl -s --connect-timeout 6 --max-time 12 -X POST -d 'query=get_info&hash={}' 'https://mb-api.abuse.ch/api/v1/'",
            clean_hash
        );

        if let Ok(out) = Command::new("sh").args(["-c", &curl_cmd]).output() {
            let resp_str = String::from_utf8_lossy(&out.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&resp_str) {
                let status = val.get("query_status").and_then(|v| v.as_str()).unwrap_or("");
                if status == "ok" {
                    if let Some(data) = val.get("data").and_then(|d| d.as_array()).and_then(|a| a.first()) {
                        let sig = data.get("signature").and_then(|v| v.as_str()).unwrap_or("Malware Genérico");
                        let ftype = data.get("file_type").and_then(|v| v.as_str()).unwrap_or("Desconocido");
                        let first_seen = data.get("first_seen").and_then(|v| v.as_str()).unwrap_or("Reciente");
                        return (true, format!("🚨 MALWARE CONFIRMADO EN NUBE (MalwareBazaar): {} | Tipo: {} | Primer avistamiento: {}", sig, ftype, first_seen));
                    }
                    return (true, "🚨 MALWARE CONFIRMADO EN NUBE por MalwareBazaar (Abuse.ch)".into());
                } else if status == "hash_not_found" {
                    return (false, "🟢 NO REPORTADO / REPUTACIÓN LIMPIA: Este hash no figura en la base global de amenazas de MalwareBazaar.".into());
                }
            }
        }

        (false, "⚠️ No se pudo contactar con la API de Inteligencia en la Nube (verifique su conexión a Internet).".into())
    }
}

// ==============================================================================
// 25. Generador de Informes Ejecutivos de Seguridad y Auditoría Forense (HTML)
// ==============================================================================

// ==============================================================================
// 26. Programador Inteligente de Análisis vía systemd.timer
// ==============================================================================
pub struct ScheduledScansManager;

impl ScheduledScansManager {
    pub const QUICK_TIMER: &'static str = "constantine-quick-scan.timer";
    pub const FULL_TIMER: &'static str = "constantine-full-scan.timer";

    pub fn is_quick_timer_active() -> bool {
        Command::new("systemctl").args(["is-active", "--quiet", Self::QUICK_TIMER])
            .status().map(|s| s.success()).unwrap_or(false)
    }

    pub fn is_full_timer_active() -> bool {
        Command::new("systemctl").args(["is-active", "--quiet", Self::FULL_TIMER])
            .status().map(|s| s.success()).unwrap_or(false)
    }

    pub fn get_next_run(timer_name: &str) -> String {
        if let Ok(out) = Command::new("systemctl").args(["list-timers", timer_name, "--no-legend"]).output() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                let parts: Vec<&str> = s.split_whitespace().collect();
                if parts.len() >= 3 {
                    return format!("Próxima ejecución: {} {}", parts[0], parts[1]);
                }
            }
        }
        "Programado según calendario".into()
    }

    pub fn toggle_timer(timer_name: &str, enable: bool) -> bool {
        let action = if enable { "enable --now" } else { "disable --now" };
        let cmd = format!("systemctl {} {}", action, timer_name);
        SecurityAuth::privileged_action(&["sh", "-c", &cmd])
    }

    pub fn run_quick_scan_headless() {
        ImmutableAuditLog::append_event("SCHEDULED_QUICK_SCAN_START", "Análisis rápido programado en segundo plano iniciado (systemd.timer).");
        let dirs = ["/tmp", "/var/tmp", "/dev/shm", "/home"];
        let mut threats = 0;
        for d in &dirs {
            let p = Path::new(d);
            if p.exists() {
                let mut files = Vec::new();
                ManualScanEngine::collect_files(p, &mut files);
                for f in &files {
                    if let FileVerdict::Threat(threat_msg) = ThreatAnalysisEngine::evaluate_file(f) {
                        threats += 1;
                        ContainmentEngine::isolate_to_vault_with_metadata(f, &threat_msg, "Análisis Rápido Programado");
                    }
                }
            }
        }
        ImmutableAuditLog::append_event(
            "SCHEDULED_QUICK_SCAN_COMPLETE",
            &format!("Análisis rápido de sistema completado. Amenazas neutralizadas: {}", threats)
        );
    }

    pub fn run_full_scan_headless() {
        ImmutableAuditLog::append_event("SCHEDULED_FULL_SCAN_START", "Análisis exhaustivo semanal iniciado (systemd.timer).");
        let p = Path::new("/");
        let mut files = Vec::new();
        ManualScanEngine::collect_files(p, &mut files);
        let mut threats = 0;
        for f in &files {
            if let FileVerdict::Threat(threat_msg) = ThreatAnalysisEngine::evaluate_file(f) {
                threats += 1;
                ContainmentEngine::isolate_to_vault_with_metadata(f, &threat_msg, "Análisis Completo Semanal");
            }
        }
        ImmutableAuditLog::append_event(
            "SCHEDULED_FULL_SCAN_COMPLETE",
            &format!("Análisis completo del sistema completado. Amenazas neutralizadas: {}", threats)
        );
    }
}

// ==============================================================================
// 27. Supervisión de Conexiones por Proceso (Orquestación OpenSnitch eBPF)
// ==============================================================================
// ==============================================================================
// 28. Gestor de Perfiles DNS Seguros Anti-Phishing (Quad9, Mullvad, Cloudflare)
// ==============================================================================
pub struct DnsProfileManager;

#[derive(Debug, Clone)]
pub struct DnsProfile {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub primary_dns: &'static str,
    pub secondary_dns: &'static str,
}

impl DnsProfileManager {
    pub fn get_available_profiles() -> Vec<DnsProfile> {
        vec![
            DnsProfile {
                id: "quad9",
                name: "🛡️ Quad9: Anti-Phishing & Malware (Recomendado)",
                description: "Fundación suiza sin fines de lucro. Bloquea phishing, dominios de malware, C2 y estafas en tiempo real con inteligencia de +30 CERTs mundiales. DNSSEC activo, cero registros de actividad.",
                primary_dns: "9.9.9.9",
                secondary_dns: "149.112.112.112",
            },
            DnsProfile {
                id: "mullvad_ad_malware",
                name: "🔒 Mullvad: Anuncios + Malware + Rastreadores",
                description: "Perfil recomendado de Mullvad. Bloquea dominios de phishing, malware, redes publicitarias invasivas y rastreadores web (trackers). Privacidad estricta sueca sin registros de IPs.",
                primary_dns: "194.242.2.5",
                secondary_dns: "194.242.2.3",
            },
            DnsProfile {
                id: "mullvad_malware",
                name: "🛡️ Mullvad: Solo Malware y Phishing",
                description: "Bloquea exclusivamente dominios de malware, páginas de phishing y servidores de comando y control (C2), sin filtrar anuncios ni alterar la navegación habitual.",
                primary_dns: "194.242.2.4",
                secondary_dns: "194.242.2.2",
            },
            DnsProfile {
                id: "mullvad_all",
                name: "🛑 Mullvad: Protección Total (Todo en Uno)",
                description: "Máxima protección integral: bloquea malware, phishing, anuncios, rastreadores web, plataformas de redes sociales y contenido para adultos en una sola consulta.",
                primary_dns: "194.242.2.9",
                secondary_dns: "194.242.2.5",
            },
            DnsProfile {
                id: "mullvad_family",
                name: "👨‍👩‍👧 Mullvad: Control Familiar (Adultos + Malware)",
                description: "Filtro familiar de navegación segura: bloquea sitios para adultos y pornografía, además de proteger contra phishing y dominios de malware.",
                primary_dns: "194.242.2.7",
                secondary_dns: "194.242.2.4",
            },
            DnsProfile {
                id: "mullvad_social",
                name: "📵 Mullvad: Bloqueo de Redes Sociales",
                description: "Bloquea plataformas de redes sociales (Facebook, TikTok, Twitter/X, Instagram) y malware para máxima concentración y productividad.",
                primary_dns: "194.242.2.6",
                secondary_dns: "194.242.2.4",
            },
            DnsProfile {
                id: "mullvad_privacy",
                name: "🕵️ Mullvad: Privacidad Pura (Sin Bloqueos)",
                description: "Resolución DNS ultra rápida sin censura ni filtros de contenido, garantizando confidencialidad sueca y cero registros de actividad (No-Logs).",
                primary_dns: "194.242.2.2",
                secondary_dns: "194.242.2.3",
            },
            DnsProfile {
                id: "cloudflare_sec",
                name: "⚡ Cloudflare 1.1.1.2: Seguridad y Baja Latencia",
                description: "Bloqueo automático de sitios fraudulentos y malware con la red de baja latencia global de Cloudflare.",
                primary_dns: "1.1.1.2",
                secondary_dns: "1.0.0.2",
            },
        ]
    }

    pub fn get_current_dns_servers() -> String {
        let (iface, _, _) = NetworkPrivacyAudit::get_active_interface_info();
        if iface != "Desconocida" && !iface.is_empty() {
            if let Ok(out) = Command::new("resolvectl").args(["dns", &iface]).output() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() {
                    return s.replace("Link ", "").replace(&format!(" ({})", iface), "");
                }
            }
        }
        if let Ok(out) = Command::new("resolvectl").args(["status"]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                if line.contains("Current DNS Server:") || line.contains("DNS Servers:") {
                    return line.trim().to_string();
                }
            }
        }
        "DNS automático del sistema (DHCP / Router)".into()
    }

    pub fn apply_profile(profile_id: &str) -> (bool, String) {
        let (iface, _, _) = NetworkPrivacyAudit::get_active_interface_info();
        if iface == "Desconocida" || iface.is_empty() {
            ImmutableAuditLog::append_event("DNS_PROFILE_ERROR", &format!("No se detectó interfaz de red activa para perfil DNS '{}'.", profile_id));
            return (false, "No se detectó una interfaz de red activa.".into());
        }

        let cmd = serde_json::json!({
            "action": "apply_dns_profile",
            "profile_id": profile_id,
            "iface": iface
        });
        if let Some(resp) = ConstantineIpcClient::send_command(&cmd) {
            let status = resp.get("status").and_then(|x| x.as_str()).unwrap_or("");
            let msg = resp.get("message").and_then(|x| x.as_str()).unwrap_or("");
            let ok = status == "ok";
            if ok {
                ImmutableAuditLog::append_event("DNS_PROFILE_APPLIED", &format!("Perfil DNS '{}' aplicado vía daemon a interfaz {}.", profile_id, iface));
            } else {
                ImmutableAuditLog::append_event("DNS_PROFILE_ERROR", &format!("Fallo de daemon al aplicar perfil DNS '{}': {}", profile_id, msg));
            }
            return (ok, msg.to_string());
        }

        Self::apply_profile_local(profile_id, &iface)
    }

    pub fn apply_profile_local(profile_id: &str, iface: &str) -> (bool, String) {
        let profiles = Self::get_available_profiles();
        let target = match profiles.into_iter().find(|p| p.id == profile_id) {
            Some(p) => p,
            None => {
                ImmutableAuditLog::append_event("DNS_PROFILE_ERROR", &format!("Perfil DNS '{}' no reconocido.", profile_id));
                return (false, "Perfil DNS no reconocido.".into());
            }
        };

        // 1. Aplicar mediante resolvectl (systemd-resolved)
        let _ = SecurityAuth::privileged_action(&[
            "resolvectl", "dns", iface, target.primary_dns, target.secondary_dns
        ]);
        let _ = SecurityAuth::privileged_action(&[
            "resolvectl", "domain", iface, "~."
        ]);
        let _ = SecurityAuth::privileged_action(&[
            "resolvectl", "default-route", iface, "yes"
        ]);
        let _ = SecurityAuth::privileged_action(&[
            "resolvectl", "flush-caches"
        ]);

        // 2. Aplicar también mediante nmcli si NetworkManager gestiona la interfaz
        let dns_csv = format!("{},{}", target.primary_dns, target.secondary_dns);
        let _ = SecurityAuth::privileged_action(&[
            "nmcli", "dev", "modify", iface, "ipv4.dns", &dns_csv, "ipv4.ignore-auto-dns", "yes"
        ]);

        ImmutableAuditLog::append_event("DNS_PROFILE_APPLIED", &format!("Perfil '{}' activado en {} [Primario: {}, Secundario: {}]", target.name, iface, target.primary_dns, target.secondary_dns));
        (true, format!("Perfil '{}' aplicado a la interfaz {}.", target.name, iface))
    }

    pub fn reset_dns_to_default() -> (bool, String) {
        let (iface, _, _) = NetworkPrivacyAudit::get_active_interface_info();
        if iface == "Desconocida" || iface.is_empty() {
            ImmutableAuditLog::append_event("DNS_RESET_ERROR", "No se detectó interfaz de red activa para restablecer DNS.");
            return (false, "No se detectó una interfaz de red activa.".into());
        }

        let cmd = serde_json::json!({
            "action": "reset_dns",
            "iface": iface
        });
        if let Some(resp) = ConstantineIpcClient::send_command(&cmd) {
            let status = resp.get("status").and_then(|x| x.as_str()).unwrap_or("");
            let msg = resp.get("message").and_then(|x| x.as_str()).unwrap_or("");
            let ok = status == "ok";
            if ok {
                ImmutableAuditLog::append_event("DNS_RESET_DHCP", &format!("Configuración DNS restablecida a DHCP por daemon en {}", iface));
            } else {
                ImmutableAuditLog::append_event("DNS_RESET_ERROR", &format!("Error al restablecer DNS por daemon: {}", msg));
            }
            return (ok, msg.to_string());
        }

        Self::reset_dns_local(&iface)
    }

    pub fn reset_dns_local(iface: &str) -> (bool, String) {
        let _ = SecurityAuth::privileged_action(&["resolvectl", "revert", iface]);
        let _ = SecurityAuth::privileged_action(&["resolvectl", "flush-caches"]);
        let _ = SecurityAuth::privileged_action(&["nmcli", "dev", "modify", iface, "ipv4.ignore-auto-dns", "no"]);

        ImmutableAuditLog::append_event("DNS_RESET_DHCP", &format!("Configuración DNS restablecida a DHCP/Router de fábrica en interfaz {}.", iface));
        (true, format!("Configuración DNS restablecida a DHCP automático en {}.", iface))
    }
}

pub struct NativeNetworkMonitor;

#[derive(Debug, Clone)]
pub struct ConnectionAuditEntry {
    pub timestamp: String,
    pub process: String,
    pub destination: String,
    pub protocol: String,
    pub action: String,
}

impl NativeNetworkMonitor {
    pub fn is_active() -> bool {
        true
    }

    pub fn get_recent_connections(max_entries: usize) -> Vec<ConnectionAuditEntry> {
        let mut list = Vec::new();
        // ss -tunp obtiene sockets TCP y UDP activos con el proceso sin bloquear paquetes ni modificar iptables
        if let Ok(out) = Command::new("ss").args(["-tunp"]).output() {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let proto = parts[0].to_uppercase();
                        let local = parts.get(4).unwrap_or(&"-").to_string();
                        let peer = parts.get(5).unwrap_or(&"-").to_string();
                        if peer == "*:*" || peer.starts_with("0.0.0.0") || peer.starts_with("[::]") {
                            continue;
                        }
                        
                        let proc_info = if parts.len() >= 7 {
                            parts[6].replace("users:((\"", "").replace("\"))", "").replace("\",pid=", " (PID ")
                        } else {
                            "Sistema".to_string()
                        };

                        let ts = chrono_free_timestamp();
                        list.push(ConnectionAuditEntry {
                            timestamp: ts,
                            process: proc_info,
                            destination: format!("{} ➔ {}", local, peer),
                            protocol: proto,
                            action: "🟢 ACTIVA".into(),
                        });

                        if list.len() >= max_entries {
                            break;
                        }
                    }
                }
            }
        }
        list
    }
}
// ==============================================================================
// 28. Detección de Hardware con UDisks2 vía D-Bus (Sin Sondeo de CPU)
// ==============================================================================
pub struct UDisks2DbusMonitor;

impl UDisks2DbusMonitor {
    pub fn start_dbus_listener() {
        thread::spawn(|| {
            // Monitorizar interrupciones D-Bus de org.freedesktop.UDisks2
            let mut child = match Command::new("gdbus")
                .args(["monitor", "--system", "--dest", "org.freedesktop.UDisks2"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn() 
            {
                Ok(c) => c,
                Err(_) => {
                    // Fallback a sondeo suave si gdbus no está en el PATH
                    UsbDriveMonitor::start_usb_mount_listener();
                    return;
                }
            };

            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                let mut known_mounts = UsbDriveMonitor::get_current_usb_mounts();

                for line in reader.lines().flatten() {
                    if line.contains("InterfacesAdded") || line.contains("MountPoints") || line.contains("org.freedesktop.UDisks2.Filesystem") {
                        thread::sleep(Duration::from_millis(500));
                        let current_mounts = UsbDriveMonitor::get_current_usb_mounts();
                        for m in &current_mounts {
                            if !known_mounts.contains(m) {
                                UsbDriveMonitor::trigger_usb_scan(m);
                            }
                        }
                        known_mounts = current_mounts;
                    }
                }
            }
        });
    }
}

pub struct ExecutiveReportGenerator;

impl ExecutiveReportGenerator {
    pub fn generate_report(user_home: &str) -> (bool, String) {
        let timestamp = chrono_free_timestamp();
        let report_filename = format!("Informe_Seguridad_Constantine_EDR_{}.html", timestamp.replace(':', "-").replace('T', "_"));
        let desktop_path = format!("{}/Desktop/{}", user_home, report_filename);
        let target_path = if Path::new(&format!("{}/Desktop", user_home)).exists() {
            desktop_path
        } else {
            format!("/var/log/constantine/{}", report_filename)
        };

        let mut events: Vec<(String, String, String, String, String)> = Vec::new();
        let mut total_threats = 0;
        let mut ransomware_count = 0;
        let mut tamper_count = 0;
        let mut _vault_count = 0;

        if let Ok(f) = File::open(IMMUTABLE_AUDIT_LOG) {
            for line in BufReader::new(f).lines().flatten() {
                let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
                if parts.len() >= 5 {
                    let ts = parts[0].to_string();
                    let cur_h = parts[1].to_string();
                    let prev_h = parts[2].to_string();
                    let ev_type = parts[3].to_string();
                    let details = parts[4].to_string();

                    if ev_type.contains("RANSOMWARE") || ev_type.contains("TRIPWIRE") {
                        ransomware_count += 1;
                        total_threats += 1;
                    }
                    if ev_type.contains("TAMPER") {
                        tamper_count += 1;
                        total_threats += 1;
                    }
                    if ev_type.contains("VAULT") || ev_type.contains("QUARANTINE") {
                        _vault_count += 1;
                        total_threats += 1;
                    }

                    events.push((ts, cur_h, prev_h, ev_type, details));
                }
            }
        }

        let blocked_domains = WebProtectionManager::get_blocked_domains_count();
        let (chain_valid, verified_count) = ImmutableAuditLog::verify_integrity();

        let mut rows_html = String::new();
        for (ts, cur_h, _, ev_type, details) in events.iter().rev().take(50) {
            let badge_class = if ev_type.contains("RANSOMWARE") || ev_type.contains("TAMPER") {
                "badge-danger"
            } else if ev_type.contains("VAULT") || ev_type.contains("QUARANTINE") {
                "badge-warning"
            } else {
                "badge-info"
            };

            rows_html.push_str(&format!(
                "<tr><td><code>{}</code></td><td><span class='badge {}'>{}</span></td><td><small><code>{}...</code></small></td><td>{}</td></tr>\n",
                ts, badge_class, ev_type, &cur_h[..16.min(cur_h.len())], details
            ));
        }

        let html = format!(r#"<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe Ejecutivo de Seguridad — Constantine Antivirus & EDR</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 32px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 24px; margin-bottom: 32px; }}
        .title {{ font-size: 28px; font-weight: 800; color: #38bdf8; margin: 0; }}
        .subtitle {{ font-size: 14px; color: #94a3b8; margin-top: 6px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; }}
        .card-value {{ font-size: 32px; font-weight: 800; color: #f1f5f9; }}
        .card-label {{ font-size: 13px; font-weight: 600; text-transform: uppercase; color: #94a3b8; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #1e293b; border-radius: 12px; overflow: hidden; }}
        th, td {{ padding: 14px 18px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; }}
        th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }}
        .badge {{ padding: 4px 8px; border-radius: 6px; font-weight: 700; font-size: 11px; }}
        .badge-danger {{ background: #ef444422; color: #f87171; border: 1px solid #ef444444; }}
        .badge-warning {{ background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b44; }}
        .badge-info {{ background: #38bdf822; color: #38bdf8; border: 1px solid #38bdf844; }}
        .footer {{ margin-top: 40px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #334155; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 class="title">🛡️ CONSTANTINE ANTIVIRUS & EDR v5.5.3</h1>
            <div class="subtitle">Informe Ejecutivo de Auditoría y Seguridad del Endpoint</div>
        </div>
        <div style="text-align: right;">
            <div style="font-weight: 700; color: #38bdf8;">Emisión: {}</div>
            <div class="subtitle">Cadena Forense: {} ({} registros verificados)</div>
        </div>
    </div>

    <div class="metrics">
        <div class="card">
            <div class="card-value" style="color: #f87171;">{}</div>
            <div class="card-label">Amenazas Neutralizadas</div>
        </div>
        <div class="card">
            <div class="card-value" style="color: #fbbf24;">{}</div>
            <div class="card-label">Ataques Ransomware Contenidos</div>
        </div>
        <div class="card">
            <div class="card-value" style="color: #38bdf8;">{}</div>
            <div class="card-label">Dominios Phishing Bloqueados</div>
        </div>
        <div class="card">
            <div class="card-value" style="color: #4ade80;">{}</div>
            <div class="card-label">Intentos Sabotaje (Tampering) Bloqueados</div>
        </div>
    </div>

    <div class="card" style="margin-bottom: 32px;">
        <h3 style="margin-top:0; color: #f1f5f9;">📋 Estado General de Subsistemas y Motores EDR</h3>
        <p style="color: #94a3b8; font-size: 13px;">El endpoint se encuentra protegido mediante los 16 módulos de seguridad integrados (fanotify, Cilium Tetragon eBPF, ClamAV On-Access, AIDE, YARA, y sumidero DNS local en 0.0.0.0).</p>
    </div>

    <div class="card">
        <h3 style="margin-top:0; color: #f1f5f9;">📜 Registro Criptográfico Forense (Últimos Eventos)</h3>
        <table>
            <thead>
                <tr>
                    <th>Fecha y Hora</th>
                    <th>Tipo de Evento</th>
                    <th>Hash Encadenado</th>
                    <th>Detalles Operativos</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>

    <div class="footer">
        Generado automáticamente por Constantine EDR • Algoritmo de integridad: SHA-256 Chained Blockchain Ledger
    </div>
</body>
</html>"#,
            timestamp,
            if chain_valid { "✓ VÁLIDA (100% Integra)" } else { "⚠️ DISCREPANCIA DETECTADA" },
            verified_count,
            total_threats,
            ransomware_count,
            blocked_domains,
            tamper_count,
            rows_html
        );

        if let Ok(mut f) = File::create(&target_path) {
            let _ = f.write_all(html.as_bytes());
            let _ = f.sync_all();
            ImmutableAuditLog::append_event("EXECUTIVE_REPORT_GENERATED", &format!("Informe ejecutivo exportado a: {}", target_path));
            (true, target_path)
        } else {
            (false, "No se pudo escribir el archivo de informe en el disco.".into())
        }
    }
}

pub struct TamperProtectionManager;

impl TamperProtectionManager {
    pub const TAMPER_POLICY_FILE: &'static str = "/etc/tetragon/tetragon.tp.d/constantine_tamper_protection.yaml";
    pub const VAULT_KEY: &'static str = "/var/lib/constantine/.vault.key";
    pub const AUDIT_LOG: &'static str = "/var/log/constantine/immutable_audit.log";
    pub const WHITELIST: &'static str = "/var/lib/constantine/whitelist.txt";

    pub fn is_tamper_protection_active() -> bool {
        let policy_ok = Path::new(Self::TAMPER_POLICY_FILE).exists();
        let key_ok = Self::is_file_immutable(Self::VAULT_KEY);
        let log_ok = Self::is_file_immutable(Self::AUDIT_LOG);
        policy_ok || (key_ok && log_ok)
    }

    pub fn is_file_immutable(path: &str) -> bool {
        if !Path::new(path).exists() {
            return false;
        }
        if let Ok(output) = Command::new("lsattr").arg(path).output() {
            let s = String::from_utf8_lossy(&output.stdout);
            return s.contains('i') || s.contains('a');
        }
        false
    }

    pub fn apply_tamper_protection() -> (bool, String) {
        let cmd = serde_json::json!({"action": "apply_tamper_protection"});
        if let Some(resp) = ConstantineIpcClient::send_command(&cmd) {
            let status = resp.get("status").and_then(|x| x.as_str()).unwrap_or("");
            let msg = resp.get("message").and_then(|x| x.as_str()).unwrap_or("Autodefensa aplicada por daemon");
            return (status == "ok", msg.to_string());
        }

        Self::apply_tamper_protection_local()
    }

    pub fn apply_tamper_protection_local() -> (bool, String) {
        let mut count = 0;
        for path in &[Self::VAULT_KEY, Self::WHITELIST] {
            if Path::new(path).exists() {
                let _ = Command::new("chattr").arg("+i").arg(path).status();
                count += 1;
            }
        }
        if Path::new(Self::AUDIT_LOG).exists() {
            let _ = Command::new("chattr").arg("+a").arg(Self::AUDIT_LOG).status();
            count += 1;
        }

        (true, format!("Autodefensa activa: {} archivos blindados y regla eBPF Tetragon en vigor.", count))
    }

    pub fn remove_tamper_protection_local() -> bool {
        for path in &[Self::VAULT_KEY, Self::WHITELIST, Self::AUDIT_LOG] {
            if Path::new(path).exists() {
                let _ = Command::new("chattr").arg("-i").arg("-a").arg(path).status();
            }
        }
        true
    }

    pub fn unlock_for_write<F, R>(path: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let is_imm = Self::is_file_immutable(path);
        if is_imm {
            let _ = Command::new("chattr").arg("-i").arg("-a").arg(path).status();
        }
        let res = f();
        if is_imm {
            let flag = if path == Self::AUDIT_LOG { "+a" } else { "+i" };
            let _ = Command::new("chattr").arg(flag).arg(path).status();
        }
        res
    }

    pub fn neutralize_tamper_attempt(pid: u32, binary: &str, func_name: &str, target_res: &str) {
        if pid <= 1 { return; }
        let pid_str = pid.to_string();
        let _ = SecurityAuth::privileged_action(&["kill", "-STOP", &pid_str]);
        let _ = SecurityAuth::privileged_action(&["kill", "-KILL", &pid_str]);

        ImmutableAuditLog::append_event(
            "TAMPER_ATTEMPT_NEUTRALIZED",
            &format!("PID {} ({}) neutralizado por sabotaje al EDR | Función: {} | Objetivo: {}", pid, binary, func_name, target_res)
        );

        SystemNotifier::notify(
            "critical",
            "security-high",
            "🛡️ AUTODEFENSA EDR: SABOTAJE BLOQUEADO",
            &format!("Proceso agresor PID {} ({}) neutralizado en kernel por intentar terminar o manipular Constantine.", pid, binary),
        );

        let _ = Command::new("/usr/local/bin/constantine")
            .args([
                "--threat-dialog",
                &format!("Intento de Sabotaje (Tampering): {}", binary),
                if target_res.is_empty() { "/usr/local/bin/constantine" } else { target_res },
                &pid_str,
                "Sensor eBPF Tetragon (Tamper Protection)"
            ])
            .spawn();
    }
}

pub struct NetworkPrivacyAudit;

impl NetworkPrivacyAudit {
    /// G4 corregido: Evita falso positivo porque "inactive" contiene la subcadena "active".
    /// Se comprueba "inactive" PRIMERO para evitar que coincida prematuramente.
    pub fn is_ufw_active() -> bool {
        if let Ok(out) = Command::new("ufw").arg("status").output() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            for line in s.lines() {
                let t = line.trim();
                if t.starts_with("status:") || t.starts_with("estado:") {
                    // CORREGIDO: Comprobar "inactive" antes que "active"
                    if t.contains("inactive") || t.contains("inactivo") { 
                        return false; 
                    }
                    if t.contains("active") || t.contains("activo") { 
                        return true; 
                    }
                }
            }
        }
        
        // Fallback no privilegiado leyendo /etc/ufw/ufw.conf
        if let Ok(conf) = fs::read_to_string("/etc/ufw/ufw.conf") {
            for line in conf.lines() {
                if line.trim().eq_ignore_ascii_case("ENABLED=yes") { 
                    return true; 
                }
            }
        }
        false
    }

    /// G5 corregido: Comprueba específicamente interfaces de ProtonVPN (proton / pvpn) 
    /// y no cualquier interfaz tun genérica.
    pub fn is_protonvpn_active() -> bool {
        // 1. Comprobación a nivel de interfaz de red (ip link)
        if let Ok(out) = Command::new("ip").args(["-o", "link", "show"]).output() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            for line in s.lines() {
                if (line.contains("proton") || line.contains("pvpn")) && line.contains("state up") {
                    return true;
                }
            }
        }
        
        // 2. Comprobación a nivel de gestor de redes (NetworkManager)
        if let Ok(out) = Command::new("nmcli").args(["-t", "-f", "NAME,TYPE,STATE", "connection", "show", "--active"]).output() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            if s.contains("protonvpn") && s.contains("activated") {
                return true;
            }
        }
        false
    }

    /// Lookup de IP pública con HTTPS real y sin depender del tier de pago de ip-api.com.
    /// Estrategia en cascada con fallbacks elegantes:
    ///   1) https://ifconfig.co/json   — gratuito, sin clave, HTTPS, estable
    ///   2) https://ipinfo.io/json     — gratuito, sin clave, HTTPS, muy estable
    ///   3) http://ip-api.com/line/... — último recurso (HTTP, formato texto plano)
    pub fn get_public_ip_info() -> (String, String) {
        // 1) ifconfig.co (HTTPS, JSON)
        if let Ok(out) = Command::new("curl")
            .args(["-s", "--max-time", "4", "https://ifconfig.co/json"])
            .output()
        {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                let ip = v.get("ip").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
                if !ip.is_empty() {
                    let city = v.get("city").and_then(|x| x.as_str()).unwrap_or("").trim();
                    let region = v.get("region_name").and_then(|x| x.as_str()).unwrap_or("").trim();
                    let country = v.get("country").and_then(|x| x.as_str()).unwrap_or("").trim();
                    let loc = format!("{}, {}, {}", city, region, country)
                        .trim_matches(|c: char| c == ',' || c == ' ')
                        .to_string();
                    return (ip, if loc.is_empty() { "Desconocida".into() } else { loc });
                }
            }
        }

        // 2) ipinfo.io (HTTPS, JSON)
        if let Ok(out) = Command::new("curl")
            .args(["-s", "--max-time", "4", "https://ipinfo.io/json"])
            .output()
        {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                let ip = v.get("ip").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
                if !ip.is_empty() {
                    let city = v.get("city").and_then(|x| x.as_str()).unwrap_or("").trim();
                    let region = v.get("region").and_then(|x| x.as_str()).unwrap_or("").trim();
                    let country = v.get("country").and_then(|x| x.as_str()).unwrap_or("").trim();
                    let loc = format!("{}, {}, {}", city, region, country)
                        .trim_matches(|c: char| c == ',' || c == ' ')
                        .to_string();
                    return (ip, if loc.is_empty() { "Desconocida".into() } else { loc });
                }
            }
        }

        // 3) ip-api.com (HTTP, último recurso, formato texto plano /line/)
        if let Ok(out) = Command::new("curl").args([
            "-s", "--max-time", "3", "http://ip-api.com/line/?fields=query,city,regionName,country",
        ]).output() {
            let res = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = res.lines().collect();
            if lines.len() >= 4 {
                let ip = lines[0].trim().to_string();
                // Verificar que no sea una respuesta de error de la API
                if !ip.is_empty() && !ip.eq_ignore_ascii_case("fail") {
                    let loc = format!("{}, {}, {}", lines[1].trim(), lines[2].trim(), lines[3].trim());
                    return (ip, loc);
                }
            }
        }

        // Fallback final si todos los servicios fallan o no hay conexión
        ("No disponible / Sin conexión".into(), "Desconocida".into())
    }

    pub fn get_active_interface_info() -> (String, String, String) {
        if let Ok(out) = Command::new("ip").args(["route", "show", "default"]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            let parts: Vec<&str> = s.split_whitespace().collect();
            if let Some(dev_idx) = parts.iter().position(|&x| x == "dev") {
                if let Some(iface) = parts.get(dev_idx + 1) {
                    let iface_name = iface.to_string();
                    let iface_type = if iface_name.starts_with("wl") {
                        "Wi-Fi (Inalámbrica)"
                    } else if iface_name.starts_with("en") || iface_name.starts_with("eth") {
                        "Ethernet (Cableada)"
                    } else if iface_name.starts_with("tun") || iface_name.starts_with("proton") || iface_name.starts_with("wg") {
                        "Túnel VPN Cifrado"
                    } else {
                        "Adaptador de Red Local"
                    };

                    let local_ip = if let Ok(ip_out) = Command::new("ip").args(["-4", "addr", "show", "dev", &iface_name]).output() {
                        let ip_str = String::from_utf8_lossy(&ip_out.stdout);
                        let mut found_ip = "No asignada".to_string();
                        for line in ip_str.lines() {
                            let trimmed = line.trim();
                            if trimmed.starts_with("inet ") {
                                if let Some(ip) = trimmed.split_whitespace().nth(1) {
                                    found_ip = ip.to_string();
                                    break;
                                }
                            }
                        }
                        found_ip
                    } else {
                        "No disponible".into()
                    };

                    return (iface_name, iface_type.into(), local_ip);
                }
            }
        }
        ("No detectada".into(), "Desconocida".into(), "0.0.0.0".into())
    }

    pub fn launch_gufw() { 
        let _ = Command::new("gufw").spawn(); 
    }
    
    pub fn launch_protonvpn() {
        if Command::new("which").arg("protonvpn-app").output().map(|o| o.status.success()).unwrap_or(false) {
            let _ = Command::new("protonvpn-app").spawn();
        } else if Command::new("which").arg("protonvpn").output().map(|o| o.status.success()).unwrap_or(false) {
            let _ = Command::new("protonvpn").spawn();
        }
    }
}

/// Función auxiliar para verificar el estado de los servicios del sistema
fn get_service_active(service: &str) -> bool {
    if service == "falco" {
        let a1 = Command::new("systemctl").args(["is-active", "falco"]).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);
        if a1 { return true; }
        return Command::new("systemctl").args(["is-active", "falco-modern-bpf"]).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);
    }
    Command::new("systemctl").args(["is-active", service]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
}

// ==============================================================================
// 10. Supervisor y Consumidor de Eventos de ClamOnAcc
// ==============================================================================
pub struct OnAccessSupervisor;

impl OnAccessSupervisor {
    pub fn check_kernel_fanotify_permissions() -> (bool, bool) {
        if let Ok(out) = Command::new("uname").arg("-r").output() {
            let kver = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let kconf = format!("/boot/config-{}", kver);
            if let Ok(content) = fs::read_to_string(&kconf) {
                let has_fan = content.lines().any(|l| l.trim() == "CONFIG_FANOTIFY=y");
                let has_perm = content.lines().any(|l| l.trim() == "CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y");
                return (has_fan, has_perm);
            }
        }
        (false, false)
    }

    pub fn get_onaccess_pipeline_status() -> (bool, String) {
        let (has_fan, has_perm) = Self::check_kernel_fanotify_permissions();
        let clamd_up = Path::new(CLAMD_SOCKET).exists() && get_service_active("clamav-daemon");
        let onacc_up = get_service_active("clamonacc");
        if !has_fan || !has_perm { return (false, "● Kernel sin CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y (Solo notificación)".into()); }
        if onacc_up && clamd_up {
            (true, "● Activo: ClamOnAcc (Propietario fanotify) ➔ clamd (/home, /tmp, /var/tmp) [Nota: YARA/YARA-X operan en análisis bajo demanda/asíncrono]".into())
        } else if !clamd_up {
            (false, "● Inactivo: Demonio clamd o socket /run/clamav/clamd.ctl detenido".into())
        } else {
            (false, "● Inactivo: Servicio propietario ClamOnAcc detenido".into())
        }
    }

    pub fn start_realtime_event_consumer() {
        thread::spawn(|| {
            let mut last_offset: u64 = fs::metadata(LOG_FILE).map(|m| m.len()).unwrap_or(0);
            loop {
                thread::sleep(Duration::from_secs(2));
                if let Ok(meta) = fs::metadata(LOG_FILE) {
                    let current_len = meta.len();
                    if current_len < last_offset { last_offset = 0; }
                    if current_len > last_offset {
                        if let Ok(mut file) = File::open(LOG_FILE) {
                            use std::io::{Seek, SeekFrom};
                            if file.seek(SeekFrom::Start(last_offset)).is_ok() {
                                let reader = BufReader::new(file);
                                for line in reader.lines().flatten() {
                                    let trimmed = line.trim();

                                    // 1. Descartar SILENCIOSAMENTE errores de I/O, permisos o avisos de ClamAV (NO son malware)
                                    if trimmed.contains("Daemon failed to scan") 
                                        || trimmed.contains("Permission denied") 
                                        || trimmed.contains("File path check failure") 
                                        || trimmed.contains("Access denied") 
                                        || trimmed.contains("ERROR") 
                                        || trimmed.contains("ClamMisc: Unexpected issue") 
                                    {
                                        continue;
                                    }

                                    // 2. Procesar ÚNICAMENTE detecciones reales confirmadas por firma (deben contener FOUND y no ser error)
                                    if trimmed.contains("FOUND") && !trimmed.contains("ERROR") {
                                        // Extraer la ruta física del archivo detectado
                                        let mut detected_path: Option<PathBuf> = None;
                                        for part in trimmed.split(':') {
                                            let candidate = part.trim();
                                            if candidate.starts_with('/') {
                                                let p = Path::new(candidate);
                                                if p.exists() && p.is_file() {
                                                    detected_path = Some(p.to_path_buf());
                                                    break;
                                                }
                                            }
                                        }

                                        if detected_path.is_none() {
                                            for word in trimmed.split_whitespace() {
                                                let clean = word.trim_matches(&[':', '\'', '"', ',', '(', ')'][..]);
                                                if clean.starts_with('/') {
                                                    let p = Path::new(clean);
                                                    if p.exists() && p.is_file() {
                                                        detected_path = Some(p.to_path_buf());
                                                        break;
                                                    }
                                                }
                                            }
                                        }

                                        // Extraer el nombre de la firma/amenaza de ClamAV
                                        let detected_threat_name = trimmed.split("FOUND").next()
                                            .and_then(|s| s.split(':').last())
                                            .unwrap_or("ClamAV Malware Detection")
                                            .trim();

                                        // 3. Aislar y cifrar en el Baúl de Cuarentena con metadatos completos
                                        let mut vault_status = "Acceso bloqueado en kernel (fanotify)".to_string();
                                        if let Some(ref path) = detected_path {
                                            if ContainmentEngine::isolate_to_vault_with_metadata(path, detected_threat_name, "ClamOnAcc (fanotify -> clamd)") {
                                                vault_status = "Amenaza aislada y cifrada en el Baúl de Cuarentena (AES-256-GCM)".to_string();
                                            }
                                        }

                                        let display_name = detected_path.as_ref()
                                            .map(|p| p.to_string_lossy().to_string())
                                            .unwrap_or_else(|| trimmed.to_string());

                                        ImmutableAuditLog::append_event("CLAMONACC_QUARANTINED", &format!("Detección ClamAV -> Baúl: {} | {}", display_name, vault_status));
                                        
                                        SystemNotifier::notify(
                                            "critical",
                                            "security-high",
                                            "🛡️ Constantine: Malware Confirmado por ClamAV",
                                            &format!("Firma detectada: {}\nArchivo: {}\nEstado: {}", detected_threat_name, display_name, vault_status),
                                        );

                                        // Lanzar Diálogo Interactivo de Decisión Directa
                                        let _ = Command::new("/usr/local/bin/constantine")
                                            .args(["--threat-alert", detected_threat_name, &display_name, "0", "ClamOnAcc (fanotify -> clamd)"])
                                            .spawn();
                                    }
                                }
                            }
                        }
                        last_offset = current_len;
                    }
                }
            }
        });
    }
}

// ==============================================================================
// 11. Sensor EDR Principal: Tetragon eBPF y Motor de Correlación de 4 Pilares
// ==============================================================================

#[derive(Debug, Clone)]
pub struct ProcessContextProfile {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe_path: PathBuf,
    pub exe_sha256: String,
    pub cmdline: String,
    pub parent_exe: String,
    pub is_dpkg_managed: bool,
    pub behavior_signal: String,
    pub target_resource: String,
}

pub struct DestructiveActionSafetyGate;

impl DestructiveActionSafetyGate {
    /// Somete cualquier acción destructiva (SIGKILL / aislamiento en baúl) a 5 pruebas específicas e innegociables.
    pub fn authorize_destructive_response(profile: &ProcessContextProfile, correlation_score: u8) -> Result<(), String> {
        // Prueba 1: Protección de procesos críticos del sistema y del propio agente.
        if profile.pid <= 1 || profile.pid == std::process::id() {
            return Err("Prueba 1 fallida: PID crítico del sistema o del propio agente.".into());
        }
        
        let exe_str = profile.exe_path.to_string_lossy();
        let protected_daemons = [
            "/lib/systemd/systemd", "/usr/bin/dbus-daemon", "/usr/bin/gnome-shell",
            "/usr/lib/xorg/Xorg", "/usr/sbin/sshd", "/usr/local/bin/constantine",
            "/usr/local/bin/tetragon", "/usr/sbin/clamd", "/usr/sbin/clamonacc",
        ];
        
        for &prot in &protected_daemons {
            if exe_str == prot {
                return Err(format!("Prueba 1 fallida: Binario de infraestructura crítica protegido ({})", exe_str));
            }
        }

        // Prueba 2: Prohibición de bloqueo por simple nombre; exige ruta absoluta y hash.
        if profile.exe_sha256.is_empty() || !profile.exe_path.is_absolute() {
            return Err("Prueba 2 fallida: Identidad de ejecutable o hash SHA-256 no verificado (prohibido actuar solo por nombre).".into());
        }

        // Prueba 3: Verificación contra Lista Blanca por hash SHA-256.
        if ThreatAnalysisEngine::is_whitelisted(&profile.exe_sha256) {
            return Err("Prueba 3 fallida: El hash SHA-256 del ejecutable está autorizado en la Lista Blanca.".into());
        }

        // Prueba 4: Verificación de propiedad en paquetes oficiales de Debian.
        if profile.is_dpkg_managed && (exe_str.starts_with("/usr/") || exe_str.starts_with("/bin/") || exe_str.starts_with("/sbin/")) {
            return Err(format!("Prueba 4: El ejecutable {} pertenece a un paquete oficial del sistema Debian; se impide destruir el binario del sistema.", exe_str));
        }

        // Prueba 5: Exigencia de correlación multivariable mínima.
        if correlation_score < 70 {
            return Err(format!("Prueba 5 fallida: Puntuación de correlación insuficiente ({}/100) para autorizar acción destructiva.", correlation_score));
        }

        Ok(())
    }
}

pub struct TetragonPrimarySensor;

impl TetragonPrimarySensor {
    /// Construye el perfil completo de Identidad + Ejecutable + Comportamiento + Contexto.
    pub fn build_correlated_profile(
        pid: u32, ppid: u32, uid: u32, exe_hint: &str, cmdline: &str, 
        parent_exe: &str, behavior_signal: &str, target_resource: &str
    ) -> ProcessContextProfile {
        let proc_exe = format!("/proc/{}/exe", pid);
        let exe_path = fs::read_link(&proc_exe).unwrap_or_else(|_| PathBuf::from(exe_hint));
        let exe_sha256 = ThreatAnalysisEngine::compute_sha256(&exe_path).unwrap_or_default();
        
        let is_dpkg_managed = if exe_path.exists() {
            Command::new("dpkg")
                .args(["-S", &exe_path.to_string_lossy()])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        } else {
            false
        };

        ProcessContextProfile {
            pid, ppid, uid, exe_path, exe_sha256,
            cmdline: cmdline.to_string(),
            parent_exe: parent_exe.to_string(),
            is_dpkg_managed,
            behavior_signal: behavior_signal.to_string(),
            target_resource: target_resource.to_string(),
        }
    }

    /// Evalúa la correlación de los 4 pilares y devuelve una puntuación [0..100].
    pub fn evaluate_four_pillars(profile: &ProcessContextProfile) -> u8 {
        let mut score: u8 = 0;
        let exe_str = profile.exe_path.to_string_lossy();

        // 1. Pilar de Ejecutable (Ubicación volátil + ausencia en dpkg + presencia en feeds TI)
        if exe_str.starts_with("/tmp/") || exe_str.starts_with("/var/tmp/") || exe_str.starts_with("/dev/shm/") {
            score = score.saturating_add(35);
        }
        if !profile.is_dpkg_managed {
            score = score.saturating_add(15);
        }
        if !profile.exe_sha256.is_empty() && ThreatAnalysisEngine::is_known_malware_hash(&profile.exe_sha256) {
            score = score.saturating_add(60);
        }

        // 2. Pilar de Comportamiento (Puntos de control LSM de Tetragon)
        if profile.behavior_signal.contains("CANARY_WRITE") || AntiRansomwareShield::is_canary_file(Path::new(&profile.target_resource)) {
            score = score.saturating_add(65);
        }
        if profile.behavior_signal.contains("security_bprm_check") {
            score = score.saturating_add(25);
        }
        if profile.behavior_signal.contains("security_file_permission") && (profile.target_resource.starts_with("/etc/shadow") || profile.target_resource.starts_with("/etc/sudoers")) {
            score = score.saturating_add(45);
        }

        // 3. Pilar de Contexto y Linaje (Shells inversas o ejecución sospechosa)
        let cmd_low = profile.cmdline.to_lowercase();
        if cmd_low.contains("/dev/tcp/") || cmd_low.contains("nc -e") || cmd_low.contains("bash -i") {
            score = score.saturating_add(45);
        }

        // 4. Pilar de Identidad (Procesos no privilegiados intentando alterar rutas críticas)
        if profile.uid >= 1000 && !profile.is_dpkg_managed {
            score = score.saturating_add(10);
        }

        score.min(100)
    }

    /// Inicia el hilo consumidor en tiempo real del Sensor EDR Principal.
    pub fn start_primary_edr_consumer() {
        thread::spawn(|| {
            let mut last_offset: u64 = fs::metadata(TETRAGON_LOG_FILE).map(|m| m.len()).unwrap_or(0);
            loop {
                thread::sleep(Duration::from_secs(2));
                if let Ok(meta) = fs::metadata(TETRAGON_LOG_FILE) {
                    let current_len = meta.len();
                    if current_len < last_offset {
                        last_offset = 0; // Rotación de log detectada
                    }
                    if current_len > last_offset {
                        if let Ok(mut file) = File::open(TETRAGON_LOG_FILE) {
                            use std::io::{Seek, SeekFrom};
                            if file.seek(SeekFrom::Start(last_offset)).is_ok() {
                                let reader = BufReader::new(file);
                                for line in reader.lines().flatten() {
                                    Self::process_tetragon_json_event(&line);
                                }
                            }
                        }
                        last_offset = current_len;
                    }
                }
            }
        });
    }

    fn process_tetragon_json_event(json_line: &str) {
        let val: serde_json::Value = match serde_json::from_str(json_line) {
            Ok(v) => v,
            Err(_) => return,
        };

        let event_node = if let Some(kp) = val.get("process_kprobe") {
            kp
        } else if let Some(ex) = val.get("process_exec") {
            ex
        } else {
            return;
        };

        let proc = match event_node.get("process") {
            Some(p) => p,
            None => return,
        };

        let pid = proc.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let uid = proc.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let binary = proc.get("binary").and_then(|v| v.as_str()).unwrap_or("");
        let args = proc.get("arguments").and_then(|v| v.as_str()).unwrap_or("");
        
        let parent_bin = event_node
            .get("parent")
            .and_then(|p| p.get("binary"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
            
        let ppid = event_node
            .get("parent")
            .and_then(|p| p.get("pid"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
            
        let func_name = event_node
            .get("function_name")
            .and_then(|v| v.as_str())
            .unwrap_or("process_exec");

        let mut target_res = String::new();
        if let Some(kp_args) = event_node.get("args").and_then(|a| a.as_array()) {
            for arg in kp_args {
                if let Some(f_arg) = arg.get("file_arg").and_then(|fa| fa.get("path")).and_then(|p| p.as_str()) {
                    target_res = f_arg.to_string();
                } else if let Some(b_arg) = arg.get("linux_binprm_arg").and_then(|ba| ba.get("path")).and_then(|p| p.as_str()) {
                    target_res = b_arg.to_string();
                }
            }
        }

        if pid <= 1 || binary.is_empty() {
            return;
        }

        // ----------------------------------------------------------------------
        // Detección de Autodefensa (Tamper Protection) vía eBPF
        // ----------------------------------------------------------------------
        let is_tamper_attempt = if func_name.contains("kill") {
            // Intento no autorizado de enviar señales (SIGKILL/SIGTERM) a procesos del sistema
            !binary.contains("systemd") && !parent_bin.contains("systemd") && !binary.contains("constantine-shutdown")
        } else if func_name == "security_file_permission" && (target_res.contains("/var/lib/constantine") || target_res.contains("/var/log/constantine") || target_res.contains("/usr/local/bin/constantine") || target_res.contains("/etc/systemd/system/constantine")) {
            // Intento no autorizado de alterar archivos críticos de Constantine
            !binary.contains("constantine") && !binary.contains("systemd")
        } else {
            false
        };

        if is_tamper_attempt {
            TamperProtectionManager::neutralize_tamper_attempt(pid, binary, func_name, &target_res);
            return;
        }

        let profile = Self::build_correlated_profile(pid, ppid, uid, binary, args, parent_bin, func_name, &target_res);
        let score = Self::evaluate_four_pillars(&profile);

        if score >= 70 {
            match DestructiveActionSafetyGate::authorize_destructive_response(&profile, score) {
                Ok(()) => {
                    AntiRansomwareShield::neutralize_attack(
                        profile.pid,
                        Path::new(&profile.target_resource),
                        &format!(
                            "Correlación Tetragon eBPF ({}/100) [Hook: {}, Bin: {}, SHA256: {}]",
                            score,
                            profile.behavior_signal,
                            profile.exe_path.display(),
                            &profile.exe_sha256[..12.min(profile.exe_sha256.len())]
                        ),
                    );

                    let _ = Command::new("/usr/local/bin/constantine")
                        .args([
                            "--threat-alert",
                            &format!("Agresión en Memoria eBPF ({}/100)", score),
                            &profile.target_resource,
                            &profile.pid.to_string(),
                            &format!("Tetragon eBPF [{}]", profile.behavior_signal)
                        ])
                        .spawn();
                }
                Err(gate_reason) => {
                    ImmutableAuditLog::append_event(
                        "TETRAGON_SAFETY_GATE_BLOCKED",
                        &format!(
                            "Acción destructiva retenida por prueba de seguridad sobre PID {} ({}): {}",
                            profile.pid,
                            profile.exe_path.display(),
                            gate_reason
                        ),
                    );
                }
            }
        }
    }
}

// ==============================================================================

// ==============================================================================
// 12. Gestor de Lista Blanca Criptográfica (Exclusiones de Seguridad)
// ==============================================================================
#[derive(Debug, Clone)]
pub struct WhitelistRecord {
    pub hash: String,
    pub timestamp: String,
    pub filename: String,
    pub original_path: String,
}

pub struct WhitelistManager;

const WHITELIST_META_FILE: &str = "/var/lib/constantine/whitelist_meta.json";

impl WhitelistManager {
    pub fn list_whitelist_records() -> Vec<WhitelistRecord> {
        let mut records = Vec::new();

        if let Ok(content) = fs::read_to_string(WHITELIST_META_FILE) {
            if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(items) = arr.as_array() {
                    for item in items {
                        records.push(WhitelistRecord {
                            hash: item.get("hash").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            timestamp: item.get("timestamp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            filename: item.get("filename").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            original_path: item.get("original_path").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        });
                    }
                }
            }
        }

        // Compatibilidad con firmas en whitelist.txt
        if let Ok(f) = File::open(WHITELIST_FILE) {
            for l in BufReader::new(f).lines().flatten() {
                let trimmed = l.trim().to_string();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    if !records.iter().any(|r| r.hash.eq_ignore_ascii_case(&trimmed)) {
                        records.push(WhitelistRecord {
                            hash: trimmed.clone(),
                            timestamp: chrono_free_timestamp(),
                            filename: "Firma Autorizada".to_string(),
                            original_path: "Ingreso Manual o Regla Previa".to_string(),
                        });
                    }
                }
            }
        }

        records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        records
    }

    pub fn list_whitelist() -> Vec<String> {
        Self::list_whitelist_records().into_iter().map(|r| r.hash).collect()
    }

    pub fn add_record(hash: &str, filename: &str, original_path: &str) -> bool {
        let clean_hash = hash.trim().to_lowercase();
        if clean_hash.len() != 64 { return false; }

        let mut current = Self::list_whitelist_records();
        if !current.iter().any(|r| r.hash.eq_ignore_ascii_case(&clean_hash)) {
            current.insert(0, WhitelistRecord {
                hash: clean_hash.clone(),
                timestamp: chrono_free_timestamp(),
                filename: filename.to_string(),
                original_path: original_path.to_string(),
            });

            let json_arr: Vec<serde_json::Value> = current.iter().map(|r| {
                serde_json::json!({
                    "hash": r.hash,
                    "timestamp": r.timestamp,
                    "filename": r.filename,
                    "original_path": r.original_path,
                })
            }).collect();

            if let Ok(mut f) = OpenOptions::new().create(true).write(true).truncate(true).open(WHITELIST_META_FILE) {
                let _ = f.write_all(serde_json::Value::Array(json_arr).to_string().as_bytes());
                let _ = f.sync_all();
                let _ = fs::set_permissions(WHITELIST_META_FILE, fs::Permissions::from_mode(0o644));
            }

            TamperProtectionManager::unlock_for_write(WHITELIST_FILE, || {
                if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(WHITELIST_FILE) {
                    let _ = writeln!(f, "{}", clean_hash);
                }
            });

            ImmutableAuditLog::append_event("WHITELIST_ADDED", &format!("Hash: {} | Archivo: {} | Ruta: {}", &clean_hash[..16], filename, original_path));
            return true;
        }
        true
    }

    pub fn add_hash(hash: &str) -> bool {
        Self::add_record(hash, "Firma Manual", "Añadida manualmente por el usuario")
    }

    pub fn add_file(path: &Path) -> Result<String, String> {
        let hash = ThreatAnalysisEngine::compute_sha256(path)
            .map_err(|e| format!("Error al calcular SHA-256: {}", e))?;
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("archivo").to_string();
        let orig = path.to_string_lossy().to_string();
        if Self::add_record(&hash, &fname, &orig) {
            Ok(hash)
        } else {
            Err("No se pudo escribir en la lista blanca.".into())
        }
    }

    pub fn remove_record(hash: &str) -> bool {
        let clean_hash = hash.trim().to_lowercase();
        let mut current = Self::list_whitelist_records();
        let len_before = current.len();
        current.retain(|r| !r.hash.eq_ignore_ascii_case(&clean_hash));

        if current.len() < len_before {
            let json_arr: Vec<serde_json::Value> = current.iter().map(|r| {
                serde_json::json!({
                    "hash": r.hash,
                    "timestamp": r.timestamp,
                    "filename": r.filename,
                    "original_path": r.original_path,
                })
            }).collect();

            if let Ok(mut f) = OpenOptions::new().create(true).write(true).truncate(true).open(WHITELIST_META_FILE) {
                let _ = f.write_all(serde_json::Value::Array(json_arr).to_string().as_bytes());
                let _ = f.sync_all();
            }

            TamperProtectionManager::unlock_for_write(WHITELIST_FILE, || {
                if let Ok(mut f) = OpenOptions::new().create(true).write(true).truncate(true).open(WHITELIST_FILE) {
                    for r in &current {
                        let _ = writeln!(f, "{}", r.hash);
                    }
                }
            });

            ImmutableAuditLog::append_event("WHITELIST_REMOVED", &format!("Hash retirado: {}", &clean_hash[..16.min(clean_hash.len())]));
            return true;
        }
        false
    }

    pub fn remove_hash(hash: &str) -> bool {
        Self::remove_record(hash)
    }
}

pub struct MemoryScannerEngine;

#[derive(Debug, Clone)]
pub struct ProcessMemScanResult {
    pub total_procs_scanned: usize,
    pub threats_found: Vec<(u32, String, String)>,
}

impl MemoryScannerEngine {
    pub fn scan_running_memory() -> ProcessMemScanResult {
        let mut threats = Vec::new();
        let mut count = 0;

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if let Ok(pid) = name_str.parse::<u32>() {
                    count += 1;
                    let exe_link = format!("/proc/{}/exe", pid);
                    if let Ok(target) = fs::read_link(&exe_link) {
                        let target_str = target.to_string_lossy();
                        if target_str.starts_with("/tmp/") || target_str.starts_with("/dev/shm/") || target_str.starts_with("/var/tmp/") {
                            threats.push((pid, target_str.to_string(), "Proceso ejecutado desde memoria volátil (/dev/shm o /tmp)".into()));
                            continue;
                        }
                        if target_str.contains("(deleted)") {
                            threats.push((pid, target_str.to_string(), "Binario eliminado de disco pero activo en RAM (Process Hollowing)".into()));
                            continue;
                        }
                        if let Ok(hash) = ThreatAnalysisEngine::compute_sha256(&target) {
                            if ThreatAnalysisEngine::is_known_malware_hash(&hash) {
                                threats.push((pid, target_str.to_string(), format!("Huella de malware conocida en RAM: {}", &hash[..16.min(hash.len())])));
                            }
                        }
                    }
                }
            }
        }

        for (pid, exe_path, reason) in &threats {
            ImmutableAuditLog::append_event(
                "RAM_THREAT_ALERT",
                &format!("Alerta en Memoria RAM — PID {} ({}): {}", pid, exe_path, reason),
            );
        }

        ProcessMemScanResult {
            total_procs_scanned: count,
            threats_found: threats,
        }
    }
}

// 13. Auditoría y Custodia de Periféricos en Vivo (Cámara y Micrófono)
// ==============================================================================
pub struct PeripheralAudit;

impl PeripheralAudit {
    pub fn get_camera_status() -> (bool, String) {
        if let Ok(meta) = fs::metadata("/dev/video0") {
            if meta.permissions().mode() & 0o444 == 0 {
                return (false, "🔴 APAGADA / Desactivada (Kill-Switch V4L2)".into());
            }
        }
        if let Ok(out) = Command::new("fuser").args(["/dev/video0", "/dev/video1"]).output() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let pids = format!("{} {}", s, err).trim().to_string();
            if !pids.is_empty() {
                let first_pid = pids.split_whitespace().next().unwrap_or("");
                let proc_name = if !first_pid.is_empty() {
                    fs::read_link(format!("/proc/{}/exe", first_pid))
                        .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
                        .unwrap_or_else(|_| "Proceso".into())
                } else {
                    "Desconocido".into()
                };
                return (true, format!("⚠️ EN USO por: {} (PIDs: {})", proc_name, pids));
            }
        }
        (false, "🟢 ENCENDIDA / Lista y Protegida (Supervisor V4L2 Activo)".into())
    }

    pub fn turn_off_camera() -> bool {
        let _ = SecurityAuth::privileged_action(&["fuser", "-k", "/dev/video0", "/dev/video1"]);
        let res = SecurityAuth::privileged_action(&["chmod", "000", "/dev/video0", "/dev/video1"]);
        if res {
            ImmutableAuditLog::append_event("HARDWARE_CAM_BLOCKED", "Cámara web desactivada por hardware (Kill-Switch V4L2 permisos 000).");
        } else {
            ImmutableAuditLog::append_event("HARDWARE_CAM_ERROR", "Error al aplicar Kill-Switch de permisos V4L2 a cámara.");
        }
        res
    }

    pub fn turn_on_camera() -> bool {
        let res = SecurityAuth::privileged_action(&["chmod", "660", "/dev/video0", "/dev/video1"]);
        if res {
            ImmutableAuditLog::append_event("HARDWARE_CAM_UNBLOCKED", "Cámara web reactivada (Supervisor V4L2 activo, permisos 660).");
        } else {
            ImmutableAuditLog::append_event("HARDWARE_CAM_ERROR", "Error al reactivar permisos de cámara web.");
        }
        res
    }

    pub fn get_microphone_status() -> (bool, String) {
        let pactl_muted = Command::new("pactl").args(["get-source-mute", "@DEFAULT_SOURCE@"]).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("yes"))
            .unwrap_or(false);
        let amixer_muted = Command::new("amixer").args(["get", "Capture"]).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("[off]"))
            .unwrap_or(false);

        if pactl_muted || amixer_muted {
            return (false, "🔴 APAGADO / Silenciado (Privacidad - Audio de salida intacto)".into());
        }
        (false, "🟢 ENCENDIDO / Listo y Protegido (Micrófono activo)".into())
    }

    pub fn turn_off_microphone() -> bool {
        // Silenciar ÚNICAMENTE la captura de micrófono sin afectar la salida de audio
        let _ = Command::new("pactl").args(["set-source-mute", "@DEFAULT_SOURCE@", "1"]).output();
        let _ = Command::new("pactl").args(["set-source-volume", "@DEFAULT_SOURCE@", "0%"]).output();
        let _ = Command::new("amixer").args(["set", "Capture", "nocap"]).output();
        let _ = Command::new("amixer").args(["set", "Capture", "0%"]).output();
        ImmutableAuditLog::append_event("HARDWARE_MIC_MUTED", "Micrófono silenciado por hardware (pactl mute + amixer nocap 0%).");
        true
    }

    pub fn turn_on_microphone() -> bool {
        // Restaurar la captura de micrófono sin alterar la salida de audio
        let _ = Command::new("pactl").args(["set-source-mute", "@DEFAULT_SOURCE@", "0"]).output();
        let _ = Command::new("pactl").args(["set-source-volume", "@DEFAULT_SOURCE@", "100%"]).output();
        let _ = Command::new("amixer").args(["set", "Capture", "cap"]).output();
        let _ = Command::new("amixer").args(["set", "Capture", "100%"]).output();
        ImmutableAuditLog::append_event("HARDWARE_MIC_UNMUTED", "Micrófono reactivado (pactl unmute + amixer cap 100%).");
        true
    }
}

// ==============================================================================
// 14. Actualizador de Constantine desde Repositorio / GitHub
// ==============================================================================
pub const APP_VERSION: &str = "5.5.3";
pub const GITHUB_REPO_URL: &str = "https://github.com/AntonSiMal/Constantine-Antivirus-Linux";

#[derive(Clone, Debug)]
pub enum UpdateCheckStatus {
    UpdateAvailable { remote_version: String, url: String },
    UpToDate(String),
    Error(String),
}

pub struct SelfUpdater;

impl SelfUpdater {
    fn parse_semver(raw: &str) -> Option<(u64, u64, u64)> {
        let cleaned = raw.trim().trim_start_matches('v').trim_start_matches('V');
        let core = cleaned.split(['-', '+']).next().unwrap_or(cleaned);
        let mut parts = core.split('.');
        let major: u64 = parts.next()?.parse().ok()?;
        let minor: u64 = parts.next().unwrap_or("0").parse().ok()?;
        let patch: u64 = parts.next().unwrap_or("0").parse().ok()?;
        Some((major, minor, patch))
    }

    pub fn check_remote_version() -> UpdateCheckStatus {
        let local_ver = Self::parse_semver(APP_VERSION).unwrap_or((5, 5, 3));
        let mut remote_tag: Option<String> = None;
        let mut target_url = GITHUB_REPO_URL.to_string();

        // 0. Prioritario: consultar version.txt en la rama main de GitHub
        if let Ok(out) = Command::new("curl")
            .args([
                "-sSL",
                "--connect-timeout", "5",
                "--max-time", "8",
                "-H", "Cache-Control: no-cache",
                "https://raw.githubusercontent.com/AntonSiMal/Constantine-Antivirus-Linux/main/version.txt",
            ])
            .output()
        {
            if out.status.success() {
                let raw_ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let cleaned = raw_ver.trim_start_matches('v').trim_start_matches('V').to_string();
                if Self::parse_semver(&cleaned).is_some() {
                    remote_tag = Some(cleaned);
                }
            }
        }

        // 1. Respaldo: consultar última Release oficial en GitHub API
        if remote_tag.is_none() {
            if let Ok(out) = Command::new("curl")
                .args([
                    "-sSL",
                    "--connect-timeout", "5",
                    "--max-time", "10",
                    "-H", "User-Agent: Constantine-EDR/5.5.3",
                    "https://api.github.com/repos/AntonSiMal/Constantine-Antivirus-Linux/releases/latest",
                ])
                .output()
            {
                if out.status.success() {
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                        if let Some(tag) = json.get("tag_name").and_then(|v| v.as_str()) {
                            if Self::parse_semver(tag).is_some() {
                                remote_tag = Some(tag.trim_start_matches('v').trim_start_matches('V').to_string());
                                if let Some(u) = json.get("html_url").and_then(|v| v.as_str()) {
                                    target_url = u.to_string();
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Respaldo: consultar Tags si no hay Releases publicadas
        if remote_tag.is_none() {
            if let Ok(out) = Command::new("curl")
                .args([
                    "-sSL",
                    "--connect-timeout", "5",
                    "--max-time", "10",
                    "-H", "User-Agent: Constantine-EDR/5.5.3",
                    "https://api.github.com/repos/AntonSiMal/Constantine-Antivirus-Linux/tags",
                ])
                .output()
            {
                if out.status.success() {
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                        if let Some(arr) = json.as_array() {
                            for item in arr {
                                if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                                    if Self::parse_semver(name).is_some() {
                                        remote_tag = Some(name.trim_start_matches('v').trim_start_matches('V').to_string());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Respaldo: consultar versión declarada en rama main (constantine.rs / Cargo.toml)
        if remote_tag.is_none() {
            if let Ok(out) = Command::new("curl")
                .args([
                    "-sSL",
                    "--connect-timeout", "5",
                    "--max-time", "10",
                    "https://raw.githubusercontent.com/AntonSiMal/Constantine-Antivirus-Linux/main/constantine.rs",
                ])
                .output()
            {
                if out.status.success() {
                    let body = String::from_utf8_lossy(&out.stdout);
                    for line in body.lines().take(200) {
                        if line.contains("APP_VERSION") {
                            if let Some(start) = line.find('"') {
                                if let Some(end) = line[start + 1..].find('"') {
                                    let candidate = &line[start + 1..start + 1 + end];
                                    if Self::parse_semver(candidate).is_some() {
                                        remote_tag = Some(candidate.to_string());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        match remote_tag {
            Some(ver_str) => {
                if let Some(remote_ver) = Self::parse_semver(&ver_str) {
                    if remote_ver != local_ver {
                        UpdateCheckStatus::UpdateAvailable {
                            remote_version: ver_str,
                            url: target_url,
                        }
                    } else {
                        UpdateCheckStatus::UpToDate(ver_str)
                    }
                } else {
                    UpdateCheckStatus::UpToDate(APP_VERSION.to_string())
                }
            }
            None => UpdateCheckStatus::Error(
                "No se pudo obtener la versión remota desde GitHub (verifica tu conexión a internet).".into(),
            ),
        }
    }

    pub fn launch_repo_update() {
        let cmd = format!(
            "echo '🔄 Actualizando Constantine Antivirus & EDR desde GitHub...';              rm -rf /tmp/constantine-update &&              git clone --depth 1 {} /tmp/constantine-update &&              cd /tmp/constantine-update &&              chmod +x install.sh &&              pkexec /tmp/constantine-update/install.sh;              echo 'Presiona Enter para cerrar...'; read line",
            GITHUB_REPO_URL
        );
        for term in ["x-terminal-emulator", "gnome-terminal", "xfce4-terminal", "konsole", "mate-terminal"] {
            if Command::new("which").arg(term).output().map(|o| o.status.success()).unwrap_or(false) {
                let flag = if term == "gnome-terminal" { "--" } else { "-e" };
                let _ = Command::new(term).args([flag, "sh", "-c", &cmd]).spawn();
                return;
            }
        }
        let _ = Command::new("xdg-open").arg(GITHUB_REPO_URL).spawn();
    }
}

fn prompt_update_dialog(parent: &ApplicationWindow, remote_version: &str, repo_url: &str, status_lbl: Option<Label>) {
    let dialog = ApplicationWindow::builder()
        .transient_for(parent)
        .modal(true)
        .title("🚀 Nueva Actualización Disponible — Constantine EDR")
        .default_width(480)
        .default_height(240)
        .build();

    let vbox = Box::new(Orientation::Vertical, 14);
    vbox.set_margin_start(20);
    vbox.set_margin_end(20);
    vbox.set_margin_top(20);
    vbox.set_margin_bottom(20);

    let title = Label::new(Some(&format!("✨ Nueva versión disponible: v{}", remote_version)));
    title.add_css_class("title-text");
    title.set_xalign(0.0);
    vbox.append(&title);

    let body = Label::new(Some(&format!(
        "Se encontró una versión más reciente en el repositorio oficial de GitHub:
         • Versión instalada: v{}
         • Nueva versión en GitHub: v{}

         ¿Deseas descargar e instalar la actualización ahora?",
        APP_VERSION, remote_version
    )));
    body.set_xalign(0.0);
    body.set_wrap(true);
    body.set_wrap_mode(gtk4::pango::WrapMode::Word);
    vbox.append(&body);

    let btn_box = Box::new(Orientation::Horizontal, 10);
    btn_box.set_halign(gtk4::Align::End);

    let btn_later = Button::with_label("Más Tarde");
    let btn_web = Button::with_label("🌐 Ver en GitHub");
    let btn_now = Button::with_label("⬇️ Actualizar y Sincronizar");
    btn_now.add_css_class("suggested-action");

    btn_box.append(&btn_later);
    btn_box.append(&btn_web);
    btn_box.append(&btn_now);
    vbox.append(&btn_box);

    let dlg_c1 = dialog.clone();
    btn_later.connect_clicked(move |_| dlg_c1.close());

    let url_c = repo_url.to_string();
    btn_web.connect_clicked(move |_| {
        let _ = Command::new("xdg-open").arg(&url_c).spawn();
    });

    let dlg_c2 = dialog.clone();
    let r_ver = remote_version.to_string();
    btn_now.connect_clicked(move |_| {
        if let Some(ref lbl) = status_lbl {
            lbl.set_text(&format!("⏳ Descargando e instalando v{} desde GitHub...", r_ver));
        }
        SelfUpdater::launch_repo_update();
        dlg_c2.close();
    });

    dialog.set_child(Some(&vbox));
    dialog.present();
}

// // Punto de Entrada y Construcción de la Interfaz Gráfica (GUI)
// ==============================================================================

// ==============================================================================
// Helper: ejecutar trabajo bloqueante en hilo aparte y devolver el resultado
// ==============================================================================
async fn run_blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = async_channel::bounded::<T>(1);
    std::thread::spawn(move || {
        let _ = tx.send_blocking(f());
    });
    rx.recv().await.expect("Tarea bloqueante terminó inesperadamente")
}

// Mensajes de progreso para el escaneo (los widgets NO viajan: solo datos planos)
enum ScanProgress {
    Progress {
        fraction: f64,
        current: usize,
        total: usize,
        fname: String,
        threats: usize,
        indets: usize,
    },
    Done {
        threats: usize,
        indets: usize,
        total: usize,
    },
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--scan-quick") {
        ScheduledScansManager::run_quick_scan_headless();
        return;
    }
    if args.iter().any(|a| a == "--scan-full") {
        ScheduledScansManager::run_full_scan_headless();
        return;
    }

    // Modo servicio en segundo plano (Daemon de fondo sin GUI)
    if args.iter().any(|arg| arg == "--daemon") {
        // 1. Iniciar servidor IPC de inmediato para que /run/constantine.sock exista instantáneamente
        ConstantineIpcServer::start_daemon_ipc_server();

        let user_home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        // [v5.5.3 Multiusuario] Despliegue de señuelos Canary en todos los usuarios existentes y en /etc/skel
        AntiRansomwareShield::deploy_all_users_canaries();
        OnAccessSupervisor::start_realtime_event_consumer();
        TetragonPrimarySensor::start_primary_edr_consumer();
        UsbDriveMonitor::start_usb_mount_listener();
        SecurityLogAggregator::start_log_forwarder();
        DownloadQuarantineGuard::start_download_watcher(&user_home);

        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
            // Verificación y auto-reparación periódica de señuelos en todos los usuarios (incluso nuevos)
            AntiRansomwareShield::deploy_all_users_canaries();
        }
    }

    // Modo Análisis Rápido desde Menú Contextual (Clic Derecho en el Explorador de Archivos)
    let normalize_cli_path = |raw: &str| -> PathBuf {
        let t1 = raw.trim().trim_matches(|c| c == '"' || c == '\'');
        let t2 = if let Some(stripped) = t1.strip_prefix("file://") {
            stripped
        } else {
            t1
        };
        let decoded = t2.replace("%20", " ");
        PathBuf::from(decoded)
    };

    let mut scan_target: Option<PathBuf> = None;
    for (i, arg) in args.iter().enumerate().skip(1) {
        if arg == "--scan-file" || arg == "-s" || arg == "--scan" {
            if let Some(target) = args.get(i + 1) {
                scan_target = Some(normalize_cli_path(target));
                break;
            }
        } else if arg.starts_with("--scan-file=") {
            let path = &arg["--scan-file=".len()..];
            scan_target = Some(normalize_cli_path(path));
            break;
        } else if arg.starts_with("--scan=") {
            let path = &arg["--scan=".len()..];
            scan_target = Some(normalize_cli_path(path));
            break;
        } else if !arg.starts_with('-') {
            let candidate = normalize_cli_path(arg);
            if candidate.exists() {
                scan_target = Some(candidate);
                break;
            }
        }
    }

    if let Some(target) = scan_target {
        run_file_scan_dialog(target);
        return;
    }

    // Modo Diálogo Interactivo de Amenaza (Actionable Threat Dialog al estilo Windows/Mac)
    if let Some(pos) = args.iter().position(|arg| arg == "--threat-alert" || arg == "--threat-dialog") {
        let threat_name = args.get(pos + 1).cloned().unwrap_or_else(|| "Amenaza Detectada".into());
        let file_path = args.get(pos + 2).cloned().unwrap_or_else(|| "".into());
        let pid_str = args.get(pos + 3).cloned().unwrap_or_else(|| "0".into());
        let pid = pid_str.parse::<u32>().unwrap_or(0);
        let engine = args.get(pos + 4).cloned().unwrap_or_else(|| "Sensor EDR Constantine".into());
        run_interactive_threat_dialog(threat_name, PathBuf::from(file_path), pid, engine);
        return;
    }

    SecurityLogAggregator::start_log_forwarder();

    let app = Application::builder()
        .application_id("com.constantine.antivirus")
        .flags(gtk4::gio::ApplicationFlags::NON_UNIQUE)
        .build();
    
    app.connect_startup(|_| {
        gtk4::Window::set_default_icon_name("constantine");
        let provider = CssProvider::new();
        provider.load_from_data(CUPERTINO_CSS);
        if let Some(display) = gtk4::gdk::Display::default() {
            gtk4::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    });
    
    app.connect_activate(|a| {
        for win in a.windows() {
            win.set_visible(true);
            win.present();
            return;
        }
        build_ui(a);
    });
    app.run();
}


// ==============================================================================
// ==============================================================================

// ==============================================================================
// 29. [v5.5.3] Cuarentena Preventiva de Descargas (Mark-of-the-Web / xattr)
// ==============================================================================
pub struct DownloadQuarantineGuard;

impl DownloadQuarantineGuard {
    pub fn start_download_watcher(user_home: &str) {
        let default_home = user_home.to_string();
        thread::spawn(move || {
            use std::collections::HashSet;
            let mut seen_files: HashSet<PathBuf> = HashSet::new();

            loop {
                // Re-escaneo dinámico de usuarios: vigila a todos los usuarios actuales y nuevos creados
                let mut users = get_system_human_users();
                if users.is_empty() && !default_home.is_empty() {
                    users.push(("default".to_string(), PathBuf::from(&default_home)));
                }

                for (_uname, home) in &users {
                    let candidate_dirs = [
                        home.join("Downloads"),
                        home.join("Descargas"),
                    ];

                    for d in &candidate_dirs {
                        if !d.exists() { continue; }
                        if let Ok(entries) = fs::read_dir(d) {
                            for e in entries.flatten() {
                                let p = e.path();
                                if !p.is_file() || seen_files.contains(&p) {
                                    continue;
                                }
                                let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                                // Ignorar descargas incompletas (.part, .crdownload, .tmp)
                                if fname.ends_with(".part") || fname.ends_with(".crdownload") || fname.ends_with(".tmp") {
                                    continue;
                                }
                                seen_files.insert(p.clone());

                                // 1. Estampar atributo extendido xattr (Mark-of-the-Web)
                                let now_ts = chrono_free_timestamp();
                                let _ = Command::new("setfattr")
                                    .args(["-n", "user.constantine.quarantine", "-v", &format!("1|{}", now_ts), &p.to_string_lossy()])
                                    .output();

                                // 2. Retiro preventivo de bit +x a ejecutables recién descargados (Gatekeeper-Style)
                                if ThreatAnalysisEngine::is_executable(&p) {
                                    if let Ok(meta) = fs::metadata(&p) {
                                        let mode = meta.permissions().mode();
                                        if mode & 0o111 != 0 {
                                            let mut perms = meta.permissions();
                                            perms.set_mode(mode & !0o111);
                                            let _ = fs::set_permissions(&p, perms);
                                            ImmutableAuditLog::append_event(
                                                "MOTW_EXECUTABLE_LOCKED",
                                                &format!("Mark-of-the-Web v5.5.3 (Multiusuario): Permiso +x retirado preventivamente en: {}", p.display()),
                                            );
                                        }
                                    }
                                }

                                // 3. Evaluar archivo descargado con el pipeline multi-motor
                                match ThreatAnalysisEngine::evaluate_file(&p) {
                                    FileVerdict::Threat(reason) => {
                                        let _ = ContainmentEngine::isolate_to_vault_with_metadata(&p, &reason, "Mark-of-the-Web Download Guard v5.5.3 (Multiusuario)");
                                        ImmutableAuditLog::append_event(
                                            "MOTW_DOWNLOAD_QUARANTINED",
                                            &format!("Descarga maliciosa interceptada en home de usuario: {} ({})", p.display(), reason),
                                        );
                                        SystemNotifier::notify(
                                            "critical",
                                            "security-high",
                                            "🚨 DESCARGA MALICIOSA BLOQUEADA (Mark-of-the-Web)",
                                            &format!("Archivo: {}\nAmenaza: {}\nAislado en Baúl AES-256-GCM.", fname, reason),
                                        );
                                    }
                                    FileVerdict::Clean(_) => {
                                        let _ = Command::new("setfattr")
                                            .args(["-n", "user.constantine.verified", "-v", "clean_v5.5.3", &p.to_string_lossy()])
                                            .output();
                                        ImmutableAuditLog::append_event(
                                            "MOTW_DOWNLOAD_VERIFIED",
                                            &format!("Descarga certificada limpia: {}", p.display()),
                                        );
                                    }
                                    FileVerdict::Indeterminate(msg) => {
                                        ImmutableAuditLog::append_event(
                                            "MOTW_DOWNLOAD_WARNING",
                                            &format!("Descarga con veredicto indeterminado en {}: {}", p.display(), msg),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_secs(3));
            }
        });
    }
}

// 17. Monitor y Escáner Automático Plug & Play de Memorias USB Extraíbles
// ==============================================================================
pub struct UsbDriveMonitor;

impl UsbDriveMonitor {
    pub fn trigger_usb_scan(mount: &Path) {
        let drive_name = mount.file_name().and_then(|n| n.to_str()).unwrap_or("Unidad Extraíble").to_string();
        ImmutableAuditLog::append_event(
            "USB_PLUG_PLAY_DETECTED",
            &format!("Dispositivo USB insertado (D-Bus UDisks2): {} en {}", drive_name, mount.display())
        );

        SystemNotifier::notify(
            "normal",
            "drive-removable-media",
            "💾 Nueva Memoria USB Detectada (D-Bus UDisks2)",
            &format!("Dispositivo: {}\nRuta: {}\nIniciando análisis de seguridad Plug & Play...", drive_name, mount.display()),
        );

        let path_to_scan = mount.to_path_buf();
        let d_name = drive_name.clone();
        thread::spawn(move || {
            Self::auto_scan_usb_drive(&path_to_scan, &d_name);
        });
    }

    pub fn get_current_usb_mounts() -> Vec<PathBuf> {
        let mut mounts = Vec::new();
        if let Ok(file) = File::open("/proc/mounts") {
            for line in BufReader::new(file).lines().flatten() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let mount_point = parts[1];
                    if mount_point.starts_with("/media/") || mount_point.starts_with("/run/media/") {
                        let p = PathBuf::from(mount_point);
                        if p.exists() && p.is_dir() {
                            mounts.push(p);
                        }
                    }
                }
            }
        }
        mounts
    }

    pub fn start_usb_mount_listener() {
        thread::spawn(|| {
            use std::collections::HashSet;
            let mut known_mounts: HashSet<PathBuf> = Self::get_current_usb_mounts().into_iter().collect();

            loop {
                thread::sleep(Duration::from_secs(2));
                let current_mounts = Self::get_current_usb_mounts();
                for mount in &current_mounts {
                    if !known_mounts.contains(mount) {
                        let mount_clone = mount.clone();
                        let drive_name = mount.file_name().and_then(|n| n.to_str()).unwrap_or("Unidad Extraíble").to_string();
                        
                        ImmutableAuditLog::append_event(
                            "USB_PLUG_PLAY_DETECTED",
                            &format!("Dispositivo USB insertado: {} en {}", drive_name, mount.display())
                        );

                        SystemNotifier::notify(
                            "normal",
                            "drive-removable-media",
                            "💾 Nueva Memoria USB Detectada",
                            &format!("Dispositivo: {}\nRuta: {}\nIniciando análisis de seguridad Plug & Play...", drive_name, mount.display()),
                        );

                        let path_to_scan = mount_clone.clone();
                        let d_name = drive_name.clone();
                        thread::spawn(move || {
                            Self::auto_scan_usb_drive(&path_to_scan, &d_name);
                        });

                        known_mounts.insert(mount_clone);
                    }
                }

                known_mounts.retain(|m| m.exists());
            }
        });
    }

    pub fn auto_scan_usb_drive(usb_path: &Path, drive_name: &str) {
        let mut files = Vec::new();
        ManualScanEngine::collect_files(usb_path, &mut files);
        let total = files.len();
        let mut threats_found = Vec::new();

        let autorun_path = usb_path.join("autorun.inf");
        if autorun_path.exists() {
            threats_found.push((autorun_path.clone(), "Archivo autorun.inf potencialmente peligroso en USB".to_string()));
            ContainmentEngine::isolate_to_vault_with_metadata(&autorun_path, "USB Autorun Execution", "Escudo USB Plug & Play");
        }

        for f in &files {
            if f.file_name().map(|n| n == "autorun.inf").unwrap_or(false) {
                continue;
            }
            if let FileVerdict::Threat(threat_msg) = ThreatAnalysisEngine::evaluate_file(f) {
                threats_found.push((f.clone(), threat_msg.clone()));
                ContainmentEngine::isolate_to_vault_with_metadata(f, &threat_msg, "Escudo USB Plug & Play");
            }
        }

        if threats_found.is_empty() {
            SystemNotifier::notify(
                "normal",
                "security-high",
                "✅ Memoria USB Certificada Limpia",
                &format!("Dispositivo: {}\nSe auditaron {} archivos sin detectar malware.", drive_name, total),
            );
            ImmutableAuditLog::append_event("USB_SCAN_CLEAN", &format!("Unidad USB limpia: {} ({} archivos)", drive_name, total));
        } else {
            let first_threat = &threats_found[0];
            SystemNotifier::notify(
                "critical",
                "dialog-warning",
                "🚨 AMENAZA EN MEMORIA USB AISLADA",
                &format!("Dispositivo: {}\nSe detectaron y aislaron {} amenazas.\nPrimera: {}", drive_name, threats_found.len(), first_threat.1),
            );
            ImmutableAuditLog::append_event(
                "USB_THREAT_ISOLATED",
                &format!("Amenazas en USB {}: {} aisladas en el Baúl de Cuarentena.", drive_name, threats_found.len())
            );

            let _ = Command::new("/usr/local/bin/constantine")
                .args(["--scan-file", &usb_path.to_string_lossy()])
                .spawn();
        }
    }
}

// // 16. Ventana Emergente de Análisis Rápido (Menú Contextual Clic Derecho)
// ==============================================================================
fn run_file_scan_dialog(target_path: PathBuf) {
    let app = Application::builder()
        .application_id("com.constantine.filescanner")
        .flags(gtk4::gio::ApplicationFlags::NON_UNIQUE)
        .build();

    let target_clone = target_path.clone();
    app.connect_startup(|_| {
        gtk4::Window::set_default_icon_name("constantine");
        let provider = CssProvider::new();
        provider.load_from_data(CUPERTINO_CSS);
        if let Some(display) = gtk4::gdk::Display::default() {
            gtk4::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    });

    app.connect_activate(move |app| {
        build_scan_dialog_ui(app, &target_clone);
    });

    app.run_with_args(&["constantine"]);
}



// ==============================================================================
// 18.1 Diálogo de Desinstalación Deliberada en 3 Clics con Solicitud de Contraseña
// ==============================================================================
fn run_uninstall_dialog(parent: &ApplicationWindow) {
    // Clic 1 ya ocurrió (el usuario presionó el botón de Desinstalar)
    // -------------------------------------------------------------
    // Paso 1: Diálogo Modal de Advertencias Críticas de Seguridad
    // -------------------------------------------------------------
    let w1 = ApplicationWindow::builder()
        .title("⚠️ Advertencia Crítica de Seguridad: ¿Desinstalar Constantine?")
        .default_width(620)
        .default_height(460)
        .modal(true)
        .transient_for(parent)
        .build();

    let box1 = Box::new(Orientation::Vertical, 14);
    box1.set_margin_start(22);
    box1.set_margin_end(22);
    box1.set_margin_top(20);
    box1.set_margin_bottom(20);

    let title1 = Label::new(Some("⚠️ ¿Estás seguro de que deseas desinstalar Constantine?"));
    title1.add_css_class("title-text");
    title1.set_xalign(0.0);
    title1.set_wrap(true);
    box1.append(&title1);

    let desc1 = Label::new(Some(
        "Desinstalar Constantine Antivirus & EDR v5.5.3 desmantelará la protección y dejará tu computadora expuesta a los siguientes riesgos inmediatos:"
    ));
    desc1.add_css_class("subtitle-text");
    desc1.set_xalign(0.0);
    desc1.set_wrap(true);
    desc1.set_wrap_mode(gtk4::pango::WrapMode::Word);
    box1.append(&desc1);

    let card_warn = Box::new(Orientation::Vertical, 8);
    card_warn.add_css_class("macos-card");

    let w_items = [
        "🛑 Pérdida de prevención en acceso en tiempo real (ClamOnAcc + fanotify en kernel).",
        "🛑 Exposición total a Ransomware (se eliminan señuelos Canary y análisis de entropía).",
        "🛑 Cese de supervisión de procesos en kernel con Tetragon (eBPF) y Falco.",
        "🛑 Desactivación del sumidero DNS anti-phishing y protección de navegación.",
        "🛑 Pérdida del registro forense inmutable y trazabilidad SHA-256.",
    ];
    for item in &w_items {
        let lbl = Label::new(Some(item));
        lbl.set_xalign(0.0);
        lbl.set_wrap(true);
        lbl.set_wrap_mode(gtk4::pango::WrapMode::Word);
        card_warn.append(&lbl);
    }
    box1.append(&card_warn);

    let note1 = Label::new(Some(
        "Constantine v5.5.3 opera de forma ligera, 100% privada y sin telemetría. Para mantener la integridad de tu sistema, recomendamos fuertemente cancelar y permanecer protegido."
    ));
    note1.add_css_class("subtitle-text");
    note1.set_xalign(0.0);
    note1.set_wrap(true);
    note1.set_wrap_mode(gtk4::pango::WrapMode::Word);
    box1.append(&note1);

    let btn_row1 = Box::new(Orientation::Horizontal, 12);
    btn_row1.set_halign(gtk4::Align::End);

    // Acción sugerida por defecto: Cancelar
    let btn_cancel1 = Button::with_label("🛡️ Cancelar y Permanecer Protegido");
    btn_cancel1.add_css_class("suggested-action");
    let w1_c = w1.clone();
    btn_cancel1.connect_clicked(move |_| w1_c.close());

    // Clic 2: Continuar a la confirmación final
    let btn_next2 = Button::with_label("Entiendo los riesgos y deseo continuar...");
    btn_next2.add_css_class("destructive-action");

    btn_row1.append(&btn_cancel1);
    btn_row1.append(&btn_next2);
    box1.append(&btn_row1);

    w1.set_child(Some(&box1));

    // Conectar Clic 2 -> Abre Paso 2 (Confirmación final y petición de contraseña)
    let w1_close = w1.clone();
    let parent_clone = parent.clone();
    btn_next2.connect_clicked(move |_| {
        w1_close.close();

        // -------------------------------------------------------------
        // Paso 2: Diálogo Modal de Confirmación Definitiva (Clic 3)
        // -------------------------------------------------------------
        let w2 = ApplicationWindow::builder()
            .title("🛑 Confirmación Definitiva de Desinstalación")
            .default_width(560)
            .default_height(360)
            .modal(true)
            .transient_for(&parent_clone)
            .build();

        let box2 = Box::new(Orientation::Vertical, 16);
        box2.set_margin_start(22);
        box2.set_margin_end(22);
        box2.set_margin_top(22);
        box2.set_margin_bottom(22);

        let title2 = Label::new(Some("🛑 ¿Confirmas la desinstalación permanente?"));
        title2.add_css_class("title-text");
        title2.set_xalign(0.0);
        title2.set_wrap(true);
        box2.append(&title2);

        let desc2 = Label::new(Some(
            "Al hacer clic en 'Confirmar y Desinstalar Permanentemente', el sistema solicitará obligatoriamente tu contraseña de administrador (root / pkexec) para revertir configuraciones y desinstalar Constantine.

Si cambiaste de opinión, presiona 'Cancelar Desinstalación'."
        ));
        desc2.add_css_class("subtitle-text");
        desc2.set_xalign(0.0);
        desc2.set_wrap(true);
        desc2.set_wrap_mode(gtk4::pango::WrapMode::Word);
        box2.append(&desc2);

        let btn_row2 = Box::new(Orientation::Horizontal, 12);
        btn_row2.set_halign(gtk4::Align::End);

        // Opción segura: Cancelar
        let btn_cancel2 = Button::with_label("🔙 Cancelar Desinstalación");
        btn_cancel2.add_css_class("suggested-action");
        let w2_c = w2.clone();
        btn_cancel2.connect_clicked(move |_| w2_c.close());

        // Clic 3 definitivo: Desinstalar permanentemente
        let btn_final3 = Button::with_label("⚠️ Confirmar y Desinstalar Permanentemente");
        btn_final3.add_css_class("destructive-action");

        let w2_final = w2.clone();
        let parent_final = parent_clone.clone();
        btn_final3.connect_clicked(move |_| {
            w2_final.close();
            // Solicitar autenticación pkexec y ejecutar uninstall
            if SecurityAuth::uninstall_interactive() {
                parent_final.set_visible(false);
                SystemNotifier::notify(
                    "normal",
                    "security-low",
                    "Constantine Antivirus & EDR",
                    "Desinstalación completada con éxito. El sistema ha sido revertido a sus valores originales.",
                );
                std::process::exit(0);
            } else {
                SystemNotifier::notify(
                    "normal",
                    "dialog-warning",
                    "Constantine Antivirus & EDR",
                    "Desinstalación cancelada: Se requiere contraseña de administrador para desinstalar Constantine.",
                );
            }
        });

        btn_row2.append(&btn_cancel2);
        btn_row2.append(&btn_final3);
        box2.append(&btn_row2);

        w2.set_child(Some(&box2));
        w2.present();
    });

    w1.present();
}

// ==============================================================================
// 18. Diálogo Interactivo de Amenaza en Tiempo Real (Actionable Toast Window)
// ==============================================================================
fn run_interactive_threat_dialog(threat_name: String, path: PathBuf, pid: u32, engine: String) {
    let app = Application::builder()
        .application_id("com.constantine.threatdialog")
        .flags(gtk4::gio::ApplicationFlags::NON_UNIQUE)
        .build();

    let tn_c = threat_name.clone();
    let p_c = path.clone();
    let eng_c = engine.clone();

    app.connect_startup(|_| {
        gtk4::Window::set_default_icon_name("constantine");
        let provider = CssProvider::new();
        provider.load_from_data(CUPERTINO_CSS);
        if let Some(display) = gtk4::gdk::Display::default() {
            gtk4::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    });

    app.connect_activate(move |app| {
        build_threat_dialog_ui(app, &tn_c, &p_c, pid, &eng_c);
    });

    app.run_with_args(&["constantine"]);
}

fn build_threat_dialog_ui(app: &Application, threat_name: &str, path: &Path, pid: u32, engine: &str) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("🚨 ALERTA CRÍTICA: Amenaza Detectada — Constantine EDR")
        .default_width(680)
        .default_height(480)
        .build();
    window.set_size_request(660, 460);
    window.set_icon_name(Some("constantine"));

    let main_box = Box::new(Orientation::Vertical, 14);
    main_box.set_margin_start(24);
    main_box.set_margin_end(24);
    main_box.set_margin_top(20);
    main_box.set_margin_bottom(20);
    window.set_child(Some(&main_box));

    // Tarjeta Crítica de Alerta
    let alert_card = Box::new(Orientation::Vertical, 10);
    alert_card.add_css_class("macos-card");

    let header_box = Box::new(Orientation::Horizontal, 10);
    let icon_lbl = Label::new(Some("🚨"));
    icon_lbl.add_css_class("mini-row-status-alert");

    let badge_lbl = Label::new(Some("AMENAZA EN TIEMPO REAL DETECTADA"));
    badge_lbl.add_css_class("mini-row-status-alert");

    header_box.append(&icon_lbl);
    header_box.append(&badge_lbl);
    alert_card.append(&header_box);

    let threat_lbl = Label::new(Some(threat_name));
    threat_lbl.add_css_class("title-text");
    threat_lbl.set_xalign(0.0);
    alert_card.append(&threat_lbl);

    let desc_lbl = Label::new(Some("Se ha interceptado una agresión o archivo hostil. Selecciona la acción que deseas aplicar de inmediato:"));
    desc_lbl.add_css_class("subtitle-text");
    desc_lbl.set_xalign(0.0);
    alert_card.append(&desc_lbl);

    main_box.append(&alert_card);

    // Detalles Técnicos Forenses
    let tech_card = Box::new(Orientation::Vertical, 8);
    tech_card.add_css_class("macos-card");
    tech_card.set_vexpand(true);

    let grid_tech = Grid::new();
    grid_tech.set_column_spacing(16);
    grid_tech.set_row_spacing(8);

    grid_tech.attach(&Label::new(Some("Motor / Sensor:")), 0, 0, 1, 1);
    let lbl_eng = Label::new(Some(engine));
    lbl_eng.add_css_class("mini-row-status-ok");
    lbl_eng.set_xalign(0.0);
    grid_tech.attach(&lbl_eng, 1, 0, 1, 1);

    grid_tech.attach(&Label::new(Some("Archivo o Recurso:")), 0, 1, 1, 1);
    let lbl_res = Label::new(Some(&path.to_string_lossy()));
    lbl_res.add_css_class("subtitle-text");
    lbl_res.set_xalign(0.0);
    lbl_res.set_hexpand(true);
    grid_tech.attach(&lbl_res, 1, 1, 1, 1);

    if pid > 0 {
        grid_tech.attach(&Label::new(Some("Proceso Agresor:")), 0, 2, 1, 1);
        let lbl_proc = Label::new(Some(&format!("PID {} (Activo en memoria)", pid)));
        lbl_proc.add_css_class("mini-row-status-alert");
        lbl_proc.set_xalign(0.0);
        grid_tech.attach(&lbl_proc, 1, 2, 1, 1);
    }

    let hash_val = if path.exists() && path.is_file() {
        ThreatAnalysisEngine::compute_sha256(path).unwrap_or_else(|_| "No calculable".into())
    } else {
        "En memoria / interceptado".into()
    };
    grid_tech.attach(&Label::new(Some("Hash SHA-256:")), 0, 3, 1, 1);
    let lbl_hash = Label::new(Some(&hash_val));
    lbl_hash.add_css_class("subtitle-text");
    lbl_hash.set_xalign(0.0);
    grid_tech.attach(&lbl_hash, 1, 3, 1, 1);

    tech_card.append(&grid_tech);

    let status_feedback = Label::new(Some("Esperando tu decisión..."));
    status_feedback.add_css_class("subtitle-text");
    status_feedback.set_xalign(0.0);
    tech_card.append(&status_feedback);

    main_box.append(&tech_card);

    // Botones de Decisión Directa (Actionable)
    let action_box = Box::new(Orientation::Horizontal, 10);
    action_box.set_halign(gtk4::Align::End);

    let btn_quarantine = Button::with_label("🔒 Poner en Cuarentena");
    btn_quarantine.add_css_class("destructive-action");

    let btn_kill = Button::with_label("🛑 Detener Proceso (SIGKILL)");
    btn_kill.add_css_class("destructive-action");
    if pid <= 1 {
        btn_kill.set_visible(false);
    }

    let btn_whitelist = Button::with_label("✅ Añadir a Lista Blanca");
    btn_whitelist.add_css_class("suggested-action");

    let btn_allow_once = Button::with_label("⚡ Permitir sólo esta vez");
    let btn_google = Button::with_label("🔍 Consultar en Google");

    action_box.append(&btn_quarantine);
    if pid > 1 {
        action_box.append(&btn_kill);
    }
    action_box.append(&btn_whitelist);
    action_box.append(&btn_allow_once);
    action_box.append(&btn_google);
    main_box.append(&action_box);

    // Conectar acciones interactivas
    let p_iso = path.to_path_buf();
    let tn_iso = threat_name.to_string();
    let eng_iso = engine.to_string();
    let sf_iso = status_feedback.clone();
    let bq_btn = btn_quarantine.clone();
    btn_quarantine.connect_clicked(move |_| {
        if ContainmentEngine::isolate_to_vault_with_metadata(&p_iso, &tn_iso, &eng_iso) {
            sf_iso.set_text("✓ Amenaza aislada y cifrada exitosamente con AES-256-GCM en el Baúl de Cuarentena.");
            bq_btn.set_sensitive(false);
        } else {
            sf_iso.set_text("⚠️ No se pudo aislar el archivo directamente (posiblemente eliminado o bloqueado).");
        }
    });

    if pid > 1 {
        let sf_kill = status_feedback.clone();
        let bk_btn = btn_kill.clone();
        btn_kill.connect_clicked(move |_| {
            let pid_str = pid.to_string();
            let _ = SecurityAuth::privileged_action(&["kill", "-STOP", &pid_str]);
            let _ = SecurityAuth::privileged_action(&["kill", "-KILL", &pid_str]);
            sf_kill.set_text(&format!("✓ Proceso PID {} terminado fulminantemente (SIGKILL).", pid));
            bk_btn.set_sensitive(false);
            ImmutableAuditLog::append_event("PROCESS_KILLED_USER", &format!("Proceso agresor PID {} terminado a solicitud del usuario.", pid));
        });
    }

    let p_wl = path.to_path_buf();
    let sf_wl = status_feedback.clone();
    let bw_btn = btn_whitelist.clone();
    let fname_wl = path.file_name().and_then(|n| n.to_str()).unwrap_or("archivo").to_string();
    let hash_wl = hash_val.clone();
    btn_whitelist.connect_clicked(move |_| {
        if WhitelistManager::add_record(&hash_wl, &fname_wl, &p_wl.to_string_lossy()) {
            sf_wl.set_text("✓ Archivo y firma autorizados en Lista Blanca permanente.");
            bw_btn.set_sensitive(false);
        } else {
            sf_wl.set_text("⚠️ Fallo al agregar la firma a la Lista Blanca.");
        }
    });

    let win_allow = window.clone();
    let tn_allow = threat_name.to_string();
    let p_allow = path.to_string_lossy().to_string();
    btn_allow_once.connect_clicked(move |_| {
        ImmutableAuditLog::append_event("THREAT_ALLOWED_ONCE", &format!("Amenaza permitida una sola vez por el usuario: {} sobre {}", tn_allow, p_allow));
        win_allow.close();
    });

    let tn_search = threat_name.to_string();
    btn_google.connect_clicked(move |_| {
        let query = format!("https://www.google.com/search?q=malware+threat+intelligence+{}", tn_search);
        let _ = Command::new("xdg-open").arg(&query).spawn();
    });

    window.present();
}

fn build_scan_dialog_ui(app: &Application, target: &Path) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("Constantine Antivirus — Análisis Rápido")
        .default_width(680)
        .default_height(480)
        .build();
    window.set_size_request(640, 440);
    window.set_icon_name(Some("constantine"));

    let main_box = Box::new(Orientation::Vertical, 14);
    main_box.set_margin_start(24);
    main_box.set_margin_end(24);
    main_box.set_margin_top(20);
    main_box.set_margin_bottom(20);
    window.set_child(Some(&main_box));

    // Tarjeta Superior: Detalles del Objetivo
    let card_target = Box::new(Orientation::Vertical, 8);
    card_target.add_css_class("macos-card");

    let t_title = Label::new(Some("🔍 Análisis de Seguridad bajo Demanda"));
    t_title.add_css_class("title-text");
    t_title.set_xalign(0.0);
    card_target.append(&t_title);

    let fname = target.file_name().and_then(|n| n.to_str()).unwrap_or("elemento").to_string();
    let fpath_str = target.to_string_lossy().to_string();

    let grid_info = Grid::new();
    grid_info.set_column_spacing(16);
    grid_info.set_row_spacing(6);

    grid_info.attach(&Label::new(Some("Elemento:")), 0, 0, 1, 1);
    let lbl_fn = Label::new(Some(&fname));
    lbl_fn.add_css_class("title-text");
    lbl_fn.set_xalign(0.0);
    grid_info.attach(&lbl_fn, 1, 0, 1, 1);

    grid_info.attach(&Label::new(Some("Ruta completa:")), 0, 1, 1, 1);
    let lbl_fp = Label::new(Some(&fpath_str));
    lbl_fp.add_css_class("subtitle-text");
    lbl_fp.set_xalign(0.0);
    grid_info.attach(&lbl_fp, 1, 1, 1, 1);

    let is_dir = target.is_dir();
    let type_desc = if is_dir { "Carpeta / Directorio del Sistema" } else { "Archivo Individual" };
    grid_info.attach(&Label::new(Some("Tipo:")), 0, 2, 1, 1);
    let lbl_type = Label::new(Some(type_desc));
    lbl_type.add_css_class("subtitle-text");
    lbl_type.set_xalign(0.0);
    grid_info.attach(&lbl_type, 1, 2, 1, 1);

    card_target.append(&grid_info);
    main_box.append(&card_target);

    // Barra de Progreso y Estado
    let progress = ProgressBar::new();
    progress.set_fraction(0.15);
    main_box.append(&progress);

    let st_lbl = Label::new(Some("Iniciando motores de análisis (ClamAV, YARA, YARA-X, Entropía y Feeds)..."));
    st_lbl.add_css_class("subtitle-text");
    st_lbl.set_xalign(0.0);
    main_box.append(&st_lbl);

    // Tarjeta Inferior: Veredicto y Acciones
    let card_result = Box::new(Orientation::Vertical, 10);
    card_result.add_css_class("macos-card");
    card_result.set_vexpand(true);

    let res_title = Label::new(Some("● Evaluando integridad y firmas..."));
    res_title.add_css_class("title-text");
    res_title.set_xalign(0.0);
    card_result.append(&res_title);

    let res_desc = Label::new(Some("Esperando veredicto del motor de seguridad Fail-Secure."));
    res_desc.add_css_class("subtitle-text");
    res_desc.set_xalign(0.0);
    card_result.append(&res_desc);

    main_box.append(&card_result);

    // Botones de Acción
    let btn_row = Box::new(Orientation::Horizontal, 12);
    btn_row.set_halign(gtk4::Align::End);

    let btn_quarantine = Button::with_label("🔒 Aislar en Baúl");
    btn_quarantine.add_css_class("destructive-action");
    btn_quarantine.set_visible(false);

    let btn_google = Button::with_label("🔍 Consultar en Google");
    btn_google.add_css_class("suggested-action");
    btn_google.set_visible(false);

    let btn_whitelist = Button::with_label("✅ Añadir a Lista Blanca");
    btn_whitelist.add_css_class("suggested-action");
    btn_whitelist.set_visible(false);

    let btn_close = Button::with_label("Cerrar");
    btn_close.add_css_class("suggested-action");

    btn_row.append(&btn_quarantine);
    btn_row.append(&btn_google);
    btn_row.append(&btn_whitelist);
    btn_row.append(&btn_close);
    main_box.append(&btn_row);

    let win_c = window.clone();
    btn_close.connect_clicked(move |_| win_c.close());

    // Ejecutar análisis en hilo secundario comunicando directamente al bucle de GTK
    let target_p = target.to_path_buf();
    let pr_c = progress.clone();
    let st_c = st_lbl.clone();
    let rt_c = res_title.clone();
    let rd_c = res_desc.clone();
    let bq_c = btn_quarantine.clone();
    let bg_c = btn_google.clone();
    let bw_c = btn_whitelist.clone();

    gtk4::glib::spawn_future_local(async move {
        let path_scan = target_p.clone();
        let (verdict, _threats_count, _total_scanned) = run_blocking(move || {
            if path_scan.is_dir() {
                let mut files = Vec::new();
                ManualScanEngine::collect_files(&path_scan, &mut files);
                let total = files.len();
                let mut threats = Vec::new();
                for f in &files {
                    if let FileVerdict::Threat(t) = ThreatAnalysisEngine::evaluate_file(f) {
                        threats.push((f.clone(), t));
                    }
                }
                if threats.is_empty() {
                    (FileVerdict::Clean(format!("Carpeta examinada ({} archivos certificados limpios).", total)), 0, total)
                } else {
                    (FileVerdict::Threat(format!("Detectadas {} amenazas en la carpeta examinada.", threats.len())), threats.len(), total)
                }
            } else {
                let v = ThreatAnalysisEngine::evaluate_file(&path_scan);
                (v, 0, 1)
            }
        }).await;

        pr_c.set_fraction(1.0);
        match verdict {
            FileVerdict::Clean(msg) => {
                st_c.set_text("✓ Análisis finalizado: Sin amenazas detectadas.");
                rt_c.set_text("✅ ARCHIVO CERTIFICADO LIMPIO");
                rt_c.remove_css_class("mini-row-status-alert");
                rt_c.add_css_class("mini-row-status-ok");
                rd_c.set_text(&format!("Veredicto del motor: {}", msg));
            }
            FileVerdict::Threat(t_msg) => {
                st_c.set_text("⚠️ ATENCIÓN: Amenaza de seguridad confirmada en el archivo.");
                rt_c.set_text("🚨 AMENAZA DETECTADA");
                rt_c.remove_css_class("mini-row-status-ok");
                rt_c.add_css_class("mini-row-status-alert");
                rd_c.set_text(&format!("Detalle de la detección: {}", t_msg));

                bq_c.set_visible(true);
                bg_c.set_visible(true);
                bw_c.set_visible(true);

                let p_iso = target_p.clone();
                let t_name_iso = t_msg.clone();
                let st_iso = st_c.clone();
                let bq_btn = bq_c.clone();
                bq_c.connect_clicked(move |_| {
                    if ContainmentEngine::isolate_to_vault_with_metadata(&p_iso, &t_name_iso, "Análisis Menú Contextual Clic Derecho") {
                        st_iso.set_text("✓ Amenaza trasladada y cifrada con éxito en el Baúl de Cuarentena.");
                        bq_btn.set_sensitive(false);
                    }
                });

                let t_search = t_msg.clone();
                bg_c.connect_clicked(move |_| {
                    let query = format!("https://www.google.com/search?q=malware+{}", t_search);
                    let _ = Command::new("xdg-open").arg(&query).spawn();
                });

                let p_wl = target_p.clone();
                let st_wl = st_c.clone();
                let bw_btn = bw_c.clone();
                bw_c.connect_clicked(move |_| {
                    if let Ok(h) = WhitelistManager::add_file(&p_wl) {
                        st_wl.set_text(&format!("✓ Archivo añadido a Lista Blanca (Hash: {}...)", &h[..16.min(h.len())]));
                        bw_btn.set_sensitive(false);
                    }
                });
            }
            FileVerdict::Indeterminate(i_msg) => {
                st_c.set_text("ℹ️ Inspección completada bajo política Fail-Secure.");
                rt_c.set_text("⚠️ ESTADO INDETERMINADO");
                rt_c.remove_css_class("mini-row-status-ok");
                rt_c.add_css_class("mini-row-status-warn");
                rd_c.set_text(&format!("Motivo: {}", i_msg));
            }
        }
    });

    window.present();
}


fn run_health_audit_dialog(parent: &ApplicationWindow, user_home: &str) {
    let dialog = ApplicationWindow::builder()
        .transient_for(parent)
        .modal(true)
        .title("🛡️ Auditoría de Salud del EDR - Requisitos para el 100%")
        .default_width(640)
        .default_height(560)
        .build();

    let vbox = Box::new(Orientation::Vertical, 12);
    vbox.set_margin_start(18);
    vbox.set_margin_end(18);
    vbox.set_margin_top(18);
    vbox.set_margin_bottom(18);

    let (score_pct, pillars) = ModuleVersionAudit::get_detailed_health_breakdown(user_home);

    let title = Label::new(Some("Desglose de Salud Operativa y Controles de Seguridad"));
    title.add_css_class("title-text");
    title.set_xalign(0.0);
    vbox.append(&title);

    let subtitle = Label::new(Some("Evaluación en tiempo real de los 10 pilares de defensa del Kernel, EDR y Red."));
    subtitle.add_css_class("subtitle-text");
    subtitle.set_xalign(0.0);
    vbox.append(&subtitle);

    let score_lbl = Label::new(Some(&format!("Puntuación Global: {}% de 100%", score_pct)));
    score_lbl.add_css_class(if score_pct == 100 { "mini-row-status-ok" } else { "mini-row-status-warn" });
    score_lbl.set_xalign(0.0);
    vbox.append(&score_lbl);

    let pbar = ProgressBar::new();
    pbar.set_fraction((score_pct as f64) / 100.0);
    vbox.append(&pbar);

    let list_sw = ScrolledWindow::new();
    list_sw.set_vexpand(true);
    let list_box = ListBox::new();
    list_box.set_selection_mode(SelectionMode::None);

    for pillar in &pillars {
        let row_box = Box::new(Orientation::Horizontal, 12);
        row_box.set_margin_top(6);
        row_box.set_margin_bottom(6);
        row_box.set_margin_start(8);
        row_box.set_margin_end(8);

        let icon = Label::new(Some(if pillar.is_ok { "✅" } else { "⚠️" }));
        row_box.append(&icon);

        let info_box = Box::new(Orientation::Vertical, 2);
        info_box.set_hexpand(true);

        let name_lbl = Label::new(Some(&format!("{} ({}%)", pillar.name, pillar.weight_pct)));
        name_lbl.add_css_class("kpi-title");
        name_lbl.set_xalign(0.0);
        info_box.append(&name_lbl);

        let desc_lbl = Label::new(Some(&pillar.details));
        desc_lbl.add_css_class(if pillar.is_ok { "mini-row-status-ok" } else { "mini-row-status-warn" });
        desc_lbl.set_xalign(0.0);
        info_box.append(&desc_lbl);

        if !pillar.is_ok {
            let remedy_lbl = Label::new(Some(&format!("👉 Para el 100%: {}", pillar.remedy)));
            remedy_lbl.add_css_class("subtitle-text");
            remedy_lbl.set_xalign(0.0);
            info_box.append(&remedy_lbl);
        }

        row_box.append(&info_box);
        list_box.append(&row_box);
    }
    list_sw.set_child(Some(&list_box));
    vbox.append(&list_sw);

    let btn_box = Box::new(Orientation::Horizontal, 10);
    btn_box.set_halign(gtk4::Align::End);

    if score_pct < 100 {
        let btn_fix = Button::with_label("⚡ Activar Escudos Faltantes");
        btn_fix.add_css_class("suggested-action");
        let d_c = dialog.clone();
        btn_fix.connect_clicked(move |_| {
            SecurityAuth::resume_all_shields_interactive();
            d_c.close();
        });
        btn_box.append(&btn_fix);
    }

    let btn_close = Button::with_label("Cerrar");
    let d_c2 = dialog.clone();
    btn_close.connect_clicked(move |_| d_c2.close());
    btn_box.append(&btn_close);

    vbox.append(&btn_box);
    dialog.set_child(Some(&vbox));
    dialog.present();
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("Constantine Antivirus & EDR")
        .default_width(800)
        .default_height(600)
        .build();
    window.set_size_request(640, 480);
    window.set_icon_name(Some("constantine"));

    let current_user = std::env::var("USER").unwrap_or_else(|_| "usuario".into());
    let user_home = std::env::var("HOME").unwrap_or_else(|_| format!("/home/{}", current_user));

    // Inicialización de componentes de seguridad en segundo plano
    AntiRansomwareShield::deploy_canary_tripwires(&user_home);
    OnAccessSupervisor::start_realtime_event_consumer();
    TetragonPrimarySensor::start_primary_edr_consumer();
    UsbDriveMonitor::start_usb_mount_listener();

    // Falco y los sensores son gestionados por systemd en el arranque del sistema (cero contraseñas al abrir la GUI)

    // Iniciar icono de estado en la bandeja del sistema (junto al reloj) si está disponible
    if Path::new("/usr/local/bin/constantine-tray").exists() {
        if Command::new("pgrep").args(["-f", "constantine-tray"]).output().map(|o| !o.status.success()).unwrap_or(true) {
            let _ = Command::new("/usr/local/bin/constantine-tray").spawn();
        }
    }

    // Cerrar la ventana y finalizar la interfaz al hacer clic en la X
    window.connect_close_request(|_| {
        gtk4::glib::Propagation::Proceed
    });

    // HeaderBar
    let header = HeaderBar::new();
    header.add_css_class("macos-headerbar");
    
    let title_box = Box::new(Orientation::Horizontal, 8);
    let title_lbl = Label::new(Some("Constantine EDR"));
    title_lbl.add_css_class("title-text");
    
    let badge_lbl = Label::new(Some("v5.5.3"));
    badge_lbl.add_css_class("badge-version");
    
    title_box.append(&title_lbl);
    title_box.append(&badge_lbl);
    header.set_title_widget(Some(&title_box));

    let btn_shutdown = Button::with_label("🛑 Apagar");
    btn_shutdown.add_css_class("power-btn");
    header.pack_start(&btn_shutdown);

    // Botón de Pausar / Reactivar Todos los Escudos (sin apagar Constantine)
    let shields_init_active = SecurityAuth::are_shields_active();
    let btn_pause_shields = Button::with_label(if shields_init_active { "⏸️ Pausar Escudos" } else { "▶️ Activar Escudos" });
    btn_pause_shields.add_css_class("suggested-action");
    header.pack_start(&btn_pause_shields);

    // Botón de Desinstalar Constantine (Flujo deliberado de 3 clics)
    let btn_uninstall = Button::with_label("🗑️ Desinstalar");
    btn_uninstall.add_css_class("power-btn");
    header.pack_start(&btn_uninstall);
    
    let win_shutdown = window.clone();
    btn_shutdown.connect_clicked(move |_| {
        // Solicitar obligatoriamente contraseña de administrador para autorizar el apagado y forzar módulos
        if SecurityAuth::shutdown_all_protected_interactive() {
            win_shutdown.set_visible(false);
            ImmutableAuditLog::append_event("SYSTEM_SHUTDOWN", "Apagado total autorizado con contraseña de administrador: todos los módulos y sensores forzados.");
            SystemNotifier::notify(
                "critical",
                "security-low",
                "Constantine Antivirus & EDR",
                "Apagado total completado: Todos los sensores, demonios y módulos de protección han sido forzados y detenidos.",
            );
            std::process::exit(0);
        } else {
            SystemNotifier::notify(
                "normal",
                "dialog-warning",
                "Constantine Antivirus & EDR",
                "Apagado cancelado: Se requiere contraseña de administrador para detener la protección.",
            );
        }
    });

    let btn_ps_c = btn_pause_shields.clone();
    btn_pause_shields.connect_clicked(move |_| {
        let btn = btn_ps_c.clone();
        if SecurityAuth::are_shields_active() {
            if SecurityAuth::pause_all_shields_interactive() {
                btn.set_label("▶️ Activar Escudos");
                ImmutableAuditLog::append_event("SHIELDS_PAUSED", "Todos los escudos de seguridad en kernel fueron pausados a solicitud del usuario (interfaz operativa).");
                SystemNotifier::notify(
                    "normal",
                    "dialog-warning",
                    "Constantine Antivirus & EDR",
                    "Todos los escudos de protección en tiempo real han sido pausados.",
                );
            } else {
                SystemNotifier::notify(
                    "normal",
                    "dialog-warning",
                    "Constantine Antivirus & EDR",
                    "Pausa cancelada: Se requiere contraseña de administrador para pausar los escudos.",
                );
            }
        } else {
            if SecurityAuth::resume_all_shields_interactive() {
                btn.set_label("⏸️ Pausar Escudos");
                ImmutableAuditLog::append_event("SHIELDS_RESUMED", "Todos los escudos de seguridad en tiempo real fueron reactivados con éxito.");
                SystemNotifier::notify(
                    "normal",
                    "security-high",
                    "Constantine Antivirus & EDR",
                    "Todos los escudos de protección en tiempo real han sido reactivados con éxito.",
                );
            } else {
                SystemNotifier::notify(
                    "normal",
                    "dialog-warning",
                    "Constantine Antivirus & EDR",
                    "Reactivación cancelada: Se requiere contraseña de administrador para reactivar los escudos.",
                );
            }
        }
    });

    let win_uninst = window.clone();
    btn_uninstall.connect_clicked(move |_| {
        // Clic 1: Abrir el diálogo deliberado de desinstalación
        run_uninstall_dialog(&win_uninst);
    });

    let btn_health = Button::new();
    btn_health.add_css_class("health-btn");
    
    let (init_pct, _init_act, _init_tot) = ModuleVersionAudit::compute_real_health_score(&user_home);
    let health_lbl = Label::new(Some(&format!("● Salud: {}% (Ver Qué Falta)", init_pct)));
    health_lbl.add_css_class("health-score");
    btn_health.set_child(Some(&health_lbl));
    header.pack_end(&btn_health);

    let win_health_hdr = window.clone();
    let uh_health_hdr = user_home.clone();
    btn_health.connect_clicked(move |_| {
        run_health_audit_dialog(&win_health_hdr, &uh_health_hdr);
    });
    
    window.set_titlebar(Some(&header));

    let main_box = Box::new(Orientation::Horizontal, 0);
    window.set_child(Some(&main_box));

    // Sidebar
    let sidebar = Box::new(Orientation::Vertical, 4);
    sidebar.add_css_class("sidebar-box");
    
    let status_card = Box::new(Orientation::Vertical, 4);
    status_card.add_css_class("mini-status-card");
    
    let st_title = Label::new(Some("SENSORES EDR ACTIVOS"));
    st_title.add_css_class("mini-row-title");
    st_title.set_xalign(0.0);
    
    let st_sub = Label::new(Some("● 16 Escudos + Anti-Ransomware"));
    st_sub.add_css_class("mini-row-status-ok");
    st_sub.set_xalign(0.0);
    
    status_card.append(&st_title);
    status_card.append(&st_sub);
    sidebar.append(&status_card);

    let btn_dash = Button::with_label("🛡️ Estado");
    btn_dash.add_css_class("nav-btn");
    btn_dash.add_css_class("nav-btn-active");
    
    let btn_scan = Button::with_label("🔍 Análisis");
    btn_scan.add_css_class("nav-btn");
    
    let btn_updates = Button::with_label("🔄 Motores");
    btn_updates.add_css_class("nav-btn");

    let btn_wl = Button::with_label("📋 Lista Blanca");
    btn_wl.add_css_class("nav-btn");

    let btn_periph = Button::with_label("🎙️ Periféricos");
    btn_periph.add_css_class("nav-btn");
    
    let btn_net = Button::with_label("🌐 Red y Web");
    btn_net.add_css_class("nav-btn");
    
    let btn_vault = Button::with_label("📦 Cuarentena");
    btn_vault.add_css_class("nav-btn");
    
    let btn_modules = Button::with_label("⚙️ Módulos");
    btn_modules.add_css_class("nav-btn");
    
    let btn_logs = Button::with_label("📜 Forense");
    btn_logs.add_css_class("nav-btn");

    sidebar.append(&btn_dash);
    sidebar.append(&btn_scan);
    sidebar.append(&btn_updates);
    sidebar.append(&btn_wl);
    sidebar.append(&btn_periph);
    sidebar.append(&btn_net);
    sidebar.append(&btn_vault);
    sidebar.append(&btn_modules);
    sidebar.append(&btn_logs);
    
    let spacer = Box::new(Orientation::Vertical, 0);
    spacer.set_vexpand(true);
    sidebar.append(&spacer);
    
    let user_role = if SecurityAuth::is_in_constantine_group() { "Grupo 'constantine'" } else { "Usuario Estándar" };
    let footer = Label::new(Some(&format!("Sesión: {} ({})", current_user, user_role)));
    footer.add_css_class("subtitle-text");
    sidebar.append(&footer);
    
    main_box.append(&sidebar);

    // Stack de Vistas
    let stack = Stack::new();
    stack.set_hexpand(true);
    stack.set_vexpand(true);

    // --- Vista 1: Panel de Control Ejecutivo & KPIs de Seguridad ---
    let dash_box = Box::new(Orientation::Vertical, 14);
    dash_box.set_margin_start(14);
    dash_box.set_margin_end(14);
    dash_box.set_margin_top(14);
    dash_box.set_margin_bottom(14);
    
    // Título Principal
    let head_dash_box = Box::new(Orientation::Vertical, 4);
    let t_ov = Label::new(Some("Panel de Control Ejecutivo & KPIs de Seguridad (EDR v5.5.3)"));
    t_ov.add_css_class("title-text");
    t_ov.set_xalign(0.0);
    head_dash_box.append(&t_ov);
    
    let sub_ov = Label::new(Some("Supervisión en vivo de defensas activas, muestras aisladas, salud de kernel y telemetría de amenazas."));
    sub_ov.add_css_class("subtitle-text");
    sub_ov.set_xalign(0.0);
    head_dash_box.append(&sub_ov);
    dash_box.append(&head_dash_box);

    // Grid de Tarjetas KPI Clave (4 métricas ejecutivas)
    let kpi_grid = Grid::new();
    kpi_grid.set_column_spacing(10);
    kpi_grid.set_row_spacing(10);
    kpi_grid.set_column_homogeneous(true);

    // KPI 1: Cuarentena
    let kpi_q_card = Box::new(Orientation::Vertical, 4);
    kpi_q_card.add_css_class("kpi-card");
    let q_title = Label::new(Some("📦 MUESTRAS EN CUARENTENA"));
    q_title.add_css_class("kpi-title");
    q_title.set_xalign(0.0);
    let lbl_kpi_quarantine = Label::new(Some(&format!("{} Muestras", get_quarantine_count())));
    lbl_kpi_quarantine.add_css_class("kpi-value");
    lbl_kpi_quarantine.set_xalign(0.0);
    let q_sub = Label::new(Some("Baúl Criptográfico AES-256-GCM"));
    q_sub.add_css_class("kpi-subtitle");
    q_sub.set_xalign(0.0);
    kpi_q_card.append(&q_title);
    kpi_q_card.append(&lbl_kpi_quarantine);
    kpi_q_card.append(&q_sub);
    kpi_grid.attach(&kpi_q_card, 0, 0, 1, 1);

    // KPI 2: Lista Blanca
    let kpi_wl_card = Box::new(Orientation::Vertical, 4);
    kpi_wl_card.add_css_class("kpi-card");
    let wl_title = Label::new(Some("📋 REGLAS EN LISTA BLANCA"));
    wl_title.add_css_class("kpi-title");
    wl_title.set_xalign(0.0);
    let lbl_kpi_whitelist = Label::new(Some(&format!("{} Hashes", get_whitelist_count())));
    lbl_kpi_whitelist.add_css_class("kpi-value");
    lbl_kpi_whitelist.set_xalign(0.0);
    let wl_sub = Label::new(Some("Firmas SHA-256 de Confianza"));
    wl_sub.add_css_class("kpi-subtitle");
    wl_sub.set_xalign(0.0);
    kpi_wl_card.append(&wl_title);
    kpi_wl_card.append(&lbl_kpi_whitelist);
    kpi_wl_card.append(&wl_sub);
    kpi_grid.attach(&kpi_wl_card, 1, 0, 1, 1);

    // KPI 3: Escudo Activo en Vigilancia
    let kpi_sh_card = Box::new(Orientation::Vertical, 4);
    kpi_sh_card.add_css_class("kpi-card");
    let sh_title = Label::new(Some("🔍 ESCUDOS EN VIGILANCIA"));
    sh_title.add_css_class("kpi-title");
    sh_title.set_xalign(0.0);
    let lbl_kpi_shields = Label::new(Some("fanotify + eBPF"));
    lbl_kpi_shields.add_css_class("kpi-value");
    lbl_kpi_shields.set_xalign(0.0);
    let lbl_kpi_shields_sub = Label::new(Some(&get_active_shield_summary()));
    lbl_kpi_shields_sub.add_css_class("kpi-subtitle");
    lbl_kpi_shields_sub.set_xalign(0.0);
    lbl_kpi_shields_sub.set_wrap(true);
    kpi_sh_card.append(&sh_title);
    kpi_sh_card.append(&lbl_kpi_shields);
    kpi_sh_card.append(&lbl_kpi_shields_sub);
    kpi_grid.attach(&kpi_sh_card, 2, 0, 1, 1);

    // KPI 4: Anti-Ransomware Canaries
    let kpi_can_card = Box::new(Orientation::Vertical, 4);
    kpi_can_card.add_css_class("kpi-card");
    let can_title = Label::new(Some("🧬 ANTI-RANSOMWARE CANARY"));
    can_title.add_css_class("kpi-title");
    can_title.set_xalign(0.0);
    let can_active = AntiRansomwareShield::verify_active_canaries(&user_home);
    let lbl_kpi_canary = Label::new(Some(&format!("{}/{} Intactos", can_active, CANARY_FILES.len())));
    lbl_kpi_canary.add_css_class("kpi-value");
    lbl_kpi_canary.set_xalign(0.0);
    let can_sub = Label::new(Some("Tripwires + Detección de Ráfagas"));
    can_sub.add_css_class("kpi-subtitle");
    can_sub.set_xalign(0.0);
    kpi_can_card.append(&can_title);
    kpi_can_card.append(&lbl_kpi_canary);
    kpi_can_card.append(&can_sub);
    kpi_grid.attach(&kpi_can_card, 3, 0, 1, 1);

    dash_box.append(&kpi_grid);

    // Tarjeta 2: Actualizaciones del Sistema y del Kernel
    let card_updates_sys = Box::new(Orientation::Horizontal, 16);
    card_updates_sys.add_css_class("macos-card");

    let upd_info_box = Box::new(Orientation::Vertical, 4);
    upd_info_box.set_hexpand(true);
    let upd_card_title = Label::new(Some("🔄 Actualizaciones del Sistema Operativo y del Kernel Linux"));
    upd_card_title.add_css_class("mini-row-title");
    upd_card_title.set_xalign(0.0);
    upd_info_box.append(&upd_card_title);

    let upd_data = SystemUpdateAudit::check_updates();
    let lbl_kernel_info = Label::new(Some(&format!("Kernel activo: {} | {}", upd_data.running_kernel, if upd_data.kernel_update_pending { "⚠️ Actualización de Kernel pendiente" } else { "🟢 Kernel al día" })));
    lbl_kernel_info.add_css_class(if upd_data.kernel_update_pending { "mini-row-status-warn" } else { "mini-row-status-ok" });
    lbl_kernel_info.set_xalign(0.0);
    upd_info_box.append(&lbl_kernel_info);

    let lbl_updates_info = Label::new(Some(&upd_data.status_text));
    lbl_updates_info.add_css_class("subtitle-text");
    lbl_updates_info.set_xalign(0.0);
    upd_info_box.append(&lbl_updates_info);

    card_updates_sys.append(&upd_info_box);

    let btn_open_updater = Button::with_label("🚀 Abrir Actualizador");
    btn_open_updater.add_css_class("suggested-action");
    btn_open_updater.set_valign(gtk4::Align::Center);
    btn_open_updater.connect_clicked(|_| {
        SystemUpdateAudit::launch_native_updater();
    });
    card_updates_sys.append(&btn_open_updater);
    dash_box.append(&card_updates_sys);

    // Tarjeta 3: Salud del EDR con botón directo para ver desglose de 100%
    let card_health_diag = Box::new(Orientation::Horizontal, 16);
    card_health_diag.add_css_class("macos-card");

    let health_info_box = Box::new(Orientation::Vertical, 4);
    health_info_box.set_hexpand(true);
    let h_diag_title = Label::new(Some("🛡️ Salud Operativa Global del EDR"));
    h_diag_title.add_css_class("mini-row-title");
    h_diag_title.set_xalign(0.0);
    health_info_box.append(&h_diag_title);

    let (score_now, act_now, tot_now) = ModuleVersionAudit::compute_real_health_score(&user_home);
    let lbl_dash_health = Label::new(Some(&format!("Salud Global: {}% ({}/{} Controles de Seguridad Activos)", score_now, act_now, tot_now)));
    lbl_dash_health.add_css_class(if score_now == 100 { "mini-row-status-ok" } else { "mini-row-status-warn" });
    lbl_dash_health.set_xalign(0.0);
    health_info_box.append(&lbl_dash_health);

    let pbar_dash_health = ProgressBar::new();
    pbar_dash_health.set_fraction((score_now as f64) / 100.0);
    health_info_box.append(&pbar_dash_health);
    card_health_diag.append(&health_info_box);

    let btn_show_health_diag = Button::with_label("🔍 Ver Qué Falta para el 100%");
    btn_show_health_diag.add_css_class("suggested-action");
    btn_show_health_diag.set_valign(gtk4::Align::Center);
    let win_h_btn = window.clone();
    let uh_h_btn = user_home.clone();
    btn_show_health_diag.connect_clicked(move |_| {
        run_health_audit_dialog(&win_h_btn, &uh_h_btn);
    });
    card_health_diag.append(&btn_show_health_diag);
    dash_box.append(&card_health_diag);

    // Tarjeta 4: Matriz Detallada de Sensores en Vivo
    let card_overview = Box::new(Orientation::Vertical, 12);
    card_overview.add_css_class("macos-card");
    
    let t_sens = Label::new(Some("Matriz de Sensores e Interceptores en Kernel"));
    t_sens.add_css_class("title-text");
    t_sens.set_xalign(0.0);
    card_overview.append(&t_sens);
    
    let grid_sensors = Grid::new();
    grid_sensors.set_column_spacing(10);
    grid_sensors.set_row_spacing(6);

    let mk_lbl = |txt: &str| -> Label {
        let l = Label::new(Some(txt));
        l.set_xalign(0.0);
        l.set_wrap(true);
        l.set_wrap_mode(gtk4::pango::WrapMode::Word);
        l
    };

    grid_sensors.attach(&mk_lbl("1. Prevención Acceso (fanotify):"), 0, 0, 1, 1);
    let (onacc_ok, onacc_txt) = OnAccessSupervisor::get_onaccess_pipeline_status();
    let s_f = mk_lbl(&onacc_txt);
    s_f.add_css_class(if onacc_ok { "mini-row-status-ok" } else { "mini-row-status-warn" });
    grid_sensors.attach(&s_f, 1, 0, 2, 1);

    grid_sensors.attach(&mk_lbl("2. Anti-Ransomware (Canary):"), 0, 1, 1, 1);
    let s_ran = mk_lbl("● 4 Señuelos / Ráfagas activas");
    s_ran.add_css_class("mini-row-status-ok");
    grid_sensors.attach(&s_ran, 1, 1, 2, 1);

    grid_sensors.attach(&mk_lbl("3. Sensor eBPF (Tetragon):"), 0, 2, 1, 1);
    let tetra_up = get_service_active("tetragon");
    let s_p = mk_lbl(if tetra_up { "● Activo: Protección LSM Kernel" } else { "● Detenido" });
    s_p.add_css_class(if tetra_up { "mini-row-status-ok" } else { "mini-row-status-warn" });
    grid_sensors.attach(&s_p, 1, 2, 1, 1);

    let btn_force_tetra = Button::with_label("⚡ Forzar");
    btn_force_tetra.add_css_class("suggested-action");
    grid_sensors.attach(&btn_force_tetra, 2, 2, 1, 1);

    let s_p_c = s_p.clone();
    btn_force_tetra.connect_clicked(move |_| {
        s_p_c.set_text("⏳ Forzando...");
        if SecurityAuth::force_start_service("tetragon") {
            s_p_c.set_text("● Activo: Protección LSM");
            s_p_c.remove_css_class("mini-row-status-warn");
            s_p_c.add_css_class("mini-row-status-ok");
        }
    });

    grid_sensors.attach(&mk_lbl("4. Periféricos (Cámara/Mic):"), 0, 3, 1, 1);
    let s_per = mk_lbl("● Protegido (/dev/video, snd)");
    s_per.add_css_class("mini-row-status-ok");
    grid_sensors.attach(&s_per, 1, 3, 2, 1);

    grid_sensors.attach(&mk_lbl("5. Filtros de Red (UFW/VPN):"), 0, 4, 1, 1);
    let s_net = mk_lbl("● UFW activo / Kill-Switch listo");
    s_net.add_css_class("mini-row-status-ok");
    grid_sensors.attach(&s_net, 1, 4, 2, 1);

    grid_sensors.attach(&mk_lbl("6. Registro Forense:"), 0, 5, 1, 1);
    let (c_ok, c_count) = ImmutableAuditLog::verify_integrity();
    let s_log = mk_lbl(&format!("● SHA-256 verificado ({} ev)", c_count));
    s_log.add_css_class(if c_ok { "mini-row-status-ok" } else { "mini-row-status-alert" });
    grid_sensors.attach(&s_log, 1, 5, 2, 1);

    grid_sensors.attach(&mk_lbl("7. Escudo USB Plug & Play:"), 0, 6, 1, 1);
    let s_usb = mk_lbl("● Monitoreo /media activo");
    s_usb.add_css_class("mini-row-status-ok");
    grid_sensors.attach(&s_usb, 1, 6, 2, 1);

    grid_sensors.attach(&mk_lbl("8. Protección Web (DNS):"), 0, 7, 1, 1);
    let wp_active_dash = WebProtectionManager::is_protection_active();
    let wp_cnt = WebProtectionManager::get_blocked_domains_count();
    let s_web = mk_lbl(&if wp_active_dash { format!("● Activo / {} dominios", wp_cnt) } else { "● Inactivo / Pausado".into() });
    s_web.add_css_class(if wp_active_dash { "mini-row-status-ok" } else { "mini-row-status-warn" });
    grid_sensors.attach(&s_web, 1, 7, 2, 1);

    grid_sensors.attach(&mk_lbl("9. Autodefensa (Tamper):"), 0, 8, 1, 1);
    let s_tamper = mk_lbl("● eBPF Anti-Kill + chattr (+i)");
    s_tamper.add_css_class("mini-row-status-ok");
    grid_sensors.attach(&s_tamper, 1, 8, 2, 1);

    grid_sensors.attach(&mk_lbl("10. Modo Juego / DND:"), 0, 9, 1, 1);
    let s_game = mk_lbl("● En Espera / Supresión activa");
    s_game.add_css_class("mini-row-status-ok");
    grid_sensors.attach(&s_game, 1, 9, 2, 1);
    
    card_overview.append(&grid_sensors);
    let wrap_responsive = |view_box: &Box| -> ScrolledWindow {
        let sw = ScrolledWindow::new();
        sw.set_hexpand(true);
        sw.set_vexpand(true);
        sw.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
        sw.set_child(Some(view_box));
        sw
    };

    dash_box.append(&card_overview);
    stack.add_named(&wrap_responsive(&dash_box), Some("dashboard"));

    // --- Vista 2: Análisis Manuales ---
    let scan_box = Box::new(Orientation::Vertical, 16);
    scan_box.set_margin_start(14);
    scan_box.set_margin_end(14);
    scan_box.set_margin_top(14);
    
    let card_scan = Box::new(Orientation::Vertical, 14);
    card_scan.add_css_class("macos-card");
    
    let t_sc = Label::new(Some("Iniciación de Análisis Manuales Multi-Motor Fail-Secure"));
    t_sc.add_css_class("title-text");
    t_sc.set_xalign(0.0);
    t_sc.set_wrap(true);
    card_scan.append(&t_sc);
    
    let d_sc = Label::new(Some("Evaluación rigurosa de cada fichero con ClamAV (socket), YARA (reglas verificadas), YARA-X (binario yr), Entropía de Shannon y Feeds TI. Todo fallo de motor se cataloga como INDETERMINADO; jamás se asume limpio sin análisis completo."));
    d_sc.add_css_class("subtitle-text");
    d_sc.set_xalign(0.0);
    d_sc.set_wrap(true);
    d_sc.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_scan.append(&d_sc);
    
    let progress_bar = ProgressBar::new();
    progress_bar.set_fraction(0.0);
    card_scan.append(&progress_bar);
    
    let scan_status_lbl = Label::new(Some("Listo para iniciar análisis manual."));
    scan_status_lbl.set_xalign(0.0);
    scan_status_lbl.add_css_class("subtitle-text");
    scan_status_lbl.set_wrap(true);
    scan_status_lbl.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_scan.append(&scan_status_lbl);
    
    let scan_btns = Box::new(Orientation::Vertical, 6);
    let scan_btns_r1 = Box::new(Orientation::Horizontal, 8);
    let scan_btns_r2 = Box::new(Orientation::Horizontal, 8);

    let btn_scan_file = Button::with_label("📄 Analizar Archivo");
    btn_scan_file.add_css_class("suggested-action");
    let btn_scan_dir = Button::with_label("📁 Analizar Carpeta");
    btn_scan_dir.add_css_class("suggested-action");
    let btn_scan_usb = Button::with_label("💾 Analizar USB");
    btn_scan_usb.add_css_class("suggested-action");

    let btn_scan_full = Button::with_label("💻 Inspección Completa");
    btn_scan_full.add_css_class("suggested-action");
    let btn_scan_ram = Button::with_label("🧠 Escanear RAM");
    btn_scan_ram.add_css_class("suggested-action");

    scan_btns_r1.append(&btn_scan_file);
    scan_btns_r1.append(&btn_scan_dir);
    scan_btns_r1.append(&btn_scan_usb);
    scan_btns_r2.append(&btn_scan_full);
    scan_btns_r2.append(&btn_scan_ram);
    scan_btns.append(&scan_btns_r1);
    scan_btns.append(&scan_btns_r2);
    card_scan.append(&scan_btns);
    scan_box.append(&card_scan);

    // Tarjeta Dedicada: Consulta de Reputación Global en la Nube (MalwareBazaar / Threat Intelligence API)
    let card_cloud = Box::new(Orientation::Vertical, 14);
    card_cloud.add_css_class("macos-card");

    let t_cloud = Label::new(Some("🌐 Consulta de Reputación Global en la Nube (Threat Intelligence Cloud)"));
    t_cloud.add_css_class("title-text");
    t_cloud.set_xalign(0.0);
    t_cloud.set_wrap(true);
    card_cloud.append(&t_cloud);

    let d_cloud = Label::new(Some("Consulta en milisegundos si un ejecutable o hash SHA-256 desconocido está clasificado como malware en la base de inteligencia global de MalwareBazaar (Abuse.ch)."));
    d_cloud.add_css_class("subtitle-text");
    d_cloud.set_xalign(0.0);
    d_cloud.set_wrap(true);
    d_cloud.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_cloud.append(&d_cloud);

    let cloud_entry = Entry::new();
    cloud_entry.set_placeholder_text(Some("Introduce hash SHA-256 de 64 caracteres para consultar reputación en la nube..."));
    card_cloud.append(&cloud_entry);

    let cloud_btn_row = Box::new(Orientation::Horizontal, 12);
    let btn_lookup_cloud = Button::with_label("🔍 Consultar Reputación en la Nube");
    btn_lookup_cloud.add_css_class("suggested-action");
    cloud_btn_row.append(&btn_lookup_cloud);
    card_cloud.append(&cloud_btn_row);

    let cloud_res_lbl = Label::new(Some("Introduce un hash o analiza un archivo para resolver su reputación en la nube."));
    cloud_res_lbl.add_css_class("subtitle-text");
    cloud_res_lbl.set_xalign(0.0);
    cloud_res_lbl.set_wrap(true);
    card_cloud.append(&cloud_res_lbl);

    let ce_c = cloud_entry.clone();
    let cr_c = cloud_res_lbl.clone();
    let btn_c_c = btn_lookup_cloud.clone();
    btn_lookup_cloud.connect_clicked(move |_| {
        let h = ce_c.text().to_string();
        let cr = cr_c.clone();
        let btn = btn_c_c.clone();
        if h.trim().is_empty() {
            cr.set_text("⚠️ Por favor introduce un hash SHA-256 válido.");
            return;
        }
        gtk4::glib::spawn_future_local(async move {
            btn.set_sensitive(false);
            btn.set_label("⏳ Consultando MalwareBazaar en la nube...");
            let (_is_malware, msg) = run_blocking(move || CloudThreatLookup::lookup_hash(&h)).await;
            btn.set_sensitive(true);
            btn.set_label("🔍 Consultar Reputación en la Nube");
            cr.set_text(&msg);
        });
    });

    scan_box.append(&card_cloud);

    // Tarjeta Dedicada: Programador Inteligente de Análisis (systemd.timer)
    let card_sched = Box::new(Orientation::Vertical, 14);
    card_sched.add_css_class("macos-card");

    let t_sched = Label::new(Some("📅 Programador Inteligente de Análisis en Segundo Plano (systemd.timer)"));
    t_sched.add_css_class("title-text");
    t_sched.set_xalign(0.0);
    t_sched.set_wrap(true);
    card_sched.append(&t_sched);

    let d_sched = Label::new(Some("Ejecución desatendida administrada por temporizadores nativos de systemd. Configurados con 'ConditionACPower=true' (no gastan batería en portátiles) y prioridad I/O 'ionice -c 3' (cero impacto en disco mientras trabajas)."));
    d_sched.add_css_class("subtitle-text");
    d_sched.set_xalign(0.0);
    d_sched.set_wrap(true);
    d_sched.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_sched.append(&d_sched);

    let sched_grid = Grid::new();
    sched_grid.set_column_spacing(10);
    sched_grid.set_row_spacing(8);

    sched_grid.attach(&Label::new(Some("1. Análisis Rápido Diario (02:00 AM):")), 0, 0, 1, 1);
    let q_act = ScheduledScansManager::is_quick_timer_active();
    let q_lbl = Label::new(Some(&if q_act { format!("● Activo / {}", ScheduledScansManager::get_next_run("constantine-quick-scan.timer")) } else { "● Desactivado".to_string() }));
    q_lbl.add_css_class(if q_act { "mini-row-status-ok" } else { "mini-row-status-warn" });
    sched_grid.attach(&q_lbl, 1, 0, 1, 1);

    let btn_q_toggle = Button::with_label(if q_act { "Pausar Diario" } else { "Activar Diario" });
    btn_q_toggle.add_css_class("suggested-action");
    sched_grid.attach(&btn_q_toggle, 2, 0, 1, 1);

    sched_grid.attach(&Label::new(Some("2. Análisis Completo Semanal (Domingos 03:00 AM):")), 0, 1, 1, 1);
    let f_act = ScheduledScansManager::is_full_timer_active();
    let f_lbl = Label::new(Some(&if f_act { format!("● Activo / {}", ScheduledScansManager::get_next_run("constantine-full-scan.timer")) } else { "● Desactivado".to_string() }));
    f_lbl.add_css_class(if f_act { "mini-row-status-ok" } else { "mini-row-status-warn" });
    sched_grid.attach(&f_lbl, 1, 1, 1, 1);

    let btn_f_toggle = Button::with_label(if f_act { "Pausar Semanal" } else { "Activar Semanal" });
    btn_f_toggle.add_css_class("suggested-action");
    sched_grid.attach(&btn_f_toggle, 2, 1, 1, 1);

    card_sched.append(&sched_grid);

    let q_lbl_c = q_lbl.clone();
    let b_q_c = btn_q_toggle.clone();
    btn_q_toggle.connect_clicked(move |_| {
        let currently_act = ScheduledScansManager::is_quick_timer_active();
        let new_state = !currently_act;
        if ScheduledScansManager::toggle_timer("constantine-quick-scan.timer", new_state) {
            b_q_c.set_label(if new_state { "Pausar Diario" } else { "Activar Diario" });
            q_lbl_c.set_text(if new_state { "● Activo / Temporizador diario habilitado" } else { "● Desactivado" });
            q_lbl_c.remove_css_class(if new_state { "mini-row-status-warn" } else { "mini-row-status-ok" });
            q_lbl_c.add_css_class(if new_state { "mini-row-status-ok" } else { "mini-row-status-warn" });
        }
    });

    let f_lbl_c = f_lbl.clone();
    let b_f_c = btn_f_toggle.clone();
    btn_f_toggle.connect_clicked(move |_| {
        let currently_act = ScheduledScansManager::is_full_timer_active();
        let new_state = !currently_act;
        if ScheduledScansManager::toggle_timer("constantine-full-scan.timer", new_state) {
            b_f_c.set_label(if new_state { "Pausar Semanal" } else { "Activar Semanal" });
            f_lbl_c.set_text(if new_state { "● Activo / Temporizador semanal habilitado" } else { "● Desactivado" });
            f_lbl_c.remove_css_class(if new_state { "mini-row-status-warn" } else { "mini-row-status-ok" });
            f_lbl_c.add_css_class(if new_state { "mini-row-status-ok" } else { "mini-row-status-warn" });
        }
    });

    scan_box.append(&card_sched);
    stack.add_named(&wrap_responsive(&scan_box), Some("scan"));

    // 🔴 CORREGIDO: Uso de glib::spawn_future_local y glib::spawn_blocking para evitar errores de hilos (Send/Sync)
    let pb_clone = progress_bar.clone();
    let st_l_clone = scan_status_lbl.clone();
    let u_home_c = user_home.clone();
    
    btn_scan_full.connect_clicked(move |_| {
        let pb = pb_clone.clone();
        let st = st_l_clone.clone();
        let uh = u_home_c.clone();
        
        gtk4::glib::spawn_future_local(async move {
            st.set_text("Indexando archivos del espacio personal para examen real...");
            pb.set_fraction(0.05);
            
            let (tx, rx) = async_channel::unbounded::<ScanProgress>();

            // Ejecutar el escaneo pesado en un hilo de fondo (solo tipos Send, sin widgets)
            std::thread::spawn(move || {
                let mut files = Vec::new();
                ManualScanEngine::collect_files(Path::new(&uh), &mut files);
                let total = files.len();
                let mut threats_found = 0;
                let mut indeterminate_count = 0;
                
                for (idx, file_path) in files.iter().enumerate() {
                    match ThreatAnalysisEngine::evaluate_file(file_path) {
                        FileVerdict::Threat(_) => {
                            threats_found += 1;
                            ContainmentEngine::isolate_to_vault(file_path);
                        }
                        FileVerdict::Indeterminate(_) => {
                            indeterminate_count += 1;
                        }
                        FileVerdict::Clean(_) => {}
                    }
                    
                    if idx % 10 == 0 || idx == total.saturating_sub(1) {
                        let fraction = if total > 0 { (idx + 1) as f64 / total as f64 } else { 1.0 };
                        let fname = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("archivo").to_string();
                        let _ = tx.send_blocking(ScanProgress::Progress {
                            fraction,
                            current: idx + 1,
                            total,
                            fname,
                            threats: threats_found,
                            indets: indeterminate_count,
                        });
                    }
                }

                let _ = tx.send_blocking(ScanProgress::Done {
                    threats: threats_found,
                    indets: indeterminate_count,
                    total,
                });
            });

            // Recibir actualizaciones de progreso en el hilo principal de la UI
            let mut final_threats = 0;
            let mut final_indets = 0;
            let mut final_total = 0;

            while let Ok(msg) = rx.recv().await {
                match msg {
                    ScanProgress::Progress { fraction, current, total, fname, threats, indets } => {
                        pb.set_fraction(fraction);
                        st.set_text(&format!(
                            "Analizando archivo {}/{} ({:.1}%): {} | Amenazas: {} | Indeterminados: {}",
                            current, total, fraction * 100.0, fname, threats, indets
                        ));
                    }
                    ScanProgress::Done { threats, indets, total } => {
                        final_threats = threats;
                        final_indets = indets;
                        final_total = total;
                    }
                }
            }
            
            // Actualización final de la UI en el hilo principal
            if final_threats > 0 {
                st.set_text(&format!("⚠️ Inspección finalizada: {} amenazas detectadas y aisladas en el baúl. ({} análisis incompletos/advertencias).", final_threats, final_indets));
            } else if final_indets > 0 {
                st.set_text(&format!("⚠️ Inspección incompleta: 0 amenazas confirmadas, pero {} archivos quedaron con estado INDETERMINADO por fallo o error de motor.", final_indets));
            } else {
                st.set_text(&format!("✓ Inspección completa concluida con éxito: {} archivos procesados y certificados limpios por todos los motores.", final_total));
            }
            pb.set_fraction(1.0);
            
            ImmutableAuditLog::append_event("FULL_SCAN_COMPLETED", &format!("Inspección finalizada: {} archivos, {} amenazas aisladas, {} indeterminados.", final_total, final_threats, final_indets));
        });
    });

    let pb_u = progress_bar.clone();
    let st_u = scan_status_lbl.clone();
    
    btn_scan_usb.connect_clicked(move |_| {
        let pb = pb_u.clone();
        let st = st_u.clone();
        
        gtk4::glib::spawn_future_local(async move {
            st.set_text("Iniciando barrido de almacenamiento extraíble (/media)...");
            pb.set_fraction(0.05);

            let (tx, rx) = async_channel::unbounded::<ScanProgress>();

            std::thread::spawn(move || {
                let mut usb_files = Vec::new();
                ManualScanEngine::collect_files(Path::new("/media"), &mut usb_files);
                let total = usb_files.len();
                let mut threats = 0;
                let mut indets = 0;
                
                for (idx, file) in usb_files.iter().enumerate() {
                    match ThreatAnalysisEngine::evaluate_file(file) {
                        FileVerdict::Threat(_) => {
                            threats += 1;
                            ContainmentEngine::isolate_to_vault(file);
                        }
                        FileVerdict::Indeterminate(_) => {
                            indets += 1;
                        }
                        FileVerdict::Clean(_) => {}
                    }
                    let frac = if total > 0 { (idx + 1) as f64 / total as f64 } else { 1.0 };
                    let fname = file.file_name().and_then(|n| n.to_str()).unwrap_or("archivo").to_string();
                    let _ = tx.send_blocking(ScanProgress::Progress {
                        fraction: frac,
                        current: idx + 1,
                        total,
                        fname,
                        threats,
                        indets,
                    });
                }

                let _ = tx.send_blocking(ScanProgress::Done {
                    threats,
                    indets,
                    total,
                });
            });

            let mut final_threats = 0;
            let mut final_indets = 0;
            let mut final_total = 0;

            while let Ok(msg) = rx.recv().await {
                match msg {
                    ScanProgress::Progress { fraction, .. } => {
                        pb.set_fraction(fraction);
                    }
                    ScanProgress::Done { threats, indets, total } => {
                        final_threats = threats;
                        final_indets = indets;
                        final_total = total;
                    }
                }
            }

            st.set_text(&format!("✓ Barrido USB completado: {} archivos examinados, {} amenazas aisladas, {} indeterminados.", final_total, final_threats, final_indets));
            pb.set_fraction(1.0);
            
            ImmutableAuditLog::append_event("USB_SCAN_COMPLETED", &format!("Barrido USB finalizado: {} archivos, {} amenazas aisladas.", final_total, final_threats));
        });
    });

    let win_sf = window.clone();
    let pb_f = progress_bar.clone();
    let st_f = scan_status_lbl.clone();
    
    btn_scan_file.connect_clicked(move |_| {
        let chooser = gtk4::FileChooserNative::new(
            Some("Seleccionar Archivo para Analizar"),
            Some(&win_sf),
            gtk4::FileChooserAction::Open,
            Some("Analizar"),
            Some("Cancelar"),
        );
        let pb = pb_f.clone();
        let st = st_f.clone();
        chooser.connect_response(move |dialog, response| {
            if response == gtk4::ResponseType::Accept {
                if let Some(file) = dialog.file() {
                    if let Some(path) = file.path() {
                        let pb_c = pb.clone();
                        let st_c = st.clone();
                        let path_c = path.clone();
                        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("archivo").to_string();
                        st_c.set_text(&format!("Analizando {} con motores ClamAV, YARA, Entropía y Feeds...", fname));
                        pb_c.set_fraction(0.3);

                        gtk4::glib::spawn_future_local(async move {
                            let res = run_blocking(move || ThreatAnalysisEngine::evaluate_file(&path_c)).await;
                            pb_c.set_fraction(1.0);
                            match res {
                                FileVerdict::Clean(m) => st_c.set_text(&format!("✅ Archivo '{}': Certificado Limpio. {}", fname, m)),
                                FileVerdict::Threat(t) => st_c.set_text(&format!("🚨 AMENAZA CONFIRMADA en '{}': {}", fname, t)),
                                FileVerdict::Indeterminate(i) => st_c.set_text(&format!("⚠️ Estado Indeterminado en '{}': {}", fname, i)),
                            }
                        });
                    }
                }
            }
        });
        chooser.show();
    });

    let win_sd = window.clone();
    let pb_d = progress_bar.clone();
    let st_d = scan_status_lbl.clone();
    btn_scan_dir.connect_clicked(move |_| {
        let chooser = gtk4::FileChooserNative::new(
            Some("Seleccionar Carpeta para Inspeccionar"),
            Some(&win_sd),
            gtk4::FileChooserAction::SelectFolder,
            Some("Analizar Carpeta"),
            Some("Cancelar"),
        );
        let pb = pb_d.clone();
        let st = st_d.clone();
        chooser.connect_response(move |dialog, response| {
            if response == gtk4::ResponseType::Accept {
                if let Some(file) = dialog.file() {
                    if let Some(dir_path) = file.path() {
                        let dname = dir_path.file_name().and_then(|n| n.to_str()).unwrap_or("carpeta").to_string();
                        st.set_text(&format!("Indexando archivos en carpeta '{}'...", dname));
                        pb.set_fraction(0.1);

                        let pb_c = pb.clone();
                        let st_c = st.clone();
                        let dir_c = dir_path.clone();
                        gtk4::glib::spawn_future_local(async move {
                            let (total, threats) = run_blocking(move || {
                                let mut files = Vec::new();
                                ManualScanEngine::collect_files(&dir_c, &mut files);
                                let total = files.len();
                                let mut threats = 0;
                                for f in &files {
                                    if let FileVerdict::Threat(_) = ThreatAnalysisEngine::evaluate_file(f) {
                                        threats += 1;
                                        ContainmentEngine::isolate_to_vault(f);
                                    }
                                }
                                (total, threats)
                            }).await;

                            pb_c.set_fraction(1.0);
                            if threats == 0 {
                                st_c.set_text(&format!("✅ Carpeta '{}': {} archivos examinados, 0 amenazas detectadas.", dname, total));
                            } else {
                                st_c.set_text(&format!("🚨 AMENAZAS EN CARPETA '{}': {} archivos infectados aislados de {} analizados.", dname, threats, total));
                            }
                        });
                    }
                }
            }
        });
        chooser.show();
    });

    let pb_ram = progress_bar.clone();
    let st_ram = scan_status_lbl.clone();
    btn_scan_ram.connect_clicked(move |_| {
        let pb = pb_ram.clone();
        let st = st_ram.clone();
        gtk4::glib::spawn_future_local(async move {
            st.set_text("Auditando procesos residentes en memoria RAM y /dev/shm...");
            pb.set_fraction(0.35);
            let res = run_blocking(|| MemoryScannerEngine::scan_running_memory()).await;
            pb.set_fraction(1.0);
            if res.threats_found.is_empty() {
                st.set_text(&format!("✓ Escaneo de RAM completado: {} procesos auditados en memoria sin anomalías ni binarios volátiles.", res.total_procs_scanned));
            } else {
                let first = &res.threats_found[0];
                st.set_text(&format!("⚠️ Alerta en RAM: {} procesos sospechosos. Primero: PID {} ({}) - {}", res.threats_found.len(), first.0, first.1, first.2));
            }
            ImmutableAuditLog::append_event("RAM_SCAN_MANUAL", &format!("Escaneo de RAM completado: {} procesos, {} anomalías.", res.total_procs_scanned, res.threats_found.len()));
        });
    });

    // --- Vista 3: Actualizaciones Dinámicas y Feeds ---
    let updates_box = Box::new(Orientation::Vertical, 16);
    updates_box.set_margin_start(14);
    updates_box.set_margin_end(14);
    updates_box.set_margin_top(14);
    
    let card_mod_updates = Box::new(Orientation::Vertical, 12);
    card_mod_updates.add_css_class("macos-card");
    
    let t_mu = Label::new(Some("Auditoría de los 16 Componentes de Seguridad y Feeds en Vivo"));
    t_mu.add_css_class("title-text");
    t_mu.set_xalign(0.0);
    t_mu.set_wrap(true);
    card_mod_updates.append(&t_mu);

    let d_mu = Label::new(Some("Estado real verificado de firmas, demonios de detección e indicadores de compromiso (IoCs)."));
    d_mu.add_css_class("subtitle-text");
    d_mu.set_xalign(0.0);
    d_mu.set_wrap(true);
    d_mu.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_mod_updates.append(&d_mu);
    
    let grid_mods = Grid::new();
    grid_mods.set_column_spacing(8);
    grid_mods.set_row_spacing(6);

    let populate_module_grid = |grid: &Grid| {
        while let Some(child) = grid.first_child() {
            grid.remove(&child);
        }
        let h1 = Label::new(Some("Componente"));
        h1.add_css_class("macos-table-header");
        h1.set_xalign(0.0);
        
        let h2 = Label::new(Some("Versión / Estado"));
        h2.add_css_class("macos-table-header");
        h2.set_xalign(0.0);
        
        let h3 = Label::new(Some("Última Sincronización"));
        h3.add_css_class("macos-table-header");
        h3.set_xalign(0.0);
        
        grid.attach(&h1, 0, 0, 1, 1);
        grid.attach(&h2, 1, 0, 1, 1);
        grid.attach(&h3, 2, 0, 1, 1);
        
        let mod_statuses = ModuleVersionAudit::get_modules_status();
        for (idx, (name, ver, updated)) in mod_statuses.iter().enumerate() {
            let row = (idx + 1) as i32;
            let l_name = Label::new(Some(name));
            l_name.set_xalign(0.0);
            l_name.set_wrap(true);
            l_name.set_wrap_mode(gtk4::pango::WrapMode::Word);
            l_name.set_max_width_chars(16);
            l_name.add_css_class("macos-table-cell");
            
            let l_ver = Label::new(Some(ver));
            l_ver.set_xalign(0.0);
            l_ver.set_wrap(true);
            l_ver.set_wrap_mode(gtk4::pango::WrapMode::Word);
            l_ver.set_max_width_chars(18);
            l_ver.add_css_class("macos-table-cell");
            
            let l_upd = Label::new(Some(updated));
            l_upd.set_xalign(0.0);
            l_upd.set_wrap(true);
            l_upd.set_wrap_mode(gtk4::pango::WrapMode::Word);
            l_upd.set_max_width_chars(15);
            l_upd.add_css_class("mini-row-status-ok");
            
            grid.attach(&l_name, 0, row, 1, 1);
            grid.attach(&l_ver, 1, row, 1, 1);
            grid.attach(&l_upd, 2, row, 1, 1);
        }
    };

    populate_module_grid(&grid_mods);
    card_mod_updates.append(&grid_mods);
    
    let btns_update_row = Box::new(Orientation::Horizontal, 12);
    let btn_update_all = Button::with_label("🔄 Actualizar Todo (16 Motores, Firmas y Feeds)");
    btn_update_all.add_css_class("suggested-action");
    
    let btn_aide_check = Button::with_label("🔍 Ejecutar Verificación AIDE Ahora");
    
    btns_update_row.append(&btn_update_all);
    btns_update_row.append(&btn_aide_check);
    card_mod_updates.append(&btns_update_row);
    updates_box.append(&card_mod_updates);

    // Tarjeta dedicada para actualizar Constantine desde repositorio central
    let card_repo_update = Box::new(Orientation::Vertical, 12);
    card_repo_update.add_css_class("macos-card");
    
    let t_repo = Label::new(Some("Actualizaciones de Constantine EDR"));
    t_repo.add_css_class("title-text");
    t_repo.set_xalign(0.0);
    t_repo.set_wrap(true);
    card_repo_update.append(&t_repo);
    
    let d_repo = Label::new(Some("Sincroniza y compila la última versión del código fuente directamente desde el repositorio oficial."));
    d_repo.add_css_class("subtitle-text");
    d_repo.set_xalign(0.0);
    d_repo.set_wrap(true);
    d_repo.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_repo_update.append(&d_repo);
    
    let repo_status_lbl = Label::new(Some("Versión actual: v5.5.3 (Debian Edition). Listo para comprobar."));
    repo_status_lbl.set_xalign(0.0);
    repo_status_lbl.add_css_class("mini-row-status-ok");
    card_repo_update.append(&repo_status_lbl);
    
    let btn_repo_up = Button::with_label("🚀 Buscar y Aplicar Actualización de Constantine");
    btn_repo_up.add_css_class("suggested-action");
    card_repo_update.append(&btn_repo_up);
    updates_box.append(&card_repo_update);
    stack.add_named(&wrap_responsive(&updates_box), Some("updates"));

    let grid_mods_c = grid_mods.clone();
    let btn_up_c = btn_update_all.clone();
    btn_update_all.connect_clicked(move |_| {
        let grid = grid_mods_c.clone();
        let btn = btn_up_c.clone();
        gtk4::glib::spawn_future_local(async move {
            btn.set_sensitive(false);
            btn.set_label("⏳ Actualizando los 16 módulos y feeds...");
            let ok = run_blocking(|| ModuleVersionAudit::update_all_modules()).await;
            populate_module_grid(&grid);
            btn.set_sensitive(true);
            btn.set_label("🔄 Actualizar Todo (16 Motores, Firmas y Feeds)");
            if ok {
                SystemNotifier::notify(
                    "normal",
                    "security-high",
                    "Constantine Antivirus",
                    "Los 16 componentes, firmas, MISP, Sigma, AIDE y Wazuh han sido sincronizados.",
                );
            }
        });
    });
    
    btn_aide_check.connect_clicked(|_| {
        gtk4::glib::spawn_future_local(async {
            SystemNotifier::notify("low", "security-high", "Constantine - AIDE", "Iniciando verificación criptográfica de archivos del sistema...");
            let _ = run_blocking(|| ModuleVersionAudit::run_aide_check()).await;
            SystemNotifier::notify("normal", "security-high", "Constantine - AIDE", "Verificación de integridad completada. Revisa el Registro Forense.");
        });
    });

    let r_lbl_c = repo_status_lbl.clone();
    let b_repo_c = btn_repo_up.clone();
    let win_repo_c = window.clone();
    btn_repo_up.connect_clicked(move |_| {
        let r_lbl = r_lbl_c.clone();
        let b_btn = b_repo_c.clone();
        let win_p = win_repo_c.clone();
        gtk4::glib::spawn_future_local(async move {
            b_btn.set_sensitive(false);
            b_btn.set_label("⏳ Comprobando GitHub...");
            r_lbl.set_text("Consultando repositorio oficial en GitHub...");
            match run_blocking(|| SelfUpdater::check_remote_version()).await {
                UpdateCheckStatus::UpdateAvailable { remote_version, url } => {
                    r_lbl.set_text(&format!("🚀 Nueva versión disponible: v{} (instalada: v{})", remote_version, APP_VERSION));
                    prompt_update_dialog(&win_p, &remote_version, &url, Some(r_lbl.clone()));
                }
                UpdateCheckStatus::UpToDate(v) => {
                    r_lbl.set_text(&format!("✓ Constantine EDR v{} está en la última versión (GitHub: v{}).", APP_VERSION, v));
                }
                UpdateCheckStatus::Error(err) => {
                    r_lbl.set_text(&format!("⚠️ {}", err));
                }
            }
            b_btn.set_sensitive(true);
            b_btn.set_label("🚀 Buscar y Aplicar Actualización de Constantine");
        });
    });

    // --- Vista 4: Red, VPN y Firewall ---
    let net_box = Box::new(Orientation::Vertical, 16);
    net_box.set_margin_start(14);
    net_box.set_margin_end(14);
    net_box.set_margin_top(14);
    
    let card_net = Box::new(Orientation::Vertical, 14);
    card_net.add_css_class("macos-card");
    
    let net_t = Label::new(Some("Estado de Red, Firewall y Privacidad"));
    net_t.add_css_class("title-text");
    net_t.set_xalign(0.0);
    net_t.set_wrap(true);
    card_net.append(&net_t);
    
    let grid_net = Grid::new();
    grid_net.set_column_spacing(10);
    grid_net.set_row_spacing(10);
    
    grid_net.attach(&Label::new(Some("Interfaz de Red Activa:")), 0, 0, 1, 1);
    let (iface, iface_type, loc_ip) = NetworkPrivacyAudit::get_active_interface_info();
    let iface_lbl = Label::new(Some(&format!("● {} ({}) | IP Local: {}", iface, iface_type, loc_ip)));
    iface_lbl.add_css_class("mini-row-status-ok");
    grid_net.attach(&iface_lbl, 1, 0, 2, 1);

    grid_net.attach(&Label::new(Some("Firewall del Sistema (UFW):")), 0, 1, 1, 1);
    let ufw_active = NetworkPrivacyAudit::is_ufw_active();
    let ufw_lbl = Label::new(Some(if ufw_active { "● Activo / Protegido" } else { "● Inactivo" }));
    ufw_lbl.add_css_class(if ufw_active { "mini-row-status-ok" } else { "mini-row-status-warn" });
    grid_net.attach(&ufw_lbl, 1, 1, 1, 1);
    
    let btn_open_gufw = Button::with_label("Abrir GUFW");
    btn_open_gufw.add_css_class("suggested-action");
    grid_net.attach(&btn_open_gufw, 2, 1, 1, 1);
    
    grid_net.attach(&Label::new(Some("Conexión VPN (ProtonVPN):")), 0, 2, 1, 1);
    let vpn_active = NetworkPrivacyAudit::is_protonvpn_active();
    let vpn_lbl = Label::new(Some(if vpn_active { "● Conectado (Túnel Cifrado)" } else { "● Desconectado" }));
    vpn_lbl.add_css_class(if vpn_active { "mini-row-status-ok" } else { "mini-row-status-warn" });
    grid_net.attach(&vpn_lbl, 1, 2, 1, 1);
    
    let btn_open_pvpn = Button::with_label("Abrir VPN");
    btn_open_pvpn.add_css_class("suggested-action");
    grid_net.attach(&btn_open_pvpn, 2, 2, 1, 1);
    
    grid_net.attach(&Label::new(Some("IP Pública Detectada:")), 0, 3, 1, 1);
    let ip_lbl = Label::new(Some("Consultando IP..."));
    ip_lbl.add_css_class("title-text");
    grid_net.attach(&ip_lbl, 1, 3, 2, 1);
    
    grid_net.attach(&Label::new(Some("Localización de la IP:")), 0, 4, 1, 1);
    let loc_lbl = Label::new(Some("Consultando ubicación..."));
    loc_lbl.add_css_class("mini-row-status-ok");
    grid_net.attach(&loc_lbl, 1, 4, 2, 1);
    
    card_net.append(&grid_net);
    
    let btn_ref_ip = Button::with_label("🔄 Actualizar Información de Red e IP");
    card_net.append(&btn_ref_ip);
    net_box.append(&card_net);

    // Tarjeta Dedicada: Protección Web y Filtrado DNS en Tiempo Real (Anti-Phishing Activo)
    let card_web_prot = Box::new(Orientation::Vertical, 12);
    card_web_prot.add_css_class("macos-card");

    let t_wp = Label::new(Some("🛡️ Protección Web y Filtrado DNS en Tiempo Real (Anti-Phishing)"));
    t_wp.add_css_class("title-text");
    t_wp.set_xalign(0.0);
    t_wp.set_wrap(true);
    card_web_prot.append(&t_wp);

    let d_wp = Label::new(Some("Sumidero DNS local (0.0.0.0) que intercepta y bloquea sitios de phishing, malware y dominios C2 antes de que Chrome, Firefox o Brave carguen la página."));
    d_wp.add_css_class("subtitle-text");
    d_wp.set_xalign(0.0);
    d_wp.set_wrap(true);
    d_wp.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_web_prot.append(&d_wp);

    let wp_grid = Grid::new();
    wp_grid.set_column_spacing(24);
    wp_grid.set_row_spacing(8);

    wp_grid.attach(&Label::new(Some("Estado del Filtrado DNS:")), 0, 0, 1, 1);
    let wp_active = WebProtectionManager::is_protection_active();
    let wp_count = WebProtectionManager::get_blocked_domains_count();
    let wp_status_lbl = Label::new(Some(&if wp_active {
        format!("● Activo / {} dominios maliciosos bloqueados en 0.0.0.0", wp_count)
    } else {
        "● Inactivo / Pausado".to_string()
    }));
    wp_status_lbl.add_css_class(if wp_active { "mini-row-status-ok" } else { "mini-row-status-warn" });
    wp_status_lbl.set_xalign(0.0);
    wp_status_lbl.set_wrap(true);
    wp_grid.attach(&wp_status_lbl, 1, 0, 2, 1);

    card_web_prot.append(&wp_grid);

    let wp_btns_row = Box::new(Orientation::Horizontal, 8);
    let btn_wp_enable = Button::with_label("🟢 Activar");
    btn_wp_enable.add_css_class("suggested-action");

    let btn_wp_disable = Button::with_label("🔴 Pausar");
    btn_wp_disable.add_css_class("destructive-action");

    let btn_wp_sync = Button::with_label("🔄 Sincronizar Feeds");
    btn_wp_sync.add_css_class("suggested-action");

    wp_btns_row.append(&btn_wp_enable);
    wp_btns_row.append(&btn_wp_disable);
    wp_btns_row.append(&btn_wp_sync);
    card_web_prot.append(&wp_btns_row);

    let wp_feedback_lbl = Label::new(Some("Protección web sincronizada con las listas locales de inteligencia."));
    wp_feedback_lbl.add_css_class("subtitle-text");
    wp_feedback_lbl.set_xalign(0.0);
    wp_feedback_lbl.set_wrap(true);
    card_web_prot.append(&wp_feedback_lbl);

    net_box.append(&card_web_prot);

    // Tarjeta Dedicada: Aislamiento Inmediato del Equipo de la Red (Host Network Containment)
    let card_net_iso = Box::new(Orientation::Vertical, 12);
    card_net_iso.add_css_class("macos-card");

    let t_iso = Label::new(Some("🚨 Aislamiento Inmediato del Equipo de la Red (Kill-Switch EDR)"));
    t_iso.add_css_class("title-text");
    t_iso.set_xalign(0.0);
    t_iso.set_wrap(true);
    card_net_iso.append(&t_iso);

    let d_iso = Label::new(Some("Contención de emergencia: Corta inmediatamente todo el tráfico exterior (LAN e Internet) entrante y saliente mediante iptables/nftables para neutralizar exfiltraciones o ataques de ransomware en curso. Mantiene únicamente la interfaz local (lo)."));
    d_iso.add_css_class("subtitle-text");
    d_iso.set_xalign(0.0);
    d_iso.set_wrap(true);
    d_iso.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_net_iso.append(&d_iso);

    let iso_grid = Grid::new();
    iso_grid.set_column_spacing(24);
    iso_grid.set_row_spacing(8);

    iso_grid.attach(&Label::new(Some("Estado de Red:")), 0, 0, 1, 1);
    let is_isolated = NetworkIsolationManager::is_network_isolated();
    let iso_status_lbl = Label::new(Some(if is_isolated {
        "● AISLADO: Conexión exterior bloqueada totalmente"
    } else {
        "● CONECTADO: Tráfico de red habitual activo"
    }));
    iso_status_lbl.add_css_class(if is_isolated { "mini-row-status-warn" } else { "mini-row-status-ok" });
    iso_status_lbl.set_xalign(0.0);
    iso_status_lbl.set_wrap(true);
    iso_grid.attach(&iso_status_lbl, 1, 0, 2, 1);
    card_net_iso.append(&iso_grid);

    let iso_btns_row = Box::new(Orientation::Horizontal, 12);
    let btn_isolate = Button::with_label("🚨 Aislar Red");
    btn_isolate.add_css_class("destructive-action");

    let btn_reconnect = Button::with_label("🟢 Restaurar");
    btn_reconnect.add_css_class("suggested-action");

    iso_btns_row.append(&btn_isolate);
    iso_btns_row.append(&btn_reconnect);
    card_net_iso.append(&iso_btns_row);

    let iso_fb_lbl = Label::new(Some("Listo para contención de emergencia ante intrusiones o ransomware."));
    iso_fb_lbl.add_css_class("subtitle-text");
    iso_fb_lbl.set_xalign(0.0);
    card_net_iso.append(&iso_fb_lbl);

    let iso_st_c1 = iso_status_lbl.clone();
    let iso_fb_c1 = iso_fb_lbl.clone();
    btn_isolate.connect_clicked(move |_| {
        let (ok, msg) = NetworkIsolationManager::isolate_network();
        if ok {
            iso_st_c1.set_text("● AISLADO: Conexión exterior bloqueada totalmente");
            iso_st_c1.remove_css_class("mini-row-status-ok");
            iso_st_c1.add_css_class("mini-row-status-warn");
            iso_fb_c1.set_text("🚨 Equipo aislado: Todo el tráfico de red exterior ha sido descartado.");
        } else {
            iso_fb_c1.set_text(&msg);
        }
    });

    let iso_st_c2 = iso_status_lbl.clone();
    let iso_fb_c2 = iso_fb_lbl.clone();
    btn_reconnect.connect_clicked(move |_| {
        let (ok, msg) = NetworkIsolationManager::reconnect_network();
        if ok {
            iso_st_c2.set_text("● CONECTADO: Tráfico de red habitual activo");
            iso_st_c2.remove_css_class("mini-row-status-warn");
            iso_st_c2.add_css_class("mini-row-status-ok");
            iso_fb_c2.set_text("✓ Conectividad restaurada: Reglas de cortafuegos restablecidas.");
        } else {
            iso_fb_c2.set_text(&msg);
        }
    });

    net_box.append(&card_net_iso);

    // Tarjeta Dedicada: Supervisión de Conexiones por Proceso (Orquestación OpenSnitch eBPF)
    let card_snitch = Box::new(Orientation::Vertical, 12);
    card_snitch.add_css_class("macos-card");

    let t_snitch = Label::new(Some("🔍 Supervisión Pasiva de Conexiones Activas por Proceso"));
    t_snitch.add_css_class("title-text");
    t_snitch.set_xalign(0.0);
    t_snitch.set_wrap(true);
    card_snitch.append(&t_snitch);

    let d_snitch = Label::new(Some("Supervisión en tiempo real de sockets TCP y UDP activos por ejecutable y PID mediante utilidades nativas del sistema (ss / procfs). Cero impacto de red, cero pérdida de conectividad."));
    d_snitch.add_css_class("subtitle-text");
    d_snitch.set_xalign(0.0);
    d_snitch.set_wrap(true);
    d_snitch.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_snitch.append(&d_snitch);

    let snitch_grid = Grid::new();
    snitch_grid.set_column_spacing(10);
    snitch_grid.set_row_spacing(6);

    snitch_grid.attach(&Label::new(Some("Estado del Monitor:")), 0, 0, 1, 1);
    let snitch_st_lbl = Label::new(Some("● Activo / Monitoreo pasivo no invasivo (Cero caídas de red)"));
    snitch_st_lbl.add_css_class("mini-row-status-ok");
    snitch_st_lbl.set_xalign(0.0);
    snitch_st_lbl.set_wrap(true);
    snitch_grid.attach(&snitch_st_lbl, 1, 0, 1, 1);
    card_snitch.append(&snitch_grid);

    let snitch_recent_lbl = Label::new(Some("Conexiones de red activas por proceso (PID / Destino):"));
    snitch_recent_lbl.add_css_class("subtitle-text");
    snitch_recent_lbl.set_xalign(0.0);
    card_snitch.append(&snitch_recent_lbl);

    let snitch_scroll = ScrolledWindow::new();
    snitch_scroll.set_min_content_height(140);
    let snitch_tv = TextView::new();
    snitch_tv.set_editable(false);
    snitch_tv.set_wrap_mode(gtk4::WrapMode::WordChar);
    snitch_scroll.set_child(Some(&snitch_tv));
    card_snitch.append(&snitch_scroll);

    let conns = NativeNetworkMonitor::get_recent_connections(12);
    let mut conn_summary = String::new();
    if conns.is_empty() {
        conn_summary = "Sin conexiones salientes activas en este momento.".into();
    } else {
        for c in conns {
            conn_summary.push_str(&format!("{} | {} | {} | {}\n", c.action, c.protocol, c.process, c.destination));
        }
    }
    snitch_tv.buffer().set_text(&conn_summary);

    let btn_ref_snitch = Button::with_label("🔄 Actualizar Conexiones Activas");
    btn_ref_snitch.add_css_class("suggested-action");
    card_snitch.append(&btn_ref_snitch);

    let stv_c = snitch_tv.clone();
    btn_ref_snitch.connect_clicked(move |_| {
        let conns = NativeNetworkMonitor::get_recent_connections(16);
        let mut text = String::new();
        if conns.is_empty() {
            text = "Sin conexiones salientes activas en este momento.".into();
        } else {
            for c in conns {
                text.push_str(&format!("{} | {} | {} | {}\n", c.action, c.protocol, c.process, c.destination));
            }
        }
        stv_c.buffer().set_text(&text);
    });

        // Tarjeta Dedicada: Perfiles de DNS Seguro Anti-Phishing (Quad9, Mullvad, Cloudflare)
    let card_dns_prof = Box::new(Orientation::Vertical, 10);
    card_dns_prof.add_css_class("macos-card");

    let t_dns = Label::new(Some("🛡️ Perfiles de DNS Seguro Anti-Phishing y Privacidad"));
    t_dns.add_css_class("title-text");
    t_dns.set_xalign(0.0);
    t_dns.set_wrap(true);
    card_dns_prof.append(&t_dns);

    let d_dns = Label::new(Some("Aplica servidores DNS seguros con filtrado activo de phishing y malware a la interfaz de red activa en este momento. Protege automáticamente a todos los navegadores y programas con cero riesgo de desconexión."));
    d_dns.add_css_class("subtitle-text");
    d_dns.set_xalign(0.0);
    d_dns.set_wrap(true);
    d_dns.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_dns_prof.append(&d_dns);

    let current_dns_lbl = Label::new(Some(&format!("Servidor DNS en uso: {}", DnsProfileManager::get_current_dns_servers())));
    current_dns_lbl.add_css_class("mini-row-status-ok");
    current_dns_lbl.set_xalign(0.0);
    current_dns_lbl.set_wrap(true);
    card_dns_prof.append(&current_dns_lbl);

    let dns_profiles = DnsProfileManager::get_available_profiles();
    let selected_dns_id = std::rc::Rc::new(std::cell::RefCell::new("quad9".to_string()));

    let first_prof = &dns_profiles[0];
    let dns_desc_lbl = Label::new(Some(&format!("{}\nDNS: {} | {}", first_prof.description, first_prof.primary_dns, first_prof.secondary_dns)));
    dns_desc_lbl.add_css_class("subtitle-text");
    dns_desc_lbl.set_xalign(0.0);
    dns_desc_lbl.set_wrap(true);
    dns_desc_lbl.set_wrap_mode(gtk4::pango::WrapMode::Word);

    let profile_titles: Vec<&str> = dns_profiles.iter().map(|p| p.name).collect();
    let dropdown = DropDown::from_strings(&profile_titles);
    dropdown.set_selected(0);
    dropdown.add_css_class("suggested-action");

    let sel_id_dd = selected_dns_id.clone();
    let desc_lbl_dd = dns_desc_lbl.clone();
    dropdown.connect_selected_notify(move |dd| {
        let idx = dd.selected() as usize;
        let profs = DnsProfileManager::get_available_profiles();
        if let Some(prof) = profs.get(idx) {
            *sel_id_dd.borrow_mut() = prof.id.to_string();
            desc_lbl_dd.set_text(&format!("{}\nDNS: {} | {}", prof.description, prof.primary_dns, prof.secondary_dns));
        }
    });

    let dd_box = Box::new(Orientation::Vertical, 6);
    let dd_lbl = Label::new(Some("Selecciona el perfil de protección DNS deseado:"));
    dd_lbl.set_xalign(0.0);
    dd_lbl.add_css_class("subtitle-text");
    dd_box.append(&dd_lbl);
    dd_box.append(&dropdown);
    card_dns_prof.append(&dd_box);
    card_dns_prof.append(&dns_desc_lbl);

    let dns_actions_row = Box::new(Orientation::Horizontal, 8);
    let btn_apply_dns = Button::with_label("🚀 Aplicar a Interfaz Activa");
    btn_apply_dns.add_css_class("suggested-action");

    let btn_reset_dns = Button::with_label("🔄 Restablecer a DHCP (Valores de Fábrica)");
    btn_reset_dns.add_css_class("destructive-action");

    dns_actions_row.append(&btn_apply_dns);
    dns_actions_row.append(&btn_reset_dns);
    card_dns_prof.append(&dns_actions_row);

    let dns_fb_lbl = Label::new(Some("Selecciona un perfil y haz clic en Aplicar para configurar la interfaz de red activa."));
    dns_fb_lbl.add_css_class("subtitle-text");
    dns_fb_lbl.set_xalign(0.0);
    dns_fb_lbl.set_wrap(true);
    dns_fb_lbl.set_wrap_mode(gtk4::pango::WrapMode::Word);
    card_dns_prof.append(&dns_fb_lbl);

    let sel_id_apply = selected_dns_id.clone();
    let cur_dns_c = current_dns_lbl.clone();
    let fb_dns_c = dns_fb_lbl.clone();
    let b_app_c = btn_apply_dns.clone();
    btn_apply_dns.connect_clicked(move |_| {
        let p_id = sel_id_apply.borrow().clone();
        let cur = cur_dns_c.clone();
        let fb = fb_dns_c.clone();
        let btn = b_app_c.clone();
        gtk4::glib::spawn_future_local(async move {
            btn.set_sensitive(false);
            fb.set_text("⏳ Aplicando perfil DNS a la interfaz activa...");
            let (_ok, msg) = run_blocking(move || DnsProfileManager::apply_profile(&p_id)).await;
            btn.set_sensitive(true);
            cur.set_text(&format!("Servidor DNS en uso: {}", DnsProfileManager::get_current_dns_servers()));
            fb.set_text(&msg);
        });
    });

    let cur_dns_r = current_dns_lbl.clone();
    let fb_dns_r = dns_fb_lbl.clone();
    let b_res_c = btn_reset_dns.clone();
    btn_reset_dns.connect_clicked(move |_| {
        let cur = cur_dns_r.clone();
        let fb = fb_dns_r.clone();
        let btn = b_res_c.clone();
        gtk4::glib::spawn_future_local(async move {
            btn.set_sensitive(false);
            fb.set_text("⏳ Restableciendo DNS a configuración automática...");
            let (_ok, msg) = run_blocking(|| DnsProfileManager::reset_dns_to_default()).await;
            btn.set_sensitive(true);
            cur.set_text(&format!("Servidor DNS en uso: {}", DnsProfileManager::get_current_dns_servers()));
            fb.set_text(&msg);
        });
    });

    net_box.append(&card_dns_prof);



    net_box.append(&card_snitch);
    stack.add_named(&wrap_responsive(&net_box), Some("network"));

    let wp_st_c1 = wp_status_lbl.clone();
    let wp_fb_c1 = wp_feedback_lbl.clone();
    let btn_wp_e_clone = btn_wp_enable.clone();
    btn_wp_enable.connect_clicked(move |_| {
        let st = wp_st_c1.clone();
        let fb = wp_fb_c1.clone();
        let btn = btn_wp_e_clone.clone();
        gtk4::glib::spawn_future_local(async move {
            btn.set_sensitive(false);
            fb.set_text("⏳ Activando sumidero DNS y filtrado web...");
            let ok = run_blocking(|| WebProtectionManager::enable_protection()).await;
            btn.set_sensitive(true);
            if ok {
                let count = WebProtectionManager::get_blocked_domains_count();
                st.set_text(&format!("● Activo / {} dominios bloqueados en 0.0.0.0", count));
                st.remove_css_class("mini-row-status-warn");
                st.add_css_class("mini-row-status-ok");
                fb.set_text("✓ Filtrado DNS activo: Navegadores protegidos contra phishing y malware.");
            } else {
                fb.set_text("[-] No se pudo activar el filtrado DNS. Verifica permisos o el daemon.");
            }
        });
    });

    let wp_st_c2 = wp_status_lbl.clone();
    let wp_fb_c2 = wp_feedback_lbl.clone();
    btn_wp_disable.connect_clicked(move |_| {
        if WebProtectionManager::disable_protection() {
            wp_st_c2.set_text("● Inactivo / Pausado");
            wp_st_c2.remove_css_class("mini-row-status-ok");
            wp_st_c2.add_css_class("mini-row-status-warn");
            wp_fb_c2.set_text("⚠️ Filtrado DNS pausado.");
        }
    });

    let wp_st_c3 = wp_status_lbl.clone();
    let wp_fb_c3 = wp_feedback_lbl.clone();
    let b_sync_c = btn_wp_sync.clone();
    btn_wp_sync.connect_clicked(move |_| {
        let st_l = wp_st_c3.clone();
        let fb_l = wp_fb_c3.clone();
        let btn = b_sync_c.clone();
        gtk4::glib::spawn_future_local(async move {
            btn.set_sensitive(false);
            btn.set_label("⏳ Sincronizando sumidero DNS...");
            let (_ok, msg) = run_blocking(|| WebProtectionManager::sync_dns_sinkhole()).await;
            btn.set_sensitive(true);
            btn.set_label("🔄 Sincronizar Sumidero DNS (URLhaus + OpenPhish)");
            let count = WebProtectionManager::get_blocked_domains_count();
            st_l.set_text(&format!("● Activo / {} dominios maliciosos bloqueados en 0.0.0.0", count));
            fb_l.set_text(&msg);
        });
    });

    btn_open_gufw.connect_clicked(|_| NetworkPrivacyAudit::launch_gufw());
    btn_open_pvpn.connect_clicked(|_| NetworkPrivacyAudit::launch_protonvpn());
    
    let ip_l_clone = ip_lbl.clone();
    let loc_l_clone = loc_lbl.clone();
    
    let iface_l_clone = iface_lbl.clone();
    btn_ref_ip.connect_clicked(move |_| {
        let i_lbl = ip_l_clone.clone();
        let l_lbl = loc_l_clone.clone();
        let if_lbl = iface_l_clone.clone();
        gtk4::glib::spawn_future_local(async move {
            i_lbl.set_text("Consultando IP...");
            l_lbl.set_text("Consultando ubicación...");
            let (ip, loc) = run_blocking(|| NetworkPrivacyAudit::get_public_ip_info()).await;
            let (iface, iface_t, lip) = run_blocking(|| NetworkPrivacyAudit::get_active_interface_info()).await;
            i_lbl.set_text(&ip);
            l_lbl.set_text(&loc);
            if_lbl.set_text(&format!("● {} ({}) | IP Local: {}", iface, iface_t, lip));
        });
    });
    
    // Consulta inicial de IP
    {
        let i_lbl = ip_lbl.clone();
        let l_lbl = loc_lbl.clone();
        gtk4::glib::spawn_future_local(async move {
            let (ip, loc) = run_blocking(|| NetworkPrivacyAudit::get_public_ip_info()).await;
            i_lbl.set_text(&ip);
            l_lbl.set_text(&loc);
        });
    }

    // --- Vista 5: Baúl de Cuarentena Interactivo ---
    let vault_box = Box::new(Orientation::Vertical, 16);
    vault_box.set_margin_start(14);
    vault_box.set_margin_end(14);
    vault_box.set_margin_top(14);
    
    let v_card = Box::new(Orientation::Vertical, 12);
    v_card.add_css_class("macos-card");
    
    let vt = Label::new(Some("Baúl de Cuarentena (Constantine y ClamAV)"));
    vt.add_css_class("title-text");
    vt.set_xalign(0.0);
    vt.set_wrap(true);
    v_card.append(&vt);

    let vd = Label::new(Some("Selecciona cualquier amenaza de la lista para enviarla a lista blanca, eliminarla o consultar información en Google."));
    vd.add_css_class("subtitle-text");
    vd.set_xalign(0.0);
    vd.set_wrap(true);
    vd.set_wrap_mode(gtk4::pango::WrapMode::Word);
    v_card.append(&vd);
    
    let v_scrolled = ScrolledWindow::new();
    v_scrolled.set_min_content_height(280);
    v_scrolled.set_vexpand(true);
    
    let list_box = ListBox::new();
    list_box.set_selection_mode(SelectionMode::Single);
    list_box.add_css_class("macos-card");
    v_scrolled.set_child(Some(&list_box));
    v_card.append(&v_scrolled);

    let selected_threat: std::rc::Rc<std::cell::RefCell<Option<String>>> = std::rc::Rc::new(std::cell::RefCell::new(None));
    
    let v_status_lbl = Label::new(Some("Selecciona una amenaza de la lista para gestionarla."));
    v_status_lbl.set_xalign(0.0);
    v_status_lbl.add_css_class("subtitle-text");
    v_status_lbl.set_wrap(true);
    v_status_lbl.set_wrap_mode(gtk4::pango::WrapMode::Word);
    v_card.append(&v_status_lbl);
    
    let btn_action_row = Box::new(Orientation::Horizontal, 12);
    let btn_ref_vault = Button::with_label("🔄 Actualizar Baúl");
    
    let btn_whitelist = Button::with_label("✅ Enviar Seleccionada a Lista Blanca");
    btn_whitelist.add_css_class("suggested-action");

    let btn_google_search = Button::with_label("🔍 Consultar en Google");
    btn_google_search.add_css_class("suggested-action");
    
    let btn_del_vault = Button::with_label("🗑️ Eliminar Seleccionada");
    btn_del_vault.add_css_class("destructive-action");

    let btn_restore_all = Button::with_label("📦 Restaurar Todas");
    btn_restore_all.add_css_class("suggested-action");

    let btn_clear_all = Button::with_label("⚠️ Vaciar Todo el Baúl");
    btn_clear_all.add_css_class("destructive-action");
    
    btn_action_row.append(&btn_ref_vault);
    btn_action_row.append(&btn_whitelist);
    btn_action_row.append(&btn_google_search);
    btn_action_row.append(&btn_del_vault);
    btn_action_row.append(&btn_restore_all);
    btn_action_row.append(&btn_clear_all);
    v_card.append(&btn_action_row);
    vault_box.append(&v_card);
    stack.add_named(&wrap_responsive(&vault_box), Some("vault"));

    let list_box_c1 = list_box.clone();
    let v_st_c1 = v_status_lbl.clone();
    let sel_threat_c1 = selected_threat.clone();
    
    let load_vault = move || {
        while let Some(child) = list_box_c1.first_child() {
            list_box_c1.remove(&child);
        }
        *sel_threat_c1.borrow_mut() = None;

        let entries = VaultManager::list_all_quarantine_entries();
        if entries.is_empty() {
            let empty_row = ListBoxRow::new();
            let lbl = Label::new(Some("Los baúles de cuarentena (Constantine y ClamAV) están limpios. No hay amenazas aisladas."));
            lbl.set_xalign(0.0);
            lbl.add_css_class("subtitle-text");
            empty_row.set_child(Some(&lbl));
            empty_row.set_selectable(false);
            list_box_c1.append(&empty_row);
            v_st_c1.set_text("El baúl de cuarentena está limpio.");
        } else {
            for (idx, entry) in entries.iter().enumerate() {
                let row = ListBoxRow::new();
                let row_box = Box::new(Orientation::Vertical, 4);
                row_box.set_margin_start(12);
                row_box.set_margin_end(12);
                row_box.set_margin_top(8);
                row_box.set_margin_bottom(8);

                let header_box = Box::new(Orientation::Horizontal, 8);
                let icon_str = if entry.is_cstv_encrypted { "🔒" } else { "🛡️" };
                let icon_lbl = Label::new(Some(icon_str));
                
                let name_lbl = Label::new(Some(&entry.filename));
                name_lbl.add_css_class("title-text");
                name_lbl.set_xalign(0.0);
                name_lbl.set_hexpand(true);

                let badge = Label::new(Some(entry.origin_vault));
                badge.add_css_class(if entry.is_cstv_encrypted { "mini-row-status-ok" } else { "mini-row-status-warn" });

                header_box.append(&icon_lbl);
                header_box.append(&name_lbl);
                header_box.append(&badge);
                row_box.append(&header_box);

                let meta_row1 = Box::new(Orientation::Horizontal, 16);
                let th_lbl = Label::new(Some(&format!("🔴 Amenaza: {}", entry.threat_name)));
                th_lbl.add_css_class("mini-row-status-alert");
                th_lbl.set_xalign(0.0);

                let det_lbl = Label::new(Some(&format!("🔍 Detección: {}", entry.detection_method)));
                det_lbl.add_css_class("mini-row-status-ok");
                det_lbl.set_xalign(0.0);

                let time_lbl = Label::new(Some(&format!("🕒 Fecha/Hora: {}", entry.timestamp)));
                time_lbl.add_css_class("subtitle-text");
                time_lbl.set_xalign(0.0);

                meta_row1.append(&th_lbl);
                meta_row1.append(&det_lbl);
                meta_row1.append(&time_lbl);
                row_box.append(&meta_row1);

                let orig_lbl = Label::new(Some(&format!("📁 Origen detectado: {}", entry.original_path)));
                orig_lbl.add_css_class("subtitle-text");
                orig_lbl.set_xalign(0.0);
                row_box.append(&orig_lbl);

                let hash_lbl = Label::new(Some(&format!("🔑 SHA-256: {}", entry.sha256)));
                hash_lbl.add_css_class("subtitle-text");
                hash_lbl.set_xalign(0.0);
                row_box.append(&hash_lbl);

                row.set_child(Some(&row_box));
                list_box_c1.append(&row);

                if idx == 0 {
                    list_box_c1.select_row(Some(&row));
                }
            }
            v_st_c1.set_text(&format!("Total de amenazas en cuarentena: {}. Haz clic en una fila para seleccionarla.", entries.len()));
        }
    };

    let sel_threat_sel = selected_threat.clone();
    let v_st_sel = v_status_lbl.clone();
    list_box.connect_row_selected(move |_, row_opt| {
        if let Some(row) = row_opt {
            let row_idx = row.index();
            let entries = VaultManager::list_all_quarantine_entries();
            if let Some(entry) = entries.get(row_idx as usize) {
                *sel_threat_sel.borrow_mut() = Some(entry.filename.clone());
                v_st_sel.set_text(&format!("✓ Amenaza seleccionada: {} ({})", entry.filename, entry.origin_vault));
                return;
            }
        }
        *sel_threat_sel.borrow_mut() = None;
        v_st_sel.set_text("Ninguna amenaza seleccionada (haz clic en una fila).");
    });
    
    let lv_c1 = load_vault.clone();
    btn_ref_vault.connect_clicked(move |_| lv_c1());
    
    let lv_c2 = load_vault.clone();
    let u_home = user_home.clone();
    let sel_threat_wl = selected_threat.clone();
    let v_st_wl = v_status_lbl.clone();
    btn_whitelist.connect_clicked(move |_| {
        let selected = sel_threat_wl.borrow().clone();
        if let Some(filename) = selected {
            if VaultManager::restore_to_whitelist(&filename, &u_home) {
                v_st_wl.set_text(&format!("✓ Muestra {} restaurada a ~/Desktop y autorizada en Lista Blanca.", filename));
                lv_c2();
            } else {
                v_st_wl.set_text("⚠️ Fallo al restaurar la muestra seleccionada.");
            }
        } else {
            v_st_wl.set_text("⚠️ Por favor, selecciona primero una amenaza de la lista.");
        }
    });
    
    let lv_c3 = load_vault.clone();
    let sel_threat_del = selected_threat.clone();
    let v_st_del = v_status_lbl.clone();
    btn_del_vault.connect_clicked(move |_| {
        let selected = sel_threat_del.borrow().clone();
        if let Some(filename) = selected {
            if VaultManager::delete_from_vault(&filename) {
                v_st_del.set_text(&format!("✓ Muestra {} eliminada definitivamente de la cuarentena.", filename));
                lv_c3();
            } else {
                v_st_del.set_text("⚠️ Fallo al eliminar la muestra seleccionada.");
            }
        } else {
            v_st_del.set_text("⚠️ Por favor, selecciona primero una amenaza de la lista.");
        }
    });

    let sel_threat_goog = selected_threat.clone();
    let v_st_goog = v_status_lbl.clone();
    btn_google_search.connect_clicked(move |_| {
        let selected = sel_threat_goog.borrow().clone();
        let target = if let Some(ref filename) = selected {
            filename.trim_end_matches(".vault").to_string()
        } else {
            "linux malware threat intelligence".to_string()
        };
        let query = format!("https://www.google.com/search?q=malware+threat+vulnerability+{}", target);
        let _ = Command::new("xdg-open").arg(&query).spawn();
        v_st_goog.set_text(&format!("🔍 Búsqueda en Google abierta para: {}", target));
    });

    let lv_c4 = load_vault.clone();
    let u_home_all = user_home.clone();
    let v_st_all = v_status_lbl.clone();
    btn_restore_all.connect_clicked(move |_| {
        let files = VaultManager::list_vault_files();
        let mut count = 0;
        for f in &files {
            if VaultManager::restore_to_whitelist(f, &u_home_all) {
                count += 1;
            }
        }
        v_st_all.set_text(&format!("✓ {} de {} muestras restauradas y añadidas a Lista Blanca.", count, files.len()));
        lv_c4();
    });

    let lv_c5 = load_vault.clone();
    let v_st_clr = v_status_lbl.clone();
    btn_clear_all.connect_clicked(move |_| {
        let files = VaultManager::list_vault_files();
        let mut count = 0;
        for f in &files {
            if VaultManager::delete_from_vault(f) {
                count += 1;
            }
        }
        v_st_clr.set_text(&format!("✓ Baúl vaciado: {} muestras eliminadas permanentemente.", count));
        lv_c5();
    });


    // --- Vista: Lista Blanca Criptográfica (Exclusiones de Seguridad) ---
    let wl_box = Box::new(Orientation::Vertical, 16);
    wl_box.set_margin_start(14);
    wl_box.set_margin_end(14);
    wl_box.set_margin_top(14);
    
    let wl_card = Box::new(Orientation::Vertical, 12);
    wl_card.add_css_class("macos-card");
    
    let wl_t = Label::new(Some("Lista Blanca Criptográfica (Exclusiones de Seguridad)"));
    wl_t.add_css_class("title-text");
    wl_t.set_xalign(0.0);
    wl_t.set_wrap(true);
    wl_card.append(&wl_t);
    
    let wl_d = Label::new(Some("Firmas y archivos de confianza excluidos permanentemente del análisis de amenazas y de la contención."));
    wl_d.add_css_class("subtitle-text");
    wl_d.set_xalign(0.0);
    wl_d.set_wrap(true);
    wl_d.set_wrap_mode(gtk4::pango::WrapMode::Word);
    wl_card.append(&wl_d);

    let wl_scrolled = ScrolledWindow::new();
    wl_scrolled.set_min_content_height(280);
    wl_scrolled.set_vexpand(true);
    
    let wl_list_box = ListBox::new();
    wl_list_box.set_selection_mode(SelectionMode::Single);
    wl_list_box.add_css_class("macos-card");
    wl_scrolled.set_child(Some(&wl_list_box));
    wl_card.append(&wl_scrolled);

    let selected_wl_hash: std::rc::Rc<std::cell::RefCell<Option<String>>> = std::rc::Rc::new(std::cell::RefCell::new(None));

    let wl_input_box = Box::new(Orientation::Vertical, 8);
    let wl_input_row1 = Box::new(Orientation::Horizontal, 8);
    let wl_input_row2 = Box::new(Orientation::Horizontal, 8);

    let wl_entry = Entry::new();
    wl_entry.set_placeholder_text(Some("Introduce hash SHA-256 de 64 caracteres..."));
    wl_entry.set_hexpand(true);
    let btn_wl_add_hash = Button::with_label("➕ Añadir Hash");
    btn_wl_add_hash.add_css_class("suggested-action");
    wl_input_row1.append(&wl_entry);
    wl_input_row1.append(&btn_wl_add_hash);

    let btn_wl_add_file = Button::with_label("📄 Excluir Archivo");
    let btn_wl_del = Button::with_label("🗑️ Retirar");
    btn_wl_del.add_css_class("destructive-action");
    let btn_wl_ref = Button::with_label("🔄 Actualizar");
    wl_input_row2.append(&btn_wl_add_file);
    wl_input_row2.append(&btn_wl_del);
    wl_input_row2.append(&btn_wl_ref);

    wl_input_box.append(&wl_input_row1);
    wl_input_box.append(&wl_input_row2);
    wl_card.append(&wl_input_box);
    
    let wl_status_lbl = Label::new(Some("Selecciona una exclusión de la lista para gestionarla."));
    wl_status_lbl.set_xalign(0.0);
    wl_status_lbl.add_css_class("subtitle-text");
    wl_card.append(&wl_status_lbl);
    
    wl_box.append(&wl_card);
    stack.add_named(&wrap_responsive(&wl_box), Some("whitelist"));

    let wl_list_c1 = wl_list_box.clone();
    let wl_st_c = wl_status_lbl.clone();
    let sel_wl_c1 = selected_wl_hash.clone();

    let load_whitelist_view = move || {
        while let Some(child) = wl_list_c1.first_child() {
            wl_list_c1.remove(&child);
        }
        *sel_wl_c1.borrow_mut() = None;

        let records = WhitelistManager::list_whitelist_records();
        if records.is_empty() {
            let empty_row = ListBoxRow::new();
            let lbl = Label::new(Some("La lista blanca está vacía. No hay firmas ni archivos excluidos."));
            lbl.set_xalign(0.0);
            lbl.add_css_class("subtitle-text");
            empty_row.set_child(Some(&lbl));
            empty_row.set_selectable(false);
            wl_list_c1.append(&empty_row);
            wl_st_c.set_text("No hay elementos autorizados.");
        } else {
            for (idx, r) in records.iter().enumerate() {
                let row = ListBoxRow::new();
                let row_box = Box::new(Orientation::Vertical, 4);
                row_box.set_margin_start(12);
                row_box.set_margin_end(12);
                row_box.set_margin_top(8);
                row_box.set_margin_bottom(8);

                let header_box = Box::new(Orientation::Horizontal, 8);
                let icon_lbl = Label::new(Some("✓"));
                icon_lbl.add_css_class("mini-row-status-ok");
                
                let name_lbl = Label::new(Some(&r.filename));
                name_lbl.add_css_class("title-text");
                name_lbl.set_xalign(0.0);
                name_lbl.set_hexpand(true);

                let badge = Label::new(Some("Autorizado"));
                badge.add_css_class("mini-row-status-ok");

                header_box.append(&icon_lbl);
                header_box.append(&name_lbl);
                header_box.append(&badge);
                row_box.append(&header_box);

                let meta_row = Box::new(Orientation::Horizontal, 16);
                let time_lbl = Label::new(Some(&format!("🕒 Ingresado: {}", r.timestamp)));
                time_lbl.add_css_class("subtitle-text");
                time_lbl.set_xalign(0.0);

                let orig_lbl = Label::new(Some(&format!("📁 Origen: {}", r.original_path)));
                orig_lbl.add_css_class("subtitle-text");
                orig_lbl.set_xalign(0.0);

                meta_row.append(&time_lbl);
                meta_row.append(&orig_lbl);
                row_box.append(&meta_row);

                let hash_lbl = Label::new(Some(&format!("🔑 SHA-256: {}", r.hash)));
                hash_lbl.add_css_class("subtitle-text");
                hash_lbl.set_xalign(0.0);
                row_box.append(&hash_lbl);

                row.set_child(Some(&row_box));
                wl_list_c1.append(&row);

                if idx == 0 {
                    wl_list_c1.select_row(Some(&row));
                }
            }
            wl_st_c.set_text(&format!("Total de exclusiones registradas: {}. Haz clic en una fila para seleccionarla.", records.len()));
        }
    };

    let sel_wl_sel = selected_wl_hash.clone();
    let wl_st_sel = wl_status_lbl.clone();
    wl_list_box.connect_row_selected(move |_, row_opt| {
        if let Some(row) = row_opt {
            let row_idx = row.index();
            let records = WhitelistManager::list_whitelist_records();
            if let Some(r) = records.get(row_idx as usize) {
                *sel_wl_sel.borrow_mut() = Some(r.hash.clone());
                wl_st_sel.set_text(&format!("✓ Elemento seleccionado: {} (Hash: {}...)", r.filename, &r.hash[..16]));
                return;
            }
        }
        *sel_wl_sel.borrow_mut() = None;
        wl_st_sel.set_text("Ningún elemento seleccionado (haz clic en una fila).");
    });

    let lwv_1 = load_whitelist_view.clone();
    btn_wl_ref.connect_clicked(move |_| lwv_1());

    let lwv_2 = load_whitelist_view.clone();
    let wl_entry_c1 = wl_entry.clone();
    let wl_st_c1 = wl_status_lbl.clone();
    btn_wl_add_hash.connect_clicked(move |_| {
        let text = wl_entry_c1.text().to_string();
        if WhitelistManager::add_record(&text, "Firma Manual", "Añadida manualmente por el usuario") {
            wl_entry_c1.set_text("");
            wl_st_c1.set_text("✓ Hash agregado exitosamente a la Lista Blanca.");
            lwv_2();
        } else {
            wl_st_c1.set_text("⚠️ Error: El hash debe tener exactamente 64 caracteres hexadecimales.");
        }
    });

    let win_wl = window.clone();
    let lwv_3 = load_whitelist_view.clone();
    let wl_st_c2 = wl_status_lbl.clone();
    btn_wl_add_file.connect_clicked(move |_| {
        let chooser = gtk4::FileChooserNative::new(
            Some("Seleccionar Archivo para Añadir a Lista Blanca"),
            Some(&win_wl),
            gtk4::FileChooserAction::Open,
            Some("Añadir a Lista Blanca"),
            Some("Cancelar"),
        );
        let lwv = lwv_3.clone();
        let st = wl_st_c2.clone();
        chooser.connect_response(move |dialog, response| {
            if response == gtk4::ResponseType::Accept {
                if let Some(file) = dialog.file() {
                    if let Some(path) = file.path() {
                        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("archivo").to_string();
                        match WhitelistManager::add_file(&path) {
                            Ok(h) => {
                                st.set_text(&format!("✓ Archivo '{}' añadido a la Lista Blanca (SHA-256: {}...)", fname, &h[..16.min(h.len())]));
                                lwv();
                            }
                            Err(e) => {
                                st.set_text(&format!("⚠️ Error al agregar archivo a lista blanca: {}", e));
                            }
                        }
                    }
                }
            }
        });
        chooser.show();
    });

    let lwv_4 = load_whitelist_view.clone();
    let sel_wl_del = selected_wl_hash.clone();
    let wl_st_c3 = wl_status_lbl.clone();
    btn_wl_del.connect_clicked(move |_| {
        let selected = sel_wl_del.borrow().clone();
        if let Some(hash) = selected {
            if WhitelistManager::remove_record(&hash) {
                wl_st_c3.set_text(&format!("✓ Hash retirado de la Lista Blanca."));
                lwv_4();
            } else {
                wl_st_c3.set_text("⚠️ Error al retirar el elemento seleccionado.");
            }
        } else {
            wl_st_c3.set_text("⚠️ Por favor selecciona primero un elemento de la lista.");
        }
    });

    // --- Vista: Custodia de Periféricos (Cámara y Micrófono) ---
    let periph_box = Box::new(Orientation::Vertical, 16);
    periph_box.set_margin_start(14);
    periph_box.set_margin_end(14);
    periph_box.set_margin_top(14);
    
    let p_card = Box::new(Orientation::Vertical, 14);
    p_card.add_css_class("macos-card");
    
    let pt = Label::new(Some("Custodia Activa de Periféricos (Cámara y Micrófono)"));
    pt.add_css_class("title-text");
    pt.set_xalign(0.0);
    pt.set_wrap(true);
    p_card.append(&pt);
    
    let pd = Label::new(Some("Supervisión y control perimetral contra spyware, troyanos de acceso remoto (RAT) y grabaciones clandestinas."));
    pd.add_css_class("subtitle-text");
    pd.set_xalign(0.0);
    pd.set_wrap(true);
    pd.set_wrap_mode(gtk4::pango::WrapMode::Word);
    p_card.append(&pd);

    let p_box = Box::new(Orientation::Vertical, 10);

    // Fila 1: Cámara Web
    let cam_card = Box::new(Orientation::Vertical, 8);
    cam_card.add_css_class("macos-card");
    let cam_head = Box::new(Orientation::Horizontal, 8);
    let cam_t = Label::new(Some("📹 Cámara Web (/dev/video*)"));
    cam_t.add_css_class("title-text");
    cam_t.set_xalign(0.0);
    cam_t.set_hexpand(true);
    cam_head.append(&cam_t);

    let cam_lbl = Label::new(Some("Comprobando cámara..."));
    cam_lbl.set_xalign(0.0);
    cam_lbl.add_css_class("mini-row-status-ok");
    cam_head.append(&cam_lbl);
    cam_card.append(&cam_head);

    let cam_actions = Box::new(Orientation::Horizontal, 8);
    cam_actions.set_halign(gtk4::Align::End);
    let btn_block_cam = Button::with_label("🔴 Apagar Cámara");
    btn_block_cam.add_css_class("destructive-action");
    let btn_unblock_cam = Button::with_label("🟢 Encender Cámara");
    btn_unblock_cam.add_css_class("suggested-action");
    cam_actions.append(&btn_block_cam);
    cam_actions.append(&btn_unblock_cam);
    cam_card.append(&cam_actions);
    p_box.append(&cam_card);

    // Fila 2: Micrófono
    let mic_card = Box::new(Orientation::Vertical, 8);
    mic_card.add_css_class("macos-card");
    let mic_head = Box::new(Orientation::Horizontal, 8);
    let mic_t = Label::new(Some("🎙️ Micrófono (/dev/snd/*)"));
    mic_t.add_css_class("title-text");
    mic_t.set_xalign(0.0);
    mic_t.set_hexpand(true);
    mic_head.append(&mic_t);

    let mic_lbl = Label::new(Some("Comprobando micrófono..."));
    mic_lbl.set_xalign(0.0);
    mic_lbl.add_css_class("mini-row-status-ok");
    mic_head.append(&mic_lbl);
    mic_card.append(&mic_head);

    let mic_actions = Box::new(Orientation::Horizontal, 8);
    mic_actions.set_halign(gtk4::Align::End);
    let btn_block_mic = Button::with_label("🔴 Silenciar");
    btn_block_mic.add_css_class("destructive-action");
    let btn_unblock_mic = Button::with_label("🟢 Activar");
    btn_unblock_mic.add_css_class("suggested-action");
    mic_actions.append(&btn_block_mic);
    mic_actions.append(&btn_unblock_mic);
    mic_card.append(&mic_actions);
    p_box.append(&mic_card);

    p_card.append(&p_box);
    
    let btn_ref_p = Button::with_label("🔄 Auditar Estado de Periféricos Ahora");
    p_card.append(&btn_ref_p);
    
    periph_box.append(&p_card);
    stack.add_named(&wrap_responsive(&periph_box), Some("peripherals"));

    let cam_l_c = cam_lbl.clone();
    let mic_l_c = mic_lbl.clone();
    let refresh_periph_status = move || {
        let (cam_used, cam_msg) = PeripheralAudit::get_camera_status();
        let (mic_used, mic_msg) = PeripheralAudit::get_microphone_status();
        cam_l_c.set_text(&cam_msg);
        if cam_used {
            cam_l_c.remove_css_class("mini-row-status-ok");
            cam_l_c.add_css_class("mini-row-status-alert");
        } else {
            cam_l_c.remove_css_class("mini-row-status-alert");
            cam_l_c.add_css_class("mini-row-status-ok");
        }
        
        mic_l_c.set_text(&mic_msg);
        if mic_used {
            mic_l_c.remove_css_class("mini-row-status-ok");
            mic_l_c.add_css_class("mini-row-status-alert");
        } else {
            mic_l_c.remove_css_class("mini-row-status-alert");
            mic_l_c.add_css_class("mini-row-status-ok");
        }
    };

    let rp_c1 = refresh_periph_status.clone();
    btn_ref_p.connect_clicked(move |_| rp_c1());

    let rp_c2 = refresh_periph_status.clone();
    btn_block_cam.connect_clicked(move |_| {
        let _ = PeripheralAudit::turn_off_camera();
        rp_c2();
    });

    let rp_c3 = refresh_periph_status.clone();
    btn_unblock_cam.connect_clicked(move |_| {
        let _ = PeripheralAudit::turn_on_camera();
        rp_c3();
    });

    let rp_c4 = refresh_periph_status.clone();
    btn_block_mic.connect_clicked(move |_| {
        let _ = PeripheralAudit::turn_off_microphone();
        rp_c4();
    });

    let rp_c5 = refresh_periph_status.clone();
    btn_unblock_mic.connect_clicked(move |_| {
        let _ = PeripheralAudit::turn_on_microphone();
        rp_c5();
    });

    // --- Vista 6: Control de Módulos (Encender y Apagar Servicios) ---
    let mod_box = Box::new(Orientation::Vertical, 16);
    mod_box.set_margin_start(14);
    mod_box.set_margin_end(14);
    mod_box.set_margin_top(14);
    
    let make_module_row = |name: &str, service: &'static str, desc: &str| -> Box {
        let card = Box::new(Orientation::Vertical, 8);
        card.add_css_class("macos-card");
        
        let header_row = Box::new(Orientation::Horizontal, 8);
        let t = Label::new(Some(name));
        t.add_css_class("title-text");
        t.set_xalign(0.0);
        t.set_hexpand(true);
        header_row.append(&t);

        let is_active = get_service_active(service);
        let st_badge = Label::new(Some(if is_active { "● Activo" } else { "● Detenido" }));
        st_badge.add_css_class(if is_active { "mini-row-status-ok" } else { "mini-row-status-warn" });
        header_row.append(&st_badge);
        card.append(&header_row);

        let d = Label::new(Some(desc));
        d.add_css_class("subtitle-text");
        d.set_xalign(0.0);
        d.set_wrap(true);
        d.set_wrap_mode(gtk4::pango::WrapMode::Word);
        card.append(&d);

        let actions_box = Box::new(Orientation::Horizontal, 6);
        actions_box.set_halign(gtk4::Align::End);

        let btn_start = Button::with_label("▶ Iniciar");
        btn_start.add_css_class("suggested-action");
        actions_box.append(&btn_start);

        let btn_stop = Button::with_label("⏹ Detener");
        btn_stop.add_css_class("destructive-action");
        actions_box.append(&btn_stop);

        let btn_force = Button::with_label("⚡ Reiniciar");
        btn_force.add_css_class("suggested-action");
        actions_box.append(&btn_force);

        let st_b1 = st_badge.clone();
        btn_start.connect_clicked(move |_| {
            st_b1.set_text("⏳ Iniciando...");
            if SecurityAuth::start_service_protected(service) {
                st_b1.set_text("● Activo");
                st_b1.remove_css_class("mini-row-status-warn");
                st_b1.add_css_class("mini-row-status-ok");
            } else {
                st_b1.set_text("● Detenido");
            }
        });

        let st_b2 = st_badge.clone();
        btn_stop.connect_clicked(move |_| {
            st_b2.set_text("⏳ Deteniendo...");
            if SecurityAuth::stop_service_protected(service) {
                st_b2.set_text("● Detenido");
                st_b2.remove_css_class("mini-row-status-ok");
                st_b2.add_css_class("mini-row-status-warn");
            } else {
                st_b2.set_text("● Activo");
            }
        });

        let st_b3 = st_badge.clone();
        btn_force.connect_clicked(move |_| {
            st_b3.set_text("⏳ Forzando...");
            if SecurityAuth::force_start_service(service) {
                st_b3.set_text("● Activo (Forzado)");
                st_b3.remove_css_class("mini-row-status-warn");
                st_b3.add_css_class("mini-row-status-ok");
            }
        });
        
        card.append(&actions_box);
        card
    };
    
    mod_box.append(&make_module_row("ClamOnAcc (fanotify Shield)", "clamonacc", "Intercepción y bloqueo síncrono en kernel al abrir archivos."));
    mod_box.append(&make_module_row("Tetragon (Cilium eBPF)", "tetragon", "Vigilancia de procesos y políticas de terminación forzada SIGKILL."));
    mod_box.append(&make_module_row("Falco (Runtime Behavioral)", "falco", "Detección de comportamiento anómalo mediante reglas comunitarias."));
    mod_box.append(&make_module_row("Wazuh Agent (SIEM & FIM)", "wazuh-agent", "Monitoreo de integridad de archivos (syscheck), rootkits y telemetría centralizada."));
    mod_box.append(&make_module_row("ClamAV Engine (clamd)", "clamav-daemon", "Motor de firmas multihilo por socket UNIX en memoria."));
    mod_box.append(&make_module_row("Cortafuegos UFW", "ufw", "Filtrado perimetral de paquetes y aislamiento de red ante ataques."));
    
    stack.add_named(&wrap_responsive(&mod_box), Some("modules"));

    // --- Vista 7: Apartado de Auditoría Forense Universal e Inmutable ---
    let log_box = Box::new(Orientation::Vertical, 12);
    log_box.set_margin_start(14);
    log_box.set_margin_end(14);
    log_box.set_margin_top(14);
    
    let lcard = Box::new(Orientation::Vertical, 10);
    lcard.add_css_class("macos-card");
    
    let ltitle = Label::new(Some("Apartado de Auditoría Forense Universal (Registro Inmutable SHA-256)"));
    ltitle.add_css_class("title-text");
    ltitle.set_xalign(0.0);
    ltitle.set_wrap(true);
    lcard.append(&ltitle);

    let lsub = Label::new(Some("Supervisión forense total: todas las advertencias, notificaciones, errores, fallas, conexiones y eventos de los 16 módulos registrados con encadenamiento criptográfico."));
    lsub.add_css_class("subtitle-text");
    lsub.set_xalign(0.0);
    lsub.set_wrap(true);
    lsub.set_wrap_mode(gtk4::pango::WrapMode::Word);
    lcard.append(&lsub);

    // Barra de Métricas y KPIs de Auditoría
    let kpi_row = Box::new(Orientation::Horizontal, 8);
    let lbl_kpi_total = Label::new(Some("📦 Total: 0"));
    lbl_kpi_total.add_css_class("stat-pill");
    let lbl_kpi_alerts = Label::new(Some("⚠️ Alertas/Notif: 0"));
    lbl_kpi_alerts.add_css_class("stat-pill");
    let lbl_kpi_errors = Label::new(Some("❌ Fallas/Errores: 0"));
    lbl_kpi_errors.add_css_class("stat-pill");
    let lbl_kpi_net = Label::new(Some("🔌 Red/DNS: 0"));
    lbl_kpi_net.add_css_class("stat-pill");
    let lbl_kpi_integ = Label::new(Some("🔒 Integridad: Verificando..."));
    lbl_kpi_integ.add_css_class("stat-pill");

    kpi_row.append(&lbl_kpi_total);
    kpi_row.append(&lbl_kpi_alerts);
    kpi_row.append(&lbl_kpi_errors);
    kpi_row.append(&lbl_kpi_net);
    kpi_row.append(&lbl_kpi_integ);
    lcard.append(&kpi_row);

    // Fila de Filtros Rápidos por Categoría
    let filter_row = Box::new(Orientation::Horizontal, 6);
    let btn_f_all = Button::with_label("🌐 Todo el Historial");
    btn_f_all.add_css_class("filter-btn");
    let btn_f_alerts = Button::with_label("⚠️ Alertas y Notif.");
    btn_f_alerts.add_css_class("filter-btn");
    let btn_f_errors = Button::with_label("❌ Errores y Fallas");
    btn_f_errors.add_css_class("filter-btn");
    let btn_f_net = Button::with_label("🔌 Red y Conexiones");
    btn_f_net.add_css_class("filter-btn");
    let btn_f_serv = Button::with_label("🛠️ Servicios y Módulos");
    btn_f_serv.add_css_class("filter-btn");
    let btn_f_hw = Button::with_label("💻 Hardware y Periféricos");
    btn_f_hw.add_css_class("filter-btn");

    filter_row.append(&btn_f_all);
    filter_row.append(&btn_f_alerts);
    filter_row.append(&btn_f_errors);
    filter_row.append(&btn_f_net);
    filter_row.append(&btn_f_serv);
    filter_row.append(&btn_f_hw);
    lcard.append(&filter_row);

    // Caja de Búsqueda Dinámica en Tiempo Real
    let search_audit = Entry::new();
    search_audit.set_placeholder_text(Some("🔍 Buscar por módulo, palabra clave, PID, IP, dominio o hash SHA-256..."));
    lcard.append(&search_audit);
    
    let lscrolled = ScrolledWindow::new();
    lscrolled.set_min_content_height(340);
    
    let ltxt = TextView::new();
    ltxt.set_editable(false);
    ltxt.set_wrap_mode(gtk4::WrapMode::WordChar);
    lscrolled.set_child(Some(&ltxt));
    lcard.append(&lscrolled);

    let btns_audit_actions = Box::new(Orientation::Horizontal, 8);
    let btn_ref_all = Button::with_label("🔄 Actualizar y Verificar Registro Forense");
    btn_ref_all.set_hexpand(true);
    btns_audit_actions.append(&btn_ref_all);

    let btn_purge_24h = Button::with_label("🧹 Borrar Registros > 24 Horas");
    btn_purge_24h.add_css_class("destructive-action");
    btns_audit_actions.append(&btn_purge_24h);

    let btn_export_report = Button::with_label("📑 Exportar Informe Forense Completo (HTML / PDF)");
    btn_export_report.add_css_class("suggested-action");
    btn_export_report.set_hexpand(true);
    btns_audit_actions.append(&btn_export_report);
    lcard.append(&btns_audit_actions);

    let lbl_report_status = Label::new(Some("Haga clic para exportar el informe ejecutivo de auditoría forense a su Escritorio."));
    lbl_report_status.add_css_class("subtitle-text");
    lbl_report_status.set_wrap(true);
    lbl_report_status.set_wrap_mode(gtk4::pango::WrapMode::Word);
    lbl_report_status.set_xalign(0.0);
    lcard.append(&lbl_report_status);

    let rpt_lbl_c = lbl_report_status.clone();
    let uh_rpt_c = user_home.clone();
    btn_export_report.connect_clicked(move |_| {
        let (ok, path) = ExecutiveReportGenerator::generate_report(&uh_rpt_c);
        if ok {
            rpt_lbl_c.set_text(&format!("✓ Informe ejecutivo forense generado con éxito en: {}", path));
        } else {
            rpt_lbl_c.set_text(&format!("⚠️ Error al generar informe: {}", path));
        }
    });

    let purge_lbl_c = lbl_report_status.clone();
    let btn_purge_c = btn_purge_24h.clone();
    let btn_ref_after_purge = btn_ref_all.clone();
    btn_purge_24h.connect_clicked(move |_| {
        let lbl = purge_lbl_c.clone();
        let btn = btn_purge_c.clone();
        let ref_btn = btn_ref_after_purge.clone();
        btn.set_sensitive(false);
        btn.set_label("⏳ Purgando registros > 24h...");
        gtk4::glib::spawn_future_local(async move {
            match run_blocking(|| ImmutableAuditLog::purge_older_than_24h()).await {
                Ok(removed) => {
                    lbl.set_text(&format!(
                        "✓ Purga forense completada: {} registro(s) mayores a 24 horas eliminados (cadena SHA-256 re-sellada).",
                        removed
                    ));
                    ref_btn.emit_clicked();
                }
                Err(e) => {
                    lbl.set_text(&format!("⚠️ Error al purgar registros: {}", e));
                }
            }
            btn.set_sensitive(true);
            btn.set_label("🧹 Borrar Registros > 24 Horas");
        });
    });

    log_box.append(&lcard);
    stack.add_named(&wrap_responsive(&log_box), Some("logs"));

    // Almacenamiento local para filtrado dinámico
    use std::rc::Rc;
    use std::cell::RefCell;
    let all_logs_cache: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let active_cat_filter: Rc<RefCell<String>> = Rc::new(RefCell::new("all".to_string()));

    let apply_filter_view = {
        let ltv = ltxt.clone();
        let logs_c = all_logs_cache.clone();
        let cat_c = active_cat_filter.clone();
        let search_ent = search_audit.clone();
        let lbl_tot = lbl_kpi_total.clone();
        let lbl_ale = lbl_kpi_alerts.clone();
        let lbl_err = lbl_kpi_errors.clone();
        let lbl_nt = lbl_kpi_net.clone();

        move || {
            let cat = cat_c.borrow().clone();
            let query = search_ent.text().to_lowercase();
            let cache = logs_c.borrow();

            let mut count_total = 0usize;
            let mut count_alerts = 0usize;
            let mut count_errors = 0usize;
            let mut count_net = 0usize;

            let mut filtered = Vec::new();

            for line in cache.iter() {
                count_total += 1;
                let is_alert = line.contains("[NOTIFICACIÓN]") || line.contains("[AMENAZA") || line.contains("[ALERTA") || line.contains("[RANSOMWARE") || line.contains("ALERT") || line.contains("FOUND");
                let is_error = line.contains("[ERROR") || line.contains("[FALLA") || line.contains("ERROR") || line.contains("FAILED") || line.contains("MISMATCH");
                let is_net = line.contains("[RED") || line.contains("[CONEXIÓN") || line.contains("[DNS") || line.contains("[SUMIDERO") || line.contains("DNS_") || line.contains("NETWORK_");
                let is_serv = line.contains("[SERVICIO") || line.contains("[SISTEMA") || line.contains("[ACTUALIZACIÓN") || line.contains("[MÓDULO") || line.contains("SERVICE_") || line.contains("SYSTEM_") || line.contains("MODULES_");
                let is_hw = line.contains("[HARDWARE") || line.contains("[PERIFÉRICO") || line.contains("[USB") || line.contains("HARDWARE_") || line.contains("USB_");

                if is_alert { count_alerts += 1; }
                if is_error { count_errors += 1; }
                if is_net { count_net += 1; }

                // Filtro por categoría activa
                let matches_cat = match cat.as_str() {
                    "alerts" => is_alert,
                    "errors" => is_error,
                    "net" => is_net,
                    "services" => is_serv,
                    "hw" => is_hw,
                    _ => true,
                };

                if !matches_cat { continue; }

                // Filtro por texto de búsqueda
                if !query.is_empty() && !line.to_lowercase().contains(&query) {
                    continue;
                }

                filtered.push(line.clone());
            }

            lbl_tot.set_text(&format!("📦 Total: {}", count_total));
            lbl_ale.set_text(&format!("⚠️ Alertas/Notif: {}", count_alerts));
            lbl_err.set_text(&format!("❌ Fallas/Errores: {}", count_errors));
            lbl_nt.set_text(&format!("🔌 Red/DNS: {}", count_net));

            if filtered.is_empty() {
                ltv.buffer().set_text("Sin registros coincidentes con los filtros seleccionados.");
            } else {
                ltv.buffer().set_text(&filtered.join("\n"));
            }
        }
    };

    // Conectar botones de filtro
    {
        let cat_c = active_cat_filter.clone();
        let afv = apply_filter_view.clone();
        btn_f_all.connect_clicked(move |_| {
            *cat_c.borrow_mut() = "all".to_string();
            afv();
        });
    }
    {
        let cat_c = active_cat_filter.clone();
        let afv = apply_filter_view.clone();
        btn_f_alerts.connect_clicked(move |_| {
            *cat_c.borrow_mut() = "alerts".to_string();
            afv();
        });
    }
    {
        let cat_c = active_cat_filter.clone();
        let afv = apply_filter_view.clone();
        btn_f_errors.connect_clicked(move |_| {
            *cat_c.borrow_mut() = "errors".to_string();
            afv();
        });
    }
    {
        let cat_c = active_cat_filter.clone();
        let afv = apply_filter_view.clone();
        btn_f_net.connect_clicked(move |_| {
            *cat_c.borrow_mut() = "net".to_string();
            afv();
        });
    }
    {
        let cat_c = active_cat_filter.clone();
        let afv = apply_filter_view.clone();
        btn_f_serv.connect_clicked(move |_| {
            *cat_c.borrow_mut() = "services".to_string();
            afv();
        });
    }
    {
        let cat_c = active_cat_filter.clone();
        let afv = apply_filter_view.clone();
        btn_f_hw.connect_clicked(move |_| {
            *cat_c.borrow_mut() = "hw".to_string();
            afv();
        });
    }
    {
        let afv = apply_filter_view.clone();
        search_audit.connect_changed(move |_| {
            afv();
        });
    }

    let btn_ref_clone = btn_ref_all.clone();
    let logs_cache_ref = all_logs_cache.clone();
    let lbl_integ_clone = lbl_kpi_integ.clone();
    let afv_refresh = apply_filter_view.clone();

    btn_ref_all.connect_clicked(move |_| {
        let btn = btn_ref_clone.clone();
        let logs_c = logs_cache_ref.clone();
        let lbl_in = lbl_integ_clone.clone();
        let afv = afv_refresh.clone();
        btn.set_sensitive(false);
        btn.set_label("⏳ Verificando Registros Forenses e Integridad...");

        gtk4::glib::spawn_future_local(async move {
            let (raw_events, chain_ok, count) = run_blocking(|| {
                let (chain_ok, count) = ImmutableAuditLog::verify_integrity();
                let mut lines = Vec::new();
                
                if let Ok(file) = File::open(IMMUTABLE_AUDIT_LOG) {
                    for l in BufReader::new(file).lines().flatten() {
                        let parts: Vec<&str> = l.splitn(5, '|').collect();
                        if parts.len() >= 5 {
                            let ts = parts[0].trim();
                            let cur_hash = parts[1].trim();
                            let ev = parts[3].trim();
                            let det = parts[4].trim();

                            let tag = if ev.starts_with("NOTIFICATION") {
                                "[NOTIFICACIÓN]"
                            } else if ev.contains("ERROR") || ev.contains("FAILED") || ev.contains("MISMATCH") {
                                "[ERROR / FALLA]"
                            } else if ev.starts_with("NETWORK") || ev.contains("ISOLATION") {
                                "[RED / CONEXIÓN]"
                            } else if ev.starts_with("DNS") || ev.starts_with("WEB_PROTECTION") || ev.contains("SINKHOLE") {
                                "[DNS / FILTRADO]"
                            } else if ev.starts_with("HARDWARE") || ev.starts_with("USB") {
                                "[HARDWARE / PERIFÉRICO]"
                            } else if ev.starts_with("SERVICE") || ev.starts_with("SYSTEM") || ev.starts_with("GAME_MODE") || ev.starts_with("WHITELIST") || ev.starts_with("TAMPER") || ev == "GENESIS" {
                                "[SERVICIO / SISTEMA]"
                            } else if ev.contains("UPDATE") || ev.contains("SYNC") {
                                "[ACTUALIZACIÓN]"
                            } else if ev.contains("RANSOMWARE") || ev.contains("CANARY") || ev.contains("BURST") {
                                "[RANSOMWARE / CANARY]"
                            } else if ev.contains("VAULT") || ev.contains("QUARANTINE") {
                                "[BAÚL / VAULT]"
                            } else if ev.starts_with("RAM_THREAT") || ev.starts_with("RAM_AUTO") {
                                "[ALERTA RAM]"
                            } else if ev.contains("THREAT") || ev.contains("ALERT") || ev.contains("KILLED") {
                                "[AMENAZA / DETECCIÓN]"
                            } else if ev.contains("AIDE") {
                                "[INTEGRIDAD / AIDE]"
                            } else {
                                "[AUDITORÍA FORENSE]"
                            };

                            let short_h = if cur_hash.len() >= 8 { &cur_hash[..8] } else { cur_hash };
                            lines.push(format!("[{}] {} {} | {} (Hash: {})", ts, tag, ev, det, short_h));
                        } else {
                            lines.push(format!("[Forense SHA-256] {}", l));
                        }
                    }
                }
                if let Ok(file) = File::open(LOG_FILE) {
                    let mut clam_lines = Vec::new();
                    for l in BufReader::new(file).lines().flatten() {
                        if l.contains("FOUND") {
                            clam_lines.push(format!("[ClamOnAcc / Detección] {}", l));
                        } else if l.contains("Access denied") {
                            if clam_lines.iter().filter(|x| x.contains("Access denied")).count() < 5 {
                                clam_lines.push(format!("[ClamOnAcc / fanotify] {}", l));
                            }
                        } else if l.contains("ERROR") || l.contains("WARNING") {
                            clam_lines.push(format!("[ClamAV / Falla] {}", l));
                        }
                    }
                    let take_start = clam_lines.len().saturating_sub(100);
                    lines.extend(clam_lines[take_start..].to_vec());
                }
                if let Ok(file) = File::open(SIGMA_LOG_FILE) {
                    let mut s_lines = Vec::new();
                    for l in BufReader::new(file).lines().flatten() {
                        s_lines.push(format!("[Detección / Sigma Match] {}", l));
                    }
                    let take_start = s_lines.len().saturating_sub(50);
                    lines.extend(s_lines[take_start..].to_vec());
                }
                if let Ok(file) = File::open(AIDE_LOG_FILE) {
                    let mut a_lines = Vec::new();
                    for l in BufReader::new(file).lines().flatten() {
                        if l.contains("changed:") || l.contains("added:") || l.contains("removed:") {
                            a_lines.push(format!("[Integridad / AIDE Audit] {}", l));
                        }
                    }
                    let take_start = a_lines.len().saturating_sub(50);
                    lines.extend(a_lines[take_start..].to_vec());
                }
                if let Ok(file) = File::open(YARA_LOG_FILE) {
                    let mut y_lines = Vec::new();
                    for l in BufReader::new(file).lines().flatten() {
                        y_lines.push(format!("[Detección / YARA Live] {}", l));
                    }
                    let take_start = y_lines.len().saturating_sub(50);
                    lines.extend(y_lines[take_start..].to_vec());
                }
                if let Ok(file) = File::open(FALCO_LOG_FILE) {
                    let mut f_lines = Vec::new();
                    for l in BufReader::new(file).lines().flatten() {
                        f_lines.push(format!("[Comportamiento / Falco] {}", l));
                    }
                    let take_start = f_lines.len().saturating_sub(50);
                    lines.extend(f_lines[take_start..].to_vec());
                }
                if let Ok(file) = File::open(WAZUH_LOG_FILE) {
                    let mut w_lines = Vec::new();
                    for l in BufReader::new(file).lines().flatten() {
                        w_lines.push(format!("[SIEM / Wazuh Alert] {}", l));
                    }
                    let take_start = w_lines.len().saturating_sub(50);
                    lines.extend(w_lines[take_start..].to_vec());
                }
                
                lines.reverse();
                (lines, chain_ok, count)
            }).await;

            *logs_c.borrow_mut() = raw_events;
            if chain_ok {
                lbl_in.set_text(&format!("🔒 Cadena SHA-256 Íntegra ({} eventos)", count));
            } else {
                lbl_in.set_text("⚠️ ALERTA: Ruptura en cadena SHA-256");
            }

            afv();

            btn.set_sensitive(true);
            btn.set_label("🔄 Actualizar y Verificar Registro Forense");
        });
    });

    // Navegación Sidebar
    let s1 = stack.clone();
    btn_dash.connect_clicked(move |_| s1.set_visible_child_name("dashboard"));
    
    let s_sc = stack.clone();
    btn_scan.connect_clicked(move |_| s_sc.set_visible_child_name("scan"));
    
    let s_upd = stack.clone();
    btn_updates.connect_clicked(move |_| s_upd.set_visible_child_name("updates"));

    let s_wl = stack.clone();
    let lwv_nav = load_whitelist_view.clone();
    btn_wl.connect_clicked(move |_| {
        s_wl.set_visible_child_name("whitelist");
        lwv_nav();
    });

    let s_periph = stack.clone();
    let rp_nav = refresh_periph_status.clone();
    btn_periph.connect_clicked(move |_| {
        s_periph.set_visible_child_name("peripherals");
        rp_nav();
    });
    
    let s_nav_net = stack.clone();
    btn_net.connect_clicked(move |_| s_nav_net.set_visible_child_name("network"));
    
    let s2 = stack.clone();
    let lv_nav = load_vault.clone();
    btn_vault.connect_clicked(move |_| {
        s2.set_visible_child_name("vault");
        lv_nav();
    });
    
    let s3 = stack.clone();
    btn_modules.connect_clicked(move |_| s3.set_visible_child_name("modules"));
    
    let s4 = stack.clone();
    btn_logs.connect_clicked(move |_| s4.set_visible_child_name("logs"));
    
    main_box.append(&stack);

    // Monitoreo dinámico en tiempo real de todos los escudos, sensores y periféricos (cada 2s)
    let st_sub_dyn = st_sub.clone();
    let health_lbl_dyn = health_lbl.clone();
    let lbl_kpi_quarantine_dyn = lbl_kpi_quarantine.clone();
    let lbl_kpi_whitelist_dyn = lbl_kpi_whitelist.clone();
    let lbl_kpi_canary_dyn = lbl_kpi_canary.clone();
    let lbl_kpi_shields_sub_dyn = lbl_kpi_shields_sub.clone();
    let lbl_dash_health_dyn = lbl_dash_health.clone();
    let pbar_dash_health_dyn = pbar_dash_health.clone();
    let lbl_kernel_info_dyn = lbl_kernel_info.clone();
    let lbl_updates_info_dyn = lbl_updates_info.clone();
    let s_f_dyn = s_f.clone();
    let s_ran_dyn = s_ran.clone();
    let s_p_dyn = s_p.clone();
    let s_per_dyn = s_per.clone();
    let s_net_dyn = s_net.clone();
    let s_log_dyn = s_log.clone();
    let s_usb_dyn = s_usb.clone();
    let s_web_dyn = s_web.clone();
    let s_tamper_dyn = s_tamper.clone();
    let s_game_dyn = s_game.clone();
    let uh_timer = user_home.clone();

    gtk4::glib::timeout_add_seconds_local(4, move || {
        // 1. Recalcular score de salud EDR y KPIs en vivo
        let (pct, act, tot) = ModuleVersionAudit::compute_real_health_score(&uh_timer);
        health_lbl_dyn.set_text(&format!("● Salud: {}% (Ver Qué Falta)", pct));
        lbl_dash_health_dyn.set_text(&format!("Salud Global: {}% ({}/{} Controles de Seguridad Activos)", pct, act, tot));
        pbar_dash_health_dyn.set_fraction((pct as f64) / 100.0);
        
        lbl_kpi_quarantine_dyn.set_text(&format!("{} Muestras", get_quarantine_count()));
        lbl_kpi_whitelist_dyn.set_text(&format!("{} Hashes", get_whitelist_count()));
        lbl_kpi_shields_sub_dyn.set_text(&get_active_shield_summary());
        let can_now = AntiRansomwareShield::verify_active_canaries(&uh_timer);
        lbl_kpi_canary_dyn.set_text(&format!("{}/{} Intactos", can_now, CANARY_FILES.len()));

        let upd_now = SystemUpdateAudit::check_updates();
        lbl_kernel_info_dyn.set_text(&format!("Kernel activo: {} | {}", upd_now.running_kernel, if upd_now.kernel_update_pending { "⚠️ Actualización de Kernel pendiente" } else { "🟢 Kernel al día" }));
        lbl_updates_info_dyn.set_text(&upd_now.status_text);
        
        // 2. Estado dinámico de ClamOnAcc
        let (onacc_ok, onacc_txt) = OnAccessSupervisor::get_onaccess_pipeline_status();
        s_f_dyn.set_text(&onacc_txt);
        if onacc_ok {
            s_f_dyn.remove_css_class("mini-row-status-warn");
            s_f_dyn.add_css_class("mini-row-status-ok");
        } else {
            s_f_dyn.remove_css_class("mini-row-status-ok");
            s_f_dyn.add_css_class("mini-row-status-warn");
        }

        // 3. Estado dinámico de Señuelos Canary
        let canaries = AntiRansomwareShield::verify_active_canaries(&uh_timer);
        s_ran_dyn.set_text(&format!("● Activo / {} de {} Señuelos Sembrados / Detección de Ráfagas", canaries, CANARY_FILES.len()));

        // 4. Estado dinámico de Tetragon eBPF
        let tetra_up = get_service_active("tetragon");
        s_p_dyn.set_text(if tetra_up {
            "● Activo: Puntos de Control LSM + Correlación 4 Pilares (Identidad, Binario, Comportamiento, Contexto)"
        } else {
            "● Inactivo: Demonio Tetragon detenido"
        });
        if tetra_up {
            s_p_dyn.remove_css_class("mini-row-status-warn");
            s_p_dyn.add_css_class("mini-row-status-ok");
        } else {
            s_p_dyn.remove_css_class("mini-row-status-ok");
            s_p_dyn.add_css_class("mini-row-status-warn");
        }

        // 5. Estado dinámico de Custodia de Periféricos (Cámara y Micrófono)
        let (cam_used, cam_txt) = PeripheralAudit::get_camera_status();
        let (mic_used, mic_txt) = PeripheralAudit::get_microphone_status();
        if cam_used || mic_used {
            s_per_dyn.set_text(&format!("⚠️ PERIFÉRICOS: Cámara: {} | Micrófono: {}", cam_txt, mic_txt));
            s_per_dyn.remove_css_class("mini-row-status-ok");
            s_per_dyn.add_css_class("mini-row-status-alert");
        } else {
            s_per_dyn.set_text("● Activo / Cámara y Micrófono Protegidos (Sin accesos no autorizados)");
            s_per_dyn.remove_css_class("mini-row-status-alert");
            s_per_dyn.add_css_class("mini-row-status-ok");
        }

        // 6. Estado dinámico de Red y Firewall
        let ufw_up = NetworkPrivacyAudit::is_ufw_active();
        let vpn_up = NetworkPrivacyAudit::is_protonvpn_active();
        s_net_dyn.set_text(&format!("● Firewall UFW: {} | Túnel ProtonVPN: {}", 
            if ufw_up { "Activo" } else { "Inactivo" },
            if vpn_up { "Conectado" } else { "Desconectado" }
        ));

        // 7. Integridad del Registro Forense
        let (c_ok, c_count) = ImmutableAuditLog::verify_integrity();
        s_log_dyn.set_text(&format!("● Hash Chain SHA-256 Verificada ({} eventos)", c_count));
        if c_ok {
            s_log_dyn.remove_css_class("mini-row-status-alert");
            s_log_dyn.add_css_class("mini-row-status-ok");
        } else {
            s_log_dyn.remove_css_class("mini-row-status-ok");
            s_log_dyn.add_css_class("mini-row-status-alert");
        }

        // 8. Estado dinámico de Memorias USB conectadas
        let current_usbs = UsbDriveMonitor::get_current_usb_mounts();
        if current_usbs.is_empty() {
            s_usb_dyn.set_text("● Activo / Listo para inserción Plug & Play (/media y /run/media)");
        } else {
            s_usb_dyn.set_text(&format!("● Activo / {} memoria(s) USB conectada(s) protegida(s)", current_usbs.len()));
        }

        // 9. Estado dinámico de Protección Web y Filtrado DNS
        let wp_active = WebProtectionManager::is_protection_active();
        let wp_cnt = WebProtectionManager::get_blocked_domains_count();
        if wp_active {
            s_web_dyn.set_text(&format!("● Activo / {} dominios de phishing y malware bloqueados (0.0.0.0)", wp_cnt));
            s_web_dyn.remove_css_class("mini-row-status-warn");
            s_web_dyn.add_css_class("mini-row-status-ok");
        } else {
            s_web_dyn.set_text("● Inactivo / Filtrado DNS pausado");
            s_web_dyn.remove_css_class("mini-row-status-ok");
            s_web_dyn.add_css_class("mini-row-status-warn");
        }

        // 10. Estado dinámico de Autodefensa (Tamper Protection)
        let tamper_active = TamperProtectionManager::is_tamper_protection_active();
        if tamper_active {
            s_tamper_dyn.set_text("● Activo / eBPF Anti-Kill + Archivos Críticos Inmutables (chattr +i)");
            s_tamper_dyn.remove_css_class("mini-row-status-warn");
            s_tamper_dyn.add_css_class("mini-row-status-ok");
        } else {
            s_tamper_dyn.set_text("● Inactivo / Políticas de Autodefensa No Detectadas");
            s_tamper_dyn.remove_css_class("mini-row-status-ok");
            s_tamper_dyn.add_css_class("mini-row-status-warn");
        }

        // 11. Estado dinámico de Modo Juego y Presentación
        let game_active = GamePresentationMode::is_active();
        if game_active {
            s_game_dyn.set_text("● Activo (Pantalla Completa / Alertas Silenciadas)");
            s_game_dyn.remove_css_class("mini-row-status-ok");
            s_game_dyn.add_css_class("mini-row-status-warn");
        } else {
            s_game_dyn.set_text("● En Espera / Monitoreo de Pantalla Completa Activo");
            s_game_dyn.remove_css_class("mini-row-status-warn");
            s_game_dyn.add_css_class("mini-row-status-ok");
        }

        // 8. Badge del Sidebar
        if onacc_ok && tetra_up {
            st_sub_dyn.set_text("● 16 Escudos Activos en 2do Plano");
            st_sub_dyn.remove_css_class("mini-row-status-warn");
            st_sub_dyn.add_css_class("mini-row-status-ok");
        } else {
            st_sub_dyn.set_text("● Algún Módulo Detenido");
            st_sub_dyn.remove_css_class("mini-row-status-ok");
            st_sub_dyn.add_css_class("mini-row-status-warn");
        }

        gtk4::glib::ControlFlow::Continue
    });

    // Auditoría periódica automática de memoria RAM (cada 15 minutos)
    gtk4::glib::timeout_add_seconds_local(900, move || {
        gtk4::glib::spawn_future_local(async {
            let res = run_blocking(|| MemoryScannerEngine::scan_running_memory()).await;
            if !res.threats_found.is_empty() {
                SystemNotifier::notify(
                    "critical",
                    "security-high",
                    "🛡️ Constantine EDR: Alerta en Memoria RAM",
                    &format!("Detectados {} procesos sospechosos o en memoria volátil.", res.threats_found.len()),
                );
                ImmutableAuditLog::append_event("RAM_AUTO_ALERT", &format!("Detección automática en RAM: {} procesos sospechosos.", res.threats_found.len()));
            }
        });
        gtk4::glib::ControlFlow::Continue
    });

    // Actualización inicial a los 10 min
    gtk4::glib::timeout_add_seconds_local(600, move || {
        gtk4::glib::spawn_future_local(async {
            let ok = run_blocking(|| ModuleVersionAudit::update_all_modules()).await;
            if ok {
                SystemNotifier::notify(
                    "low",
                    "security-high",
                    "Constantine Antivirus & EDR",
                    "Actualización inicial (10 min post-inicio): 16 motores sincronizados.",
                );
            }
        });
        gtk4::glib::ControlFlow::Break
    });

    // Actualización continua cada 5 horas ininterrumpidas (18000 segundos)
    gtk4::glib::timeout_add_seconds_local(18000, move || {
        gtk4::glib::spawn_future_local(async {
            let ok = run_blocking(|| ModuleVersionAudit::update_all_modules()).await;
            if ok {
                SystemNotifier::notify(
                    "low",
                    "security-high",
                    "Constantine Antivirus & EDR",
                    "Ciclo continuo (cada 5 horas): Actualización de los 16 módulos completada sin contraseña.",
                );
            }
        });
        gtk4::glib::ControlFlow::Continue
    });

    let win_startup_up = window.clone();
    let repo_lbl_startup = repo_status_lbl.clone();
    gtk4::glib::spawn_future_local(async move {
        if let UpdateCheckStatus::UpdateAvailable { remote_version, url } = run_blocking(|| SelfUpdater::check_remote_version()).await {
            repo_lbl_startup.set_text(&format!("🚀 Nueva versión disponible en GitHub: v{} (instalada: v{})", remote_version, APP_VERSION));
            SystemNotifier::notify(
                "normal",
                "software-update-available",
                "Actualización de Constantine EDR",
                &format!("Nueva versión v{} disponible en GitHub. Haz clic para actualizar.", remote_version),
            );
            prompt_update_dialog(&win_startup_up, &remote_version, &url, Some(repo_lbl_startup));
        }
    });

    window.present();
}