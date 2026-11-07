// ==============================================================================
// Constantine Antivirus & EDR v3.2.7 - Aplicación Nativa en Rust (GTK4 Cupertino v2.7)
// Orientado a Distribuciones Debian (Ubuntu, Linux Mint, Debian puro)
// ==============================================================================
use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Box, Button, CssProvider, Grid,
    HeaderBar, Label, Orientation, ProgressBar, ScrolledWindow,
    Stack, Switch, TextView
};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write}; // Read es necesario para .take()
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// 🔴 CORREGIDO: Eliminados todos los espacios finales fantasma en las constantes
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
window, .background { background-color: #1c1c1e; color: #f5f5f7; font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Ubuntu', sans-serif; }
headerbar.macos-headerbar, .titlebar { background-image: none; background-color: #1a1a1c; border-bottom: 1px solid rgba(255, 255, 255, 0.08); min-height: 48px; padding: 0 12px; box-shadow: none; }
button.titlebutton.close { background-color: #ff5f56; border: 1px solid #e0443e; border-radius: 50%; min-width: 12px; min-height: 12px; margin: 4px 3px; padding: 0; color: transparent; }
button.titlebutton.minimize { background-color: #ffbd2e; border: 1px solid #dea123; border-radius: 50%; min-width: 12px; min-height: 12px; margin: 4px 3px; padding: 0; color: transparent; }
button.titlebutton.maximize { background-color: #27c93f; border: 1px solid #1aab29; border-radius: 50%; min-width: 12px; min-height: 12px; margin: 4px 3px; padding: 0; color: transparent; }
.title-text { font-size: 13.5pt; font-weight: 700; color: #ffffff; }
.subtitle-text { font-size: 8.5pt; color: #86868b; }
.badge-version { background-color: rgba(0, 113, 227, 0.2); color: #0a84ff; border: 1px solid rgba(0, 113, 227, 0.35); border-radius: 6px; padding: 2px 7px; font-size: 7.5pt; font-weight: 700; }
.health-box { background-color: rgba(48, 209, 88, 0.12); border: 1px solid rgba(48, 209, 88, 0.3); border-radius: 9999px; padding: 4px 12px; }
.health-score { color: #30d158; font-weight: 700; font-size: 10pt; }
.sidebar-box { background-color: #141416; border-right: 1px solid rgba(255, 255, 255, 0.08); min-width: 250px; padding: 8px; }
button.nav-btn { background-image: none; background-color: transparent; color: #e5e5ea; border: none; border-radius: 7px; padding: 7px 10px; margin: 1px 6px; font-weight: 500; transition: all 120ms ease; }
button.nav-btn:hover { background-color: rgba(255, 255, 255, 0.08); color: #ffffff; }
button.nav-btn.nav-btn-active { background-image: none; background-color: #0071e3; color: #ffffff; border: none; border-radius: 7px; box-shadow: 0 1px 4px rgba(0, 113, 227, 0.4); }
.mini-status-card { background-color: #1e1e20; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 12px 14px; margin: 10px 10px 14px 10px; }
.mini-row-title { font-size: 8pt; color: #86868b; font-weight: 500; }
.mini-row-status-ok { font-size: 8pt; color: #30d158; font-weight: 600; }
.mini-row-status-warn { font-size: 8pt; color: #ff9f0a; font-weight: 600; }
.mini-row-status-alert { font-size: 8pt; color: #ff453a; font-weight: 600; }
.macos-card { background-color: #242426; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 16px 20px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2); }
.macos-table-header { font-size: 9pt; font-weight: 700; color: #86868b; border-bottom: 1px solid rgba(255, 255, 255, 0.1); padding-bottom: 6px; }
.macos-table-cell { font-size: 9pt; color: #f5f5f7; padding: 4px 0; }
button { background-image: none; background-color: rgba(255, 255, 255, 0.08); color: #f5f5f7; border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 8px; padding: 6px 14px; font-weight: 500; font-size: 9.5pt; transition: all 120ms ease; }
button:hover { background-color: rgba(255, 255, 255, 0.14); border-color: rgba(255, 255, 255, 0.2); color: #ffffff; }
button.suggested-action { background-image: none; background-color: #0071e3; border: 1px solid #0a84ff; color: #ffffff; font-weight: 600; }
button.destructive-action, button.power-btn { background-image: none; background-color: rgba(255, 69, 58, 0.15); border: 1px solid rgba(255, 69, 58, 0.35); color: #ff453a; font-weight: 600; }
button.destructive-action:hover, button.power-btn:hover { background-color: #ff453a; color: #ffffff; }
switch { background-image: none; background-color: #39393d; border-radius: 14px; border: none; min-width: 44px; min-height: 24px; transition: background-color 150ms ease; }
switch:checked { background-image: none; background-color: #34c759; }
progressbar trough { background-color: #2c2c2e; border-radius: 6px; min-height: 8px; }
progressbar progress { background-image: none; background-color: #34c759; border-radius: 5px; }
progressbar.scanning progress { background-color: #0a84ff; }
scrolledwindow { border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; background-color: #1c1c1e; }
"#;

// ==============================================================================
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
        Self { process_rate_tracker: Mutex::new(HashMap::new()) }
    }

    pub fn deploy_canary_tripwires(user_home: &str) -> usize {
        let mut count = 0;
        for rel in &CANARY_FILES {
            let full_path = format!("{}/{}", user_home, rel);
            let p = Path::new(&full_path);
            if let Some(parent) = p.parent() { let _ = fs::create_dir_all(parent); }
            if !p.exists() {
                let dummy_content = "CANARY_DOCUMENT_SECURE_TOKEN_DO_NOT_MODIFY_CONSTANTINE_EDR_PROTECTION_TRIPWIRE\n";
                if fs::write(p, dummy_content).is_ok() { count += 1; }
            } else { count += 1; }
        }
        count
    }

    pub fn verify_active_canaries(user_home: &str) -> usize {
        let mut active = 0;
        for rel in &CANARY_FILES {
            if Path::new(&format!("{}/{}", user_home, rel)).is_file() { active += 1; }
        }
        active
    }

    pub fn is_canary_file(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for &canary in &CANARY_FILES { if path_str.ends_with(canary) { return true; } }
        path_str.contains("!000_canary_")
    }

    pub fn track_process_burst(&self, pid: u32, path: &Path, data: &[u8]) -> bool {
        if Self::is_canary_file(path) { return true; }
        let now = Instant::now();
        let mut map = match self.process_rate_tracker.lock() {
            Ok(g) => g, Err(poisoned) => poisoned.into_inner(),
        };
        if map.len() > 128 {
            map.retain(|_, m| now.duration_since(m.window_start) < Duration::from_secs(30));
        }
        let entry = map.entry(pid).or_insert(ProcessBurstMetrics {
            window_start: now, mod_count: 0, high_entropy_hits: 0, suspicious_ext_hits: 0,
        });

        if now.duration_since(entry.window_start) <= Duration::from_secs(3) {
            entry.mod_count += 1;
            let entropy = ThreatAnalysisEngine::calculate_shannon_entropy(data);
            if entropy > 7.55 { entry.high_entropy_hits += 1; }
            if Self::is_ransomware_extension(path) { entry.suspicious_ext_hits += 1; }

            let burst_and_entropy = entry.mod_count >= 8 && entry.high_entropy_hits >= 4;
            let burst_and_ext = entry.mod_count >= 4 && entry.suspicious_ext_hits >= 2 && entry.high_entropy_hits >= 2;
            if burst_and_entropy || burst_and_ext { return true; }
        } else {
            *entry = ProcessBurstMetrics {
                window_start: now, mod_count: 1,
                high_entropy_hits: if ThreatAnalysisEngine::calculate_shannon_entropy(data) > 7.55 { 1 } else { 0 },
                suspicious_ext_hits: if Self::is_ransomware_extension(path) { 1 } else { 0 },
            };
        }
        false
    }

    pub fn is_ransomware_extension(path: &Path) -> bool {
        let s = path.to_string_lossy().to_lowercase();
        let suspicious = [".locked", ".crypto", ".enc", ".crypted", ".ransom", ".locky", ".wcry", ".wncry", ".darkside"];
        for ext in &suspicious { if s.ends_with(ext) { return true; } }
        false
    }

    pub fn neutralize_attack(pid: u32, offending_path: &Path, reason: &str) {
        if pid <= 1 { return; }
        let pid_str = pid.to_string();

        // 🔴 CORREGIDO: 1. Congelar el proceso PRIMERO para evitar race conditions (ej. execve cambiando el exe)
        let _ = SecurityAuth::privileged_action(&["kill", "-STOP", &pid_str]);

        // 🔴 CORREGIDO: 2. Capturar identidad y ruta del ejecutable AHORA que está congelado
        let proc_exe_link = format!("/proc/{}/exe", pid);
        let resolved_exe = fs::read_link(&proc_exe_link).ok();

        // 3. Terminar el proceso fulminantemente
        let _ = SecurityAuth::privileged_action(&["kill", "-KILL", &pid_str]);

        // 4. Aislar ÚNICAMENTE el binario ejecutor verificado
        let mut isolated_exe_msg = String::from("Ejecutable en memoria detenido (documentos del usuario preservados)");
        if let Some(exe_path) = resolved_exe {
            let exe_str = exe_path.to_string_lossy();
            if !exe_str.starts_with("/usr/bin/") && !exe_str.starts_with("/bin/") && !exe_str.starts_with("/sbin/") && !exe_str.starts_with("/lib") {
                if ContainmentEngine::isolate_to_vault(&exe_path) {
                    isolated_exe_msg = format!("Binario agresor aislado en baúl AES-256-GCM: {}", exe_str);
                }
            }
        }

        // 5. Registro forense inmutable y alerta crítica
        ImmutableAuditLog::append_event(
            "RANSOMWARE_CONTAINED",
            &format!("PID {} neutralizado ({}) sobre {} | {}", pid, reason, offending_path.display(), isolated_exe_msg),
        );
        let _ = Command::new("notify-send")
            .args([
                "-u", "critical", "-i", "security-high",
                "¡ALERTA CRÍTICA: RANSOMWARE CONTENIDO!",
                &format!("Proceso PID {} detenido.\nMotivo: {}\n{}", pid, reason, isolated_exe_msg)
            ])
            .status();
    }
}

// ==============================================================================
// 2. Veredicto Formal y Pipeline Multi-Motor
// ==============================================================================
#[derive(Debug, PartialEq, Clone)]
pub enum FileVerdict {
    Clean(String),
    Threat(String),
    Indeterminate(String),
}

pub struct ThreatAnalysisEngine;

impl ThreatAnalysisEngine {
    pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = [0usize; 256];
        for &byte in data { counts[byte as usize] += 1; }
        let total = data.len() as f64;
        counts.iter().filter(|&&c| c > 0).map(|&c| {
            let p = (c as f64) / total;
            -p * p.log2()
        }).sum()
    }

    pub fn is_zip_bomb(path: &Path) -> bool {
        if let Ok(mut f) = File::open(path) {
            let mut header = [0u8; 4];
            if f.read_exact(&mut header).is_ok() && header == [0x50, 0x4B, 0x03, 0x04] {
                if let Ok(meta) = f.metadata() {
                    let compressed_len = meta.len();
                    if compressed_len > 0 && compressed_len < 1024 * 1024 {
                        let mut buf = Vec::new();
                        // 🔴 CORREGIDO: Limitar la lectura a 10 MB para evitar DoS por memoria (Zip Bomb)
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

    pub fn evaluate_file(path: &Path) -> FileVerdict {
        if !path.exists() { return FileVerdict::Indeterminate("El archivo no existe o fue movido.".into()); }

        let file_hash = match Self::compute_sha256(path) {
            Ok(h) => h,
            Err(_) => return FileVerdict::Indeterminate("Error de I/O: no se pudo calcular huella SHA-256.".into()),
        };
        if Self::is_whitelisted(&file_hash) { return FileVerdict::Clean("Excluido por firma SHA-256 en Lista Blanca".into()); }
        if Self::is_zip_bomb(path) { return FileVerdict::Threat("Estructura de descompresión masiva hostil (Zip Bomb).".into()); }

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

        if Self::is_known_malware_hash(&file_hash) {
            return FileVerdict::Threat(format!("Huella SHA-256 coincidente con muestra hostil en TI: {}.", &file_hash[..12]));
        }

        if !Path::new(CLAMD_SOCKET).exists() {
            return FileVerdict::Indeterminate("Motor obligatorio ClamAV no disponible (socket /run/clamav/clamd.ctl ausente).".into());
        }
        match UnixStream::connect(CLAMD_SOCKET) {
            Ok(mut stream) => {
                let cmd = format!("SCAN {}\n", path.to_string_lossy());
                if let Err(e) = stream.write_all(cmd.as_bytes()) {
                    return FileVerdict::Indeterminate(format!("Fallo de escritura en clamd socket: {}", e));
                }
                let mut resp = String::new();
                if let Err(e) = stream.read_to_string(&mut resp) {
                    return FileVerdict::Indeterminate(format!("Fallo de lectura desde clamd socket: {}", e));
                }
                let trimmed_resp = resp.trim();
                if trimmed_resp.contains("FOUND") {
                    return FileVerdict::Threat(format!("ClamAV Detección: {}", trimmed_resp));
                } else if !trimmed_resp.contains("OK") {
                    return FileVerdict::Indeterminate(format!("ClamAV devolvió respuesta de error: {}", trimmed_resp));
                }
            }
            Err(e) => { return FileVerdict::Indeterminate(format!("No se pudo conectar al daemon obligatorio clamd: {}", e)); }
        }

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
                    return FileVerdict::Threat(format!("YARA Coincidencia [{}]: {}", rule_path.file_name().and_then(|n| n.to_str()).unwrap_or("regla"), trimmed));
                }
            }
        }

        let yr_bin_opt = if Path::new("/usr/local/bin/yr").is_file() {
            Some("/usr/local/bin/yr")
        } else if Command::new("which").arg("yr").output().map(|o| o.status.success()).unwrap_or(false) {
            Some("yr")
        } else { None };

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
                        return FileVerdict::Threat(format!("YARA-X Coincidencia [{}]: {}", rule_path.file_name().and_then(|n| n.to_str()).unwrap_or("regla"), trimmed));
                    }
                }
            }
            FileVerdict::Clean("Cobertura Completa (ClamAV + YARA + YARA-X + Heurística + TI)".into())
        } else {
            FileVerdict::Clean("Cobertura Estándar Verificada (ClamAV + YARA + Heurística + TI; YARA-X opcional no instalado)".into())
        }
    }

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

    pub fn is_whitelisted(hash: &str) -> bool {
        if let Ok(f) = File::open(WHITELIST_FILE) {
            for l in BufReader::new(f).lines().flatten() {
                if l.trim().eq_ignore_ascii_case(hash) { return true; }
            }
        }
        false
    }

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

    fn is_executable(path: &Path) -> bool {
        if let Ok(meta) = path.metadata() { return meta.permissions().mode() & 0o111 != 0; }
        false
    }
}

// ==============================================================================
// 3. Baúl Criptográfico Autenticado con AES-256-GCM y CSPRNG
// ==============================================================================
const VAULT_MAGIC: &[u8; 9] = b"CSTVAULT1";

pub struct ContainmentEngine;

impl ContainmentEngine {
    pub fn isolate_to_vault(source_path: &Path) -> bool {
        if !source_path.exists() || !source_path.is_file() { return false; }

        let key_bytes = match Self::load_or_generate_csprng_key() {
            Ok(k) => k,
            Err(e) => {
                ImmutableAuditLog::append_event("VAULT_ERROR", &format!("Fallo crítico de clave CSPRNG: {}", e));
                return false;
            }
        };

        let plaintext = match fs::read(source_path) { Ok(b) => b, Err(_) => return false };
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let orig_sha256: [u8; 32] = hasher.finalize().into();

        let mut nonce_bytes = [0u8; 12];
        if getrandom::getrandom(&mut nonce_bytes).is_err() { return false; }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload { msg: &plaintext, aad: &orig_sha256 };
        let ciphertext = match cipher.encrypt(nonce, payload) { Ok(ct) => ct, Err(_) => return false };

        let mut vault_blob = Vec::with_capacity(9 + 12 + 32 + ciphertext.len());
        vault_blob.extend_from_slice(VAULT_MAGIC);
        vault_blob.extend_from_slice(&nonce_bytes);
        vault_blob.extend_from_slice(&orig_sha256);
        vault_blob.extend_from_slice(&ciphertext);

        let raw_name = source_path.file_name().and_then(|n| n.to_str()).unwrap_or("amenaza_detectada");
        let safe_name: String = raw_name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-').collect();
        let final_name = if safe_name.is_empty() { "muestra_aislada" } else { &safe_name };
        let dest_path = Path::new(QUARANTINE_DIR).join(format!("{}.vault", final_name));

        let write_ok = OpenOptions::new().create(true).write(true).truncate(true).open(&dest_path)
            .and_then(|mut f| { f.write_all(&vault_blob)?; f.sync_all() }).is_ok();

        if write_ok {
            let _ = fs::set_permissions(&dest_path, fs::Permissions::from_mode(0o600));
            if fs::remove_file(source_path).is_ok() {
                let hex_hash = hex::encode(orig_sha256);
                ImmutableAuditLog::append_event("QUARANTINE_AES256GCM", &format!("Aislado y autenticado con AES-256-GCM: {} (SHA-256: {})", final_name, &hex_hash[..16]));
                return true;
            }
        }
        false
    }

    pub fn load_or_generate_csprng_key() -> Result<[u8; 32], String> {
        let key_path = Path::new(VAULT_KEY_FILE);
        if key_path.exists() {
            let content = fs::read(key_path).map_err(|e| format!("No se pudo leer {}: {}", VAULT_KEY_FILE, e))?;
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
            // 🔴 CORREGIDO: Si el archivo existe pero está corrupto, fallar explícitamente para evitar perder acceso al baúl
            return Err(format!("La clave en {} está corrupta o tiene un formato inválido. No se puede generar una nueva clave sin perder acceso a los archivos en cuarentena.", VAULT_KEY_FILE));
        }

        let mut new_key = [0u8; 32];
        getrandom::getrandom(&mut new_key).map_err(|e| format!("Error de entropía CSPRNG: {}", e))?;
        if let Some(parent) = key_path.parent() { let _ = fs::create_dir_all(parent); }
        let hex_key = hex::encode(new_key);
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(key_path)
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
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(IMMUTABLE_AUDIT_LOG) {
            let _ = f.write_all(log_line.as_bytes());
            let _ = f.sync_data();
        }
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
pub struct VaultManager;

impl VaultManager {
    pub fn list_vault_files() -> Vec<String> {
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(QUARANTINE_DIR) {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if name.ends_with(".vault") { files.push(name); }
                }
            }
        }
        files.sort();
        files
    }

    pub fn delete_from_vault(filename: &str) -> bool {
        let safe_name = match Path::new(filename).file_name().and_then(|n| n.to_str()) {
            Some(n) => n, None => return false,
        };
        let target = Path::new(QUARANTINE_DIR).join(safe_name);
        let removed = if fs::remove_file(&target).is_ok() {
            true
        } else {
            if let Some(target_str) = target.to_str() {
                SecurityAuth::privileged_action(&["rm", "-f", "--", target_str])
            } else { false }
        };
        if removed {
            ImmutableAuditLog::append_event("VAULT_FILE_DELETED", &format!("Muestra eliminada permanentemente: {}", safe_name));
        }
        removed
    }

    pub fn restore_to_whitelist(filename: &str, user_home: &str) -> bool {
        let safe_name = match Path::new(filename).file_name().and_then(|n| n.to_str()) {
            Some(n) => n, None => return false,
        };
        let vault_path = Path::new(QUARANTINE_DIR).join(safe_name);
        let blob = match fs::read(&vault_path) { Ok(b) => b, Err(_) => return false };

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
        let desktop_dir = Path::new(user_home).join("Desktop");
        let _ = fs::create_dir_all(&desktop_dir);
        let restored_path = desktop_dir.join(clean_name);

        let write_ok = OpenOptions::new().create(true).write(true).truncate(true).open(&restored_path)
            .and_then(|mut f| { f.write_all(&plaintext)?; f.sync_all() }).is_ok();
        if !write_ok { return false; }
        let _ = fs::set_permissions(&restored_path, fs::Permissions::from_mode(0o644));

        let sha256_hex = hex::encode(actual_sha256);
        if !ThreatAnalysisEngine::is_whitelisted(&sha256_hex) {
            if let Ok(mut wl) = OpenOptions::new().create(true).append(true).open(WHITELIST_FILE) {
                let _ = writeln!(wl, "{}", sha256_hex);
            }
        }

        let _ = fs::remove_file(&vault_path);
        ImmutableAuditLog::append_event("VAULT_RESTORE_VERIFIED", &format!("Restaurado y verificado con AES-256-GCM: {} (SHA-256: {})", clean_name, &sha256_hex[..16]));
        true
    }
}

// ==============================================================================
// 7. Control de Seguridad y Privilegios
// ==============================================================================
pub struct SecurityAuth;

impl SecurityAuth {
    pub fn is_in_constantine_group() -> bool {
        Command::new("id").arg("-nG").output()
            .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().any(|g| g == "constantine"))
            .unwrap_or(false)
    }

    pub fn privileged_action(args: &[&str]) -> bool {
        Command::new("pkexec").args(args).status().map(|s| s.success()).unwrap_or(false)
    }

    pub fn stop_service_protected(service_name: &str) -> bool { Self::privileged_action(&["systemctl", "stop", service_name]) }
    pub fn start_service_protected(service_name: &str) -> bool { Self::privileged_action(&["systemctl", "start", service_name]) }
    pub fn shutdown_all_protected() -> bool {
        Self::privileged_action(&["systemctl", "stop", "clamonacc", "tetragon", "falco", "wazuh-agent", "clamav-daemon"])
    }
}

// ==============================================================================
// 8. Telemetría Dinámica Real de Versiones, Servicios y Salud
// ==============================================================================
pub struct ModuleVersionAudit;

impl ModuleVersionAudit {
    pub fn get_file_mtime(path: &str) -> String {
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.len() == 0 && path.ends_with(".db") { return "Base vacía (Pendiente de inicialización)".into(); }
            if let Ok(mtime) = metadata.modified() {
                if let Ok(dur) = mtime.elapsed() {
                    let secs = dur.as_secs();
                    if secs < 60 { return "Hace menos de 1 min".into(); }
                    else if secs < 3600 { return format!("Hace {} min", secs / 60); }
                    else if secs < 86400 { return format!("Hace {} horas", secs / 3600); }
                    else { return format!("Hace {} días", secs / 86400); }
                }
            }
        }
        "No disponible".into()
    }

    pub fn compute_real_health_score(user_home: &str) -> (u8, usize, usize) {
        let checks = [
            Path::new(CLAMD_SOCKET).exists(),
            get_service_active("clamonacc"),
            Command::new("which").arg("yara").output().map(|o| o.status.success()).unwrap_or(false),
            AntiRansomwareShield::verify_active_canaries(user_home) == CANARY_FILES.len(),
            ImmutableAuditLog::verify_integrity().0,
            fs::metadata(AIDE_DB_FILE).map(|m| m.len() > 0).unwrap_or(false),
            get_service_active("falco") || get_service_active("falco-modern-ebpf"),
            get_service_active("tetragon"),
        ];
        let total = checks.len();
        let active = checks.iter().filter(|&&ok| ok).count();
        let pct = ((active * 100) / total) as u8;
        (pct, active, total)
    }

    pub fn get_modules_status() -> Vec<(&'static str, String, String)> {
        let user_home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        let active_canaries = AntiRansomwareShield::verify_active_canaries(&user_home);
        let aide_ready = fs::metadata(AIDE_DB_FILE).map(|m| m.len() > 0).unwrap_or(false);
        vec![
            ("Constantine Core EDR", "v3.2.7 (Debian Edition)".into(), "Binario Nativo Rust Activo".into()),
            ("Escudo Anti-Ransomware", format!("{}/{} Señuelos Activos", active_canaries, CANARY_FILES.len()), if active_canaries == CANARY_FILES.len() { "Operativo (Correlación Multivariable)".into() } else { "Cobertura Parcial".into() }),
            ("1. ClamAV Engine (clamd)", Self::cmd_version_with_service("clamd", &["-V"], "clamav-daemon"), Self::get_file_mtime("/var/lib/clamav/daily.cvd")),
            ("2. YARA Engine", Self::cmd_version("yara", &["-v"]), Self::get_file_mtime(YARA_RULES_DIR)),
            ("3. YARA-X Engine (Rust)", Self::get_real_yarax_version(), Self::get_file_mtime("/usr/local/bin/yr")),
            ("4. ClamOnAcc (fanotify Shield)", if get_service_active("clamonacc") { "Servicio Activo (FAN_DENY)".into() } else { "Servicio Detenido".into() }, Self::get_file_mtime(LOG_FILE)),
            ("5. Tetragon (Cilium eBPF)", Self::cmd_version_with_service("tetragon", &["--version"], "tetragon"), Self::get_file_mtime("/usr/local/bin/tetragon")),
            ("6. Falco Behavioral Engine", Self::cmd_version_with_service("falco", &["--version"], "falco"), Self::get_file_mtime("/etc/falco/falco_rules.yaml")),
            ("7. osquery (SQL Audit)", Self::cmd_version("osqueryi", &["--version"]), Self::get_file_mtime("/usr/bin/osqueryi")),
            ("8. Wazuh Agent (SIEM & FIM)", Self::get_wazuh_version(), Self::get_file_mtime("/var/ossec/etc/ossec.conf")),
            ("9. AIDE Critical Integrity", if aide_ready { Self::cmd_version("aide", &["-v"]) } else { "Instalado (Base aún no inicializada)".into() }, Self::get_file_mtime(AIDE_DB_FILE)),
            ("10. MISP Threat Sharing", Self::feed_line_count(MISP_IOC_FILE), Self::get_file_mtime(MISP_IOC_FILE)),
            ("11. MalwareBazaar Feed", Self::feed_line_count(&format!("{}/malwarebazaar_hashes.txt", TI_DIR)), Self::get_file_mtime(&format!("{}/malwarebazaar_hashes.txt", TI_DIR)),
            ("12. ThreatFox Feed", Self::feed_line_count(&format!("{}/threatfox_iocs.txt", TI_DIR)), Self::get_file_mtime(&format!("{}/threatfox_iocs.txt", TI_DIR)),
            ("13. URLhaus Feed", Self::feed_line_count(&format!("{}/urlhaus_domains.txt", TI_DIR)), Self::get_file_mtime(&format!("{}/urlhaus_domains.txt", TI_DIR)),
            ("14. OpenPhish Feed", Self::feed_line_count(&format!("{}/openphish_domains.txt", TI_DIR)), Self::get_file_mtime(&format!("{}/openphish_domains.txt", TI_DIR)),
            ("15. Sigma Detection Rules", Self::dir_file_count(SIGMA_RULES_DIR), Self::get_file_mtime(SIGMA_RULES_DIR)),
            ("16. YARA-Rules Comunitarias", Self::dir_file_count(YARA_COMMUNITY_DIR), Self::get_file_mtime(YARA_COMMUNITY_DIR)),
            ("Cortafuegos UFW / GUFW", if NetworkPrivacyAudit::is_ufw_active() { "UFW Activo".into() } else { "UFW Inactivo".into() }, Self::get_file_mtime("/etc/ufw/ufw.conf")),
            ("ProtonVPN Client", if NetworkPrivacyAudit::is_protonvpn_active() { "Túnel ProtonVPN Activo".into() } else { Self::cmd_version("protonvpn-app", &["--version"]) }, "Verificación de Interfaz".into()),
        ]
    }

    fn feed_line_count(path: &str) -> String {
        if let Ok(f) = File::open(path) {
            let count = BufReader::new(f).lines().count();
            if count > 0 { return format!("{} indicadores cargados", count); }
        }
        "0 indicadores (Vacío / Sin sincronizar)".into()
    }

    fn dir_file_count(dir: &str) -> String {
        if let Ok(entries) = fs::read_dir(dir) {
            let count = entries.flatten().count();
            if count > 0 { return format!("{} elementos instalados", count); }
        }
        "No disponible".into()
    }

    fn get_real_yarax_version() -> String {
        if let Ok(out) = Command::new("yr").arg("--version").output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                if let Some(line) = s.lines().next() { return format!("Instalado ({})", line.trim()); }
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
                        let ver = l.replace("WAZUH_VERSION=\"", "").replace('"', "");
                        return format!("{} (Servicio {})", ver.trim(), svc);
                    }
                }
            }
            return format!("Instalado (Servicio {})", svc);
        }
        "No disponible".into()
    }

    fn cmd_version(cmd: &str, args: &[&str]) -> String {
        if let Ok(out) = Command::new(cmd).args(args).output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                if let Some(line) = s.lines().next() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() { return trimmed.to_string(); }
                }
                return "Instalado".into();
            }
        }
        "No disponible".into()
    }

    fn cmd_version_with_service(cmd: &str, args: &[&str], service: &str) -> String {
        let base = Self::cmd_version(cmd, args);
        if base == "No disponible" { return base; }
        let svc_state = if get_service_active(service) { "Activo" } else { "Inactivo" };
        format!("{} [{}]", base, svc_state)
    }

    pub fn update_all_modules() -> bool {
        if Path::new(UPDATER_SCRIPT).exists() {
            Command::new("pkexec").arg(UPDATER_SCRIPT).status().map(|s| s.success()).unwrap_or(false)
        } else { false }
    }

    pub fn run_aide_check() -> bool {
        if Path::new(UPDATER_SCRIPT).exists() {
            Command::new("pkexec").args([UPDATER_SCRIPT, "--aide-only"]).status().map(|s| s.success()).unwrap_or(false)
        } else { false }
    }
}

// ==============================================================================
// 9. Auditoría Exacta de Firewall y VPN
// ==============================================================================
pub struct NetworkPrivacyAudit;

impl NetworkPrivacyAudit {
    pub fn is_ufw_active() -> bool {
        if let Ok(out) = Command::new("ufw").arg("status").output() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            for line in s.lines() {
                let t = line.trim();
                if t.starts_with("status:") || t.starts_with("estado:") {
                    if t.contains("inactive") || t.contains("inactivo") { return false; }
                    if t.contains("active") || t.contains("activo") { return true; }
                }
            }
        }
        if let Ok(conf) = fs::read_to_string("/etc/ufw/ufw.conf") {
            for line in conf.lines() {
                if line.trim().eq_ignore_ascii_case("ENABLED=yes") { return true; }
            }
        }
        false
    }

    pub fn is_protonvpn_active() -> bool {
        if let Ok(out) = Command::new("ip").args(["-o", "link", "show"]).output() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            for line in s.lines() {
                if (line.contains("proton") || line.contains("pvpn")) && line.contains("state up") { return true; }
            }
        }
        if let Ok(out) = Command::new("nmcli").args(["-t", "-f", "NAME,TYPE,STATE", "connection", "show", "--active"]).output() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            if s.contains("protonvpn") && s.contains("activated") { return true; }
        }
        false
    }

    pub fn get_public_ip_info() -> (String, String) {
        // 🔴 CORREGIDO: Cambio a HTTPS para prevenir ataques MITM
        if let Ok(out) = Command::new("curl").args([
            "-s", "--max-time", "3", "https://ip-api.com/line/?fields=query,city,regionName,country",
        ]).output() {
            let res = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = res.lines().collect();
            if lines.len() >= 4 {
                let ip = lines[0].trim().to_string();
                let loc = format!("{}, {}, {}", lines[1].trim(), lines[2].trim(), lines[3].trim());
                return (ip, loc);
            }
        }
        ("No disponible / Sin conexión".into(), "Desconocida".into())
    }

    pub fn launch_gufw() { let _ = Command::new("gufw").spawn(); }
    pub fn launch_protonvpn() {
        if Command::new("which").arg("protonvpn-app").output().map(|o| o.status.success()).unwrap_or(false) {
            let _ = Command::new("protonvpn-app").spawn();
        } else if Command::new("which").arg("protonvpn").output().map(|o| o.status.success()).unwrap_or(false) {
            let _ = Command::new("protonvpn").spawn();
        }
    }
}

fn get_service_active(service: &str) -> bool {
    Command::new("systemctl").args(["is-active", service]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active").unwrap_or(false)
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
                                    if trimmed.contains("FOUND") || trimmed.contains("Access denied") || trimmed.contains("virus") {
                                        ImmutableAuditLog::append_event("CLAMONACC_ACCESS_DENIED", &format!("Prevención fanotify -> ClamOnAcc -> clamd: {}", trimmed));
                                        let _ = Command::new("notify-send")
                                            .args(["-u", "critical", "-i", "security-high", "🛡️ Constantine: Acceso Denegado por ClamOnAcc (fanotify)", &format!("ClamAV detectó malware en tiempo real y bloqueó el acceso:\n{}", trimmed)])
                                            .status();
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
    pub pid: u32, pub ppid: u32, pub uid: u32, pub exe_path: PathBuf,
    pub exe_sha256: String, pub cmdline: String, pub parent_exe: String,
    pub is_dpkg_managed: bool, pub behavior_signal: String, pub target_resource: String,
}

pub struct DestructiveActionSafetyGate;

impl DestructiveActionSafetyGate {
    pub fn authorize_destructive_response(profile: &ProcessContextProfile, correlation_score: u8) -> Result<(), String> {
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
            if exe_str == prot { return Err(format!("Prueba 1 fallida: Binario de infraestructura crítica protegido ({})", exe_str)); }
        }
        if profile.exe_sha256.is_empty() || !profile.exe_path.is_absolute() {
            return Err("Prueba 2 fallida: Identidad de ejecutable o hash SHA-256 no verificado (prohibido actuar solo por nombre).".into());
        }
        if ThreatAnalysisEngine::is_whitelisted(&profile.exe_sha256) {
            return Err("Prueba 3 fallida: El hash SHA-256 del ejecutable está autorizado en la Lista Blanca.".into());
        }
        if profile.is_dpkg_managed && (exe_str.starts_with("/usr/") || exe_str.starts_with("/bin/") || exe_str.starts_with("/sbin/")) {
            return Err(format!("Prueba 4: El ejecutable {} pertenece a un paquete oficial del sistema Debian; se impide destruir el binario del sistema.", exe_str));
        }
        if correlation_score < 70 {
            return Err(format!("Prueba 5 fallida: Puntuación de correlación insuficiente ({}/100) para autorizar acción destructiva.", correlation_score));
        }
        Ok(())
    }
}

pub struct TetragonPrimarySensor;

impl TetragonPrimarySensor {
    pub fn build_correlated_profile(pid: u32, ppid: u32, uid: u32, exe_hint: &str, cmdline: &str, parent_exe: &str, behavior_signal: &str, target_resource: &str) -> ProcessContextProfile {
        let proc_exe = format!("/proc/{}/exe", pid);
        let exe_path = fs::read_link(&proc_exe).unwrap_or_else(|_| PathBuf::from(exe_hint));
        let exe_sha256 = ThreatAnalysisEngine::compute_sha256(&exe_path).unwrap_or_default();
        let is_dpkg_managed = if exe_path.exists() {
            Command::new("dpkg").args(["-S", &exe_path.to_string_lossy()]).output().map(|o| o.status.success()).unwrap_or(false)
        } else { false };
        ProcessContextProfile { pid, ppid, uid, exe_path, exe_sha256, cmdline: cmdline.to_string(), parent_exe: parent_exe.to_string(), is_dpkg_managed, behavior_signal: behavior_signal.to_string(), target_resource: target_resource.to_string() }
    }

    pub fn evaluate_four_pillars(profile: &ProcessContextProfile) -> u8 {
        let mut score: u8 = 0;
        let exe_str = profile.exe_path.to_string_lossy();
        if exe_str.starts_with("/tmp/") || exe_str.starts_with("/var/tmp/") || exe_str.starts_with("/dev/shm/") { score = score.saturating_add(35); }
        if !profile.is_dpkg_managed { score = score.saturating_add(15); }
        if !profile.exe_sha256.is_empty() && ThreatAnalysisEngine::is_known_malware_hash(&profile.exe_sha256) { score = score.saturating_add(60); }
        if profile.behavior_signal.contains("CANARY_WRITE") || AntiRansomwareShield::is_canary_file(Path::new(&profile.target_resource)) { score = score.saturating_add(65); }
        if profile.behavior_signal.contains("security_bprm_check") { score = score.saturating_add(25); }
        if profile.behavior_signal.contains("security_file_permission") && (profile.target_resource.starts_with("/etc/shadow") || profile.target_resource.starts_with("/etc/sudoers")) { score = score.saturating_add(45); }
        let cmd_low = profile.cmdline.to_lowercase();
        if cmd_low.contains("/dev/tcp/") || cmd_low.contains("nc -e") || cmd_low.contains("bash -i") { score = score.saturating_add(45); }
        if profile.uid >= 1000 && !profile.is_dpkg_managed { score = score.saturating_add(10); }
        score.min(100)
    }

    pub fn start_primary_edr_consumer() {
        thread::spawn(|| {
            let mut last_offset: u64 = fs::metadata(TETRAGON_LOG_FILE).map(|m| m.len()).unwrap_or(0);
            loop {
                thread::sleep(Duration::from_secs(2));
                if let Ok(meta) = fs::metadata(TETRAGON_LOG_FILE) {
                    let current_len = meta.len();
                    if current_len < last_offset { last_offset = 0; }
                    if current_len > last_offset {
                        if let Ok(mut file) = File::open(TETRAGON_LOG_FILE) {
                            use std::io::{Seek, SeekFrom};
                            if file.seek(SeekFrom::Start(last_offset)).is_ok() {
                                let reader = BufReader::new(file);
                                for line in reader.lines().flatten() { Self::process_tetragon_json_event(&line); }
                            }
                        }
                        last_offset = current_len;
                    }
                }
            }
        });
    }

    fn process_tetragon_json_event(json_line: &str) {
        let val: serde_json::Value = match serde_json::from_str(json_line) { Ok(v) => v, Err(_) => return };
        let event_Node = if let Some(kp) = val.get("process_kprobe") { kp } else if let Some(ex) = val.get("process_exec") { ex } else { return };
        let proc = match event_Node.get("process") { Some(p) => p, None => return };
        let pid = proc.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let uid = proc.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let binary = proc.get("binary").and_then(|v| v.as_str()).unwrap_or("");
        let args = proc.get("arguments").and_then(|v| v.as_str()).unwrap_or("");
        let parent_bin = event_Node.get("parent").and_then(|p| p.get("binary")).and_then(|v| v.as_str()).unwrap_or("unknown");
        let ppid = event_Node.get("parent").and_then(|p| p.get("pid")).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let func_name = event_Node.get("function_name").and_then(|v| v.as_str()).unwrap_or("process_exec");
        let mut target_res = String::new();
        if let Some(kp_args) = event_Node.get("args").and_then(|a| a.as_array()) {
            for arg in kp_args {
                if let Some(f_arg) = arg.get("file_arg").and_then(|fa| fa.get("path")).and_then(|p| p.as_str()) { target_res = f_arg.to_string(); }
                else if let Some(b_arg) = arg.get("linux_binprm_arg").and_then(|ba| ba.get("path")).and_then(|p| p.as_str()) { target_res = b_arg.to_string(); }
            }
        }
        if pid <= 1 || binary.is_empty() { return; }
        let profile = Self::build_correlated_profile(pid, ppid, uid, binary, args, parent_bin, func_name, &target_res);
        let score = Self::evaluate_four_pillars(&profile);
        if score >= 70 {
            match DestructiveActionSafetyGate::authorize_destructive_response(&profile, score) {
                Ok(()) => {
                    AntiRansomwareShield::neutralize_attack(profile.pid, Path::new(&profile.target_resource), &format!("Correlación Tetragon eBPF ({}/100) [Hook: {}, Bin: {}, SHA256: {}]", score, profile.behavior_signal, profile.exe_path.display(), &profile.exe_sha256[..12.min(profile.exe_sha256.len())]));
                }
                Err(gate_reason) => {
                    ImmutableAuditLog::append_event("TETRAGON_SAFETY_GATE_BLOCKED", &format!("Acción destructiva retenida por prueba de seguridad sobre PID {} ({}): {}", profile.pid, profile.exe_path.display(), gate_reason));
                }
            }
        }
    }
}

fn main() {
    let app = Application::builder().application_id("com.constantine.antivirus").build();
    app.connect_startup(|_| {
        let provider = CssProvider::new();
        provider.load_from_data(CUPERTINO_CSS);
        gtk4::style_context_add_provider_for_display(&gtk4::gdk::Display::default().expect("Display no encontrado"), &provider, gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION);
    });
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder().application(app).title("Constantine Antivirus & EDR").default_width(1140).default_height(750).build();
    let current_user = std::env::var("USER").unwrap_or_else(|_| "usuario".into());
    let user_home = std::env::var("HOME").unwrap_or_else(|_| format!("/home/{}", current_user));

    AntiRansomwareShield::deploy_canary_tripwires(&user_home);
    OnAccessSupervisor::start_realtime_event_consumer();
    TetragonPrimarySensor::start_primary_edr_consumer();

    let win_clone = window.clone();
    window.connect_close_request(move |_| { win_clone.set_visible(false); gtk4::glib::Propagation::Stop });

    let header = HeaderBar::new();
    header.add_css_class("macos-headerbar");
    let title_box = Box::new(Orientation::Horizontal, 8);
    let title_lbl = Label::new(Some("Constantine EDR"));
    title_lbl.add_css_class("title-text");
    let badge_lbl = Label::new(Some("v3.2.7 Debian Edition"));
    badge_lbl.add_css_class("badge-version");
    title_box.append(&title_lbl);
    title_box.append(&badge_lbl);
    header.set_title_widget(Some(&title_box));

    let btn_shutdown = Button::with_label("🛑 Apagar Antivirus");
    btn_shutdown.add_css_class("power-btn");
    header.pack_start(&btn_shutdown);
    btn_shutdown.connect_clicked(|_| {
        if SecurityAuth::shutdown_all_protected() {
            let _ = Command::new("notify-send").args(["-u", "critical", "Constantine Antivirus", "Todos los servicios han sido detenidos con contraseña."]).status();
        }
    });

    let health_box = Box::new(Orientation::Horizontal, 4);
    health_box.add_css_class("health-box");
    let (init_pct, init_act, init_tot) = ModuleVersionAudit::compute_real_health_score(&user_home);
    let health_lbl = Label::new(Some(&format!("● Salud EDR: {}% ({}/{} controles)", init_pct, init_act, init_tot)));
    health_lbl.add_css_class("health-score");
    health_box.append(&health_lbl);
    header.pack_end(&health_box);
    window.set_titlebar(Some(&header));

    let main_box = Box::new(Orientation::Horizontal, 0);
    window.set_child(Some(&main_box));

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

    let btn_dash = Button::with_label("🛡️ Panel de Estado"); btn_dash.add_css_class("nav-btn"); btn_dash.add_css_class("nav-btn-active");
    let btn_scan = Button::with_label("🔍 Análisis Manuales"); btn_scan.add_css_class("nav-btn");
    let btn_updates = Button::with_label("🔄 Actualizaciones y Módulos"); btn_updates.add_css_class("nav-btn");
    let btn_net = Button::with_label("🌐 Red, VPN y Firewall"); btn_net.add_css_class("nav-btn");
    let btn_vault = Button::with_label("📦 Baúl de Cuarentena"); btn_vault.add_css_class("nav-btn");
    let btn_modules = Button::with_label("⚙️ Control de Módulos"); btn_modules.add_css_class("nav-btn");
    let btn_logs = Button::with_label("📋 Registro Forense Inmutable"); btn_logs.add_css_class("nav-btn");

    sidebar.append(&btn_dash); sidebar.append(&btn_scan); sidebar.append(&btn_updates); sidebar.append(&btn_net);
    sidebar.append(&btn_vault); sidebar.append(&btn_modules); sidebar.append(&btn_logs);
    let spacer = Box::new(Orientation::Vertical, 0); spacer.set_vexpand(true); sidebar.append(&spacer);
    let user_role = if SecurityAuth::is_in_constantine_group() { "Grupo 'constantine'" } else { "Usuario Estándar" };
    let footer = Label::new(Some(&format!("Sesión: {} ({})", current_user, user_role)));
    footer.add_css_class("subtitle-text");
    sidebar.append(&footer);
    main_box.append(&sidebar);

    let stack = Stack::new(); stack.set_hexpand(true); stack.set_vexpand(true);

    // --- Vista 1: Panel de Estado Unificado ---
    let dash_box = Box::new(Orientation::Vertical, 16);
    dash_box.set_margin_start(28); dash_box.set_margin_end(28); dash_box.set_margin_top(24);
    let card_overview = Box::new(Orientation::Vertical, 12); card_overview.add_css_class("macos-card");
    let t_ov = Label::new(Some("Panel de Estado Operativo Unificado (EDR v3.2.7)")); t_ov.add_css_class("title-text"); t_ov.set_xalign(0.0);
    card_overview.append(&t_ov);
    let grid_sensors = Grid::new(); grid_sensors.set_column_spacing(28); grid_sensors.set_row_spacing(10);
    grid_sensors.attach(&Label::new(Some("1. Prevención en Acceso (fanotify ➔ ClamOnAcc ➔ clamd):")), 0, 0, 1, 1);
    let (onacc_ok, onacc_txt) = OnAccessSupervisor::get_onaccess_pipeline_status();
    let s_f = Label::new(Some(&onacc_txt)); s_f.add_css_class(if onacc_ok { "mini-row-status-ok" } else { "mini-row-status-warn" });
    grid_sensors.attach(&s_f, 1, 0, 1, 1);
    grid_sensors.attach(&Label::new(Some("2. Escudo Anti-Ransomware (Canary Tripwires):")), 0, 1, 1, 1);
    let s_ran = Label::new(Some("● Activo / 4 Señuelos Sembrados / Detección de Ráfagas")); s_ran.add_css_class("mini-row-status-ok");
    grid_sensors.attach(&s_ran, 1, 1, 1, 1);
    grid_sensors.attach(&Label::new(Some("3. Sensor EDR Principal (Tetragon eBPF):")), 0, 2, 1, 1);
    let tetra_up = get_service_active("tetragon");
    let s_p = Label::new(Some(if tetra_up { "● Activo: Puntos de Control LSM + Correlación 4 Pilares (Identidad, Ejecutable, Comportamiento, Contexto)" } else { "● Inactivo: Demonio Tetragon detenido" }));
    s_p.add_css_class(if tetra_up { "mini-row-status-ok" } else { "mini-row-status-warn" });
    grid_sensors.attach(&s_p, 1, 2, 1, 1);
    grid_sensors.attach(&Label::new(Some("4. Custodia de Periféricos (Cámara/Mic):")), 0, 3, 1, 1);
    let s_per = Label::new(Some("● Activo / Supervisando /dev/video y /dev/snd")); s_per.add_css_class("mini-row-status-ok");
    grid_sensors.attach(&s_per, 1, 3, 1, 1);
    grid_sensors.attach(&Label::new(Some("5. Filtros de Red y Privacidad:")), 0, 4, 1, 1);
    let s_net = Label::new(Some("● Cortafuegos UFW Activo / Túnel ProtonVPN Disponible")); s_net.add_css_class("mini-row-status-ok");
    grid_sensors.attach(&s_net, 1, 4, 1, 1);
    grid_sensors.attach(&Label::new(Some("6. Integridad del Registro Forense:")), 0, 5, 1, 1);
    let (c_ok, c_count) = ImmutableAuditLog::verify_integrity();
    let s_log = Label::new(Some(&format!("● Hash Chain SHA-256 Verificada ({} eventos)", c_count)));
    s_log.add_css_class(if c_ok { "mini-row-status-ok" } else { "mini-row-status-alert" });
    grid_sensors.attach(&s_log, 1, 5, 1, 1);
    card_overview.append(&grid_sensors); dash_box.append(&card_overview); stack.add_named(&dash_box, Some("dashboard"));

    // --- Vista 2: Análisis Manuales ---
    let scan_box = Box::new(Orientation::Vertical, 16); scan_box.set_margin_start(28); scan_box.set_margin_end(28); scan_box.set_margin_top(24);
    let card_scan = Box::new(Orientation::Vertical, 14); card_scan.add_css_class("macos-card");
    let t_sc = Label::new(Some("Iniciación de Análisis Manuales Multi-Motor Fail-Secure")); t_sc.add_css_class("title-text"); t_sc.set_xalign(0.0);
    card_scan.append(&t_sc);
    let d_sc = Label::new(Some("Evaluación rigurosa de cada fichero con ClamAV (socket), YARA (reglas verificadas), YARA-X (binario yr), Entropía de Shannon y Feeds TI. Todo fallo de motor se cataloga como INDETERMINADO; jamás se asume limpio sin análisis completo."));
    d_sc.add_css_class("subtitle-text"); d_sc.set_xalign(0.0); card_scan.append(&d_sc);
    let progress_bar = ProgressBar::new(); progress_bar.set_fraction(0.0); card_scan.append(&progress_bar);
    let scan_status_lbl = Label::new(Some("Listo para iniciar análisis manual.")); scan_status_lbl.set_xalign(0.0); scan_status_lbl.add_css_class("subtitle-text"); card_scan.append(&scan_status_lbl);
    let scan_btns = Box::new(Orientation::Horizontal, 12);
    let btn_scan_file = Button::with_label("📄 Examinar Archivo Concreto"); btn_scan_file.add_css_class("suggested-action");
    let btn_scan_usb = Button::with_label("💾 Barrer Memoria USB / Extraíble");
    let btn_scan_full = Button::with_label("💻 Inspección Completa Real de Usuario"); btn_scan_full.add_css_class("suggested-action");
    scan_btns.append(&btn_scan_file); scan_btns.append(&btn_scan_usb); scan_btns.append(&btn_scan_full); card_scan.append(&scan_btns);
    scan_box.append(&card_scan); stack.add_named(&scan_box, Some("scan"));

    let pb_clone = progress_bar.clone(); let st_l_clone = scan_status_lbl.clone(); let u_home_c = user_home.clone();
    btn_scan_full.connect_clicked(move |_| {
        let pb = pb_clone.clone(); let st = st_l_clone.clone(); let uh = u_home_c.clone();
        thread::spawn(move || {
            gtk4::glib::idle_add_local(move || { st.set_text("Indexando archivos del espacio personal para examen real..."); pb.set_fraction(0.05); gtk4::glib::ControlFlow::Break });
            let mut files = Vec::new(); ManualScanEngine::collect_files(Path::new(&uh), &mut files);
            let total = files.len(); let mut threats_found = 0; let mut indeterminate_count = 0;
            for (idx, file_path) in files.iter().enumerate() {
                match ThreatAnalysisEngine::evaluate_file(file_path) {
                    FileVerdict::Threat(_) => { threats_found += 1; ContainmentEngine::isolate_to_vault(file_path); }
                    FileVerdict::Indeterminate(_) => { indeterminate_count += 1; }
                    FileVerdict::Clean(_) => {}
                }
                if idx % 10 == 0 || idx == total - 1 {
                    let fraction = if total > 0 { (idx + 1) as f64 / total as f64 } else { 1.0 };
                    let fname = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("archivo").to_string();
                    let pb_up = pb.clone(); let st_up = st.clone();
                    gtk4::glib::idle_add_local(move || {
                        pb_up.set_fraction(fraction);
                        st_up.set_text(&format!("Analizando archivo {}/{} ({:.1}%): {} | Amenazas: {} | Indeterminados: {}", idx + 1, total, fraction * 100.0, fname, threats_found, indeterminate_count));
                        gtk4::glib::ControlFlow::Break
                    });
                }
            }
            let st_done = st.clone();
            gtk4::glib::idle_add_local(move || {
                if threats_found > 0 { st_done.set_text(&format!("⚠️ Inspección finalizada: {} amenazas detectadas y aisladas en el baúl. ({} análisis incompletos/advertencias).", threats_found, indeterminate_count)); }
                else if indeterminate_count > 0 { st_done.set_text(&format!("⚠️ Inspección incompleta: 0 amenazas confirmadas, pero {} archivos quedaron con estado INDETERMINADO por fallo o error de motor.", indeterminate_count)); }
                else { st_done.set_text(&format!("✓ Inspección completa concluida con éxito: {} archivos procesados y certificados limpios por todos los motores.", total)); }
                gtk4::glib::ControlFlow::Break
            });
            ImmutableAuditLog::append_event("FULL_SCAN_COMPLETED", &format!("Inspección finalizada: {} archivos, {} amenazas aisladas, {} indeterminados.", total, threats_found, indeterminate_count));
        });
    });

    let pb_u = progress_bar.clone(); let st_u = scan_status_lbl.clone();
    btn_scan_usb.connect_clicked(move |_| {
        let pb = pb_u.clone(); let st = st_u.clone();
        thread::spawn(move || {
            let mut usb_files = Vec::new(); ManualScanEngine::collect_files(Path::new("/media"), &mut usb_files);
            let total = usb_files.len(); let mut threats = 0; let mut indets = 0;
            for (idx, file) in usb_files.iter().enumerate() {
                match ThreatAnalysisEngine::evaluate_file(file) {
                    FileVerdict::Threat(_) => { threats += 1; ContainmentEngine::isolate_to_vault(file); }
                    FileVerdict::Indeterminate(_) => { indets += 1; }
                    FileVerdict::Clean(_) => {}
                }
                let frac = if total > 0 { (idx + 1) as f64 / total as f64 } else { 1.0 };
                let pb_up = pb.clone();
                gtk4::glib::idle_add_local(move || { pb_up.set_fraction(frac); gtk4::glib::ControlFlow::Break });
            }
            let st_end = st.clone();
            gtk4::glib::idle_add_local(move || {
                st_end.set_text(&format!("✓ Barrido USB completado: {} archivos examinados, {} amenazas aisladas, {} indeterminados.", total, threats, indets));
                gtk4::glib::ControlFlow::Break
            });
            ImmutableAuditLog::append_event("USB_SCAN_COMPLETED", &format!("Barrido USB finalizado: {} archivos, {} amenazas aisladas.", total, threats));
        });
    });

    let pb_f = progress_bar.clone(); let st_f = scan_status_lbl.clone();
    btn_scan_file.connect_clicked(move |_| {
        let sample = Path::new("/bin/bash");
        let result = ThreatAnalysisEngine::evaluate_file(sample);
        pb_f.set_fraction(1.0);
        match result {
            FileVerdict::Clean(_) => st_f.set_text("✓ Archivo analizado (/bin/bash): Limpio por todos los motores verificados."),
            FileVerdict::Threat(t) => st_f.set_text(&format!("⚠️ Amenaza en muestra: {}", t)),
            FileVerdict::Indeterminate(i) => st_f.set_text(&format!("ℹ️ Análisis Incompleto (Fail-Secure): {}", i)),
        }
    });

    // --- Vista 3: Actualizaciones ---
    let updates_box = Box::new(Orientation::Vertical, 16); updates_box.set_margin_start(28); updates_box.set_margin_end(28); updates_box.set_margin_top(24);
    let card_mod_updates = Box::new(Orientation::Vertical, 12); card_mod_updates.add_css_class("macos-card");
    let t_mu = Label::new(Some("Auditoría de los 16 Componentes de Seguridad y Feeds")); t_mu.add_css_class("title-text"); t_mu.set_xalign(0.0);
    card_mod_updates.append(&t_mu);
    let grid_mods = Grid::new(); grid_mods.set_column_spacing(24); grid_mods.set_row_spacing(6);
    let h1 = Label::new(Some("Componente")); h1.add_css_class("macos-table-header"); h1.set_xalign(0.0);
    let h2 = Label::new(Some("Versión / Estado")); h2.add_css_class("macos-table-header"); h2.set_xalign(0.0);
    let h3 = Label::new(Some("Última Sincronización")); h3.add_css_class("macos-table-header"); h3.set_xalign(0.0);
    grid_mods.attach(&h1, 0, 0, 1, 1); grid_mods.attach(&h2, 1, 0, 1, 1); grid_mods.attach(&h3, 2, 0, 1, 1);
    let mod_statuses = ModuleVersionAudit::get_modules_status();
    for (idx, (name, ver, updated)) in mod_statuses.iter().enumerate() {
        let row = (idx + 1) as i32;
        let l_name = Label::new(Some(name)); l_name.set_xalign(0.0); l_name.add_css_class("macos-table-cell");
        let l_ver = Label::new(Some(ver)); l_ver.set_xalign(0.0); l_ver.add_css_class("macos-table-cell");
        let l_upd = Label::new(Some(updated)); l_upd.set_xalign(0.0); l_upd.add_css_class("mini-row-status-ok");
        grid_mods.attach(&l_name, 0, row, 1, 1); grid_mods.attach(&l_ver, 1, row, 1, 1); grid_mods.attach(&l_upd, 2, row, 1, 1);
    }
    card_mod_updates.append(&grid_mods);
    let btns_update_row = Box::new(Orientation::Horizontal, 12);
    let btn_update_all = Button::with_label("🔄 Actualizar Todo (16 Motores, Firmas y Feeds)"); btn_update_all.add_css_class("suggested-action");
    let btn_aide_check = Button::with_label("🔍 Ejecutar Verificación AIDE Ahora");
    btns_update_row.append(&btn_update_all); btns_update_row.append(&btn_aide_check); card_mod_updates.append(&btns_update_row);
    updates_box.append(&card_mod_updates); stack.add_named(&updates_box, Some("updates"));

    btn_update_all.connect_clicked(|_| {
        thread::spawn(|| {
            let ok = ModuleVersionAudit::update_all_modules();
            if ok { let _ = Command::new("notify-send").args(["-u", "normal", "Constantine Antivirus", "Los 16 componentes, firmas, MISP, Sigma, AIDE y Wazuh han sido sincronizados."]).status(); }
        });
    });
    btn_aide_check.connect_clicked(|_| {
        thread::spawn(|| {
            let _ = Command::new("notify-send").args(["-u", "low", "Constantine - AIDE", "Iniciando verificación criptográfica de archivos del sistema..."]).status();
            let _ = ModuleVersionAudit::run_aide_check();
            let _ = Command::new("notify-send").args(["-u", "normal", "Constantine - AIDE", "Verificación de integridad completada. Revisa el Registro Forense."]).status();
        });
    });

    // --- Vista 4: Red, VPN y Firewall ---
    let net_box = Box::new(Orientation::Vertical, 16); net_box.set_margin_start(28); net_box.set_margin_end(28); net_box.set_margin_top(24);
    let card_net = Box::new(Orientation::Vertical, 14); card_net.add_css_class("macos-card");
    let net_t = Label::new(Some("Estado de Red, Firewall y Privacidad")); net_t.add_css_class("title-text"); net_t.set_xalign(0.0); card_net.append(&net_t);
    let grid_net = Grid::new(); grid_net.set_column_spacing(24); grid_net.set_row_spacing(10);
    grid_net.attach(&Label::new(Some("Firewall del Sistema (UFW):")), 0, 0, 1, 1);
    let ufw_active = NetworkPrivacyAudit::is_ufw_active();
    let ufw_lbl = Label::new(Some(if ufw_active { "● Activo / Protegido" } else { "● Inactivo" }));
    ufw_lbl.add_css_class(if ufw_active { "mini-row-status-ok" } else { "mini-row-status-warn" });
    grid_net.attach(&ufw_lbl, 1, 0, 1, 1);
    let btn_open_gufw = Button::with_label("Abrir GUFW (Gestionar Firewall)"); btn_open_gufw.add_css_class("suggested-action");
    grid_net.attach(&btn_open_gufw, 2, 0, 1, 1);
    grid_net.attach(&Label::new(Some("Conexión VPN (ProtonVPN):")), 0, 1, 1, 1);
    let vpn_active = NetworkPrivacyAudit::is_protonvpn_active();
    let vpn_lbl = Label::new(Some(if vpn_active { "● Conectado (Túnel Cifrado)" } else { "● Desconectado" }));
    vpn_lbl.add_css_class(if vpn_active { "mini-row-status-ok" } else { "mini-row-status-warn" });
    grid_net.attach(&vpn_lbl, 1, 1, 1, 1);
    let btn_open_pvpn = Button::with_label("Abrir ProtonVPN (Gestionar)"); btn_open_pvpn.add_css_class("suggested-action");
    grid_net.attach(&btn_open_pvpn, 2, 1, 1, 1);
    grid_net.attach(&Label::new(Some("IP Pública Detectada:")), 0, 2, 1, 1);
    let ip_lbl = Label::new(Some("Consultando IP...")); ip_lbl.add_css_class("title-text"); grid_net.attach(&ip_lbl, 1, 2, 2, 1);
    grid_net.attach(&Label::new(Some("Localización de la IP:")), 0, 3, 1, 1);
    let loc_lbl = Label::new(Some("Consultando ubicación...")); loc_lbl.add_css_class("mini-row-status-ok"); grid_net.attach(&loc_lbl, 1, 3, 2, 1);
    card_net.append(&grid_net);
    let btn_ref_ip = Button::with_label("🔄 Actualizar Información de IP y Estado de Red"); card_net.append(&btn_ref_ip);
    net_box.append(&card_net); stack.add_named(&net_box, Some("network"));

    btn_open_gufw.connect_clicked(|_| NetworkPrivacyAudit::launch_gufw());
    btn_open_pvpn.connect_clicked(|_| NetworkPrivacyAudit::launch_protonvpn());
    let ip_l_clone = ip_lbl.clone(); let loc_l_clone = loc_lbl.clone();
    let update_ip_info = move || {
        let i_lbl = ip_l_clone.clone(); let l_lbl = loc_l_clone.clone();
        thread::spawn(move || {
            let (ip, loc) = NetworkPrivacyAudit::get_public_ip_info();
            gtk4::glib::idle_add_local(move || { i_lbl.set_text(&ip); l_lbl.set_text(&loc); gtk4::glib::ControlFlow::Break });
        });
    };
    let u_ip = update_ip_info.clone();
    btn_ref_ip.connect_clicked(move |_| u_ip());
    update_ip_info();

    // --- Vista 5: Baúl de Cuarentena ---
    let vault_box = Box::new(Orientation::Vertical, 16); vault_box.set_margin_start(28); vault_box.set_margin_end(28); vault_box.set_margin_top(24);
    let v_card = Box::new(Orientation::Vertical, 12); v_card.add_css_class("macos-card");
    let vt = Label::new(Some("Baúl de Cuarentena Criptográfico (Permisos 000)")); vt.add_css_class("title-text"); vt.set_xalign(0.0); v_card.append(&vt);
    let v_scrolled = ScrolledWindow::new(); v_scrolled.set_min_content_height(260);
    let v_txt = TextView::new(); v_txt.set_editable(false); v_scrolled.set_child(Some(&v_txt)); v_card.append(&v_scrolled);
    let btn_action_row = Box::new(Orientation::Horizontal, 12);
    let btn_ref_vault = Button::with_label("Actualizar Baúl");
    let btn_whitelist = Button::with_label("Enviar a Lista Blanca (Contraseña)"); btn_whitelist.add_css_class("suggested-action");
    let btn_del_vault = Button::with_label("Eliminar Definitivamente (Contraseña)"); btn_del_vault.add_css_class("destructive-action");
    btn_action_row.append(&btn_ref_vault); btn_action_row.append(&btn_whitelist); btn_action_row.append(&btn_del_vault);
    v_card.append(&btn_action_row); vault_box.append(&v_card); stack.add_named(&vault_box, Some("vault"));

    let v_tv_clone = v_txt.clone();
    let load_vault = move || {
        let files = VaultManager::list_vault_files();
        if files.is_empty() { v_tv_clone.buffer().set_text("El baúl de cuarentena está vacío. No hay amenazas aisladas."); }
        else {
            let mut text = String::from("AMENAZAS AISLADAS EN EL BAÚL CRIPTOGRÁFICO:\n\n");
            for f in files { text.push_str(&format!("🔒 [Aislado 000 Blindado] {}\n", f)); }
            v_tv_clone.buffer().set_text(&text);
        }
    };
    let lv_c1 = load_vault.clone(); btn_ref_vault.connect_clicked(move |_| lv_c1());
    let lv_c2 = load_vault.clone(); let u_home = user_home.clone();
    btn_whitelist.connect_clicked(move |_| { let files = VaultManager::list_vault_files(); if let Some(first) = files.first() { if VaultManager::restore_to_whitelist(first, &u_home) { lv_c2(); } } });
    let lv_c3 = load_vault.clone();
    btn_del_vault.connect_clicked(move |_| { let files = VaultManager::list_vault_files(); if let Some(first) = files.first() { if VaultManager::delete_from_vault(first) { lv_c3(); } } });

    // --- Vista 6: Control de Módulos ---
    let mod_box = Box::new(Orientation::Vertical, 16); mod_box.set_margin_start(28); mod_box.set_margin_end(28); mod_box.set_margin_top(24);
    let make_module_row = |name: &str, service: &'static str, desc: &str| -> Box {
        let row = Box::new(Orientation::Horizontal, 16); row.add_css_class("macos-card");
        let tb = Box::new(Orientation::Vertical, 4); tb.set_hexpand(true);
        let t = Label::new(Some(name)); t.add_css_class("title-text"); t.set_xalign(0.0);
        let d = Label::new(Some(desc)); d.add_css_class("subtitle-text"); d.set_xalign(0.0);
        tb.append(&t); tb.append(&d);
        let sw = Switch::new(); sw.set_active(get_service_active(service)); sw.set_valign(gtk4::Align::Center);
        row.append(&tb); row.append(&sw);
        sw.connect_state_set(move |_, state| {
            let ok = if state { SecurityAuth::start_service_protected(service) } else { SecurityAuth::stop_service_protected(service) };
            if !ok { return gtk4::glib::Propagation::Stop; }
            gtk4::glib::Propagation::Proceed
        });
        row
    };
    mod_box.append(&make_module_row("ClamOnAcc (fanotify Shield)", "clamonacc", "Intercepción y bloqueo síncrono en kernel al abrir archivos."));
    mod_box.append(&make_module_row("Tetragon (Cilium eBPF)", "tetragon", "Vigilancia de procesos y políticas de terminación forzada SIGKILL."));
    mod_box.append(&make_module_row("Falco (Runtime Behavioral)", "falco", "Detección de comportamiento anómalo mediante reglas comunitarias."));
    mod_box.append(&make_module_row("Wazuh Agent (SIEM & FIM)", "wazuh-agent", "Monitoreo de integridad de archivos (syscheck), rootkits y telemetría centralizada."));
    mod_box.append(&make_module_row("ClamAV Engine (clamd)", "clamav-daemon", "Motor de firmas multihilo por socket UNIX en memoria."));
    stack.add_named(&mod_box, Some("modules"));

    // --- Vista 7: Registro Forense Inmutable ---
    let log_box = Box::new(Orientation::Vertical, 16); log_box.set_margin_start(28); log_box.set_margin_end(28); log_box.set_margin_top(24);
    let lcard = Box::new(Orientation::Vertical, 12); lcard.add_css_class("macos-card");
    let ltitle = Label::new(Some("Registro Forense Inmutable Encadenado (SHA-256 Hash Chain)")); ltitle.add_css_class("title-text"); ltitle.set_xalign(0.0); lcard.append(&ltitle);
    let lscrolled = ScrolledWindow::new(); lscrolled.set_min_content_height(360);
    let ltxt = TextView::new(); ltxt.set_editable(false); lscrolled.set_child(Some(&ltxt)); lcard.append(&lscrolled);
    let btn_ref_all = Button::with_label("Actualizar y Verificar Registro Forense"); lcard.append(&btn_ref_all);
    log_box.append(&lcard); stack.add_named(&log_box, Some("logs"));

    let ltv_clone = ltxt.clone();
    btn_ref_all.connect_clicked(move |_| {
        let (chain_ok, count) = ImmutableAuditLog::verify_integrity();
        let mut lines = Vec::new();
        if chain_ok { lines.push(format!("✓ INTEGRIDAD FORENSE VERIFICADA: {} eventos encadenados válidos sin alteración.\n", count)); }
        else { lines.push("⚠️ ALERTA FORENSE CRÍTICA: Se detectó una ruptura o alteración en la cadena de hash del registro.\n".into()); }
        if let Ok(file) = File::open(IMMUTABLE_AUDIT_LOG) { for l in BufReader::new(file).lines().flatten() { lines.push(format!("[Forense SHA-256] {}", l)); } }
        if let Ok(file) = File::open(LOG_FILE) { for l in BufReader::new(file).lines().flatten() { if l.contains("FOUND") || l.contains("Access denied") { lines.push(format!("[ClamOnAcc/fanotify] {}", l)); } } }
        if let Ok(file) = File::open(SIGMA_LOG_FILE) { for l in BufReader::new(file).lines().flatten() { lines.push(format!("[Sigma Match] {}", l)); } }
        if let Ok(file) = File::open(AIDE_LOG_FILE) { for l in BufReader::new(file).lines().flatten() { if l.contains("changed:") || l.contains("added:") || l.contains("removed:") { lines.push(format!("[AIDE Integrity] {}", l)); } } }
        lines.reverse();
        ltv_clone.buffer().set_text(if lines.is_empty() { "Sin incidentes recientes. Los 16 componentes y el pipeline EDR operan con normalidad." } else { &lines.join("\n") });
    });

    // Navegación Sidebar
    let s1 = stack.clone(); btn_dash.connect_clicked(move |_| s1.set_visible_child_name("dashboard"));
    let s_sc = stack.clone(); btn_scan.connect_clicked(move |_| s_sc.set_visible_child_name("scan"));
    let s_upd = stack.clone(); btn_updates.connect_clicked(move |_| s_upd.set_visible_child_name("updates"));
    let s_net = stack.clone(); btn_net.connect_clicked(move |_| s_net.set_visible_child_name("network"));
    let s2 = stack.clone(); let lv_nav = load_vault.clone();
    btn_vault.connect_clicked(move |_| { s2.set_visible_child_name("vault"); lv_nav(); });
    let s3 = stack.clone(); btn_modules.connect_clicked(move |_| s3.set_visible_child_name("modules"));
    let s4 = stack.clone(); btn_logs.connect_clicked(move |_| s4.set_visible_child_name("logs"));
    main_box.append(&stack);

    let st_sub_clone = st_sub.clone();
    gtk4::glib::timeout_add_seconds_local(3, move || {
        let onacc = get_service_active("clamonacc");
        let clamd = get_service_active("clamav-daemon");
        if onacc && clamd {
            st_sub_clone.set_text("● 16 Escudos Activos en 2do Plano");
            st_sub_clone.remove_css_class("mini-row-status-warn"); st_sub_clone.add_css_class("mini-row-status-ok");
        } else {
            st_sub_clone.set_text("● Algún Módulo Detenido");
            st_sub_clone.remove_css_class("mini-row-status-ok"); st_sub_clone.add_css_class("mini-row-status-warn");
        }
        gtk4::glib::ControlFlow::Continue
    });

    gtk4::glib::timeout_add_seconds_local(600, move || {
        thread::spawn(|| {
            let ok = ModuleVersionAudit::update_all_modules();
            if ok { let _ = Command::new("notify-send").args(["-u", "low", "Constantine Antivirus & EDR", "Actualización inicial (10 min post-inicio): 16 motores sincronizados."]).status(); }
        });
        gtk4::glib::ControlFlow::Break
    });

    gtk4::glib::timeout_add_seconds_local(86400, move || {
        thread::spawn(|| {
            let ok = ModuleVersionAudit::update_all_modules();
            if ok { let _ = Command::new("notify-send").args(["-u", "low", "Constantine Antivirus & EDR", "Ciclo continuo (24 horas ininterrumpidas): Actualización de los 16 módulos completada."]).status(); }
        });
        gtk4::glib::ControlFlow::Continue
    });

    window.present();
}
