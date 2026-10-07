//! ============================================================================
//! CoreSync USB Gatekeeper - Statik Analiz ve Tehdit Tespit Motoru
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Sıfır Dış Ağ Bağımlılığı)
//!
//! Bu modül, Faz 2'nin tüm bileşenlerini (Gömülü YARA, PE Anomali Dedektörü,
//! Shannon Entropisi ve sentry.manifest Bütünlük Motoru) bir araya getirerek
//! çıkarılabilir sürücüler üzerinde derinlemesine statik analiz yürütür.
//! ============================================================================

use crate::config::Config;
use crate::crypto::hash_file;
use crate::entropy::analyze_file_entropy;
use crate::manifest::{
    compute_manifest_diff, create_drive_snapshot, load_manifest_from_drive, print_diff_report,
    ManifestDiffReport, DEFAULT_MANIFEST_FILENAME,
};
use crate::pe::analyze_pe_file;
use crate::yara::{YaraEngine, YaraMatch};
use std::fs;
use std::path::{Path, PathBuf};

/// Tespit edilen tehdidin ciddiyet seviyesi
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Clean = 0,
    Suspicious = 1,
    Critical = 2,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatLevel::Clean => "[TEMİZ]",
            ThreatLevel::Suspicious => "[ŞÜPHELİ]",
            ThreatLevel::Critical => "[KRİTİK ZARARLI]",
        }
    }
}

/// Tek bir dosyanın statik analiz bulguları
#[derive(Debug, Clone)]
pub struct FileScanResult {
    pub path: PathBuf,
    pub relative_path: String,
    pub file_size: u64,
    pub sha256: String,
    pub entropy: f64,
    pub threat_level: ThreatLevel,
    pub yara_matches: Vec<YaraMatch>,
    pub pe_anomalies: Vec<String>,
    pub flags: Vec<String>,
}

/// Sürücü tarama özeti ve istatistikleri
#[derive(Debug, Clone)]
pub struct DriveScanSummary {
    pub target_path: String,
    pub total_files_scanned: usize,
    pub total_bytes_scanned: u64,
    pub clean_count: usize,
    pub suspicious_count: usize,
    pub critical_count: usize,
    pub results: Vec<FileScanResult>,
    pub manifest_diff: Option<ManifestDiffReport>,
}

/// Statik Analiz Motoru
pub struct StaticScanner {
    yara_engine: YaraEngine,
    entropy_threshold: f64,
}

impl StaticScanner {
    pub fn new(config: &Config) -> Self {
        let yara_engine = YaraEngine::default();
        let entropy_threshold = config.entropy_threshold;

        Self {
            yara_engine,
            entropy_threshold,
        }
    }

    /// Belirtilen sürücüyü veya klasörü baştan sona analiz eder
    pub fn scan_drive(&self, drive_path: &str) -> DriveScanSummary {
        let root = Path::new(drive_path);
        println!("\n========================================================");
        println!("[*] [STATİK ANALİZ] Sürücü Taraması Başlatıldı: {}", drive_path);
        println!("========================================================");

        // 1. sentry.manifest Bütünlük ve Diff Kontrolü
        let mut manifest_diff = None;
        let manifest_path = root.join(DEFAULT_MANIFEST_FILENAME);

        if manifest_path.exists() {
            println!("[+] [Manifest] 'sentry.manifest' bulundu. Bütünlük fark analizi yapılıyor...");
            match load_manifest_from_drive(root) {
                Ok(baseline) => match create_drive_snapshot(root) {
                    Ok(current) => {
                        let diff = compute_manifest_diff(&baseline, &current);
                        print_diff_report(&diff);
                        manifest_diff = Some(diff);
                    }
                    Err(e) => eprintln!("[-] [Manifest] Anlık snapshot oluşturulamadı: {}", e),
                },
                Err(e) => eprintln!("[-] [Manifest] Mevcut manifesto okunamadı: {}", e),
            }
        } else {
            println!("[*] [Manifest] Sürücüde 'sentry.manifest' bulunamadı.");
            println!("    (Güvenli bilgisayarda '--snapshot {}' ile referans manifesto oluşturabilirsiniz).", drive_path);
        }

        // 2. Dosya Bazlı Statik ve Heuristic Tarama
        let mut results = Vec::new();
        let mut total_bytes = 0u64;

        self.walk_and_scan(root, root, &mut results, &mut total_bytes);

        let mut clean_count = 0;
        let mut suspicious_count = 0;
        let mut critical_count = 0;

        for r in &results {
            match r.threat_level {
                ThreatLevel::Clean => clean_count += 1,
                ThreatLevel::Suspicious => suspicious_count += 1,
                ThreatLevel::Critical => critical_count += 1,
            }
        }

        let summary = DriveScanSummary {
            target_path: drive_path.to_string(),
            total_files_scanned: results.len(),
            total_bytes_scanned: total_bytes,
            clean_count,
            suspicious_count,
            critical_count,
            results,
            manifest_diff,
        };

        self.print_summary(&summary);
        summary
    }

    fn walk_and_scan(
        &self,
        current_dir: &Path,
        root_path: &Path,
        results: &mut Vec<FileScanResult>,
        total_bytes: &mut u64,
    ) {
        let read_dir = match fs::read_dir(current_dir) {
            Ok(rd) => rd,
            Err(_) => return,
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Karantina, manifest ve taşınabilir kurtarma ajanını atla
            if name_str.eq_ignore_ascii_case("sentry.manifest")
                || name_str.eq_ignore_ascii_case("sentry_portable.exe")
                || name_str.eq_ignore_ascii_case(".sentry_quarantine")
                || name_str.eq_ignore_ascii_case("System Volume Information")
                || name_str.eq_ignore_ascii_case("$RECYCLE.BIN")
            {
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            // Eğer autorun.inf bir aşı klasörüyse içine girme, atla
            if meta.is_dir() && name_str.eq_ignore_ascii_case("autorun.inf") {
                continue;
            }

            if meta.is_dir() {
                self.walk_and_scan(&path, root_path, results, total_bytes);
            } else if meta.is_file() {
                let size = meta.len();
                *total_bytes += size;

                let rel_path = path
                    .strip_prefix(root_path)
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| name_str.to_string());

                let file_res = self.scan_single_file(&path, &rel_path, size);
                results.push(file_res);
            }
        }
    }

    /// Tek bir dosyayı derinlemesine inceler
    pub fn scan_single_file(&self, path: &Path, rel_path: &str, file_size: u64) -> FileScanResult {
        let mut threat_level = ThreatLevel::Clean;
        let mut flags = Vec::new();
        let mut yara_matches = Vec::new();
        let mut pe_anomalies = Vec::new();

        let sha256 = hash_file(path).unwrap_or_else(|_| "hash_error".to_string());
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // 1. Dosya Yolu ve Uzantı Heuristiği:
        // A) Çift Uzantı Kontrolü (örn: rapor.pdf.exe, resim.jpg.scr)
        if has_double_extension(file_name) {
            threat_level = ThreatLevel::Critical;
            flags.push(format!(
                "ALDATICI ÇİFT UZANTI: Dosya birden fazla uzantı ile gizlenmiş ('{}').",
                file_name
            ));
        }

        // B) RTLO (Right-to-Left Override: U+202E) Karakteri Kontrolü
        if file_name.contains('\u{202E}') {
            threat_level = ThreatLevel::Critical;
            flags.push("KRİTİK ALDATMACA: Dosya adında RTLO (\\u202E) gizleme karakteri var!".to_string());
        }

        // C) Kötücül Otomatik Çalıştırma (Autorun.inf)
        if file_name.eq_ignore_ascii_case("autorun.inf") {
            flags.push("UYARI: autorun.inf yapılandırma dosyası tespit edildi.".to_string());
            if threat_level < ThreatLevel::Suspicious {
                threat_level = ThreatLevel::Suspicious;
            }
        }

        // 2. Shannon Entropi Analizi
        let entropy_rep = analyze_file_entropy(path, Some(self.entropy_threshold)).ok();
        let entropy = entropy_rep.as_ref().map(|r| r.value).unwrap_or(0.0);

        if let Some(ref rep) = entropy_rep {
            if rep.is_suspicious {
                flags.push(format!(
                    "YÜKSEK ENTROPİ ({:.2}/8.0): Şifrelenmiş veya gizlenmiş veri yapısı.",
                    rep.value
                ));
                if threat_level < ThreatLevel::Suspicious {
                    threat_level = ThreatLevel::Suspicious;
                }
            }
        }

        // 3. PE Başlık ve Anomali Analizi
        if let Ok(pe_rep) = analyze_pe_file(path) {
            if pe_rep.is_pe {
                if pe_rep.masquerading_detected {
                    threat_level = ThreatLevel::Critical;
                }

                for anomaly in pe_rep.detected_anomalies {
                    pe_anomalies.push(anomaly);
                }

                if pe_rep.is_suspicious {
                    if threat_level < ThreatLevel::Suspicious {
                        threat_level = ThreatLevel::Suspicious;
                    }
                    if pe_rep.entry_point_in_last_section || pe_rep.masquerading_detected {
                        threat_level = ThreatLevel::Critical;
                    }
                }

                // Yüksek entropi + PE dosyası = Doğrudan Kritik Tehdit (Packer / Malware)
                if entropy >= self.entropy_threshold {
                    threat_level = ThreatLevel::Critical;
                    flags.push("KRİTİK BULGU: PE çalıştırılabilir dosyası >7.2 entropiye sahip (Crypter / Packed Malware).".to_string());
                }
            }
        }

        // 4. Gömülü YARA Kural Taraması
        match self.yara_engine.scan_file(path) {
            Ok(matches) => {
                for m in matches {
                    match m.severity.to_uppercase().as_str() {
                        "CRITICAL" => threat_level = ThreatLevel::Critical,
                        "HIGH" => {
                            if threat_level < ThreatLevel::Suspicious {
                                threat_level = ThreatLevel::Suspicious;
                            }
                        }
                        _ => {}
                    }
                    flags.push(format!("YARA [{}]: {}", m.rule_name, m.description));
                    yara_matches.push(m);
                }
            }
            Err(e) => {
                #[cfg(windows)]
                if e.raw_os_error() == Some(225) {
                    threat_level = ThreatLevel::Critical;
                    flags.push("KRİTİK ZARARLI: İşletim sistemi erişimi virüs/trojan sebebiyle engelledi (Win32 Hata 225 - ERROR_VIRUS_INFECTED).".to_string());
                }
            }
        }

        FileScanResult {
            path: path.to_path_buf(),
            relative_path: rel_path.to_string(),
            file_size,
            sha256,
            entropy,
            threat_level,
            yara_matches,
            pe_anomalies,
            flags,
        }
    }

    fn print_summary(&self, summary: &DriveScanSummary) {
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║              FAZ 2 STATİK ANALİZ VE TEHDİT ÖZETİ              ║");
        println!("╚═══════════════════════════════════════════════════════════════╝");
        println!("Hedef Sürücü          : {}", summary.target_path);
        println!("Taranan Toplam Dosya  : {}", summary.total_files_scanned);
        println!(
            "İncelenen Toplam Boyut: {:.2} MB",
            summary.total_bytes_scanned as f64 / (1024.0 * 1024.0)
        );
        println!("Temiz Dosyalar        : {}", summary.clean_count);
        println!("Şüpheli Dosyalar      : {}", summary.suspicious_count);
        println!("KRİTİK ZARARLILAR     : {}", summary.critical_count);
        println!("---------------------------------------------------------------");

        if summary.critical_count > 0 || summary.suspicious_count > 0 {
            println!("\n[!] TESPİT EDİLEN TEHDİT VE ANOMALİ LİSTESİ:");
            for r in &summary.results {
                if r.threat_level != ThreatLevel::Clean {
                    println!("\n>>> {} {}", r.threat_level.as_str(), r.relative_path);
                    println!("    Boyut: {} bayt | Entropi: {:.2}/8.0", r.file_size, r.entropy);
                    println!("    SHA256: {}", r.sha256);

                    for flag in &r.flags {
                        println!("    * [Bulgu] {}", flag);
                    }
                    for anomaly in &r.pe_anomalies {
                        println!("    ! [PE Anomali] {}", anomaly);
                    }
                    for yara in &r.yara_matches {
                        println!(
                            "    # [YARA Kuralı] {} (Şiddet: {}) -> {}",
                            yara.rule_name, yara.severity, yara.threat_type
                        );
                    }
                }
            }
            println!("\n[!] Faz 3 Uyarısı: Şüpheli ve zararlı dosyalar Faz 3 karantina motoruna devredilebilir.");
        } else {
            println!("[+] TEBRİKLER: Sürücü üzerinde herhangi bir zararlı veya anomali tespit edilmedi.");
        }
        println!("===============================================================\n");
    }
}

/// Dosya adında gizleme amaçlı çift uzantı olup olmadığını inceler
/// Örnek: `fatura.pdf.exe`, `tatil.jpg.scr`, `setup.doc.vbs`
fn has_double_extension(name: &str) -> bool {
    let lower = name.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() < 3 {
        return false;
    }

    let last_ext = parts[parts.len() - 1];
    let second_ext = parts[parts.len() - 2];

    let dangerous_execs = [
        "exe", "scr", "vbs", "js", "jse", "wsf", "hta", "bat", "cmd", "pif", "lnk", "com",
    ];
    let deceptive_exts = [
        "pdf", "docx", "doc", "xlsx", "xls", "pptx", "jpg", "jpeg", "png", "txt", "mp3", "mp4",
        "zip",
    ];

    dangerous_execs.contains(&last_ext) && deceptive_exts.contains(&second_ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_extension_detection() {
        assert!(has_double_extension("invoice.pdf.exe"));
        assert!(has_double_extension("photo.jpg.scr"));
        assert!(has_double_extension("document.docx.vbs"));
        assert!(!has_double_extension("archive.tar.gz"));
        assert!(!has_double_extension("normal_file.exe"));
        assert!(!has_double_extension("document.pdf"));
    }
}
