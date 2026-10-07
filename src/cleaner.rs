//! ============================================================================
//! CoreSync USB Gatekeeper - Kısayol Solucanı ('Attrib') Onarıcısı
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Sıfır Dış Ağ Bağımlılığı)
//!
//! Bu modül:
//! 1. USB solucanlarının klasik taktiğini bozar: Kullanıcının orijinal klasör ve
//!    dosyalarını `attrib +h +s` yaparak gizleyip yerlerine sahte `.lnk` üretmesini
//!    tersine çevirir.
//! 2. Gizlenen klasörlerin ve dosyaların sistem (+s) ve gizli (+h) niteliklerini
//!    kaldırarak (`SetFileAttributesW`) verileri tekrar görünür kılar.
//! 3. Sahte, komut çalıştıran (cmd.exe, powershell, wscript) veya klasör taklidi
//!    yapan kötücül `.lnk` dosyalarını tespit edip temizler.
//! ============================================================================

use std::fs;
use std::path::Path;

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_SYSTEM,
    INVALID_FILE_ATTRIBUTES,
};

/// Kısayol virüsü temizleme ve onarım raporu
#[derive(Debug, Clone, Default)]
pub struct ShortcutCleanReport {
    pub drive_path: String,
    pub directories_restored: Vec<String>,
    pub files_restored: Vec<String>,
    pub shortcuts_removed: Vec<String>,
    pub errors: Vec<String>,
}

impl ShortcutCleanReport {
    pub fn total_actions(&self) -> usize {
        self.directories_restored.len() + self.files_restored.len() + self.shortcuts_removed.len()
    }

    pub fn print_report(&self) {
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║       KISAYOL SOLUCANI VE 'ATTRIB' ONARIM RAPORU              ║");
        println!("╚═══════════════════════════════════════════════════════════════╝");
        println!("Hedef Sürücü: {}", self.drive_path);
        println!("---------------------------------------------------------------");
        println!("Kurtarılan / Görünür Kılınan Klasörler: {}", self.directories_restored.len());
        for dir in &self.directories_restored {
            println!("  [+] Klasör Onarıldı (-h -s) : {}", dir);
        }

        println!("Kurtarılan / Görünür Kılınan Dosyalar  : {}", self.files_restored.len());
        for f in &self.files_restored {
            println!("  [+] Dosya Onarıldı (-h -s)   : {}", f);
        }

        println!("Temizlenen Zararlı Kısayollar (.lnk)   : {}", self.shortcuts_removed.len());
        for s in &self.shortcuts_removed {
            println!("  [!] Sahte Kısayol Silindi    : {}", s);
        }

        if !self.errors.is_empty() {
            println!("\nKarşılaşılan Hatalar: {}", self.errors.len());
            for err in &self.errors {
                println!("  [-] Hata: {}", err);
            }
        }

        if self.total_actions() == 0 {
            println!("[+] Sürücüde herhangi bir gizlenmiş klasör veya sahte kısayol solucanı izine rastlanmadı.");
        } else {
            println!("\n[+] Toplam {} adet öğe başarıyla onarıldı ve temizlendi.", self.total_actions());
        }
        println!("===============================================================\n");
    }
}

/// UTF-8 string'i null-terminated UTF-16 vektörüne çevirir
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Standart sistem ve yönetim dizinlerini atlamak için filtre
fn is_system_or_special_dir(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "system volume information"
        || lower == "$recycle.bin"
        || lower == ".sentry_quarantine"
        || lower == "autorun.inf"
        || lower == "recycler"
}

/// Bir `.lnk` kısayol dosyasının şüpheli veya virüslü olup olmadığını inceler
pub fn is_suspicious_shortcut(lnk_path: &Path, content: &[u8]) -> bool {
    // Windows Shell Link (.lnk) dosyası asgari 76 bayttır
    if content.len() < 76 {
        return false;
    }

    // Header boyutu (0x0000004C) ve Link CLSID ({00021401-0000-0000-C000-000000000046})
    let magic_ok = content[0] == 0x4C && content[1] == 0x00 && content[2] == 0x00 && content[3] == 0x00;
    if !magic_ok {
        return false;
    }

    // 1. Şüpheli komut yürütücü kalıpları (ASCII ve UTF-16LE için bayt taraması)
    let suspicious_strings: &[&[u8]] = &[
        b"cmd.exe",
        b"powershell",
        b"pwsh",
        b"wscript",
        b"cscript",
        b"rundll32",
        b"mshta",
        b"regsvr32",
        b"certutil",
        b"bitsadmin",
        b"-w hidden",
        b"-enc ",
        b"-windowstyle hidden",
        b"/c start",
        b"\\System Volume Information\\",
        b".vbs",
        b".js",
        b".wsf",
        b".hta",
    ];

    let content_lower: Vec<u8> = content.iter().map(|b| b.to_ascii_lowercase()).collect();

    for &pattern in suspicious_strings {
        if contains_subslice(&content_lower, pattern) {
            return true;
        }
    }

    // 2. Kök dizinde aynı isimde bir klasör var mı kontrolü (Folder masquerading)
    // Örn: 'Fotograflar.lnk' ve aynı dizinde 'Fotograflar' klasörü varsa bu tipik solucandır.
    if let Some(parent) = lnk_path.parent() {
        if let Some(stem) = lnk_path.file_stem() {
            let candidate_dir = parent.join(stem);
            if candidate_dir.is_dir() {
                return true;
            }
        }
    }

    false
}

/// Byte dizisi içinde alt bayt dizisi arar
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Sürücüdeki tüm gizlenmiş klasör ve dosyaları (+h +s) onarır, sahte kısayolları siler
pub fn clean_shortcut_worm(drive_path: &str) -> ShortcutCleanReport {
    println!("\n[*] [Attrib Onarıcısı] Sürücü taranıyor: '{}'...", drive_path);
    let mut report = ShortcutCleanReport {
        drive_path: drive_path.to_string(),
        ..Default::default()
    };

    let root = Path::new(drive_path);
    if !root.exists() {
        report.errors.push(format!("Sürücü yolu bulunamadı: {}", drive_path));
        return report;
    }

    walk_and_clean(root, &mut report);
    report
}

/// Dizini özyinelemeli olarak gezer ve gizli nitelikleri kaldırır
fn walk_and_clean(current_dir: &Path, report: &mut ShortcutCleanReport) {
    let read_dir = match fs::read_dir(current_dir) {
        Ok(rd) => rd,
        Err(e) => {
            report.errors.push(format!("Dizin okunamadı ('{}'): {}", current_dir.display(), e));
            return;
        }
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if is_system_or_special_dir(&name_str) {
            continue;
        }

        let is_dir = path.is_dir();
        let is_file = path.is_file();

        #[cfg(windows)]
        unsafe {
            let wide_path = to_wide(&path.to_string_lossy());
            let attrs = GetFileAttributesW(wide_path.as_ptr());

            if attrs != INVALID_FILE_ATTRIBUTES {
                let is_hidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
                let is_system = (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;

                // 1. Gizlenen Klasörün (+h / +s) Onarılması
                if is_dir && (is_hidden || is_system) {
                    let clean_attrs = attrs & !(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                    let target_attrs = if clean_attrs == 0 { FILE_ATTRIBUTE_NORMAL } else { clean_attrs };

                    let res = SetFileAttributesW(wide_path.as_ptr(), target_attrs);
                    if res != 0 {
                        report.directories_restored.push(path.display().to_string());
                    } else {
                        report.errors.push(format!(
                            "Klasör niteliği değiştirilemedi ('{}'): {}",
                            path.display(),
                            std::io::Error::last_os_error()
                        ));
                    }
                }

                // 2. Kısayol (.lnk) Dosyası İncelemesi ve Temizliği
                if is_file && name_str.to_lowercase().ends_with(".lnk") {
                    if let Ok(content) = fs::read(&path) {
                        if is_suspicious_shortcut(&path, &content) {
                            // Kısayol salt okunur veya sistem olabilir, önce niteliğini sıfırla
                            SetFileAttributesW(wide_path.as_ptr(), FILE_ATTRIBUTE_NORMAL);
                            if fs::remove_file(&path).is_ok() {
                                report.shortcuts_removed.push(path.display().to_string());
                            } else {
                                report.errors.push(format!("Zararlı kısayol silinemedi: {}", path.display()));
                            }
                            continue;
                        }
                    }
                }

                // 3. Gizlenen Kullanıcı Dosyasının (+h +s) Onarılması
                if is_file && (is_hidden || is_system) && !name_str.starts_with('.') {
                    // Kullanıcı dosyalarını (fotoğraf, belge, arşiv vb.) tekrar görünür kıl
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                    let common_user_exts = [
                        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "jpg", "jpeg",
                        "png", "gif", "mp3", "mp4", "avi", "mkv", "zip", "rar", "7z", "txt",
                    ];

                    if common_user_exts.contains(&ext.as_str()) {
                        let clean_attrs = attrs & !(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                        let target_attrs = if clean_attrs == 0 { FILE_ATTRIBUTE_NORMAL } else { clean_attrs };

                        let res = SetFileAttributesW(wide_path.as_ptr(), target_attrs);
                        if res != 0 {
                            report.files_restored.push(path.display().to_string());
                        }
                    }
                }
            }
        }

        // Klasörün içine girip özyinelemeli temizle
        if is_dir {
            walk_and_clean(&path, report);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_dir_exclusion() {
        assert!(is_system_or_special_dir("System Volume Information"));
        assert!(is_system_or_special_dir("$RECYCLE.BIN"));
        assert!(is_system_or_special_dir(".sentry_quarantine"));
        assert!(is_system_or_special_dir("autorun.inf"));
        assert!(!is_system_or_special_dir("Documents"));
        assert!(!is_system_or_special_dir("Paylasim"));
    }

    #[test]
    fn test_suspicious_shortcut_detection() {
        // Geçerli .lnk header'ı oluştur (76 bayt)
        let mut lnk_data = vec![0u8; 128];
        lnk_data[0] = 0x4C; // Magic 0x0000004C
        lnk_data[1] = 0x00;
        lnk_data[2] = 0x00;
        lnk_data[3] = 0x00;

        // Temiz kısayol
        let path = Path::new("C:\\fake\\clean.lnk");
        assert!(!is_suspicious_shortcut(path, &lnk_data));

        // PowerShell içeren kısayol
        let mut malicious_lnk = lnk_data.clone();
        let payload = b"powershell.exe -w hidden -enc JABzACAAPQAg";
        malicious_lnk[50..50 + payload.len()].copy_from_slice(payload);
        assert!(is_suspicious_shortcut(path, &malicious_lnk));

        // cmd.exe /c start içeren kısayol
        let mut malicious_cmd = lnk_data.clone();
        let cmd_payload = b"cmd.exe /c start indexer.vbs";
        malicious_cmd[50..50 + cmd_payload.len()].copy_from_slice(cmd_payload);
        assert!(is_suspicious_shortcut(path, &malicious_cmd));
    }

    #[test]
    #[cfg(windows)]
    fn test_cleaner_filesystem_cycle() {
        let temp_dir = std::env::temp_dir().join("coresync_test_cleaner");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // 1. Sahte kısayol oluştur
        let fake_lnk = temp_dir.join("Documents.lnk");
        let mut lnk_data = vec![0u8; 128];
        lnk_data[0] = 0x4C;
        let payload = b"powershell.exe -w hidden -enc JABzACAAPQAg";
        lnk_data[50..50 + payload.len()].copy_from_slice(payload);
        fs::write(&fake_lnk, &lnk_data).unwrap();

        // 2. Normal kullanıcı dosyası oluştur
        let normal_file = temp_dir.join("report.docx");
        fs::write(&normal_file, b"test report content").unwrap();

        // 3. Temizleyiciyi çalıştır
        let report = clean_shortcut_worm(temp_dir.to_str().unwrap());
        assert_eq!(report.shortcuts_removed.len(), 1);
        assert!(!fake_lnk.exists(), "Zararlı kısayol silinmiş olmalıdır");
        assert!(normal_file.exists(), "Normal dosya korunmalıdır");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
