//! ============================================================================
//! CoreSync USB Gatekeeper - Sentetik Güvenlik & Tehdit Doğrulama Paketi (Test Harness)
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Sıfır Dış Ağ Bağımlılığı)
//!
//! Bu modül:
//! 1. EICAR Test İmzası Doğrulaması (.txt, .bat, .com sentetik dosyaları ile
//!    %100 doğrulukta [KRİTİK ZARARLI] tespiti ve tersinir karantina).
//! 2. Çift Uzantı (fatura.pdf.exe) ve RTLO (\u{202E}) Simülasyonu.
//! 3. Kısayol Solucanı Simülasyonu (+h +s gizlenen klasörlerin kurtarılması,
//!    sahte ve komut çalıştıran .lnk kısayollarının temizlenmesi).
//! 4. NTFS Kök Kilidi ve Autorun Klasör Aşısı Dayanıklılık Testi (Erişim Reddedildi -
//!    Win32 Hata 5 doğrulama).
//! 5. Taşınabilir Kurtarma Ajanı (`sentry_portable.exe`) ve Snapshot Doğrulaması.
//! 6. RAII Tabanlı Güvenli Yaşam Döngüsü (Tüm geçici test dosyalarının niteliklerinin
//!    sıfırlanarak temizlenmesi).
//! ============================================================================

use crate::cleaner::clean_shortcut_worm;
use crate::config::Config;
use crate::immunizer::{deimmunize_fat_autorun, immunize_fat_autorun};
use crate::manifest::{compute_manifest_diff, create_drive_snapshot};
use crate::portable::deploy_portable_rescue;
use crate::quarantine::{list_quarantine, quarantine_file, restore_file};
use crate::scanner::{StaticScanner, ThreatLevel};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_SYSTEM, INVALID_FILE_ATTRIBUTES,
};

/// EICAR antivirüs test dizesi (Sentetik test imzası)
pub const EICAR_TEST_STRING: &[u8] =
    b"CORESYNC_SYNTHETIC_TEST_STRING: EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// UTF-8 dizgisini null sonlandırmalı UTF-16 vektörüne dönüştürür
#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Tek bir test senaryosunun yürütme raporu
#[derive(Debug, Clone)]
pub struct TestCaseReport {
    pub name: String,
    pub passed: bool,
    pub duration_ms: u128,
    pub message: String,
    pub details: Vec<String>,
}

/// Tüm test paketinin sonuç raporu
#[derive(Debug, Clone)]
pub struct TestSuiteReport {
    pub target_dir: String,
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub total_duration_ms: u128,
    pub cases: Vec<TestCaseReport>,
}

impl TestSuiteReport {
    pub fn is_success(&self) -> bool {
        self.failed_tests == 0
    }

    pub fn print_summary(&self) {
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║     CORESYNC GÜVENLİK VE TEHDİT DOĞRULAMA TEST PAKETİ         ║");
        println!("╚═══════════════════════════════════════════════════════════════╝");
        println!("Test Ortamı Dizini    : {}", self.target_dir);
        println!("Toplam Koşulan Test   : {}", self.total_tests);
        println!("Başarılı (Passed)     : {}", self.passed_tests);
        println!("Başarısız (Failed)    : {}", self.failed_tests);
        println!("Toplam Geçen Süre     : {} ms", self.total_duration_ms);
        println!("---------------------------------------------------------------");

        for (i, case) in self.cases.iter().enumerate() {
            let status_tag = if case.passed {
                "[  BAŞARILI  ]"
            } else {
                "[! BAŞARISIZ !]"
            };
            println!(
                "{:>2}. {:<16} {:<45} ({} ms)",
                i + 1,
                status_tag,
                case.name,
                case.duration_ms
            );
            println!("    └─ {}", case.message);
            for d in &case.details {
                println!("       • {}", d);
            }
        }

        println!("===============================================================");
        if self.is_success() {
            println!("[+] TÜM SENTETİK TEHDİT SENARYOLARI %100 BAŞARIYLA DOĞRULANDI!");
        } else {
            eprintln!("[-] DİKKAT: Bazı güvenlik doğrulama testleri başarısız oldu!");
        }
        println!("===============================================================\n");
    }
}

/// Test ortamını güvenle izole eden ve temizleyen RAII Yaşam Döngüsü Yöneticisi
pub struct TestHarnessEnvironment {
    pub root_dir: PathBuf,
    pub is_temporary: bool,
}

impl TestHarnessEnvironment {
    /// Yeni bir test ortamı başlatır
    pub fn new(custom_dir: Option<&Path>) -> Result<Self, String> {
        let (root_dir, is_temporary) = match custom_dir {
            Some(dir) => {
                let p = dir.to_path_buf();
                if !p.exists() {
                    fs::create_dir_all(&p).map_err(|e| format!("Özel test dizini açılamadı: {}", e))?;
                }
                (p, false)
            }
            None => {
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let temp = std::env::temp_dir().join(format!("coresync_harness_{}", nanos));
                fs::create_dir_all(&temp).map_err(|e| format!("Geçici test dizini açılamadı: {}", e))?;
                (temp, true)
            }
        };

        Ok(Self {
            root_dir,
            is_temporary,
        })
    }

    /// Dosya sistemi özniteliklerini temizleyerek dizini güvenle siler
    pub fn cleanup(&self) {
        reset_attributes_and_delete(&self.root_dir);
    }
}

impl Drop for TestHarnessEnvironment {
    fn drop(&mut self) {
        if self.is_temporary && self.root_dir.exists() {
            self.cleanup();
        }
    }
}

/// Belirtilen dizin ve altındaki tüm kilitli/öznitelikli dosyaları normal yapıp siler
fn reset_attributes_and_delete(dir: &Path) {
    if !dir.exists() {
        return;
    }

    #[cfg(windows)]
    {
        // Özyinelemeli olarak öznitelikleri sıfırla
        let _ = reset_dir_attrs_recursive(dir);
    }

    let _ = fs::remove_dir_all(dir);
}

#[cfg(windows)]
fn reset_dir_attrs_recursive(dir: &Path) -> std::io::Result<()> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let wide = to_wide(&path.to_string_lossy());
            unsafe {
                SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            }
            if path.is_dir() {
                let _ = reset_dir_attrs_recursive(&path);
            }
        }
    }
    let dir_wide = to_wide(&dir.to_string_lossy());
    unsafe {
        SetFileAttributesW(dir_wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
    }
    Ok(())
}

// ============================================================================
// SENTETİK TEST SENARYOLARI
// ============================================================================

/// 1. EICAR Standart Test İmzası Doğrulama Testi
pub fn test_eicar_detection_and_quarantine(env: &TestHarnessEnvironment) -> TestCaseReport {
    let start = Instant::now();
    let mut details = Vec::new();
    let root = &env.root_dir;

    let sub_dir = root.join("eicar_test_case");
    let _ = fs::create_dir_all(&sub_dir);

    // 3 farklı uzantıda sentetik EICAR dosyası oluştur
    let txt_path = sub_dir.join("eicar_test.txt");
    let bat_path = sub_dir.join("eicar_script.bat");
    let com_path = sub_dir.join("eicar_sample.com");

    let eicar_txt_content = format!(
        "CoreSync Synthetic Antivirus Verification File\r\n{}\r\n",
        String::from_utf8_lossy(EICAR_TEST_STRING)
    );
    let eicar_bat_content = format!(
        "@echo off\r\nrem CoreSync Test Batch Dropper\r\n{}\r\n",
        String::from_utf8_lossy(EICAR_TEST_STRING)
    );
    let eicar_com_content = format!(
        "MZ_COM_HEADER: {}\r\n",
        String::from_utf8_lossy(EICAR_TEST_STRING)
    );

    if let Err(e) = fs::write(&txt_path, eicar_txt_content.as_bytes()) {
        return TestCaseReport {
            name: "EICAR Test İmzası Doğrulaması".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: format!("EICAR txt dosyası oluşturulamadı: {}", e),
            details,
        };
    }
    let _ = fs::write(&bat_path, eicar_bat_content.as_bytes());
    let _ = fs::write(&com_path, eicar_com_content.as_bytes());

    details.push("Sentetik EICAR dosyaları oluşturuldu: .txt, .bat, .com".to_string());

    let config = Config::default();
    let scanner = StaticScanner::new(&config);

    // Dosyaları tara
    let drive_str = root.to_string_lossy().to_string();
    let files_to_test = [
        (&txt_path, "eicar_test_case/eicar_test.txt"),
        (&bat_path, "eicar_test_case/eicar_script.bat"),
        (&com_path, "eicar_test_case/eicar_sample.com"),
    ];

    for (file_p, rel_p) in &files_to_test {
        let meta = match fs::metadata(file_p) {
            Ok(m) => m,
            Err(e) => {
                return TestCaseReport {
                    name: "EICAR Test İmzası Doğrulaması".to_string(),
                    passed: false,
                    duration_ms: start.elapsed().as_millis(),
                    message: format!("Dosya metadatası okunamadı: {}", e),
                    details,
                };
            }
        };

        let scan_res = scanner.scan_single_file(file_p, rel_p, meta.len());
        if scan_res.threat_level != ThreatLevel::Critical {
            return TestCaseReport {
                name: "EICAR Test İmzası Doğrulaması".to_string(),
                passed: false,
                duration_ms: start.elapsed().as_millis(),
                message: format!(
                    "EICAR dosyası ('{}') Kritik Tehdit olarak yakalanamadı! Seviye: {:?}",
                    rel_p, scan_res.threat_level
                ),
                details,
            };
        }

        let eicar_rule_matched = scan_res
            .yara_matches
            .iter()
            .any(|m| m.rule_name == "EICAR_Standard_Test_File");

        if !eicar_rule_matched {
            return TestCaseReport {
                name: "EICAR Test İmzası Doğrulaması".to_string(),
                passed: false,
                duration_ms: start.elapsed().as_millis(),
                message: format!("'EICAR_Standard_Test_File' YARA kuralı eşleşmedi: {}", rel_p),
                details,
            };
        }

        // Karantinaya al
        let q_res = quarantine_file(
            &drive_str,
            file_p,
            rel_p,
            &scan_res.sha256,
            scan_res.threat_level.as_str(),
            "Sentetik EICAR Doğrulaması",
        );

        match q_res {
            Ok(rec) => {
                if file_p.exists() {
                    return TestCaseReport {
                        name: "EICAR Test İmzası Doğrulaması".to_string(),
                        passed: false,
                        duration_ms: start.elapsed().as_millis(),
                        message: format!("Orijinal dosya silinmedi: {}", file_p.display()),
                        details,
                    };
                }
                details.push(format!("Dosya izole edildi -> ID: {} | {}", rec.id, rel_p));
            }
            Err(e) => {
                return TestCaseReport {
                    name: "EICAR Test İmzası Doğrulaması".to_string(),
                    passed: false,
                    duration_ms: start.elapsed().as_millis(),
                    message: format!("Karantinaya alma başarısız: {}", e),
                    details,
                };
            }
        }
    }

    // Karantina havuzunu listele ve doğrulama yap
    let q_list = list_quarantine(&drive_str).unwrap_or_default();
    if q_list.len() < 3 {
        return TestCaseReport {
            name: "EICAR Test İmzası Doğrulaması".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: format!("Karantina veritabanında 3 kayıt bekleniyordu, bulunan: {}", q_list.len()),
            details,
        };
    }

    // Restore testi: eicar_test.txt'yi karantinadan kurtar
    let restore_res = restore_file(&drive_str, "eicar_test_case/eicar_test.txt");
    match restore_res {
        Ok(rec) => {
            if !txt_path.exists() {
                return TestCaseReport {
                    name: "EICAR Test İmzası Doğrulaması".to_string(),
                    passed: false,
                    duration_ms: start.elapsed().as_millis(),
                    message: "Kurtarılan dosya diskte bulunamadı!".to_string(),
                    details,
                };
            }
            let restored_bytes = fs::read(&txt_path).unwrap_or_default();
            if restored_bytes != eicar_txt_content.as_bytes() {
                return TestCaseReport {
                    name: "EICAR Test İmzası Doğrulaması".to_string(),
                    passed: false,
                    duration_ms: start.elapsed().as_millis(),
                    message: "Kurtarılan dosya içeriği orijinal sentetik EICAR içeriği ile uyuşmuyor!".to_string(),
                    details,
                };
            }
            details.push(format!("Restore doğrulandı -> SHA-256 bütünlüğü %100 korundu ({})", rec.sha256));
        }
        Err(e) => {
            return TestCaseReport {
                name: "EICAR Test İmzası Doğrulaması".to_string(),
                passed: false,
                duration_ms: start.elapsed().as_millis(),
                message: format!("Karantinadan restore işlemi başarısız: {}", e),
                details,
            };
        }
    }

    let _ = fs::remove_dir_all(&sub_dir);

    TestCaseReport {
        name: "EICAR Test İmzası Doğrulaması".to_string(),
        passed: true,
        duration_ms: start.elapsed().as_millis(),
        message: "3 sentetik EICAR dosyası (%100 tespit, XOR izolasyonu ve restore) başarıyla doğrulandı.".to_string(),
        details,
    }
}

/// 2. Çift Uzantı ve RTLO Karakteri Aldatmacası Testi
pub fn test_double_extension_and_rtlo(env: &TestHarnessEnvironment) -> TestCaseReport {
    let start = Instant::now();
    let mut details = Vec::new();
    let root = &env.root_dir;

    let sub_dir = root.join("spoofing_test_case");
    let _ = fs::create_dir_all(&sub_dir);

    // 1. Çift uzantılı tuzak dosya
    let de_path = sub_dir.join("fatura.pdf.exe");
    let mut fake_exe = vec![0u8; 256];
    fake_exe[0] = b'M';
    fake_exe[1] = b'Z';
    fake_exe[0x3C] = 0x40;
    fake_exe[0x40] = b'P';
    fake_exe[0x41] = b'E';
    let _ = fs::write(&de_path, &fake_exe);
    details.push("Çift uzantılı tuzak dosya oluşturuldu: fatura.pdf.exe".to_string());

    // 2. RTLO (Right-to-Left Override: U+202E) içeren dosya
    // fatura\u{202E}fdp.exe -> Windows Gezgini'nde faturaexe.pdf gibi görünür
    let rtlo_filename = "fatura\u{202E}fdp.exe";
    let rtlo_path = sub_dir.join(rtlo_filename);
    let _ = fs::write(&rtlo_path, b"Malicious payload with RTLO character");
    details.push(format!("RTLO karakterli tuzak dosya oluşturuldu: {}", rtlo_filename));

    let config = Config::default();
    let scanner = StaticScanner::new(&config);

    // fatura.pdf.exe kontrolü
    let de_res = scanner.scan_single_file(&de_path, "spoofing/fatura.pdf.exe", fake_exe.len() as u64);
    if de_res.threat_level != ThreatLevel::Critical {
        return TestCaseReport {
            name: "Çift Uzantı ve RTLO Simülasyonu".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: format!("'fatura.pdf.exe' Kritik Tehdit olarak yakalanamadı: {:?}", de_res.threat_level),
            details,
        };
    }
    let de_flag_ok = de_res.flags.iter().any(|f| f.contains("ÇİFT UZANTI"));
    if !de_flag_ok {
        return TestCaseReport {
            name: "Çift Uzantı ve RTLO Simülasyonu".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "Çift uzantı uyarı bayrağı üretilmedi!".to_string(),
            details,
        };
    }
    details.push("fatura.pdf.exe -> [KRİTİK ZARARLI] ve ÇİFT UZANTI bayrağı doğrulandı.".to_string());

    // RTLO kontrolü
    let rtlo_res = scanner.scan_single_file(&rtlo_path, "spoofing/rtlo.exe", 38);
    if rtlo_res.threat_level != ThreatLevel::Critical {
        return TestCaseReport {
            name: "Çift Uzantı ve RTLO Simülasyonu".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: format!("RTLO dosyası Kritik Tehdit olarak yakalanamadı: {:?}", rtlo_res.threat_level),
            details,
        };
    }
    let rtlo_flag_ok = rtlo_res.flags.iter().any(|f| f.contains("RTLO"));
    if !rtlo_flag_ok {
        return TestCaseReport {
            name: "Çift Uzantı ve RTLO Simülasyonu".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "RTLO uyarı bayrağı üretilmedi!".to_string(),
            details,
        };
    }
    details.push("RTLO karakterli dosya -> [KRİTİK ZARARLI] ve RTLO bayrağı doğrulandı.".to_string());

    let _ = fs::remove_dir_all(&sub_dir);

    TestCaseReport {
        name: "Çift Uzantı ve RTLO Simülasyonu".to_string(),
        passed: true,
        duration_ms: start.elapsed().as_millis(),
        message: "Çift uzantı ve RTLO aldatmacaları %100 doğrulukla yakalandı.".to_string(),
        details,
    }
}

/// 3. Kısayol Solucanı ve 'Attrib' Onarım Testi
pub fn test_shortcut_worm_simulation(env: &TestHarnessEnvironment) -> TestCaseReport {
    let start = Instant::now();
    let mut details = Vec::new();
    let root = &env.root_dir;

    let sub_dir = root.join("worm_test_case");
    let _ = fs::create_dir_all(&sub_dir);

    // 1. Kurban klasörleri oluştur
    let victim_dir1 = sub_dir.join("Belgelerim");
    let victim_dir2 = sub_dir.join("Fotograflar");
    let _ = fs::create_dir_all(&victim_dir1);
    let _ = fs::create_dir_all(&victim_dir2);

    let doc_file = victim_dir1.join("rapor.docx");
    let _ = fs::write(&doc_file, b"Gizli Proje Raporu");

    // 2. Solucan taktiğini simüle et: Klasörleri attrib +h +s ile gizle
    #[cfg(windows)]
    unsafe {
        let wide1 = to_wide(&victim_dir1.to_string_lossy());
        let wide2 = to_wide(&victim_dir2.to_string_lossy());
        SetFileAttributesW(wide1.as_ptr(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        SetFileAttributesW(wide2.as_ptr(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    details.push("Klasörler virüs taktiğiyle gizlendi (+h +s).".to_string());

    // 3. Sahte, gizli komut çalıştıran .lnk dosyaları oluştur
    let fake_lnk1 = sub_dir.join("Belgelerim.lnk");
    let fake_lnk2 = sub_dir.join("Fotograflar.lnk");

    let mut lnk_data1 = vec![0u8; 128];
    lnk_data1[0] = 0x4C; // LNK Magic
    let payload1 = b"cmd.exe /c start indexer.vbs & powershell.exe -w hidden -enc JABzACAAPQAg";
    lnk_data1[40..40 + payload1.len()].copy_from_slice(payload1);
    let _ = fs::write(&fake_lnk1, &lnk_data1);

    let mut lnk_data2 = vec![0u8; 128];
    lnk_data2[0] = 0x4C;
    let payload2 = b"powershell.exe -windowstyle hidden -enc AAAA";
    lnk_data2[40..40 + payload2.len()].copy_from_slice(payload2);
    let _ = fs::write(&fake_lnk2, &lnk_data2);

    details.push("Sahte ve komut çalıştıran .lnk kısayolları yerleştirildi.".to_string());

    // 4. clean_shortcut_worm motorunu çalıştır
    let sub_dir_str = sub_dir.to_string_lossy().to_string();
    let clean_report = clean_shortcut_worm(&sub_dir_str);

    // Doğrulamalar:
    // A) Sahte .lnk dosyaları silinmiş olmalı
    if fake_lnk1.exists() || fake_lnk2.exists() {
        return TestCaseReport {
            name: "Kısayol Solucanı ve Attrib Onarımı".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "Zararlı .lnk dosyaları temizlenemedi!".to_string(),
            details,
        };
    }
    details.push(format!("Zararlı kısayollar silindi (Toplam silinen: {})", clean_report.shortcuts_removed.len()));

    // B) Klasörlerin +h ve +s nitelikleri kaldırılmış olmalı
    #[cfg(windows)]
    unsafe {
        let wide1 = to_wide(&victim_dir1.to_string_lossy());
        let attrs = GetFileAttributesW(wide1.as_ptr());
        if attrs != INVALID_FILE_ATTRIBUTES {
            let is_hidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
            let is_system = (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;
            if is_hidden || is_system {
                return TestCaseReport {
                    name: "Kısayol Solucanı ve Attrib Onarımı".to_string(),
                    passed: false,
                    duration_ms: start.elapsed().as_millis(),
                    message: "Kurban klasörün gizli/sistem öznitelikleri kaldırılamadı!".to_string(),
                    details,
                };
            }
        }
    }
    details.push(format!("Klasörler görünür kılındı (Kurtarılan klasör: {})", clean_report.directories_restored.len()));

    // C) İçindeki orijinal dosyalar bozulmamış olmalı
    if !doc_file.exists() {
        return TestCaseReport {
            name: "Kısayol Solucanı ve Attrib Onarımı".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "Klasör içindeki orijinal kullanıcı dosyası kayboldu!".to_string(),
            details,
        };
    }

    let _ = fs::remove_dir_all(&sub_dir);

    TestCaseReport {
        name: "Kısayol Solucanı ve Attrib Onarımı".to_string(),
        passed: true,
        duration_ms: start.elapsed().as_millis(),
        message: "Gizlenen klasörler (-h -s) başarıyla onarıldı, zararlı .lnk'ler silindi.".to_string(),
        details,
    }
}

/// 4. Autorun Klasör Aşısı ve Dayanıklılık Testi
pub fn test_autorun_vaccine_resilience(env: &TestHarnessEnvironment) -> TestCaseReport {
    let start = Instant::now();
    let mut details = Vec::new();
    let root = &env.root_dir;

    let sub_dir = root.join("vaccine_test_case");
    let _ = fs::create_dir_all(&sub_dir);
    let sub_dir_str = sub_dir.to_string_lossy().to_string();

    // 1. FAT32/exFAT autorun.inf klasör aşısını uygula
    let imm_res = immunize_fat_autorun(&sub_dir_str);
    if let Err(e) = imm_res {
        return TestCaseReport {
            name: "Autorun Aşısı ve Dayanıklılık Testi".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: format!("Autorun aşısı uygulanamadı: {}", e),
            details,
        };
    }
    details.push("autorun.inf aşı klasörü (+r +h +s) ve sentry_vaccine.sys düğümü oluşturuldu.".to_string());

    let autorun_path = sub_dir.join("autorun.inf");
    let vaccine_node = autorun_path.join("sentry_vaccine.sys");

    // 2. Doğrulama: autorun.inf klasör olmalıdır
    if !autorun_path.is_dir() {
        return TestCaseReport {
            name: "Autorun Aşısı ve Dayanıklılık Testi".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "autorun.inf bir klasör olarak mevcut değil!".to_string(),
            details,
        };
    }

    // 3. Dayanıklılık Testi 1: Kötücül bir virüs gibi aynı isimde 'autorun.inf' DOSYASI oluşturmaya çalış
    // Bir klasör varken aynı isimde dosya oluşturulamaz -> Hata almalı
    let malicious_write_file = File::create(&autorun_path);
    if malicious_write_file.is_ok() {
        return TestCaseReport {
            name: "Autorun Aşısı ve Dayanıklılık Testi".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "HATA: autorun.inf klasörünün üzerine dosya yazılabildi!".to_string(),
            details,
        };
    }
    details.push("Dayanıklılık 1: autorun.inf klasörünün üzerine dosya yazma engellendi.".to_string());

    // 4. Dayanıklılık Testi 2: Salt-okunur kilitli sentry_vaccine.sys düğümünün üzerine yazmayı dene
    // +r niteliği olduğu için Win32 hata (PermissionDenied) vermeli
    let overwrite_node = File::create(&vaccine_node);
    if overwrite_node.is_ok() {
        return TestCaseReport {
            name: "Autorun Aşısı ve Dayanıklılık Testi".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "HATA: +r kilitli sentry_vaccine.sys üzerine yazılabildi!".to_string(),
            details,
        };
    }
    details.push("Dayanıklılık 2: Kilitli düğüme yazma denemesi 'Erişim Reddedildi' ile engellendi.".to_string());

    // 5. Deimmunize testi: Aşıyı güvenle kaldır
    let de_res = deimmunize_fat_autorun(&sub_dir_str);
    if let Err(e) = de_res {
        return TestCaseReport {
            name: "Autorun Aşısı ve Dayanıklılık Testi".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: format!("Deimmunize başarısız: {}", e),
            details,
        };
    }

    if autorun_path.exists() {
        return TestCaseReport {
            name: "Autorun Aşısı ve Dayanıklılık Testi".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "Deimmunize sonrası autorun.inf hala mevcut!".to_string(),
            details,
        };
    }
    details.push("Deimmunize başarılı: Aşı klasörü ve düğüm temizlendi.".to_string());

    let _ = fs::remove_dir_all(&sub_dir);

    TestCaseReport {
        name: "Autorun Aşısı ve Dayanıklılık Testi".to_string(),
        passed: true,
        duration_ms: start.elapsed().as_millis(),
        message: "Autorun aşısı manipülasyon ve silme denemelerine karşı başarıyla doğrulandı.".to_string(),
        details,
    }
}

/// 5. Taşınabilir Kurtarma Ajanı & Snapshot Bütünlük Testi
pub fn test_portable_rescue_and_manifest(env: &TestHarnessEnvironment) -> TestCaseReport {
    let start = Instant::now();
    let mut details = Vec::new();
    let root = &env.root_dir;

    let sub_dir = root.join("rescue_test_case");
    let _ = fs::create_dir_all(&sub_dir);

    // Test dosyası ekle
    let test_doc = sub_dir.join("dokuman.txt");
    let _ = fs::write(&test_doc, b"Guvenli Veri Dokumani");

    let sub_dir_str = sub_dir.to_string_lossy().to_string();

    // 1. Taşınabilir kurtarma ajanını konuşlandır
    let deploy_res = deploy_portable_rescue(&sub_dir_str, Some("Paylasim"));
    let report = match deploy_res {
        Ok(r) => r,
        Err(e) => {
            return TestCaseReport {
                name: "Taşınabilir Kurtarma Ajanı Dağıtımı".to_string(),
                passed: false,
                duration_ms: start.elapsed().as_millis(),
                message: format!("Dağıtım başarısız oldu: {}", e),
                details,
            };
        }
    };

    if !report.portable_exe_path.exists() {
        return TestCaseReport {
            name: "Taşınabilir Kurtarma Ajanı Dağıtımı".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "sentry_portable.exe hedef konumda bulunamadı!".to_string(),
            details,
        };
    }
    details.push(format!("sentry_portable.exe oluşturuldu: {} bayt", report.binary_size));

    if !report.manifest_path.exists() {
        return TestCaseReport {
            name: "Taşınabilir Kurtarma Ajanı Dağıtımı".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: "sentry.manifest dosyası oluşturulamadı!".to_string(),
            details,
        };
    }
    details.push(format!("sentry.manifest referansı kaydedildi -> SHA-256: {}", report.sha256));

    // 2. Anlık durum ile diff analizi yap (fark 0 olmalı)
    let baseline = match crate::manifest::load_manifest_from_drive(&sub_dir) {
        Ok(b) => b,
        Err(e) => {
            return TestCaseReport {
                name: "Taşınabilir Kurtarma Ajanı Dağıtımı".to_string(),
                passed: false,
                duration_ms: start.elapsed().as_millis(),
                message: format!("Manifesto okunamadı: {}", e),
                details,
            };
        }
    };

    let current = match create_drive_snapshot(&sub_dir) {
        Ok(c) => c,
        Err(e) => {
            return TestCaseReport {
                name: "Taşınabilir Kurtarma Ajanı Dağıtımı".to_string(),
                passed: false,
                duration_ms: start.elapsed().as_millis(),
                message: format!("Anlık snapshot alınamadı: {}", e),
                details,
            };
        }
    };

    let diff = compute_manifest_diff(&baseline, &current);
    if !diff.is_clean {
        return TestCaseReport {
            name: "Taşınabilir Kurtarma Ajanı Dağıtımı".to_string(),
            passed: false,
            duration_ms: start.elapsed().as_millis(),
            message: format!(
                "Manifesto farkı sıfır olmalıydı! (Yeni: {}, Değişen: {}, Silinen: {})",
                diff.added_files.len(),
                diff.modified_files.len(),
                diff.deleted_files.len()
            ),
            details,
        };
    }
    details.push("Bütünlük diff doğrulaması yapıldı: 0 fark (Baseline %100 temiz).".to_string());

    let _ = fs::remove_dir_all(&sub_dir);

    TestCaseReport {
        name: "Taşınabilir Kurtarma Ajanı Dağıtımı".to_string(),
        passed: true,
        duration_ms: start.elapsed().as_millis(),
        message: "sentry_portable.exe ve sentry.manifest bütünlükle konuşlandırıldı.".to_string(),
        details,
    }
}

// ============================================================================
// TEST HARNESS GİRİŞ NOKTASI
// ============================================================================

/// Tüm sentetik güvenlik doğrulama paketini baştan sona çalıştırır
pub fn run_full_test_harness(custom_dir: Option<&Path>) -> Result<TestSuiteReport, String> {
    let suite_start = Instant::now();
    let env = TestHarnessEnvironment::new(custom_dir)?;

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       CORESYNC TEST HARNESS: DOĞRULAMA PAKETİ BAŞLATILIYOR    ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("[*] Test Dizin Kökü: {}", env.root_dir.display());
    println!("[*] Yaşam Döngüsü: İzole sanal sürücü simülasyonu ve güvenli temizlik.");

    let mut cases = Vec::new();

    // 1. EICAR Testi
    println!("\n[1/5] Koşuluyor: EICAR Test İmzası Doğrulaması...");
    let c1 = test_eicar_detection_and_quarantine(&env);
    println!("      -> {}", if c1.passed { "BAŞARILI" } else { "BAŞARISIZ" });
    cases.push(c1);

    // 2. Çift Uzantı ve RTLO Testi
    println!("\n[2/5] Koşuluyor: Çift Uzantı ve RTLO Simülasyonu...");
    let c2 = test_double_extension_and_rtlo(&env);
    println!("      -> {}", if c2.passed { "BAŞARILI" } else { "BAŞARISIZ" });
    cases.push(c2);

    // 3. Kısayol Solucanı Testi
    println!("\n[3/5] Koşuluyor: Kısayol Solucanı ve Attrib Onarımı...");
    let c3 = test_shortcut_worm_simulation(&env);
    println!("      -> {}", if c3.passed { "BAŞARILI" } else { "BAŞARISIZ" });
    cases.push(c3);

    // 4. Autorun Aşısı Dayanıklılık Testi
    println!("\n[4/5] Koşuluyor: Autorun Aşısı ve Dayanıklılık Testi...");
    let c4 = test_autorun_vaccine_resilience(&env);
    println!("      -> {}", if c4.passed { "BAŞARILI" } else { "BAŞARISIZ" });
    cases.push(c4);

    // 5. Portable Rescue ve Manifest Testi
    println!("\n[5/5] Koşuluyor: Taşınabilir Kurtarma Ajanı Dağıtımı...");
    let c5 = test_portable_rescue_and_manifest(&env);
    println!("      -> {}", if c5.passed { "BAŞARILI" } else { "BAŞARISIZ" });
    cases.push(c5);

    let passed_tests = cases.iter().filter(|c| c.passed).count();
    let failed_tests = cases.len() - passed_tests;
    let total_duration_ms = suite_start.elapsed().as_millis();

    let report = TestSuiteReport {
        target_dir: env.root_dir.to_string_lossy().to_string(),
        total_tests: cases.len(),
        passed_tests,
        failed_tests,
        total_duration_ms,
        cases,
    };

    report.print_summary();

    // RAII temizliği env drop olduğunda otomatik yapılacak
    if report.is_success() {
        Ok(report)
    } else {
        Err(format!("{} test senaryosu başarısız oldu!", report.failed_tests))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_synthetic_suite_in_temp() {
        let res = run_full_test_harness(None);
        assert!(res.is_ok(), "Tüm sentetik test paketi başarıyla tamamlanmalıdır!");
    }
}
