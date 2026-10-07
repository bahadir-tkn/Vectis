#![windows_subsystem = "windows"]

//! ============================================================================
//! Vectis (Coresync) Removable Media Defense - Faz 1 - Faz 5 (Air-Gapped EDR + Slint GUI)
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped / Çevrimdışı, Sıfır Ağ Bağımlılığı)
//! ============================================================================

pub mod cleaner;
pub mod config;
pub mod crypto;
pub mod detector;
pub mod entropy;
pub mod gui;
pub mod harness;
pub mod immunizer;
pub mod manifest;
pub mod pe;
pub mod portable;
pub mod quarantine;
pub mod scanner;
pub mod yara;

use cleaner::clean_shortcut_worm;
use config::{load_config, Config};
use detector::{enumerate_all_drives, enumerate_removable_drives, start_sentry_loop};
use immunizer::{
    check_immunization_status, deimmunize_drive, immunize_drive, DEFAULT_SHARED_FOLDER,
};
use manifest::{
    compute_manifest_diff, create_drive_snapshot, load_manifest_from_drive, print_diff_report,
    save_manifest_to_drive, DEFAULT_MANIFEST_FILENAME,
};
use quarantine::{list_quarantine, print_quarantine_table, quarantine_file, restore_file};
use scanner::{StaticScanner, ThreatLevel};
use std::path::Path;
use yara::YaraEngine;

/// Kullanıcının girdiği sürücü parametresini normalize eder (örn: "E" -> "E:\\", "E:" -> "E:\\")
pub fn normalize_drive_arg(arg: &str) -> String {
    let mut s = arg.trim().to_string();
    if s.len() == 1 && s.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) {
        s.push_str(":\\");
    } else if s.len() == 2 && s.ends_with(':') {
        s.push('\\');
    } else if !s.ends_with('\\') && !s.ends_with('/') {
        s.push('\\');
    }
    s
}

// ============================================================================
// GÜVENLİK BORU HATTI (PIPELINE) TETİKLEYİCİSİ (FAZ 1 + FAZ 2 + FAZ 3)
// ============================================================================

/// Algılanan veya seçilen çıkarılabilir sürücüyü tam güvenlik boru hattına sokar:
/// 1. Faz 2 Statik Analiz (PE, Entropi, YARA, Diff).
/// 2. Faz 3 Tersinir Karantina (Zararlı ve şüpheli dosyaların XOR ile izole edilmesi).
/// 3. Faz 3 Kısayol Solucanı ve Attrib Onarımı (Gizlenen klasörlerin görünür kılınması).
/// 4. Faz 3 USB Bağışıklama (Dosya sistemine göre NTFS ACL kilidi veya FAT autorun aşısı).
pub fn trigger_pipeline(drive_path: &str) {
    let clean_path = normalize_drive_arg(drive_path);

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       CORESYNC GÜVENLİK BORU HATTI (PIPELINE) ÇALIŞIYOR       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("[*] [Pipeline] Hedef Sürücü: '{}'", clean_path);
    println!("[*] [Air-Gapped] Kesin Kural: Sıfır harici ağ/soket erişimi.");

    let config = load_config();
    let scanner = StaticScanner::new(&config);

    // ADIM 1: Faz 2 Statik Analiz Taraması (YARA, PE, Entropi, Manifest Diff)
    let summary = scanner.scan_drive(&clean_path);

    println!("\n---------------------------------------------------------------");
    println!("[+] [Pipeline] Faz 2 Statik Analiz Tamamlandı.");
    println!("    - Taranan Dosya Sayısı: {}", summary.total_files_scanned);
    println!("    - Kritik Tehdit       : {}", summary.critical_count);
    println!("    - Şüpheli Durum       : {}", summary.suspicious_count);
    println!("    - Temiz Dosya         : {}", summary.clean_count);

    // ADIM 2: Faz 3 Tersinir Karantina Motoru
    if summary.critical_count > 0 || summary.suspicious_count > 0 {
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║       FAZ 3: TERSİNİR KARANTİNA İZOLASYONU BAŞLATILIYOR       ║");
        println!("╚═══════════════════════════════════════════════════════════════╝");
        let mut quarantined_count = 0;

        for r in &summary.results {
            if r.threat_level != ThreatLevel::Clean {
                let reason = if !r.yara_matches.is_empty() {
                    format!("YARA: {}", r.yara_matches[0].rule_name)
                } else if !r.pe_anomalies.is_empty() {
                    format!("PE Anomali: {}", r.pe_anomalies[0])
                } else if !r.flags.is_empty() {
                    r.flags[0].clone()
                } else {
                    "Heuristic Şüpheli Davranış".to_string()
                };

                match quarantine_file(
                    &clean_path,
                    &r.path,
                    &r.relative_path,
                    &r.sha256,
                    r.threat_level.as_str(),
                    &reason,
                ) {
                    Ok(rec) => {
                        quarantined_count += 1;
                        println!("    [+] İzole Edildi -> ID: {} | Dosya: {}", rec.id, rec.original_relative_path);
                    }
                    Err(err) => {
                        eprintln!("    [-] Karantina Hatası -> Dosya: {} | Hata: {}", r.relative_path, err);
                    }
                }
            }
        }
        println!("[+] Toplam {} adet tehdit '.sentry_quarantine' altına izole edildi (XOR şifreli).", quarantined_count);
    }

    // ADIM 3: Faz 3 Kısayol Solucanı ve Attrib Onarıcısı
    println!("\n[*] [Pipeline] Faz 3: Kısayol Solucanı ve 'Attrib' Onarım Denetimi...");
    let clean_report = clean_shortcut_worm(&clean_path);
    if clean_report.total_actions() > 0 {
        clean_report.print_report();
    } else {
        println!("[+] [Pipeline] Gizlenmiş klasör veya sahte kısayol solucanı tespit edilmedi (Temiz).");
    }

    // ADIM 4: Faz 3 USB Bağışıklama (NTFS ACL Kilidi / FAT32 Autorun Aşısı)
    if config.enable_ntfs_immunization {
        println!("\n[*] [Pipeline] Faz 3: USB Bağışıklama Motoru Devrede...");
        match immunize_drive(&clean_path, Some(DEFAULT_SHARED_FOLDER)) {
            Ok(imm_rep) => {
                println!("[+] [Pipeline] Bağışıklama Tamamlandı -> {}", imm_rep.message);
            }
            Err(err) => {
                eprintln!("[-] [Pipeline] Bağışıklama Uyarısı: {}", err);
            }
        }
    } else {
        println!("[*] [Pipeline] Yapılandırmada otomatik bağışıklama pasif (enable_ntfs_immunization: false).");
    }

    // ADIM 5: Faz 4 Taşınabilir Kurtarma Ajanı (sentry_portable.exe) ve Snapshot Manifestosu Dağıtımı
    if config.create_portable_rescue {
        println!("\n[*] [Pipeline] Faz 4: Taşınabilir Kurtarma Ajanı (sentry_portable.exe) Dağıtılıyor...");
        match portable::deploy_portable_rescue(&clean_path, Some(DEFAULT_SHARED_FOLDER)) {
            Ok(rep) => {
                println!(
                    "[+] [Pipeline] Kurtarma ajanı konuşlandırıldı -> {} ({:.2} MB)",
                    rep.portable_exe_path.display(),
                    rep.binary_size as f64 / (1024.0 * 1024.0)
                );
            }
            Err(err) => {
                eprintln!("[-] [Pipeline] Kurtarma ajanı dağıtım uyarısı: {}", err);
            }
        }
    } else {
        println!("[*] [Pipeline] Yapılandırmada taşınabilir kurtarma ajanı pasif (create_portable_rescue: false).");
    }

    println!("\n===============================================================");
    println!("[+] [Pipeline] Tüm Savunma ve Sertleştirme Aşamaları Tamamlandı: '{}'", clean_path);
    println!("===============================================================\n");
}

// ============================================================================
// ÇALIŞMA MODLARI (SENTRY VE ON-DEMAND)
// ============================================================================

/// Sentry Modunu çalıştırır:
/// Arka planda <10 MB RAM ve %0 CPU harcayarak görünmez Win32 penceresiyle
/// `WM_DEVICECHANGE` yayınlarını dinler.
pub fn run_sentry_mode(config: &Config) {
    println!("[*] [Sentry Modu] Başlatılıyor...");
    println!("[*] [Sentry Modu] Kaynak Tüketimi: <10 MB RAM, %0 CPU (Event-driven).");

    if let Err(err) = start_sentry_loop(config, trigger_pipeline) {
        eprintln!("[-] [Sentry Modu] Başlatma Hatası: {}", err);
    }
}

/// On-Demand (Manuel) Mod:
/// Sistemde takılı olan tüm çıkarılabilir sürücüleri tek seferlik denetler ve
/// bellekte hiçbir process bırakmadan sıfır (0) ayak iziyle sonlanır.
pub fn run_on_demand_mode() {
    println!("\n[*] [On-Demand Modu] Manuel tarama başlatılıyor...");
    println!("[*] [On-Demand Modu] Sistemdeki çıkarılabilir aygıtlar taranıyor...");

    let removable_drives = enumerate_removable_drives();

    if removable_drives.is_empty() {
        println!("[-] [On-Demand Modu] Sistemde takılı çıkarılabilir (USB) sürücü bulunamadı.");
        println!("[*] USB takıp programı tekrar çalıştırabilir veya 'config.json' içinde");
        println!("    \"background_monitoring\": true yaparak Sentry moduna geçebilirsiniz.");
    } else {
        println!("[+] [On-Demand Modu] {} adet çıkarılabilir sürücü tespit edildi.", removable_drives.len());
        for drive in removable_drives {
            trigger_pipeline(&drive);
        }
    }

    println!("\n[*] [On-Demand Modu] Görev tamamlandı. Sistemden çıkılıyor (0 process).");
}

// ============================================================================
// MANİFESTO YÖNETİM RUTİNLERİ
// ============================================================================

/// Güvenli bilgisayarda USB sürücünün referans SHA-256 manifestosunu oluşturur
pub fn run_create_snapshot(target: &str) {
    let p = Path::new(target);
    if !p.exists() {
        eprintln!("[-] Hata: Belirtilen hedef yol mevcut değil: {}", target);
        return;
    }

    println!("\n[*] [Snapshot Motoru] Referans sentry.manifest oluşturuluyor...");
    println!("[*] Sürücü Kökü: {}", target);

    match create_drive_snapshot(p) {
        Ok(manifest) => {
            match save_manifest_to_drive(&manifest, p) {
                Ok(path) => {
                    println!("[+] [Snapshot] Başarılı! Manifesto kaydedildi -> {}", path.display());
                    println!("    - Toplam İndekslenen Dosya: {}", manifest.total_files);
                    println!(
                        "    - Toplam Boyut            : {:.2} MB",
                        manifest.total_bytes as f64 / (1024.0 * 1024.0)
                    );
                    println!("[*] USB artık yabancı bilgisayara güvenle götürülebilir.");
                    println!("    Geri takıldığında 'coresync --diff {}' ile değişiklikler görülecektir.", target);
                }
                Err(err) => eprintln!("[-] [Snapshot] Manifesto diske yazılamadı: {}", err),
            }
        }
        Err(err) => eprintln!("[-] [Snapshot] Snapshot oluşturma hatası: {}", err),
    }
}

/// Yabancı bilgisayardan dönen USB'nin sentry.manifest farkını raporlar
pub fn run_diff_check(target: &str) {
    let p = Path::new(target);
    if !p.exists() {
        eprintln!("[-] Hata: Belirtilen hedef yol mevcut değil: {}", target);
        return;
    }

    let manifest_path = p.join(DEFAULT_MANIFEST_FILENAME);
    if !manifest_path.exists() {
        eprintln!("[-] Hata: Sürücüde '{}' bulunamadı.", manifest_path.display());
        eprintln!("    Önce '--snapshot {}' ile referans oluşturulmalıdır.", target);
        return;
    }

    println!("\n[*] [Diff Motoru] sentry.manifest okunuyor...");
    match load_manifest_from_drive(p) {
        Ok(baseline) => {
            println!("[*] [Diff Motoru] Sürücünün anlık durumu taranıyor...");
            match create_drive_snapshot(p) {
                Ok(current) => {
                    let diff = compute_manifest_diff(&baseline, &current);
                    print_diff_report(&diff);
                }
                Err(err) => eprintln!("[-] [Diff Motoru] Anlık durum çıkarılamadı: {}", err),
            }
        }
        Err(err) => eprintln!("[-] [Diff Motoru] Referans manifesto okunamadı: {}", err),
    }
}

/// Binary içine gömülmüş YARA kurallarını ve meta verilerini listeler
pub fn print_embedded_rules() {
    let engine = YaraEngine::default();
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       GÖMÜLÜ DERLENMİŞ YARA KURALLARI (AIR-GAPPED DB)         ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("Toplam Kural Sayısı: {}\n", engine.rules.len());

    for (i, r) in engine.rules.iter().enumerate() {
        println!("{}. Kural Adı : {}", i + 1, r.name);
        println!("   Tehdit Türü : {}", r.meta.get("threat_type").unwrap_or(&"-".to_string()));
        println!("   Şiddet      : {}", r.meta.get("severity").unwrap_or(&"-".to_string()));
        println!("   Açıklama    : {}", r.meta.get("description").unwrap_or(&"-".to_string()));
        println!("   Kalıp Sayısı: {}", r.patterns.len());
        println!("---------------------------------------------------------------");
    }
}

// ============================================================================
// BAŞLANGIÇ VE KOMUT SATIRI YÖNETİMİ
// ============================================================================

fn print_banner() {
    println!(r#"
  ╔═══════════════════════════════════════════════════════════════╗
  ║                 CORESYNC USB GATEKEEPER                       ║
  ║       Ultra-Lightweight Air-Gapped Storage Protection         ║
  ║   [FAZ 1, 2, 3 & 4 - TEST HARNESS, RESCUE & AIR-GAPPED EDR]   ║
  ╚═══════════════════════════════════════════════════════════════╝
    "#);
}

fn print_status(config: &Config) {
    println!("================== SİSTEM VE AYAR DURUMU ==================");
    println!("Versiyon                   : {}", config.version);
    println!("Arka Plan İzleme (Sentry) : {}", if config.background_monitoring { "AKTİF" } else { "KAPALI (On-Demand)" });
    println!("Explorer Otomatik Baskılama: {}", if config.auto_suppress_explorer { "AKTİF" } else { "KAPALI" });
    println!("NTFS Bağışıklama (ACL)     : {}", if config.enable_ntfs_immunization { "AKTİF" } else { "KAPALI" });
    println!("Portable Kurtarma Ajanı    : {}", if config.create_portable_rescue { "AKTİF" } else { "KAPALI" });
    println!("Karantina Dizini           : {}", config.quarantine_folder);
    println!("Entropi Şüphe Eşiği        : > {:.2}", config.entropy_threshold);
    println!("Azami Tarama Boyutu        : {} MB", config.max_scan_file_size_mb);
    println!("-----------------------------------------------------------");
    println!("Sistemde Algılanan Mantıksal Sürücüler:");
    let drives = enumerate_all_drives();
    if drives.is_empty() {
        println!("  (Sürücü tespit edilemedi)");
    } else {
        for (path, desc, is_rem) in drives {
            let tag = if is_rem { "[USB/REMOVABLE]" } else { "[SABIT/DIGER]" };
            let imm_status = check_immunization_status(&path);
            let imm_tag = if imm_status.is_immunized { "[BAĞIŞIKLI]" } else { "[AÇIK]" };
            println!("  * {:<5} | {:<16} | {:<10} | {} ({})", path, tag, imm_tag, desc, imm_status.fs_type.as_str());
        }
    }
    println!("===========================================================\n");
}

fn print_help() {
    println!(r#"
Kullanım:
  coresync-usb-gatekeeper.exe [SEÇENEKLER]

Faz 4 Test Paketi ve Taşınabilir Kurtarma Komutları:
  --test-suite [HEDEF_KLASÖR]  Sentetik Güvenlik ve Tehdit Doğrulama Paketini (EICAR, Çift Uzantı, RTLO, Solucan, Aşı) koşturur.
  --deploy-rescue <SÜRÜCÜ>     Sürücüye bağımsız kurtarma ajanını ('sentry_portable.exe') ve anlık 'sentry.manifest'i konuşlandırır.

Faz 3 Bağışıklama, İzin ve Karantina Komutları:
  --immunize <SÜRÜCÜ>          Sürücüyü bağışıklar (NTFS için Kök ACL kilidi + 'Paylasim' klasörü; FAT için 'autorun.inf' aşı klasörü).
  --deimmunize <SÜRÜCÜ>        Bağışıklığı kaldırır ve izinleri fabrika varsayılanına döndürür.
  --clean-shortcuts <SÜRÜCÜ>   Kısayol virüslerini (.lnk) temizler ve gizlenen (+h +s) orijinal klasörleri onarır.
  --quarantine-list <SÜRÜCÜ>   Karantina havuzundaki (.sentry_quarantine) izole edilmiş dosyaları listeler.
  --restore <SÜRÜCÜ> <DOSYA>   Karantinadaki dosyayı XOR şifresini çözerek ve SHA-256 bütünlüğünü teyit ederek kurtarır.

Faz 2 & Faz 1 Temel Komutlar:
  --scan <SÜRÜCÜ>              Sürücüyü tam güvenlik boru hattına sokar (Statik Analiz, Karantina, Attrib Onarımı, Bağışıklama, Kurtarma Ajanı).
  --snapshot <SÜRÜCÜ>          Sürücüde referans SHA-256 'sentry.manifest' dosyası oluşturur.
  --diff <SÜRÜCÜ>              Sürücüyü sentry.manifest ile karşılaştırarak bütünlük farklarını raporlar.
  --rules                      Derleme zamanında gömülen YARA kurallarını ve imzaları listeler.

Çalışma Modları:
  --sentry                     Sentry modunu başlatır (Arka planda Win32 WM_DEVICECHANGE ile USB bekler).
  --on-demand                  On-demand modunda takılı tüm çıkarılabilir aygıtları tarar ve çıkar (0 process).
  --status                     Sistemdeki diskleri, dosya sistemlerini ve bağışıklık durumlarını listeler.
  --help, -h                   Bu yardım mesajını gösterir.

Örnekler:
  coresync-usb-gatekeeper.exe --test-suite
  coresync-usb-gatekeeper.exe --scan E:\
  coresync-usb-gatekeeper.exe --immunize E:\
  coresync-usb-gatekeeper.exe --deploy-rescue E:\
  coresync-usb-gatekeeper.exe --deimmunize E:\
  coresync-usb-gatekeeper.exe --clean-shortcuts E:\
  coresync-usb-gatekeeper.exe --quarantine-list E:\
  coresync-usb-gatekeeper.exe --restore E:\ fatura.pdf.exe
  coresync-usb-gatekeeper.exe --snapshot E:\
  coresync-usb-gatekeeper.exe --diff E:\
"#);
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let _ = std::fs::write("panic.log", format!("{:?}\n", info));
    }));

    #[cfg(windows)]
    unsafe {
        if windows_sys::Win32::System::Console::AttachConsole(u32::MAX) != 0 {
            use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_GENERIC_WRITE, FILE_SHARE_WRITE, OPEN_EXISTING};
            use windows_sys::Win32::System::Console::{SetStdHandle, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
            let conout: Vec<u16> = "CONOUT$\0".encode_utf16().collect();
            let handle = CreateFileW(
                conout.as_ptr(),
                FILE_GENERIC_WRITE,
                FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0 as _,
            );
            if handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                SetStdHandle(STD_OUTPUT_HANDLE, handle);
                SetStdHandle(STD_ERROR_HANDLE, handle);
            }
        }
    }

    let args: Vec<String> = std::env::args().collect();

    // Komut satırı parametreleri varsa CLI modunu işlet
    if args.len() > 1 && args[1] != "--gui" {

        print_banner();
        let config = load_config();

        match args[1].as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--status" => {
                print_status(&config);
                return;
            }
            "--rules" => {
                print_embedded_rules();
                return;
            }
            "--on-demand" => {
                println!("[*] Komut Satırı: On-Demand Modu seçildi.");
                run_on_demand_mode();
                return;
            }
            "--sentry" => {
                println!("[*] Komut Satırı: Sentry Modu seçildi.");
                run_sentry_mode(&config);
                return;
            }
            "--immunize" => {
                if args.len() > 2 {
                    let target = normalize_drive_arg(&args[2]);
                    match immunize_drive(&target, Some(DEFAULT_SHARED_FOLDER)) {
                        Ok(rep) => {
                            println!("\n[+] [BAŞARILI] Sürücü bağışıklandı: {}", rep.drive_path);
                            println!("    - Dosya Sistemi : {}", rep.fs_type.as_str());
                            println!("    - Detay         : {}", rep.message);
                        }
                        Err(err) => eprintln!("[-] [HATA] Bağışıklama başarısız: {}", err),
                    }
                } else {
                    eprintln!("[-] Hata: --immunize parametresi için sürücü harfi belirtilmedi (örn: --immunize E:\\).");
                }
                return;
            }
            "--deimmunize" => {
                if args.len() > 2 {
                    let target = normalize_drive_arg(&args[2]);
                    match deimmunize_drive(&target) {
                        Ok(rep) => {
                            println!("\n[+] [BAŞARILI] Sürücü bağışıklığı kaldırıldı: {}", rep.drive_path);
                            println!("    - Detay: {}", rep.message);
                        }
                        Err(err) => eprintln!("[-] [HATA] De-immunize başarısız: {}", err),
                    }
                } else {
                    eprintln!("[-] Hata: --deimmunize parametresi için sürücü harfi belirtilmedi (örn: --deimmunize E:\\).");
                }
                return;
            }
            "--clean-shortcuts" => {
                if args.len() > 2 {
                    let target = normalize_drive_arg(&args[2]);
                    let report = clean_shortcut_worm(&target);
                    report.print_report();
                } else {
                    eprintln!("[-] Hata: --clean-shortcuts parametresi için sürücü harfi belirtilmedi (örn: --clean-shortcuts E:\\).");
                }
                return;
            }
            "--quarantine-list" | "--list-quarantine" => {
                if args.len() > 2 {
                    let target = normalize_drive_arg(&args[2]);
                    match list_quarantine(&target) {
                        Ok(records) => print_quarantine_table(&target, &records),
                        Err(err) => eprintln!("[-] Karantina havuzu okunamadı: {}", err),
                    }
                } else {
                    eprintln!("[-] Hata: Karantina listesi için sürücü harfi belirtilmedi (örn: --quarantine-list E:\\).");
                }
                return;
            }
            "--restore" => {
                if args.len() > 3 {
                    let target = normalize_drive_arg(&args[2]);
                    let query = &args[3];
                    match restore_file(&target, query) {
                        Ok(rec) => {
                            println!("[+] [RESTORE] Dosya başarıyla kurtarıldı: {}", rec.original_relative_path);
                        }
                        Err(err) => eprintln!("[-] [HATA] Kurtarma işlemi başarısız: {}", err),
                    }
                } else {
                    eprintln!("[-] Hata: --restore için sürücü ve dosya adı/hash belirtilmelidir.");
                    eprintln!("    Kullanım: coresync-usb-gatekeeper.exe --restore <SÜRÜCÜ> <DOSYA_VEYA_HASH>");
                    eprintln!("    Örnek   : coresync-usb-gatekeeper.exe --restore E:\\ trojan.exe");
                }
                return;
            }
            "--snapshot" => {
                if args.len() > 2 {
                    let target = normalize_drive_arg(&args[2]);
                    run_create_snapshot(&target);
                } else {
                    eprintln!("[-] Hata: --snapshot parametresi için sürücü harfi belirtilmedi (örn: --snapshot E:\\).");
                }
                return;
            }
            "--diff" => {
                if args.len() > 2 {
                    let target = normalize_drive_arg(&args[2]);
                    run_diff_check(&target);
                } else {
                    eprintln!("[-] Hata: --diff parametresi için sürücü harfi belirtilmedi (örn: --diff E:\\).");
                }
                return;
            }
            "--scan" => {
                if args.len() > 2 {
                    let target = normalize_drive_arg(&args[2]);
                    println!("[*] Komut Satırı: Doğrudan sürücü pipeline tetiklendi -> {}", target);
                    trigger_pipeline(&target);
                } else {
                    eprintln!("[-] Hata: --scan parametresi için sürücü harfi belirtilmedi (örn: --scan E:\\).");
                }
                return;
            }
            "--deploy-rescue" => {
                if args.len() > 2 {
                    let target = normalize_drive_arg(&args[2]);
                    match portable::deploy_portable_rescue(&target, Some(DEFAULT_SHARED_FOLDER)) {
                        Ok(rep) => {
                            println!("\n[+] [BAŞARILI] Kurtarma ajanı konuşlandırıldı: {}", rep.portable_exe_path.display());
                        }
                        Err(err) => eprintln!("[-] [HATA] Kurtarma ajanı konuşlandırılamadı: {}", err),
                    }
                } else {
                    eprintln!("[-] Hata: --deploy-rescue için sürücü harfi belirtilmedi (örn: --deploy-rescue E:\\).");
                }
                return;
            }
            "--test-suite" => {
                let custom_path = if args.len() > 2 {
                    Some(Path::new(&args[2]))
                } else {
                    None
                };
                match harness::run_full_test_harness(custom_path) {
                    Ok(rep) => {
                        if !rep.is_success() {
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("[-] [Test Harness] Test paketi yürütme hatası: {}", e);
                        std::process::exit(1);
                    }
                }
                return;
            }
            unknown => {
                eprintln!("[-] Bilinmeyen argüman: {}", unknown);
                print_help();
                return;
            }
        }
    }

    // Parametre yoksa veya --gui ise Slint Grafik Arayüzünü (GUI) ve Sistem Tepsisini Başlat
    let _ = std::fs::write("debug_vectis.log", "main() calling gui::run_gui()\n");
    match gui::run_gui() {
        Ok(_) => {
            let _ = std::fs::write("debug_vectis.log", "main(): gui::run_gui() returned Ok(())\n");
        }
        Err(e) => {
            let _ = std::fs::write("gui_error.log", format!("GUI Error: {}\n", e));
            eprintln!("[-] [GUI Hatası] Grafik arayüz başlatılamadı: {}", e);
        }
    }
}
