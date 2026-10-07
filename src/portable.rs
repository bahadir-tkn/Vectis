//! ============================================================================
//! CoreSync USB Gatekeeper - Taşınabilir Kurtarma Ajanı (Portable Rescue) Motoru
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Sıfır Dış Ağ Bağımlılığı)
//!
//! Bu modül:
//! 1. USB bellek bağışıklandığında veya tarandığında Gatekeeper binary'sinin
//!    kendisini hafif ve bağımsız bir kurtarma aracı (`sentry_portable.exe`) olarak
//!    USB'nin kök dizinine (veya 'Paylasim' klasörüne) dağıtır.
//! 2. Yanına en güncel referans bütünlük manifestosunu (`sentry.manifest`) kaydeder.
//! 3. Böylece kullanıcı USB'yi yabancı, çevrimdışı bir bilgisayara taktığında
//!    internete veya kurulum yapmaya gerek kalmadan doğrudan USB içinden
//!    `sentry_portable.exe` çalıştırabilir, anlık fark (`--diff`) ve tehdit
//!    taraması (`--scan`) yapabilir.
//! ============================================================================

use crate::crypto::hash_file;
use crate::manifest::{create_drive_snapshot, save_manifest_to_drive};
use std::fs;
use std::path::{Path, PathBuf};

/// Taşınabilir kurtarma ajanı dosya adı
pub const PORTABLE_EXE_NAME: &str = "sentry_portable.exe";

/// Taşınabilir kurtarma aracı dağıtım raporu
#[derive(Debug, Clone)]
pub struct PortableDeployReport {
    pub drive_path: String,
    pub portable_exe_path: PathBuf,
    pub manifest_path: PathBuf,
    pub binary_size: u64,
    pub sha256: String,
    pub message: String,
}

impl PortableDeployReport {
    pub fn print_report(&self) {
        println!("\n╔═══════════════════════════════════════════════════════════════╗");
        println!("║       TAŞINABİLİR KURTARMA AJANI (PORTABLE RESCUE) HAZIR      ║");
        println!("╚═══════════════════════════════════════════════════════════════╝");
        println!("Hedef Sürücü          : {}", self.drive_path);
        println!("Kurtarma Ajanı Konumu : {}", self.portable_exe_path.display());
        println!("Referans Manifesto    : {}", self.manifest_path.display());
        println!(
            "Binary Boyutu         : {:.2} MB ({} bayt)",
            self.binary_size as f64 / (1024.0 * 1024.0),
            self.binary_size
        );
        println!("SHA-256 Özeti         : {}", self.sha256);
        println!("---------------------------------------------------------------");
        println!("[+] {}", self.message);
        println!("[*] Bu USB yabancı bilgisayara takıldığında doğrudan '{}'", PORTABLE_EXE_NAME);
        println!("    çalıştırılarak çevrimdışı tarama ve diff bütünlük denetimi yapılabilir.");
        println!("===============================================================\n");
    }
}

/// Çalışan geçerli ikili dosyanın (self executable) yolunu bulur
pub fn find_self_executable() -> Result<PathBuf, String> {
    if let Ok(exe_path) = std::env::current_exe() {
        if exe_path.is_file() {
            return Ok(exe_path);
        }
    }

    // Yedek arama yolları (target/release veya target/debug)
    let candidates = [
        PathBuf::from("Vectis.exe"),
        PathBuf::from("coresync-usb-gatekeeper.exe"),
        PathBuf::from("target/release/Vectis.exe"),
        PathBuf::from("target/release/coresync-usb-gatekeeper.exe"),
        PathBuf::from("target/debug/Vectis.exe"),
        PathBuf::from("target/debug/coresync-usb-gatekeeper.exe"),
    ];

    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err("Mevcut çalıştırılabilir dosya (self executable) konumu belirlenemedi.".to_string())
}

/// Taşınabilir kurtarma ajanını (`sentry_portable.exe`) ve `sentry.manifest`
/// dosyasını hedef sürücüye dağıtır.
pub fn deploy_portable_rescue(
    drive_path: &str,
    shared_folder: Option<&str>,
) -> Result<PortableDeployReport, String> {
    let mut clean_root = drive_path.to_string();
    if !clean_root.ends_with('\\') && !clean_root.ends_with('/') {
        clean_root.push('\\');
    }

    let root_path = Path::new(&clean_root);
    if !root_path.exists() {
        return Err(format!("Hedef sürücü mevcut değil: '{}'", clean_root));
    }

    // 1. Hedef yerleşim dizinini belirle:
    // Eğer Paylasim klasörü varsa hem Paylasim içine hem de kök dizine (mümkünse) konuşlandırılır.
    let shared_name = shared_folder.unwrap_or("Paylasim");
    let shared_path = root_path.join(shared_name);

    let deploy_dir = if shared_path.is_dir() {
        shared_path
    } else {
        root_path.to_path_buf()
    };

    let target_exe = deploy_dir.join(PORTABLE_EXE_NAME);

    // 2. Mevcut binary'yi bul ve hedef konuma kopyala
    let src_exe = find_self_executable()?;
    fs::copy(&src_exe, &target_exe).map_err(|e| {
        format!(
            "Kurtarma ajanı ('{}') kopyalanamadı -> Hedef ('{}'): {}",
            src_exe.display(),
            target_exe.display(),
            e
        )
    })?;

    let meta = fs::metadata(&target_exe).map_err(|e| {
        format!("Hedef binary meta verisi okunamadı: {}", e)
    })?;
    let binary_size = meta.len();

    // 3. Binary SHA-256 özetini hesapla
    let sha256 = hash_file(&target_exe).unwrap_or_else(|_| "hash_error".to_string());

    // 4. Güncel Snapshot Manifestosu oluştur ve kaydet
    let snapshot = create_drive_snapshot(root_path).map_err(|e| {
        format!("Sürücü snapshot manifestosu oluşturulamadı: {}", e)
    })?;

    // Manifestoyu hem deploy_dir içine hem de köke kaydet
    let manifest_path = save_manifest_to_drive(&snapshot, &deploy_dir).map_err(|e| {
        format!("Manifesto deploy dizinine kaydedilemedi: {}", e)
    })?;

    if deploy_dir != root_path {
        let _ = save_manifest_to_drive(&snapshot, root_path);
    }

    let message = format!(
        "Taşınabilir kurtarma ajanı '{}' ve anlık referans manifestosu başarıyla konuşlandırıldı.",
        PORTABLE_EXE_NAME
    );

    let report = PortableDeployReport {
        drive_path: clean_root,
        portable_exe_path: target_exe,
        manifest_path,
        binary_size,
        sha256,
        message,
    };

    report.print_report();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_self_executable() {
        let res = find_self_executable();
        assert!(res.is_ok(), "Self executable yolu bulunabilmelidir");
    }

    #[test]
    fn test_portable_deploy_cycle() {
        let temp_dir = std::env::temp_dir().join("coresync_test_portable");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // Bir test dokümanı ekle
        let doc_file = temp_dir.join("belge.txt");
        fs::write(&doc_file, b"test dokuman icerigi").unwrap();

        let drive_str = temp_dir.to_str().unwrap();

        let rep = deploy_portable_rescue(drive_str, None).unwrap();
        assert!(rep.portable_exe_path.exists());
        assert!(rep.manifest_path.exists());
        assert!(rep.binary_size > 0);
        assert!(!rep.sha256.is_empty());
        assert_ne!(rep.sha256, "hash_error");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
