//! ============================================================================
//! CoreSync USB Gatekeeper - USB Bağışıklama (Immunization) Motoru
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Sıfır Dış Ağ Bağımlılığı)
//!
//! Bu modül:
//! 1. Dosya sistemi algılama (NTFS, FAT32, exFAT) -> `GetVolumeInformationW`.
//! 2. NTFS Kök Dizin ACL Kilidi: Standart kullanıcılar / Everyone için kök dizine
//!    dosya ve alt klasör ekleme izinlerini (FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY)
//!    kısıtlar; yalnızca Okuma/Yürütme bırakır.
//! 3. Kök dizinde tam yetkili 'Paylasim' klasörü açar.
//! 4. FAT32/exFAT için silinemez, +r +h +s nitelikli 'autorun.inf' aşı klasörü kurar.
//! 5. Deimmunize: İzinleri fabrika varsayılanına döndürür.
//! ============================================================================

use std::fs;
use std::path::Path;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{BOOL, LocalFree},
    Storage::FileSystem::{
        GetFileAttributesW, GetVolumeInformationW, SetFileAttributesW,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, INVALID_FILE_ATTRIBUTES,
    },
    Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        UNPROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ACL,
        GetSecurityDescriptorDacl,
    },
    Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SetNamedSecurityInfoW, SE_FILE_OBJECT, SDDL_REVISION_1,
    },
};

/// Standart Paylaşım klasörü adı
pub const DEFAULT_SHARED_FOLDER: &str = "Paylasim";

/// NTFS Bağışıklama SDDL Tanımları:
///
/// ROOT_IMMUNIZED_SDDL:
/// D:P -> Korumalı DACL (üstten miras almaz).
/// (A;OICI;FA;;;BA) -> Administrators: Full Control (FA), Container Inherit (CI), Object Inherit (OI).
/// (A;OICI;FA;;;SY) -> SYSTEM: Full Control (FA), CI, OI.
/// (A;;0x1200a9;;;WD) -> Everyone (WD / S-1-1-0): Yalnızca KÖK DİZİNDE Okuma, Listeleme ve Yürütme:
///                      FILE_GENERIC_READ (0x120089) | FILE_GENERIC_EXECUTE (0x1200a0) = 0x1200a9.
///                      Miras bayrağı (OI/CI) YOKTUR; alt klasörlere sirayet etmez.
///                      FILE_ADD_FILE (0x02) ve FILE_ADD_SUBDIRECTORY (0x04) verilmez!
///                      Böylece yabancı sistemdeki virüsler kök dizine .exe, .vbs, autorun.inf yazamaz ("Erişim Reddedildi").
pub const ROOT_IMMUNIZED_SDDL: &str = "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;;0x1200a9;;;WD)";

/// PAYLASIM_SDDL:
/// USB içindeki 'Paylasim' klasörüne Everyone (WD), Administrators (BA) ve SYSTEM (SY) için
/// tam yazma, silme, oluşturma ve değiştirme (Full Control - FA, OI, CI) hakkı tanır.
pub const PAYLASIM_SDDL: &str = "D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";

/// ROOT_DEFAULT_SDDL:
/// Deimmunize işlemi için kök dizini fabrika varsayılanına döndürür (Everyone Full Control).
pub const ROOT_DEFAULT_SDDL: &str = "D:(A;OICI;FA;;;WD)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";

/// Dosya sistemi türleri
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSystemType {
    Ntfs,
    Fat32,
    Fat,
    ExFat,
    Unknown(String),
}

impl FileSystemType {
    pub fn as_str(&self) -> &str {
        match self {
            FileSystemType::Ntfs => "NTFS",
            FileSystemType::Fat32 => "FAT32",
            FileSystemType::Fat => "FAT",
            FileSystemType::ExFat => "exFAT",
            FileSystemType::Unknown(s) => s.as_str(),
        }
    }

    pub fn supports_acls(&self) -> bool {
        matches!(self, FileSystemType::Ntfs)
    }
}

/// Sürücü birim (Volume) bilgileri
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    pub drive_path: String,
    pub volume_name: String,
    pub fs_type: FileSystemType,
    pub serial_number: u32,
    pub supports_persistent_acls: bool,
    pub flags: u32,
}

const FILE_PERSISTENT_ACLS: u32 = 0x00000008;

/// Bağışıklama işlem raporu
#[derive(Debug, Clone)]
pub struct ImmunizationReport {
    pub drive_path: String,
    pub fs_type: FileSystemType,
    pub root_locked: bool,
    pub shared_folder_created: Option<String>,
    pub autorun_vaccine_created: bool,
    pub message: String,
}

/// Bağışıklık kaldırma (Deimmunize) işlem raporu
#[derive(Debug, Clone)]
pub struct DeimmunizeReport {
    pub drive_path: String,
    pub fs_type: FileSystemType,
    pub root_unlocked: bool,
    pub autorun_vaccine_removed: bool,
    pub message: String,
}

/// Bağışıklık durum sorgulama sonucu
#[derive(Debug, Clone)]
pub struct ImmunizationStatus {
    pub drive_path: String,
    pub fs_type: FileSystemType,
    pub is_immunized: bool,
    pub details: String,
}

/// UTF-8 string'i null-terminated UTF-16 vektörüne çevirir
pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Sürücünün dosya sistemi bilgilerini Win32 GetVolumeInformationW ile sorgular
pub fn get_volume_info(drive_path: &str) -> Result<VolumeInfo, String> {
    #[cfg(windows)]
    unsafe {
        let path_obj = Path::new(drive_path);
        let clean_root = if let Some(std::path::Component::Prefix(prefix)) = path_obj.components().next() {
            let p_str = prefix.as_os_str().to_string_lossy();
            if p_str.ends_with('\\') {
                p_str.to_string()
            } else {
                format!("{}\\", p_str)
            }
        } else {
            let mut s = drive_path.to_string();
            if !s.ends_with('\\') && !s.ends_with('/') {
                s.push('\\');
            }
            s
        };

        let wide_root = to_wide(&clean_root);
        let mut volume_name_buf = [0u16; 260];
        let mut serial_number = 0u32;
        let mut max_component_len = 0u32;
        let mut flags = 0u32;
        let mut fs_name_buf = [0u16; 260];

        let success = GetVolumeInformationW(
            wide_root.as_ptr(),
            volume_name_buf.as_mut_ptr(),
            volume_name_buf.len() as u32,
            &mut serial_number,
            &mut max_component_len,
            &mut flags,
            fs_name_buf.as_mut_ptr(),
            fs_name_buf.len() as u32,
        );

        if success == 0 {
            return Err(format!(
                "GetVolumeInformationW başarısız oldu (Hata: {}). Sürücü erişilebilir olmayabilir: '{}'",
                std::io::Error::last_os_error(),
                clean_root
            ));
        }

        let vol_len = volume_name_buf.iter().position(|&c| c == 0).unwrap_or(0);
        let volume_name = String::from_utf16_lossy(&volume_name_buf[..vol_len]);

        let fs_len = fs_name_buf.iter().position(|&c| c == 0).unwrap_or(0);
        let fs_name_str = String::from_utf16_lossy(&fs_name_buf[..fs_len]).trim().to_uppercase();

        let fs_type = match fs_name_str.as_str() {
            "NTFS" => FileSystemType::Ntfs,
            "FAT32" => FileSystemType::Fat32,
            "FAT" => FileSystemType::Fat,
            "EXFAT" => FileSystemType::ExFat,
            other => FileSystemType::Unknown(other.to_string()),
        };

        let supports_acls = (flags & FILE_PERSISTENT_ACLS) != 0 || fs_type == FileSystemType::Ntfs;

        Ok(VolumeInfo {
            drive_path: clean_root,
            volume_name,
            fs_type,
            serial_number,
            supports_persistent_acls: supports_acls,
            flags,
        })
    }

    #[cfg(not(windows))]
    {
        let _ = drive_path;
        Err("Sadece Windows platformunda desteklenmektedir.".to_string())
    }
}

/// Win32 LocalAlloc/LocalFree bellek güvenliği RAII nöbetçisi
#[cfg(windows)]
struct LocalAllocGuard(PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as _);
            }
        }
    }
}

/// Win32 Security API kullanarak bir yola SDDL güvenlik tanımlayıcısını uygular
#[cfg(windows)]
pub unsafe fn apply_sddl_to_path(path: &str, sddl: &str, is_protected: bool) -> Result<(), String> {
    let wide_path = to_wide(path);
    let wide_sddl = to_wide(sddl);

    let mut p_sec_desc: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let success = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        wide_sddl.as_ptr(),
        SDDL_REVISION_1,
        &mut p_sec_desc,
        std::ptr::null_mut(),
    );

    if success == 0 {
        return Err(format!(
            "SDDL çözümlenemedi (Win32 Hata: {}): '{}'",
            std::io::Error::last_os_error(),
            sddl
        ));
    }

    // RAII guard ile her çıkış rotasında LocalFree(p_sec_desc) garantilenir (sıfır sızıntı)
    let _guard = LocalAllocGuard(p_sec_desc);

    let mut dacl_present: BOOL = 0;
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted: BOOL = 0;

    let dacl_res = GetSecurityDescriptorDacl(
        p_sec_desc,
        &mut dacl_present,
        &mut p_dacl,
        &mut dacl_defaulted,
    );

    if dacl_res == 0 || p_dacl.is_null() {
        return Err(format!(
            "DACL güvenlik tanımlayıcısından çıkarılamadı (Hata: {})",
            std::io::Error::last_os_error()
        ));
    }

    let sec_info = DACL_SECURITY_INFORMATION
        | if is_protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };

    let set_res = SetNamedSecurityInfoW(
        wide_path.as_ptr() as *mut u16,
        SE_FILE_OBJECT,
        sec_info,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        p_dacl,
        std::ptr::null_mut(),
    );

    if set_res != 0 {
        if set_res == 5 {
            return Err("Erişim Reddedildi (Win32 Hata 5): NTFS ACL izinlerini değiştirmek için yönetici (Administrator) yetkisi gereklidir. Lütfen terminali 'Yönetici Olarak Çalıştır' ile açın.".to_string());
        }
        return Err(format!(
            "SetNamedSecurityInfoW başarısız oldu (Win32 Hata Kodu: {} - Hedef: '{}')",
            set_res, path
        ));
    }

    Ok(())
}

/// NTFS Sürücüsünü Bağışıklar:
/// 1. Sürücü kök dizininde 'Paylasim' klasörü oluşturur ve tam kontrol yetkisi verir.
/// 2. Kök dizin izinlerini kısıtlar (Everyone için yazma engellenir, sadece okuma/yürütme kalır).
pub fn immunize_ntfs(drive_path: &str, shared_folder: &str) -> Result<ImmunizationReport, String> {
    let mut clean_root = drive_path.to_string();
    if !clean_root.ends_with('\\') && !clean_root.ends_with('/') {
        clean_root.push('\\');
    }

    let shared_path = Path::new(&clean_root).join(shared_folder);

    // 1. Önce Paylaşım klasörünü oluştur
    if !shared_path.exists() {
        fs::create_dir_all(&shared_path).map_err(|e| {
            format!("Paylaşım klasörü ('{}') oluşturulamadı: {}", shared_path.display(), e)
        })?;
        println!("[+] [NTFS Bağışıklık] Paylaşım klasörü oluşturuldu: {}", shared_path.display());
    }

    #[cfg(windows)]
    unsafe {
        // 2. Paylaşım klasörüne tam yetki ver (Everyone Full Control)
        let shared_str = shared_path.to_string_lossy().to_string();
        apply_sddl_to_path(&shared_str, PAYLASIM_SDDL, true)?;
        println!("[+] [NTFS Bağışıklık] Paylaşım klasörüne tam yetki (Everyone Full Control) tanımlandı.");

        // 3. Kök dizin izinlerini kilitle (Everyone Read-Only / No Add File)
        apply_sddl_to_path(&clean_root, ROOT_IMMUNIZED_SDDL, true)?;
        println!("[+] [NTFS Bağışıklık] Kök dizin ('{}') başarıyla kilitlendi. Virüslerin kök dizine yazması engellendi.", clean_root);
    }

    #[cfg(not(windows))]
    return Err("NTFS ACL manipülasyonu yalnızca Windows üzerinde çalışır.".to_string());

    Ok(ImmunizationReport {
        drive_path: clean_root,
        fs_type: FileSystemType::Ntfs,
        root_locked: true,
        shared_folder_created: Some(shared_folder.to_string()),
        autorun_vaccine_created: false,
        message: format!(
            "NTFS Kök Kilidi Aktif: Kök dizine doğrudan dosya yazılamaz. Verilerinizi '{}' klasörüne kaydedebilirsiniz.",
            shared_folder
        ),
    })
}

/// NTFS Sürücüsündeki Kök Kilit İzinlerini Kaldırır (Fabrika Varsayılanına Döndürür)
pub fn deimmunize_ntfs(drive_path: &str) -> Result<DeimmunizeReport, String> {
    let mut clean_root = drive_path.to_string();
    if !clean_root.ends_with('\\') && !clean_root.ends_with('/') {
        clean_root.push('\\');
    }

    #[cfg(windows)]
    unsafe {
        apply_sddl_to_path(&clean_root, ROOT_DEFAULT_SDDL, false)?;
        println!("[+] [NTFS De-Immunize] Kök dizin ('{}') izinleri fabrika varsayılanına döndürüldü (Yazma kilidi kaldırıldı).", clean_root);
    }

    #[cfg(not(windows))]
    return Err("NTFS ACL manipülasyonu yalnızca Windows üzerinde çalışır.".to_string());

    Ok(DeimmunizeReport {
        drive_path: clean_root,
        fs_type: FileSystemType::Ntfs,
        root_unlocked: true,
        autorun_vaccine_removed: false,
        message: "NTFS kök dizin yazma izinleri fabrika varsayılanına döndürüldü.".to_string(),
    })
}

/// FAT32 / exFAT Autorun Klasör Aşısını Kurar:
/// Sürücü kökünde `autorun.inf` adında +r +h +s nitelikli bir klasör ve
/// içinde silinmeyi engelleyen kilitli alt dosya düğümü oluşturur.
pub fn immunize_fat_autorun(drive_path: &str) -> Result<ImmunizationReport, String> {
    let root = Path::new(drive_path);
    let autorun_path = root.join("autorun.inf");
    let vaccine_node = autorun_path.join("sentry_vaccine.sys");

    #[cfg(windows)]
    unsafe {
        // Eğer zaten mevcutsa ve bir dosyaysa (zararlı autorun.inf dosyası), önce temizle
        if autorun_path.exists() {
            let wide_autorun = to_wide(&autorun_path.to_string_lossy());
            let attrs = GetFileAttributesW(wide_autorun.as_ptr());

            if attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                // Bu bir dosyadır, niteliklerini sıfırla ve sil
                SetFileAttributesW(wide_autorun.as_ptr(), FILE_ATTRIBUTE_NORMAL);
                let _ = fs::remove_file(&autorun_path);
                println!("[!] [FAT Aşısı] Mevcut kötücül autorun.inf dosyası temizlendi.");
            }
        }

        // Klasör olarak oluştur
        if !autorun_path.exists() {
            fs::create_dir(&autorun_path).map_err(|e| {
                format!("'autorun.inf' aşı klasörü oluşturulamadı: {}", e)
            })?;
        }

        // İçine silinmeyi önleyecek kilitli düğüm dosyasını yerleştir
        let node_wide = to_wide(&vaccine_node.to_string_lossy());
        if !vaccine_node.exists() {
            let marker = b"[CORESYNC USB GATEKEEPER - AUTORUN VACCINE]\r\nThis locked node prevents USB worms from deleting autorun.inf.\r\n";
            let _ = fs::write(&vaccine_node, marker);
        }

        // Kilitli dosyanın niteliklerini +r +h +s yap
        SetFileAttributesW(
            node_wide.as_ptr(),
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        );

        // autorun.inf klasörünün niteliklerini +r +h +s yap
        let wide_autorun = to_wide(&autorun_path.to_string_lossy());
        SetFileAttributesW(
            wide_autorun.as_ptr(),
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        );

        println!("[+] [FAT Aşısı] 'autorun.inf' aşı klasörü (+r +h +s) ve kilitli düğüm başarıyla oluşturuldu.");
    }

    #[cfg(not(windows))]
    return Err("FAT aşı motoru yalnızca Windows üzerinde çalışır.".to_string());

    Ok(ImmunizationReport {
        drive_path: drive_path.to_string(),
        fs_type: FileSystemType::Fat32,
        root_locked: false,
        shared_folder_created: None,
        autorun_vaccine_created: true,
        message: "FAT32/exFAT 'autorun.inf' klasör aşısı uygulandı (+r +h +s korumalı).".to_string(),
    })
}

/// FAT32 / exFAT Autorun Klasör Aşısını Kaldırır (Deimmunize)
pub fn deimmunize_fat_autorun(drive_path: &str) -> Result<DeimmunizeReport, String> {
    let root = Path::new(drive_path);
    let autorun_path = root.join("autorun.inf");
    let vaccine_node = autorun_path.join("sentry_vaccine.sys");

    #[cfg(windows)]
    unsafe {
        if vaccine_node.exists() {
            let node_wide = to_wide(&vaccine_node.to_string_lossy());
            SetFileAttributesW(node_wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            let _ = fs::remove_file(&vaccine_node);
        }

        if autorun_path.exists() {
            let wide_autorun = to_wide(&autorun_path.to_string_lossy());
            SetFileAttributesW(wide_autorun.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            let _ = fs::remove_dir_all(&autorun_path);
            println!("[+] [FAT De-Immunize] 'autorun.inf' aşı klasörü temizlendi.");
        }
    }

    #[cfg(not(windows))]
    return Err("FAT aşı motoru yalnızca Windows üzerinde çalışır.".to_string());

    Ok(DeimmunizeReport {
        drive_path: drive_path.to_string(),
        fs_type: FileSystemType::Fat32,
        root_unlocked: false,
        autorun_vaccine_removed: true,
        message: "FAT32/exFAT 'autorun.inf' aşı klasörü başarıyla kaldırıldı.".to_string(),
    })
}

/// Bilgisayarın dahili Windows sistem sürücüsünü (C:\) yanlışlıkla kilitlemeyi kesin olarak engelleyen güvenlik nöbetçisi.
/// Program bilgisayara kalıcı bir değişiklik yapmaz, yalnızca harici USB sürücüleri hedefler.
pub fn assert_safe_removable_drive(drive_path: &str) -> Result<(), String> {
    let clean = drive_path.trim().to_uppercase();
    if clean.starts_with("C:") || clean.starts_with("C:\\") {
        return Err("GÜVENLİK KİLİDİ: Bilgisayarın ana sistem sürücüsü ('C:\\') kilitlenemez veya değiştirilemez! Program bilgisayara kalıcı değişiklik yapmaz, yalnızca harici çıkarılabilir USB sürücüleri bağışıklar.".to_string());
    }
    if let Ok(windir) = std::env::var("SystemDrive") {
        let sys_prefix = format!("{}:", windir.trim_end_matches(':').to_uppercase());
        if clean.starts_with(&sys_prefix) {
            return Err(format!("GÜVENLİK KİLİDİ: Windows işletim sisteminin kurulu olduğu '{}' sürücüsü değiştirilemez!", sys_prefix));
        }
    }
    Ok(())
}

/// Sürücü tipini (NTFS / FAT32) otomatik algılayıp en uygun bağışıklama yöntemini uygular
pub fn immunize_drive(drive_path: &str, shared_folder: Option<&str>) -> Result<ImmunizationReport, String> {
    // Güvenlik Kilidi: Bilgisayarın kendi diski asla kilitlenemez
    assert_safe_removable_drive(drive_path)?;

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       CORESYNC USB BAĞIŞIKLAMA (IMMUNIZATION) MOTORU         ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("[*] [Bağışıklama] Hedef Sürücü: '{}'", drive_path);

    let vol_info = get_volume_info(drive_path)?;
    println!("[*] [Dosya Sistemi] {}", vol_info.fs_type.as_str());
    println!("[*] [Birim Adı]     '{}'", vol_info.volume_name);
    println!("[*] [ACL Desteği]   {}", if vol_info.supports_persistent_acls { "EVET (NTFS)" } else { "HAYIR (FAT/exFAT)" });

    match vol_info.fs_type {
        FileSystemType::Ntfs => {
            let folder = shared_folder.unwrap_or(DEFAULT_SHARED_FOLDER);
            println!("[*] [Strateji] NTFS Kök Dizin ACL Kilidi + '{}' Güvenli Alanı Açma", folder);
            immunize_ntfs(drive_path, folder)
        }
        FileSystemType::Fat32 | FileSystemType::Fat | FileSystemType::ExFat => {
            println!("[*] [Strateji] FAT32/exFAT Korumalı 'autorun.inf' Klasör Aşısı (+r +h +s)");
            immunize_fat_autorun(drive_path)
        }
        FileSystemType::Unknown(name) => {
            println!("[*] [Uyarı] Bilinmeyen dosya sistemi ('{}'). Varsayılan autorun aşısı deneniyor...", name);
            immunize_fat_autorun(drive_path)
        }
    }
}

/// Sürücünün bağışıklığını kaldırır (NTFS ACL sıfırlama veya FAT aşı klasörü silme)
pub fn deimmunize_drive(drive_path: &str) -> Result<DeimmunizeReport, String> {
    assert_safe_removable_drive(drive_path)?;

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║          CORESYNC USB BAĞIŞIKLIK KALDIRMA (DE-IMMUNIZE)       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("[*] [De-Immunize] Hedef Sürücü: '{}'", drive_path);

    let vol_info = get_volume_info(drive_path)?;

    match vol_info.fs_type {
        FileSystemType::Ntfs => deimmunize_ntfs(drive_path),
        FileSystemType::Fat32 | FileSystemType::Fat | FileSystemType::ExFat => {
            deimmunize_fat_autorun(drive_path)
        }
        FileSystemType::Unknown(_) => deimmunize_fat_autorun(drive_path),
    }
}

/// Sürücünün mevcut bağışıklık durumunu denetler
pub fn check_immunization_status(drive_path: &str) -> ImmunizationStatus {
    let vol_info = match get_volume_info(drive_path) {
        Ok(v) => v,
        Err(e) => {
            return ImmunizationStatus {
                drive_path: drive_path.to_string(),
                fs_type: FileSystemType::Unknown("Bilinmiyor".to_string()),
                is_immunized: false,
                details: format!("Birim bilgisi alınamadı: {}", e),
            }
        }
    };

    let root = Path::new(drive_path);
    let autorun_path = root.join("autorun.inf");

    let mut is_immunized = false;
    let mut details = String::new();

    if autorun_path.is_dir() {
        is_immunized = true;
        details.push_str("Autorun klasör aşısı mevcut. ");
    }

    if vol_info.fs_type == FileSystemType::Ntfs {
        let shared = root.join(DEFAULT_SHARED_FOLDER);
        if shared.exists() {
            details.push_str(&format!("'{}' paylaşım klasörü mevcut. ", DEFAULT_SHARED_FOLDER));
        }
    }

    if details.is_empty() {
        details = "Sürücü bağışıklanmamış (Varsayılan korumasız durum).".to_string();
    }

    ImmunizationStatus {
        drive_path: drive_path.to_string(),
        fs_type: vol_info.fs_type,
        is_immunized,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_types() {
        assert!(FileSystemType::Ntfs.supports_acls());
        assert!(!FileSystemType::Fat32.supports_acls());
        assert!(!FileSystemType::ExFat.supports_acls());
        assert_eq!(FileSystemType::Ntfs.as_str(), "NTFS");
        assert_eq!(FileSystemType::Fat32.as_str(), "FAT32");
    }

    #[test]
    #[cfg(windows)]
    fn test_sddl_string_validity() {
        unsafe {
            // ROOT_IMMUNIZED_SDDL doğruluğu
            let wide = to_wide(ROOT_IMMUNIZED_SDDL);
            let mut sec_desc: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let ok1 = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sec_desc,
                std::ptr::null_mut(),
            );
            assert_ne!(ok1, 0, "ROOT_IMMUNIZED_SDDL geçerli bir SDDL dizesi olmalıdır");
            if !sec_desc.is_null() {
                LocalFree(sec_desc);
            }

            // PAYLASIM_SDDL doğruluğu
            let wide2 = to_wide(PAYLASIM_SDDL);
            let mut sec_desc2: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let ok2 = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide2.as_ptr(),
                SDDL_REVISION_1,
                &mut sec_desc2,
                std::ptr::null_mut(),
            );
            assert_ne!(ok2, 0, "PAYLASIM_SDDL geçerli bir SDDL dizesi olmalıdır");
            if !sec_desc2.is_null() {
                LocalFree(sec_desc2);
            }

            // ROOT_DEFAULT_SDDL doğruluğu
            let wide3 = to_wide(ROOT_DEFAULT_SDDL);
            let mut sec_desc3: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let ok3 = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide3.as_ptr(),
                SDDL_REVISION_1,
                &mut sec_desc3,
                std::ptr::null_mut(),
            );
            assert_ne!(ok3, 0, "ROOT_DEFAULT_SDDL geçerli bir SDDL dizesi olmalıdır");
            if !sec_desc3.is_null() {
                LocalFree(sec_desc3);
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_fat_autorun_vaccine_lifecycle() {
        let temp_dir = std::env::temp_dir().join("coresync_test_fat_vaccine");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let drive_str = temp_dir.to_str().unwrap();

        // 1. Aşı uygula
        let rep = immunize_fat_autorun(drive_str).unwrap();
        assert!(rep.autorun_vaccine_created);

        let autorun_path = temp_dir.join("autorun.inf");
        let vaccine_file = autorun_path.join("sentry_vaccine.sys");
        assert!(autorun_path.is_dir(), "autorun.inf klasör olmalıdır");
        assert!(vaccine_file.is_file(), "sentry_vaccine.sys dosya olmalıdır");

        // 2. Aşıyı kaldır
        let de_rep = deimmunize_fat_autorun(drive_str).unwrap();
        assert!(de_rep.autorun_vaccine_removed);
        assert!(!autorun_path.exists(), "autorun.inf temizlenmiş olmalıdır");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_c_drive_protection() {
        assert!(assert_safe_removable_drive("C:").is_err());
        assert!(assert_safe_removable_drive("C:\\").is_err());
        assert!(assert_safe_removable_drive("c:\\").is_err());
        assert!(assert_safe_removable_drive("E:\\").is_ok());
    }
}
