//! ============================================================================
//! CoreSync USB Gatekeeper - Tersinir Karantina Motoru (Reversible Quarantine)
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Sıfır Dış Ağ Bağımlılığı)
//!
//! Bu modül:
//! 1. Statik analizde (Faz 2) tespit edilen `[KRİTİK ZARARLI]` ve `[ŞÜPHELİ]`
//!    dosyaları doğrudan silmek yerine güvenli izolasyona alır.
//! 2. Kök dizinde gizli ve sistem nitelikli `.sentry_quarantine` dizini oluşturur.
//! 3. İzolasyon Yöntemi: Dosya içeriğini 64-baytlık simetrik XOR anahtarıyla şifreler,
//!    uzantısını `.locked` yapar ve karantina dizinine taşır. Böylece dosya
//!    Windows PE yükleyicisi veya script motoru tarafından asla yürütülemez.
//! 4. Karantina Veritabanı (`quarantine.json`): İzole edilen her dosyanın orijinal
//!    yolunu, boyutunu, SHA-256 özetini, zamanını ve tespit nedenini kaydeder.
//! 5. Geri Yükleme (Restore): İstenildiğinde yanlış pozitif durumlarında dosyayı
//!    XOR şifresini çözüp SHA-256 özetini doğrulayarak orijinal konumuna geri döndürür.
//! ============================================================================

use crate::crypto::sha256::sha256_digest;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_SYSTEM,
};

/// 64-baytlık simetrik, deterministik XOR karantina anahtarı (Air-Gapped)
pub const QUARANTINE_XOR_KEY: &[u8] =
    b"CoreSync_USB_Gatekeeper_Reversible_XOR_Quarantine_Key_AirGapped_2026";

/// Standart karantina dizini adı
pub const DEFAULT_QUARANTINE_DIR: &str = ".sentry_quarantine";

/// Karantina veritabanı dosya adı
pub const QUARANTINE_DB_FILENAME: &str = "quarantine.json";

/// Tek bir karantinaya alınmış dosyanın kayıt bilgisi
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct QuarantineRecord {
    pub id: String,
    pub original_relative_path: String,
    pub original_file_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub quarantined_at: String,
    pub threat_level: String,
    pub reason: String,
    pub locked_file_name: String,
}

/// Karantina veritabanı şeması
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct QuarantineDatabase {
    pub version: String,
    pub total_records: usize,
    pub records: Vec<QuarantineRecord>,
}

/// UTF-8 string'i null-terminated UTF-16 vektörüne çevirir
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Basit ve harici bağımlılıksız UTC zaman damgası üreticisi
fn current_timestamp_str() -> String {
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let total_secs = duration.as_secs();

    let sec = total_secs % 60;
    let min = (total_secs / 60) % 60;
    let hour = (total_secs / 3600) % 24;

    // Gün ve yıl hesaplama (Unix epoch 1970-01-01)
    let mut days = total_secs / 86400;
    let mut year = 1970;

    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 1;
    for &dim in &days_in_months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    let day = days + 1;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hour, min, sec
    )
}

/// Veri üzerinde in-place simetrik XOR dönüşümü uygular
/// Çift uygulama orijinal veriyi tam olarak geri verir: xor(xor(data)) == data.
pub fn xor_transform(data: &mut [u8]) {
    let key_len = QUARANTINE_XOR_KEY.len();
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= QUARANTINE_XOR_KEY[i % key_len];
    }
}

/// Karantina dizin yolunu döndürür
pub fn get_quarantine_dir(drive_path: &str) -> PathBuf {
    let mut clean_root = drive_path.to_string();
    if !clean_root.ends_with('\\') && !clean_root.ends_with('/') {
        clean_root.push('\\');
    }
    Path::new(&clean_root).join(DEFAULT_QUARANTINE_DIR)
}

/// Karantina dizinini oluşturur ve Windows sistem + gizli niteliklerini atar
pub fn ensure_quarantine_dir(drive_path: &str) -> Result<PathBuf, String> {
    let q_dir = get_quarantine_dir(drive_path);
    if !q_dir.exists() {
        fs::create_dir_all(&q_dir).map_err(|e| {
            format!("Karantina dizini oluşturulamadı ('{}'): {}", q_dir.display(), e)
        })?;
    }

    #[cfg(windows)]
    unsafe {
        let wide = to_wide(&q_dir.to_string_lossy());
        SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }

    Ok(q_dir)
}

/// Karantina veritabanını (`quarantine.json`) okur
pub fn load_quarantine_db(drive_path: &str) -> QuarantineDatabase {
    let db_path = get_quarantine_dir(drive_path).join(QUARANTINE_DB_FILENAME);
    if db_path.exists() {
        if let Ok(content) = fs::read_to_string(&db_path) {
            if let Ok(db) = serde_json::from_str::<QuarantineDatabase>(&content) {
                return db;
            }
        }
    }

    QuarantineDatabase {
        version: "1.0.0".to_string(),
        total_records: 0,
        records: Vec::new(),
    }
}

/// Karantina veritabanını diske kaydeder
pub fn save_quarantine_db(drive_path: &str, db: &QuarantineDatabase) -> Result<(), String> {
    let q_dir = ensure_quarantine_dir(drive_path)?;
    let db_path = q_dir.join(QUARANTINE_DB_FILENAME);

    let serialized = serde_json::to_string_pretty(db)
        .map_err(|e| format!("Karantina veritabanı serileştirilemedi: {}", e))?;

    fs::write(&db_path, serialized)
        .map_err(|e| format!("Karantina veritabanı yazılamadı ('{}'): {}", db_path.display(), e))?;

    Ok(())
}

/// Belirtilen dosyayı şifreleyerek karantina dizinine izole eder
pub fn quarantine_file(
    drive_path: &str,
    file_path: &Path,
    rel_path: &str,
    sha256: &str,
    threat_level: &str,
    reason: &str,
) -> Result<QuarantineRecord, String> {
    if !file_path.exists() {
        return Err(format!("Karantinaya alınacak dosya bulunamadı: {}", file_path.display()));
    }

    // 1. Orijinal dosyayı oku
    let mut file_bytes = fs::read(file_path).map_err(|e| {
        format!("Karantinaya alınacak dosya okunamadı ('{}'): {}", file_path.display(), e)
    })?;

    let file_size = file_bytes.len() as u64;

    // 2. SHA-256 doğrulaması veya hesaplanması
    let actual_sha256 = if sha256.is_empty() || sha256 == "hash_error" {
        sha256_digest(&file_bytes)
    } else {
        sha256.to_string()
    };

    let db = load_quarantine_db(drive_path);

    // 3. Benzersiz kimlik oluştur (Hash çakışmalarında göreceli yol ile ayrıştır)
    let base_id = if actual_sha256.len() >= 10 {
        actual_sha256[..10].to_string()
    } else {
        format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis())
    };

    let short_id = if db.records.iter().any(|r| r.id == base_id && r.original_relative_path != rel_path) {
        let path_hash = sha256_digest(rel_path.as_bytes());
        format!("{}_{}", base_id, &path_hash[..4])
    } else {
        base_id
    };

    let locked_name = format!("{}.locked", short_id);

    // 4. Karantina dizinini hazırla
    let q_dir = ensure_quarantine_dir(drive_path)?;
    let locked_path = q_dir.join(&locked_name);

    // 5. İçeriği XOR anahtarı ile şifrele (PE başlıkları, scriptler çalışmaz hale gelir)
    xor_transform(&mut file_bytes);

    // 6. Şifreli dosyayı .sentry_quarantine/<short_id>.locked olarak yaz
    fs::write(&locked_path, &file_bytes).map_err(|e| {
        format!("Şifreli karantina dosyası yazılamadı ('{}'): {}", locked_path.display(), e)
    })?;

    // 7. Orijinal virüslü dosyayı güvenle sil (Salt-okunur niteliği varsa önce kaldır)
    #[cfg(windows)]
    unsafe {
        let wide = to_wide(&file_path.to_string_lossy());
        SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
    }

    fs::remove_file(file_path).map_err(|e| {
        format!("Orijinal dosya silinemedi ('{}'): {}", file_path.display(), e)
    })?;

    // 8. Karantina veritabanına kaydı işle
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let record = QuarantineRecord {
        id: short_id,
        original_relative_path: rel_path.to_string(),
        original_file_name: file_name,
        file_size,
        sha256: actual_sha256,
        quarantined_at: current_timestamp_str(),
        threat_level: threat_level.to_string(),
        reason: reason.to_string(),
        locked_file_name: locked_name,
    };

    let mut db = load_quarantine_db(drive_path);
    // Aynı ID varsa güncelle, yoksa ekle
    db.records.retain(|r| r.id != record.id);
    db.records.push(record.clone());
    db.total_records = db.records.len();
    save_quarantine_db(drive_path, &db)?;

    println!(
        "[+] [Karantina] Dosya izole edildi -> ID: '{}' | Orijinal: '{}' | Sebep: '{}'",
        record.id, record.original_relative_path, record.reason
    );

    Ok(record)
}

/// Karantinadaki bir dosyayı çözerek orijinal konumuna geri döndürür (Restore)
pub fn restore_file(drive_path: &str, query: &str) -> Result<QuarantineRecord, String> {
    let mut clean_root = drive_path.to_string();
    if !clean_root.ends_with('\\') && !clean_root.ends_with('/') {
        clean_root.push('\\');
    }

    let mut db = load_quarantine_db(drive_path);
    if db.records.is_empty() {
        return Err(format!(
            "Sürücüdeki karantina veritabanı boş veya mevcut değil: '{}'",
            drive_path
        ));
    }

    let clean_query = query.trim().to_lowercase();

    // ID, hash başlangıcı, dosya adı, orijinal yol veya locked adı ile eşleştir
    let pos = db.records.iter().position(|r| {
        r.id.to_lowercase() == clean_query
            || r.sha256.to_lowercase().starts_with(&clean_query)
            || r.original_file_name.to_lowercase() == clean_query
            || r.original_relative_path.to_lowercase() == clean_query
            || r.locked_file_name.to_lowercase() == clean_query
    });

    let index = match pos {
        Some(i) => i,
        None => {
            return Err(format!(
                "Karantina kaydı bulunamadı: '{}'. '--quarantine-list {}' ile mevcut kayıtları inceleyebilirsiniz.",
                query, drive_path
            ));
        }
    };

    let record = db.records[index].clone();
    let q_dir = get_quarantine_dir(drive_path);
    let locked_path = q_dir.join(&record.locked_file_name);

    if !locked_path.exists() {
        return Err(format!(
            "Karantinadaki kilitli dosya bulunamadı: '{}'",
            locked_path.display()
        ));
    }

    // 1. Kilitli dosyayı oku
    let mut encrypted_bytes = fs::read(&locked_path).map_err(|e| {
        format!("Karantina dosyası okunamadı ('{}'): {}", locked_path.display(), e)
    })?;

    // 2. XOR şifresini çöz
    xor_transform(&mut encrypted_bytes);

    // 3. SHA-256 bütünlüğünü doğrula
    let restored_hash = sha256_digest(&encrypted_bytes);
    if !restored_hash.eq_ignore_ascii_case(&record.sha256) {
        return Err(format!(
            "Bütünlük Doğrulama Hatası: Kurtarılan dosyanın SHA-256 özeti ({}) ile kayıtlı özet ({}) eşleşmiyor!",
            restored_hash, record.sha256
        ));
    }

    // 4. Hedef geri yükleme yolunu hazırla
    let target_path = Path::new(&clean_root).join(&record.original_relative_path);
    if let Some(parent) = target_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                format!("Geri yükleme dizini oluşturulamadı ('{}'): {}", parent.display(), e)
            })?;
        }
    }

    // 5. Dosyayı orijinal konumuna yaz
    fs::write(&target_path, &encrypted_bytes).map_err(|e| {
        format!("Kurtarılan dosya yazılamadı ('{}'): {}", target_path.display(), e)
    })?;

    // 6. Karantinadaki .locked dosyasını sil
    let _ = fs::remove_file(&locked_path);

    // 7. Veritabanından kaydı kaldır ve kaydet
    db.records.remove(index);
    db.total_records = db.records.len();
    save_quarantine_db(drive_path, &db)?;

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       KARANTİNADAN GERİ YÜKLEME (RESTORE) BAŞARILI            ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("Dosya Adı       : {}", record.original_file_name);
    println!("Hedef Konum     : {}", target_path.display());
    println!("Boyut           : {} bayt", record.file_size);
    println!("SHA-256 (Teyit) : {}", restored_hash);
    println!("---------------------------------------------------------------");
    println!("[+] Dosya XOR şifresi çözülerek ve bütünlüğü doğrulanarak kurtarıldı.");
    println!("===============================================================\n");

    Ok(record)
}

/// Sürücüdeki tüm karantina kayıtlarını listeler
pub fn list_quarantine(drive_path: &str) -> Result<Vec<QuarantineRecord>, String> {
    let db = load_quarantine_db(drive_path);
    Ok(db.records)
}

/// Karantina kayıtlarını terminale tablo formatında basar
pub fn print_quarantine_table(drive_path: &str, records: &[QuarantineRecord]) {
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       CORESYNC GÜVENLİ KARANTİNA HAVUZU (.sentry_quarantine)   ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("Hedef Sürücü          : {}", drive_path);
    println!("Karantinadaki Dosyalar: {}\n", records.len());

    if records.is_empty() {
        println!("[*] Karantina havuzu boş. Bu sürücüde izole edilmiş dosya bulunmuyor.");
        println!("===============================================================\n");
        return;
    }

    println!("{:<14} | {:<22} | {:<10} | {:<12} | {}", "ID", "DOSYA ADI", "BOYUT", "TEHDİT", "SEBEP / YARA");
    println!("-----------------------------------------------------------------------------------------------");

    for r in records {
        let size_str = if r.file_size < 1024 {
            format!("{} B", r.file_size)
        } else if r.file_size < 1024 * 1024 {
            format!("{:.1} KB", r.file_size as f64 / 1024.0)
        } else {
            format!("{:.1} MB", r.file_size as f64 / (1024.0 * 1024.0))
        };

        let file_disp = if r.original_file_name.len() > 20 {
            format!("{}...", &r.original_file_name[..17])
        } else {
            r.original_file_name.clone()
        };

        println!(
            "{:<14} | {:<22} | {:<10} | {:<12} | {}",
            r.id, file_disp, size_str, r.threat_level, r.reason
        );
        println!("  -> Orijinal Konum: {}", r.original_relative_path);
        println!("  -> SHA256        : {}", r.sha256);
        println!("  -> Tarih         : {}", r.quarantined_at);
        println!("  -> Kilitli Dosya : {}", r.locked_file_name);
        println!("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
    }

    println!("\n[*] Dosyayı kurtarmak için: coresync --restore {} <ID_VEYA_DOSYA>", drive_path);
    println!("===============================================================\n");
}

/// Karantinadaki bir dosyayı ve veritabanı kaydını kalıcı olarak siler
pub fn delete_quarantined_record(drive_path: &str, query: &str) -> Result<QuarantineRecord, String> {
    let mut db = load_quarantine_db(drive_path);
    let clean_query = query.trim().to_lowercase();

    let pos = db.records.iter().position(|r| {
        r.id.to_lowercase() == clean_query
            || r.sha256.to_lowercase().starts_with(&clean_query)
            || r.original_file_name.to_lowercase() == clean_query
            || r.original_relative_path.to_lowercase() == clean_query
            || r.locked_file_name.to_lowercase() == clean_query
    });

    let index = match pos {
        Some(i) => i,
        None => return Err(format!("Karantina kaydı bulunamadı: '{}'", query)),
    };

    let record = db.records.remove(index);
    let q_dir = get_quarantine_dir(drive_path);
    let locked_path = q_dir.join(&record.locked_file_name);
    if locked_path.exists() {
        let _ = fs::remove_file(&locked_path);
    }

    db.total_records = db.records.len();
    save_quarantine_db(drive_path, &db)?;

    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_symmetry() {
        let original = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00";
        let mut buffer = original.to_vec();

        // 1. Şifreleme
        xor_transform(&mut buffer);
        assert_ne!(buffer, original, "Şifrelenmiş veri orijinalinden farklı olmalıdır");
        assert_ne!(buffer[0], b'M', "PE MZ başlığı bozulmuş olmalıdır");

        // 2. Çözme
        xor_transform(&mut buffer);
        assert_eq!(buffer, original, "İkinci XOR işlemi orijinal veriyi birebir geri vermelidir");
    }

    #[test]
    fn test_quarantine_restore_cycle() {
        let temp_dir = std::env::temp_dir().join("coresync_test_quarantine");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let drive = temp_dir.to_str().unwrap();

        // Test dosyası oluştur
        let sample_file = temp_dir.join("payload.exe");
        let sample_content = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        fs::write(&sample_file, sample_content).unwrap();

        let sha = sha256_digest(sample_content);

        // Karantinaya al
        let record = quarantine_file(
            drive,
            &sample_file,
            "payload.exe",
            &sha,
            "CRITICAL",
            "Test Trojan",
        )
        .unwrap();

        assert!(!sample_file.exists(), "Orijinal dosya silinmiş olmalıdır");

        let q_dir = get_quarantine_dir(drive);
        let locked_file = q_dir.join(&record.locked_file_name);
        assert!(locked_file.exists(), "Kilitli dosya karantina klasöründe olmalıdır");

        // Listele
        let list = list_quarantine(drive).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, record.id);

        // Restore et
        let restored = restore_file(drive, &record.id).unwrap();
        assert_eq!(restored.original_file_name, "payload.exe");
        assert!(sample_file.exists(), "Orijinal dosya geri gelmiş olmalıdır");

        let restored_content = fs::read(&sample_file).unwrap();
        assert_eq!(restored_content, sample_content, "İçerik birebir aynı olmalıdır");

        // Karantina havuzu boşalmış olmalı
        let list_after = list_quarantine(drive).unwrap();
        assert_eq!(list_after.len(), 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
