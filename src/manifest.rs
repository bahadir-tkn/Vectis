//! ============================================================================
//! CoreSync USB Gatekeeper - Bütünlük ve Snapshot Manifestosu (sentry.manifest)
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Sıfır Harici Ağ Bağımlılığı)
//!
//! Bu modül:
//! 1. Güvenli bilgisayarda USB bellekteki tüm dosyaların SHA-256 özetini,
//!    göreceli yollarını ve dosya boyutlarını çıkaran Snapshot motorudur.
//! 2. USB yabancı bilgisayardan geri takıldığında sentry.manifest dosyasını okuyarak
//!    saniyeler içinde "Eklenen yeni dosyalar", "Değiştirilen/Bozulan dosyalar"
//!    ve "Silinen dosyalar" fark analizini (diff) eksiksiz raporlar.
//! ============================================================================

use crate::crypto::hash_file;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Varsayılan manifesto dosya adı
pub const DEFAULT_MANIFEST_FILENAME: &str = "sentry.manifest";

/// Taramada yok sayılacak özel dizin ve dosyalar
const IGNORED_NAMES: &[&str] = &[
    "sentry.manifest",
    "sentry.manifest.sig",
    "sentry_portable.exe",
    ".sentry_quarantine",
    "System Volume Information",
    "$RECYCLE.BIN",
    "desktop.ini",
    "Thumbs.db",
];

/// Tek bir dosyanın anlık görüntü (snapshot) kaydı
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FileSnapshotEntry {
    /// USB kök dizinine göre normalize edilmiş göreceli yol (örn: "Belgeler/Rapor.pdf")
    pub relative_path: String,
    /// Dosya boyutu (bayt cinsinden)
    pub file_size: u64,
    /// Küçük harfli 64 karakter SHA-256 özeti
    pub sha256: String,
    /// Son değiştirilme zamanı (UNIX epoch saniye)
    pub modified_timestamp: u64,
    /// Salt-okunur (read-only) niteliği
    pub is_readonly: bool,
}

/// Tüm USB biriminin bütünlük manifestosu
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SentryManifest {
    pub version: String,
    pub created_at_utc: String,
    pub drive_root: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub entries: Vec<FileSnapshotEntry>,
}

/// Değiştirilen veya bütünlüğü bozulan bir dosyanın detayları
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ModifiedFileDiff {
    pub relative_path: String,
    pub baseline_size: u64,
    pub current_size: u64,
    pub baseline_sha256: String,
    pub current_sha256: String,
    pub size_changed: bool,
    pub hash_changed: bool,
}

/// Manifesto Fark (Diff) ve Bütünlük Doğrulama Raporu
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ManifestDiffReport {
    pub baseline_created_at: String,
    pub added_files: Vec<FileSnapshotEntry>,
    pub modified_files: Vec<ModifiedFileDiff>,
    pub deleted_files: Vec<FileSnapshotEntry>,
    pub unchanged_count: usize,
    pub total_current_files: usize,
    pub total_baseline_files: usize,
    pub is_clean: bool,
}

// ============================================================================
// SNAPSHOT OLUŞTURMA VE DİSK İŞLEMLERİ
// ============================================================================

/// Verilen sürücü/dizin için eksiksiz SHA-256 Snapshot Manifestosu oluşturur
pub fn create_drive_snapshot(root_path: &Path) -> Result<SentryManifest, std::io::Error> {
    let mut entries = Vec::new();
    let mut total_bytes = 0u64;

    scan_dir_recursive(root_path, root_path, &mut entries, &mut total_bytes)?;

    // Belirleyici (deterministic) olması için göreceli yola göre sırala
    entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let now_utc = format!("{:?}", std::time::SystemTime::now());

    Ok(SentryManifest {
        version: "1.0.0".to_string(),
        created_at_utc: now_utc,
        drive_root: root_path.to_string_lossy().to_string(),
        total_files: entries.len(),
        total_bytes,
        entries,
    })
}

fn scan_dir_recursive(
    current_dir: &Path,
    root_path: &Path,
    entries: &mut Vec<FileSnapshotEntry>,
    total_bytes: &mut u64,
) -> Result<(), std::io::Error> {
    if !current_dir.is_dir() {
        return Ok(());
    }

    let read_dir = match fs::read_dir(current_dir) {
        Ok(rd) => rd,
        Err(err) => {
            eprintln!(
                "[-] [Snapshot] Dizin okunamadı ({:?}): {}",
                current_dir, err
            );
            return Ok(());
        }
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Yok sayılacak sistem/karantina/manifest dosyaları kontrolü
        if IGNORED_NAMES.iter().any(|&ig| name_str.eq_ignore_ascii_case(ig)) {
            continue;
        }

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Eğer autorun.inf bir aşı klasörüyse manifestoya dahil etme
        if meta.is_dir() && name_str.eq_ignore_ascii_case("autorun.inf") {
            continue;
        }

        if meta.is_dir() {
            scan_dir_recursive(&path, root_path, entries, total_bytes)?;
        } else if meta.is_file() {
            // Göreceli yolu hesapla ve ters slash'ları standartlaştır
            let rel_path = match path.strip_prefix(root_path) {
                Ok(p) => p.to_string_lossy().replace('\\', "/"),
                Err(_) => name_str.to_string(),
            };

            let file_size = meta.len();
            *total_bytes += file_size;

            let modified_timestamp = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let is_readonly = meta.permissions().readonly();

            // SHA-256 Özetini Akış Halinde Hesapla
            match hash_file(&path) {
                Ok(sha256) => {
                    entries.push(FileSnapshotEntry {
                        relative_path: rel_path,
                        file_size,
                        sha256,
                        modified_timestamp,
                        is_readonly,
                    });
                }
                Err(err) => {
                    eprintln!(
                        "[-] [Snapshot] Dosya hash'lenemedi ('{}'): {}",
                        path.display(),
                        err
                    );
                }
            }
        }
    }

    Ok(())
}

/// Manifestoyu hedef sürücünün kök dizinine pretty JSON olarak kaydeder
pub fn save_manifest_to_drive(
    manifest: &SentryManifest,
    drive_root: &Path,
) -> Result<PathBuf, std::io::Error> {
    let manifest_path = drive_root.join(DEFAULT_MANIFEST_FILENAME);
    let file = File::create(&manifest_path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(manifest_path)
}

/// Sürücüdeki mevcut `sentry.manifest` dosyasını okur
pub fn load_manifest_from_drive(drive_root: &Path) -> Result<SentryManifest, String> {
    let manifest_path = drive_root.join(DEFAULT_MANIFEST_FILENAME);
    if !manifest_path.exists() {
        return Err(format!(
            "Manifesto bulunamadı: '{}'",
            manifest_path.display()
        ));
    }

    let file = File::open(&manifest_path)
        .map_err(|e| format!("Manifesto dosyası açılamadı: {}", e))?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader)
        .map_err(|e| format!("Manifesto JSON formatı çözümlenemedi: {}", e))
}

// ============================================================================
// FARK (DIFF) VE BÜTÜNLÜK KARŞILAŞTIRMA MOTORU
// ============================================================================

/// Güvenli bilgisayarda oluşturulan referans manifesto ile yabancı bilgisayardan
/// dönen USB'nin anlık durumu arasındaki farkları (diff) mikrosaniyeler içinde hesaplar
pub fn compute_manifest_diff(
    baseline: &SentryManifest,
    current: &SentryManifest,
) -> ManifestDiffReport {
    let mut baseline_map: HashMap<&str, &FileSnapshotEntry> = HashMap::new();
    for entry in &baseline.entries {
        baseline_map.insert(entry.relative_path.as_str(), entry);
    }

    let mut current_map: HashMap<&str, &FileSnapshotEntry> = HashMap::new();
    for entry in &current.entries {
        current_map.insert(entry.relative_path.as_str(), entry);
    }

    let mut added_files = Vec::new();
    let mut modified_files = Vec::new();
    let mut unchanged_count = 0usize;

    // 1. Yeni Eklenen ve Değiştirilen/Bozulan Dosyaları Tespit Et
    for current_entry in &current.entries {
        if let Some(base_entry) = baseline_map.get(current_entry.relative_path.as_str()) {
            let size_changed = current_entry.file_size != base_entry.file_size;
            let hash_changed = current_entry.sha256 != base_entry.sha256;

            if size_changed || hash_changed {
                modified_files.push(ModifiedFileDiff {
                    relative_path: current_entry.relative_path.clone(),
                    baseline_size: base_entry.file_size,
                    current_size: current_entry.file_size,
                    baseline_sha256: base_entry.sha256.clone(),
                    current_sha256: current_entry.sha256.clone(),
                    size_changed,
                    hash_changed,
                });
            } else {
                unchanged_count += 1;
            }
        } else {
            // Referans manifestoda yok -> Yabancı bilgisayarda YENİ EKLENMİŞ
            added_files.push(current_entry.clone());
        }
    }

    // 2. Silinen Dosyaları Tespit Et
    let mut deleted_files = Vec::new();
    for base_entry in &baseline.entries {
        if !current_map.contains_key(base_entry.relative_path.as_str()) {
            deleted_files.push(base_entry.clone());
        }
    }

    let is_clean = added_files.is_empty() && modified_files.is_empty() && deleted_files.is_empty();

    ManifestDiffReport {
        baseline_created_at: baseline.created_at_utc.clone(),
        added_files,
        modified_files,
        deleted_files,
        unchanged_count,
        total_current_files: current.entries.len(),
        total_baseline_files: baseline.entries.len(),
        is_clean,
    }
}

/// Fark analizini renkli/vurgulu konsol çıktısı olarak yazdırır
pub fn print_diff_report(diff: &ManifestDiffReport) {
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       SENTRY.MANIFEST BÜTÜNLÜK VE FARK (DIFF) RAPORU          ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!("Referans Snapshot Tarihi : {}", diff.baseline_created_at);
    println!("Referanstaki Toplam Dosya: {}", diff.total_baseline_files);
    println!("Mevcut Durumdaki Dosya   : {}", diff.total_current_files);
    println!("Değişmeyen / Güvenli     : {} dosya", diff.unchanged_count);
    println!("---------------------------------------------------------------");

    if diff.is_clean {
        println!("[+] BÜTÜNLÜK TAM: Sürücü içeriğinde hiçbir değişiklik yapılmamış.");
        println!("    (0 Yeni, 0 Değiştirilen, 0 Silinen dosya).");
        return;
    }

    // 1. Yeni Eklenen Dosyalar
    if !diff.added_files.is_empty() {
        println!(
            "\n[!] DİKKAT: YABANCI BİLGİSAYARDAN YENİ EKLENEN DOSYALAR ({} Adet):",
            diff.added_files.len()
        );
        for f in &diff.added_files {
            println!(
                "    + [YENİ] {:<38} | {:>10} bayt | SHA256: {}..",
                f.relative_path,
                f.file_size,
                &f.sha256[..12]
            );
        }
    }

    // 2. Değiştirilen / Bütünlüğü Bozulan Dosyalar
    if !diff.modified_files.is_empty() {
        println!(
            "\n[!] KRİTİK UYARI: DEĞİŞTİRİLEN / ENFEKTE EDİLEN DOSYALAR ({} Adet):",
            diff.modified_files.len()
        );
        for m in &diff.modified_files {
            println!("    * [DEĞİŞTİ] {}", m.relative_path);
            if m.size_changed {
                println!(
                    "      -> Boyut Değişimi: {} bayt -> {} bayt",
                    m.baseline_size, m.current_size
                );
            }
            if m.hash_changed {
                println!(
                    "      -> SHA256 Değişimi: {}.. -> {}..",
                    &m.baseline_sha256[..12],
                    &m.current_sha256[..12]
                );
            }
        }
    }

    // 3. Silinen Dosyalar
    if !diff.deleted_files.is_empty() {
        println!(
            "\n[-] BİLGİ: SÜRÜCÜDEN SİLİNEN DOSYALAR ({} Adet):",
            diff.deleted_files.len()
        );
        for d in &diff.deleted_files {
            println!("    - [SİLİNDİ] {} ({} bayt)", d.relative_path, d.file_size);
        }
    }

    println!("\n===============================================================");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_diff_logic() {
        let base_entry1 = FileSnapshotEntry {
            relative_path: "doc.txt".to_string(),
            file_size: 100,
            sha256: "aaaa".to_string(),
            modified_timestamp: 1000,
            is_readonly: false,
        };
        let base_entry2 = FileSnapshotEntry {
            relative_path: "deleted.exe".to_string(),
            file_size: 500,
            sha256: "bbbb".to_string(),
            modified_timestamp: 1000,
            is_readonly: false,
        };

        let baseline = SentryManifest {
            version: "1.0.0".to_string(),
            created_at_utc: "2026-10-05".to_string(),
            drive_root: "E:\\".to_string(),
            total_files: 2,
            total_bytes: 600,
            entries: vec![base_entry1.clone(), base_entry2],
        };

        // Current state: doc.txt modified, deleted.exe removed, new_malware.exe added
        let cur_entry1 = FileSnapshotEntry {
            relative_path: "doc.txt".to_string(),
            file_size: 150, // Changed size
            sha256: "cccc".to_string(), // Changed hash
            modified_timestamp: 1050,
            is_readonly: false,
        };
        let cur_entry3 = FileSnapshotEntry {
            relative_path: "new_malware.exe".to_string(),
            file_size: 2048,
            sha256: "dddd".to_string(),
            modified_timestamp: 1050,
            is_readonly: false,
        };

        let current = SentryManifest {
            version: "1.0.0".to_string(),
            created_at_utc: "2026-10-06".to_string(),
            drive_root: "E:\\".to_string(),
            total_files: 2,
            total_bytes: 2198,
            entries: vec![cur_entry1, cur_entry3],
        };

        let diff = compute_manifest_diff(&baseline, &current);
        assert!(!diff.is_clean);
        assert_eq!(diff.added_files.len(), 1);
        assert_eq!(diff.added_files[0].relative_path, "new_malware.exe");
        assert_eq!(diff.modified_files.len(), 1);
        assert_eq!(diff.modified_files[0].relative_path, "doc.txt");
        assert_eq!(diff.deleted_files.len(), 1);
        assert_eq!(diff.deleted_files[0].relative_path, "deleted.exe");
        assert_eq!(diff.unchanged_count, 0);
    }
}
