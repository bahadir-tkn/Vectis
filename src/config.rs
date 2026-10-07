use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

fn default_entropy_threshold() -> f64 {
    7.2
}

fn default_max_scan_size() -> u64 {
    64
}

/// CoreSync USB Gatekeeper yapılandırma ayarları
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    /// Yapılandırma şema versiyonu
    pub version: String,
    /// Sentry modu (arka plan dinleme) aktif mi?
    /// true: Win32 mesaj döngüsüyle arka planda bekleme
    /// false: On-Demand modu (sistemde process kalmaz, manuel tetiklenir)
    pub background_monitoring: bool,
    /// USB takıldığında Windows Gezgini / AutoPlay açılışını baskılama
    pub auto_suppress_explorer: bool,
    /// Katman 2: NTFS kök dizin yazma kilidi ve aşı mekanizması
    pub enable_ntfs_immunization: bool,
    /// Katman 3: USB kök dizinine sentry_portable.exe ve manifest hazırlama
    pub create_portable_rescue: bool,
    /// İzole edilen şüpheli dosyaların XOR ile saklanacağı karantina dizini
    pub quarantine_folder: String,
    /// Shannon entropi şüphelilik eşik değeri (Varsayılan: 7.2)
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    /// Statik inceleme için taranacak azami dosya boyutu (MB)
    #[serde(default = "default_max_scan_size")]
    pub max_scan_file_size_mb: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            background_monitoring: true,
            auto_suppress_explorer: true,
            enable_ntfs_immunization: true,
            create_portable_rescue: true,
            quarantine_folder: ".sentry_quarantine".to_string(),
            entropy_threshold: 7.2,
            max_scan_file_size_mb: 64,
        }
    }
}

/// Yapılandırma dosyasının konumunu belirler.
/// Öncelik: 1) Çalışma dizini (`./config.json`), 2) Çalıştırılabilir dosyanın yanı.
pub fn get_config_path() -> PathBuf {
    let cwd_path = PathBuf::from("config.json");
    if cwd_path.exists() {
        return cwd_path;
    }

    if let Ok(mut exe_path) = std::env::current_exe() {
        exe_path.pop();
        let candidate = exe_path.join("config.json");
        if candidate.exists() {
            return candidate;
        }
    }

    cwd_path
}

/// `config.json` dosyasını yükler. Dosya mevcut değilse veya bozuksa
/// varsayılan ayarları oluşturup kaydeder.
pub fn load_config() -> Config {
    let path = get_config_path();

    if path.exists() {
        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Config>(&content) {
                Ok(cfg) => {
                    return cfg;
                }
                Err(err) => {
                    eprintln!(
                        "[-] [Config] Hata: Yapılandırma dosyası çözümlenemedi ({}). Varsayılan ayarlara dönülüyor.",
                        err
                    );
                }
            },
            Err(err) => {
                eprintln!(
                    "[-] [Config] Hata: Yapılandırma dosyası okunamadı ({}). Varsayılan ayarlara dönülüyor.",
                    err
                );
            }
        }
    }

    // Dosya yoksa veya okunamadıysa varsayılanı oluştur ve diske yaz
    let default_cfg = Config::default();
    if let Err(err) = save_config(&default_cfg, &path) {
        eprintln!(
            "[-] [Config] Uyarı: Varsayılan yapılandırma diske yazılamadı: {}",
            err
        );
    } else {
        println!("[+] [Config] Yeni varsayılan config.json oluşturuldu -> {:?}", path);
    }

    default_cfg
}

/// Belirtilen yapılandırmayı diske yazar.
pub fn save_config(config: &Config, path: &Path) -> Result<(), std::io::Error> {
    let serialized = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    fs::write(path, serialized)
}
