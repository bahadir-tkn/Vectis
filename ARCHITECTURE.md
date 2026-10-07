# Vectis Mimarisi ve Kod Tabanı Denetim Kılavuzu (Architecture & Codebase Audit Guide)

> **Proje Adı:** Vectis (CoreSync USB Gatekeeper)  
> **Lisans:** MIT  
> **Platform:** Windows x64 (Windows 10, 11, Windows Server)  
> **Geliştirme Dili:** Saf Rust (2021 Edition) + Slint UI (v1.8.0)  
> **Güvenlik Felsefesi:** Air-Gapped (Çevrimdışı, Sıfır Dış Ağ/Soket Erişimi), Sıfır C/C++ Çalışma Zamanı Bağımlılığı, <10 MB RAM  

---

## 📑 İçindekiler
1. [Projenin Amacı ve Temel Vizyonu](#1-projenin-amacı-ve-temel-vizyonu)
2. [Güvenlik ve Mimari İlkeler](#2-güvenlik-ve-mimari-ilkeler)
3. [Sistem Mimarisi ve Savunma Katmanları](#3-sistem-mimarisi-ve-savunma-katmanları)
4. [Dizin Yapısı ve Modül Dağılımı](#4-dizin-yapısı-ve-modül-dağılımı)
5. [Tüm Modüllerin ve Kaynak Dosyaların Detaylı Analizi](#5-tüm-modüllerin-ve-kaynak-dosyaların-detaylı-analizi)
   - [5.1 `src/main.rs` - Giriş Noktası & CLI/GUI Yönlendirici](#51-srcmainrs)
   - [5.2 `src/detector.rs` - Win32 Donanım Olayları & AutoPlay Kancası](#52-srcdetectorrs)
   - [5.3 `src/scanner.rs` - Derinlemesine Statik Analiz Hattı](#53-srcscannerrs)
   - [5.4 `src/yara/` - Gömülü YARA Kural Motoru](#54-srcyara)
   - [5.5 `src/pe.rs` - PE Başlık ve W+X Bellek Anomali Analizcisi](#55-srcpers)
   - [5.6 `src/entropy.rs` - Shannon Entropisi ve Crypter Tespiti](#56-srcentropyrs)
   - [5.7 `src/immunizer.rs` - Dosya Sistemi Bağışıklama (NTFS DACL / FAT Aşısı)](#57-srcimmunizerrs)
   - [5.8 `src/quarantine.rs` - Tersinir 64-Bayt XOR Karantina Motoru](#58-srcquarantiners)
   - [5.9 `src/cleaner.rs` - Kısayol Solucanı & Attrib Onarıcısı](#59-srccleanerrs)
   - [5.10 `src/manifest.rs` - SHA-256 Bütünlük ve Snapshot Motoru](#510-srcmanifestrs)
   - [5.11 `src/portable.rs` - Taşınabilir Kurtarma Ajanı Dağıtımı](#511-srcportablers)
   - [5.12 `src/crypto/sha256.rs` - Saf Rust FIPS 180-4 Kripto Motoru](#512-srccryptosha256rs)
   - [5.13 `src/gui.rs` & `ui/appwindow.slint` - Sistem Tepsisi & Slint Arayüzü](#513-srcguirs--uiappwindowslint)
   - [5.14 `src/harness.rs` - Sentetik Test Paketi (Test Harness)](#514-srcharnessrs)
   - [5.15 `src/config.rs` - Yapılandırma Yönetimi](#515-srcconfigrs)
6. [Kritik Veri Yapıları ve Tipler](#6-kritik-veri-yapıları-ve-tipler)
7. [İş Akışları ve Senaryolar](#7-iş-akışları-ve-senaryolar)
8. [Kod Denetimi (Audit) ve Refactoring Notları](#8-kod-denetimi-audit-ve-refactoring-notları)
9. [Derleme, Test ve CI/CD](#9-derleme-test-ve-cicd)

---

## 1. Projenin Amacı ve Temel Vizyonu

**Vectis**, harici depolama birimleri (USB flash bellekler, harici taşınabilir diskler, hafıza kartları) üzerinden taşınan siber tehditleri (kısayol solucanları, LNK dropper'lar, VBS/Autorun stager'ları, gizlenmiş PE ikilileri, şifreli yükler) **işletim sistemi seviyesinde yakalamak, takılan ortamları dosya sistemi mimarisiyle bağışıklamak ve tersinir karantina altına almak** üzere tasarlanmış açık kaynaklı bir uç nokta savunma motorudur.

Geleneksel ağır antivirüslerin aksine Vectis:
- Sisteme sürücü (driver) veya kernel kancası (hook) kurmaz.
- İnternete veya bulut istihbaratına ihtiyaç duymaz (%100 çevrimdışı / air-gapped).
- Bellek ve CPU tüketimini sıfıra yakın tutar.
- Yalnızca harici çıkarılabilir depolama aygıtlarına odaklanarak kesin donanımsal koruma sağlar.

---

## 2. Güvenlik ve Mimari İlkeler

1. **Air-Gapped Güvencesi:** Projenin bağımlılıklarında (`Cargo.toml`) hiçbir ağ kütüphanesi (`reqwest`, `tokio::net`, raw socket, WinSock, HTTP istemcisi) yer almaz. Kod tabanında dış dünyayla ağ üzerinden haberleşebilecek tek bir fonksiyon bulunmaz.
2. **Sıfır C/C++ Çalışma Zamanı Bağımlılığı:** Harici dinamik kütüphanelere (`MSVCRT.dll`, `libyara.dll`, `VCRUNTIME140.dll` vb.) ihtiyaç duymaz. Saf Rust ve doğrudan Win32 API (`windows-sys`) çağrıları ile çalışır.
3. **Zararsızlık ve Tersinirlik (Non-Destructive & Reversible):** Dosyalar asla geri döndürülemez şekilde silinmez. Şüpheli dosyalar 64-bayt simetrik XOR ile şifrelenip `.sentry_quarantine` dizinine taşınır ve istenildiği an orijinal haline geri yüklenebilir.
4. **Ana Sisteme (C:\) Dokunmama:** Bilgisayarın yerel sistem dosyalarına veya kayıt defterine kalıcı müdahale yapılmaz. Tüm bağışıklık ve izolasyon hedef harici sürücü üzerinde gerçekleşir.
5. **Olay Güdümlü (Event-Driven) Sıfır Kaynak:** USB takılı değilken CPU tüketimi %0, RAM tüketimi <10 MB seviyesindedir.

---

## 3. Sistem Mimarisi ve Savunma Katmanları

```
                            [Harici USB Bellek Takıldı]
                                         │
                                         ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ KATMAN 1: Host-Side Gatekeeper (Donanım Dinleyici & Mod Yönetimi)            │
│ • Win32 WM_DEVICECHANGE & DBT_DEVTYP_VOLUME Dinleyicisi                       │
│ • Sürücü Harfi Çözümleme (Bitmask Unitmask -> D:\, E:\)                      │
│ • QueryCancelAutoPlay ile Windows Gezgini Otomatik Açılışını Baskılama       │
│ • Çift Mod: Sentry (<10 MB RAM, %0 CPU) veya On-Demand (0 Process)           │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                        │
                                        ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ KATMAN 2: Deep Static Analysis & Heuristic Engine (Çevrimdışı Tehdit Analizi)  │
│ • Gömülü Çevrimdışı YARA Motoru (8 Özelleştirilmiş USB Tehdit Kuralı)          │
│ • PE Başlık Analizcisi (MZ/PE Doğrulama, W+X Bellek Anomalisi, Packer Tespiti)│
│ • Shannon Entropi Heuristiği (>7.2 Eşikli Şifrelenmiş Yük Tespiti)            │
│ • Sahte Uzantı (Masquerading), Çift Uzantı ve Unicode RTLO (\u{202E}) Tespiti │
│ • FIPS 180-4 Saf Rust SHA-256 Kripto Motoru ile Streaming Özetleme           │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                        │
                                        ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ KATMAN 3: USB Immunizer, Reversible Quarantine & Portable Rescue Agent       │
│ • NTFS Kök Dizin Kilidi: Everyone FILE_ADD_FILE kısıtlaması & 'Paylasim' alanı│
│ • FAT32/exFAT Korumalı (+r +h +s) 'autorun.inf' Klasör Aşısı & Kilitli Düğüm │
│ • Kısayol Solucanı ('Attrib') Onarıcısı: -h -s Onarımı & Sahte .lnk Silimi    │
│ • 64-Bayt Simetrik XOR Tersinir Karantina (.sentry_quarantine & quarantine.json)│
│ • Bağımsız Taşınabilir Kurtarma Ajanı (sentry_portable.exe & sentry.manifest)│
└───────────────────────────────────────┬───────────────────────────────────────┘
                                        │
                                        ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ KATMAN 4: Windows Sistem Tepsisi & Modern Slint Kullanıcı Arayüzü             │
│ • Sağ alt köşe (Taskbar Tray Flyout) VPN tarzı mini pencere (340x440)         │
│ • Bellek içi RGBA Kalkan ikonu (Yeşil: Aktif Koruma, Gri: Pasif)             │
│ • Tek tıkla tarama, bağışıklama, onarım ve karantina yönetimi                 │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Dizin Yapısı ve Modül Dağılımı

```
Vectis/
├── .github/
│   └── workflows/
│       └── release.yml          # GitHub Actions CI/CD ve Release iş akışı
├── src/
│   ├── crypto/
│   │   ├── mod.rs               # Kripto modül dışa aktarımları
│   │   └── sha256.rs            # Saf Rust FIPS 180-4 SHA-256 motoru
│   ├── yara/
│   │   ├── rules/
│   │   │   └── usb_threats.yar  # Gömülü YARA kuralları (8 kural)
│   │   └── mod.rs               # Saf Rust gömülü YARA sözdizimi ve eşleştirici
│   ├── cleaner.rs               # Kısayol solucanı ve attrib onarıcısı
│   ├── config.rs                # config.json okuma/yazma yönetimi
│   ├── detector.rs              # Win32 WM_DEVICECHANGE dinleyici ve donanım kancası
│   ├── entropy.rs               # Shannon entropi hesaplayıcı (>7.2 eşik)
│   ├── gui.rs                   # Sistem tepsisi ve Slint arayüz köprüsü
│   ├── harness.rs               # Sentetik tehdit doğrulama paketi (--test-suite)
│   ├── immunizer.rs             # NTFS DACL kilidi ve FAT autorun aşısı
│   ├── main.rs                  # CLI bayrakları ve program giriş noktası
│   ├── manifest.rs              # sentry.manifest bütünlük ve diff motoru
│   ├── pe.rs                    # PE32/PE32+ başlık ve W+X bölüm analizcisi
│   ├── portable.rs              # Taşınabilir kurtarma ajanı dağıtım motoru
│   ├── quarantine.rs            # 64-bayt XOR tersinir karantina motoru
│   └── scanner.rs               # Tüm analiz bileşenlerini birleştiren tarayıcı
├── ui/
│   └── appwindow.slint          # Modern Slint grafik arayüz deklarasyonu
├── build.rs                     # Slint arayüz derleme betiği
├── Cargo.toml                   # Proje bağımlılıkları ve derleme profilleri
├── Cargo.lock                   # Deterministik bağımlılık kilidi
├── config.json                  # Varsayılan yapılandırma dosyası
├── LICENSE                      # MIT Lisansı
├── README.md                    # Genel tanıtım ve kullanım dökümanı
└── ARCHITECTURE.md              # Bu teknik mimari ve denetim dökümanı
```

---

## 5. Tüm Modüllerin ve Kaynak Dosyaların Detaylı Analizi

### 5.1 `src/main.rs`
- **Sorumluluk:** Uygulamanın giriş noktası (`fn main()`), CLI argümanlarının ayrıştırılması, güvenlik boru hattının (`trigger_pipeline`) yönetimi ve GUI başlatıcısı.
- **Önemli Fonksiyonlar:**
  - `trigger_pipeline(drive_path: &str)`: Bir sürücüyü sırasıyla Statik Analiz -> Karantina -> Attrib Onarımı -> USB Bağışıklama -> Taşınabilir Ajan Dağıtımı adımlarından geçirir.
  - `run_sentry_mode(config: &Config)`: Arka planda donanım olaylarını bekleyen döngüyü başlatır.
  - `run_on_demand_mode()`: Takılı çıkarılabilir sürücüleri tarayıp hemen sonlanır (0 process).
  - `main()`: `std::env::args()` kontrol eder; argüman yoksa veya `--gui` ise `gui::run_gui()` çalıştırır, argüman varsa ilgili CLI modunu işletir.

### 5.2 `src/detector.rs`
- **Sorumluluk:** Win32 API donanım olaylarını yakalar.
- **Kritik Win32 Çağrıları:**
  - `CreateWindowExW` ve `RegisterClassExW`: 0x0 boyutlu görünmez bir pencere (`Vectis_Gatekeeper_Listener`) açar.
  - `WM_DEVICECHANGE`: Sistem genelindeki donanım değişikliklerini dinler.
  - `DBT_DEVICEARRIVAL` (0x8000) ve `DBT_DEVICEREMOVECOMPLETE` (0x8004): USB takılma/çıkarılma olaylarını yakalar.
  - `DEV_BROADCAST_VOLUME` ve `dbcv_unitmask`: Bit maskesini sürücü harflerine (`D:\`, `E:\`) çevirir (`unitmask_to_drive_letters`).
  - `GetDriveTypeW`: Sürücünün `DRIVE_REMOVABLE` (2) olup olmadığını denetler, sabit diskleri atlar.
  - `RegisterWindowMessageW("QueryCancelAutoPlay")`: Windows Gezgini'nin otomatik açılmasını bastırır.
  - `set_device_event_callback`: GUI'nin sıcak tak-çıkar olaylarını anlık olarak dinlemesini sağlar.

### 5.3 `src/scanner.rs`
- **Sorumluluk:** Sürücüdeki dosyaların derin statik analizini yürütür.
- **İşlem Adımları:**
  1. `sentry.manifest` kontrolü ve diff analizi.
  2. Dosyaların göreceli yollarını ve boyutlarını listeleme.
  3. Shannon entropi denetimi (`analyze_file_entropy`).
  4. Gömülü YARA kural motoru taraması (`yara_engine.scan_bytes`).
  5. PE analizi (`pe::parse_pe_bytes`): W+X bellek alanları, sahte uzantılar.
  6. Dosya adı heuristiği: Çift uzantı (`fatura.pdf.exe`), Unicode RTLO (`\u{202E}`) tespiti.
  7. Tehdit seviyesi belirleme: `ThreatLevel::Clean`, `ThreatLevel::Suspicious`, `ThreatLevel::Critical`.

### 5.4 `src/yara/` (`mod.rs` & `rules/usb_threats.yar`)
- **Sorumluluk:** Harici C kütüphanesine (`libyara`) ihtiyaç duymayan, saf Rust gömülü YARA motoru.
- **Tasarım:** `include_str!("rules/usb_threats.yar")` ile derleme zamanında binary içine gömülür.
- **Kurallar:**
  1. `USB_Shortcut_Dropper_LNK`: Kötücül komutlar içeren kısayollar.
  2. `USB_RaspberryRobin_LNK_Worm`: MSIEXEC ve rundll32 tabanlı USB solucanları.
  3. `USB_VBS_JS_Worm_Dropper`: VBScript/JScript otomatik yayılan dropper'lar.
  4. `USB_Autorun_Malware_Inf`: Kök dizinde otomatik çalıştırma direktifleri.
  5. `USB_Batch_Powershell_Stager`: Certutil, bitsadmin ve gizli batch indiricileri.
  6. `USB_RTLO_Filename_Spoofing`: Unicode `\u{202E}` dosya adı aldatmacaları.
  7. `USB_Suspicious_PowerShell_Encoded`: Base64 kodlu PowerShell komutları.
  8. `EICAR_Standard_Test_File`: Sentetik EICAR test imzası.

### 5.5 `src/pe.rs`
- **Sorumluluk:** PE32/PE32+ (Portable Executable) formatını bayt seviyesinde çözer.
- **Tespit Mekanizmaları:**
  - MZ başlığı (`0x5A4D`) ve PE başlığı (`0x00004550`) doğrulaması.
  - Section Header analizi: `IMAGE_SCN_MEM_WRITE` ve `IMAGE_SCN_MEM_EXECUTE` aynı anda set edilmişse (`is_writable_and_executable`), bu durum shellcode veya dinamik kod açıcı (packer) belirtisidir.
  - Giriş noktası (Entry Point) son bölümde mi kontrolü (`entry_point_in_last_section`).
  - Bilinen packer bölümleri: `UPX0`, `UPX1`, `.aspack`, `Themida`, `.vmp0` vb.
  - Masquerading (Sahte Uzantı): `.jpg`, `.pdf` gibi uzantılara sahip dosyaların MZ başlığı içermesi durumu.

### 5.6 `src/entropy.rs`
- **Sorumluluk:** Shannon Entropisi formülü:
  $$H(X) = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$$
- **Özellik:** 64 KB akış (streaming) tamponu ile büyük dosyalarda bile RAM tüketimi yapmadan çalışır.
- **Eşik:** >7.2 değeri şifrelenmiş veya paketlenmiş zararlı yük olarak işaretlenir.

### 5.7 `src/immunizer.rs`
- **Sorumluluk:** Harici sürücüyü dosya sistemi mimarisiyle bağışıklar.
- **NTFS Modu:**
  - Kök dizine `ROOT_IMMUNIZED_SDDL`:
    `D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;;0x1200a9;;;WD)`
  - Administrators (BA) ve SYSTEM (SY) tam yetkili (`FA`).
  - Everyone (WD) kök dizinde yalnızca Okuma/Yürütme yetkisine sahiptir (`0x1200a9`); kök dizine dosya ekleme (`FILE_ADD_FILE`) ve klasör ekleme (`FILE_ADD_SUBDIRECTORY`) hakları yoktur.
  - Kök dizin içinde `Paylasim` adında tam yetkili (`PAYLASIM_SDDL`) bir klasör oluşturulur.
  - Sonuç: USB virüslü bir bilgisayara takıldığında virüs kök dizine dosya bırakamaz ("Erişim Reddedildi" - Win32 Hata 5).
- **FAT32 / exFAT Modu:**
  - Kök dizinde `autorun.inf` adında `FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM` nitelikli bir klasör oluşturulur.
  - İçine kilitli `sentry_vaccine.sys` dosyası yerleştirilir. Virüs aynı isimde bir dosya oluşturamaz.
- **De-immunize:** İzinleri fabrika varsayılanına (`ROOT_DEFAULT_SDDL`) döndürür.

### 5.8 `src/quarantine.rs`
- **Sorumluluk:** Tehditleri zararsız ve tersinir şekilde izole eder.
- **İzolasyon Algoritması:**
  - Kök dizinde gizli `.sentry_quarantine` klasörü açar.
  - Dosyayı 64-baytlık deterministik anahtar (`QUARANTINE_XOR_KEY`) ile XOR şifreler.
  - Uzantısını `.locked` yapar. PE yükleyicisi ve script motorları dosyayı yürütemez.
  - `quarantine.json` içine meta verileri (ID, orijinal yol, SHA-256, tespit nedeni vb.) yazar.
- **Geri Yükleme (`restore_file`):** Dosyanın XOR şifresini çözer, SHA-256 hash'ini teyit eder ve orijinal konumuna iade eder.

### 5.9 `src/cleaner.rs`
- **Sorumluluk:** Kısayol solucanlarının (Shortcut Worms) tahribatını giderir.
- **İşleyiş:**
  - Virüsler kullanıcının gerçek klasörlerini `attrib +h +s` yaparak gizler ve aynı isimde sahte `.lnk` dosyaları üretir.
  - `clean_shortcut_worm`: Gizlenen klasörlerin gizli (+h) ve sistem (+s) niteliklerini kaldırarak verileri görünür kılar (`SetFileAttributesW`).
  - Şüpheli komut çalıştıran `.lnk` dosyalarını tespit edip siler.

### 5.10 `src/manifest.rs`
- **Sorumluluk:** Bütünlük snapshot'ı oluşturma ve diff analizi.
- **İşleyiş:**
  - Güvenli sistemdeyken sürücüdeki tüm dosyaların SHA-256 özetlerini alıp `sentry.manifest` dosyasına kaydeder.
  - Yabancı sistemden dönüldüğünde `compute_manifest_diff` ile saniyeler içinde eklenen, değiştirilen ve silinen dosyaların fark raporunu üretir.

### 5.11 `src/portable.rs`
- **Sorumluluk:** Taşınabilir ajan konuşlandırma.
- **İşleyiş:**
  - `Vectis.exe` ikilisini USB'ye (`Paylasim/sentry_portable.exe` veya köke) kopyalar.
  - Yanına güncel `sentry.manifest` dosyasını bırakır.
  - Kullanıcı yabancı bilgisayarda ek kurulum yapmadan doğrudan USB içinden kurtarma taraması yapabilir.

### 5.12 `src/crypto/sha256.rs`
- **Sorumluluk:** FIPS 180-4 standardına tam uyumlu saf Rust SHA-256 motoru.
- **Özellik:** Harici crate veya C kütüphanesi gerektirmez. 64 KB akış tamponu ile gigabaytlarca boyuttaki dosyaları sabit bellek tüketimiyle özetler.

### 5.13 `src/gui.rs` & `ui/appwindow.slint`
- **Sorumluluk:** Modern, karanlık temalı masaüstü arayüzü ve sistem tepsisi (system tray).
- **Özellikler:**
  - VPN tarzı kompakt flyout pencere (340x440 piksel, sağ alt görev çubuğu üzerinde açılır).
  - Bellek içi RGBA Kalkan ikonu üretimi (`create_shield_icon`): 32x32 RGBA piksel matrisi saf Rust ile üretilir; ikon için harici `.ico` dosyası gerektirmez.
  - Canlı sürücü listesi, tek tıkla Hızlı Koruma (Tarama + Temizlik + Bağışıklama).
  - Karantina yöneticisi sekmesi (Geri yükleme / Kalıcı silme).
  - Ayarlar sekmesi (`config.json` ile anlık senkronizasyon).

### 5.14 `src/harness.rs`
- **Sorumluluk:** Sentetik güvenlik ve tehdit doğrulama paketi (`--test-suite`).
- **Test Senaryoları:**
  1. EICAR Test İmzası Tespiti ve Karantinaya Alma.
  2. Çift Uzantı (`fatura.pdf.exe`) ve Unicode RTLO Tespiti.
  3. Kısayol Solucanı (+h +s onarımı ve sahte `.lnk` silimi).
  4. NTFS / FAT Aşı Dayanıklılığı (Win32 Hata 5 Erişim Reddedildi doğrulaması).
  5. Taşınabilir Ajan ve Snapshot Bütünlük Teyidi.
  6. RAII ile test ortamını sıfır iz bırakacak şekilde temizleme.

### 5.15 `src/config.rs`
- **Sorumluluk:** Yerel yapılandırmanın (`config.json`) yüklenmesi ve kaydedilmesi.

---

## 6. Kritik Veri Yapıları ve Tipler

### `ThreatLevel` (`src/scanner.rs`)
```rust
pub enum ThreatLevel {
    Clean = 0,
    Suspicious = 1,
    Critical = 2,
}
```

### `QuarantineRecord` (`src/quarantine.rs`)
```rust
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
```

### `VolumeInfo` (`src/immunizer.rs`)
```rust
pub struct VolumeInfo {
    pub drive_path: String,
    pub volume_name: String,
    pub fs_type: FileSystemType,
    pub serial_number: u32,
    pub supports_persistent_acls: bool,
    pub flags: u32,
}
```

---

## 7. İş Akışları ve Senaryolar

### Senaryo A: USB Bellek Bilgisayara Takıldığında (Sentry Modu)
1. İşletim sistemi `WM_DEVICECHANGE` (0x0219) mesajını `Vectis_Gatekeeper_Listener` penceresine iletir.
2. `wnd_proc`, `DBT_DEVICEARRIVAL` bildirimini yakalar, birim bitmask'ını sürücü harfine (`E:\`) çözer.
3. `GetDriveTypeW("E:\\")` denetlenir; çıkarılabilir aygıt (`DRIVE_REMOVABLE`) ise `QueryCancelAutoPlay` ile Windows Gezgini bastırılır.
4. Güvenlik boru hattı (`trigger_pipeline`) devreye girer:
   - Gömülü YARA ve PE motoru dosyaları tarar.
   - Zararlı/şüpheli bulunan dosyalar 64-bayt XOR ile `.sentry_quarantine` altına izole edilir.
   - `clean_shortcut_worm` gizlenmiş klasörlerin `+h +s` niteliklerini kaldırır.
   - Dosya sistemine göre (NTFS ise DACL kilidi, FAT32 ise autorun klasör aşısı) bağışıklama yapılır.
   - `sentry_portable.exe` ve `sentry.manifest` konuşlandırılır.

### Senaryo B: Güvenli Bilgisayardan Yabancı Bilgisayara Gidiş & Dönüş
1. **Çıkış Öncesi:** Kullanıcı `--snapshot E:\` çalıştırır; temiz durum `sentry.manifest` dosyasına kaydedilir.
2. **Yabancı Bilgisayarda:** Kullanıcı dosyalarını yalnızca `Paylasim` klasörüne yazar. Kök dizin kilitli olduğundan yabancı virüsler kök dizine yerleşemez. İstenirse USB içindeki `sentry_portable.exe` ile çevrimdışı tarama yapılır.
3. **Dönüşte:** Güvenli bilgisayara takıldığında `--diff E:\` ile yalnızca sonradan eklenen veya değiştirilen dosyalar denetlenir.

---

## 8. Kod Denetimi (Audit) ve Refactoring Notları

Projeyi denetleyecek ve geliştirecek geliştirici için önemli teknik notlar:

1. **Windows Alt Sistemi (`windows_subsystem = "windows"`):**
   - `src/main.rs` başında `#![windows_subsystem = "windows"]` tanımlıdır. Bu sayede program çift tıklandığında arka planda siyah CMD konsol penceresi açılmaz.
   - CLI çıktılarının konsola yazılabilmesi için `main()` içinde `AttachConsole` fonksiyonu kullanılmıştır. Konsol çıktılarında doğrudan `WriteConsoleW` veya stdio yönlendirmesi kullanılabilir.
2. **Yönetici Yetkisi (Administrator / UAC Privileges):**
   - NTFS kök dizin DACL izinlerini değiştirmek (`SetNamedSecurityInfoW`) için sürecin yönetici yetkisiyle (Run as Administrator) çalıştırılması gerekir. Yetkisiz çalıştırıldığında Win32 Hata 5 (Access Denied) alınır.
3. **Gömülü YARA Kurallarının Genişletilmesi:**
   - Yeni YARA kuralları doğrudan `src/yara/rules/usb_threats.yar` dosyasına eklenebilir. Derleme zamanında `include_str!` ile otomatik olarak ikiliye dahil olur.
4. **Slint GUI Modeli:**
   - GUI thread-safe `slint::invoke_from_event_loop` kalıbını kullanır. Uzun süren disk işlemleri ayrı thread'lerde koşturulur ve UI kilitlenmesi önlenir.
5. **Bellek Güvenliği ve Win32 Handle RAII:**
   - `LocalAlloc` ile ayrılan güvenlik tanımlayıcıları (`PSECURITY_DESCRIPTOR`) için `LocalFree` çağrıları RAII koruyucularıyla garanti altına alınmıştır.

---

## 9. Derleme, Test ve CI/CD

### Yerel Derleme (Local Build)
```powershell
# 1. Debug derleme
cargo build

# 2. Üretim (Release) boyutu minimize edilmiş bağımsız binary
cargo build --release

# 3. Sentetik Tehdit Doğrulama Paketi
.\target\release\Vectis.exe --test-suite
```

### Cargo Sürüm Optimizasyonları
- `opt-level = "z"` (Boyut optimizasyonu)
- `lto = true` (Link-Time Optimization)
- `codegen-units = 1`
- `panic = "abort"`
- `strip = true`
- **Nihai Bağımsız Boyut:** ~3.4 MB (Slint GPU/Yazılım Render Motoru ve Tüm YARA kuralları dahil, tek parça bağımsız `.exe`).
