use crate::config::Config;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicPtr, AtomicU32, Ordering};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{BOOL, HWND, LPARAM, LRESULT, WPARAM},
    Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives},
    System::Console::SetConsoleCtrlHandler,
    System::LibraryLoader::GetModuleHandleW,
    UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        PostMessageW, PostQuitMessage, RegisterClassExW, RegisterWindowMessageW,
        TranslateMessage, UnregisterClassW, MSG, WM_CLOSE, WM_DESTROY, WM_DEVICECHANGE,
        WNDCLASSEXW, WS_OVERLAPPED,
    },
};

// ============================================================================
// Win32 Sürücü Türü Sabitleri (Standart Win32 GetDriveTypeW Dönüş Değerleri)
// ============================================================================
pub const DRIVE_UNKNOWN: u32 = 0;
pub const DRIVE_NO_ROOT_DIR: u32 = 1;
pub const DRIVE_REMOVABLE: u32 = 2;
pub const DRIVE_FIXED: u32 = 3;
pub const DRIVE_REMOTE: u32 = 4;
pub const DRIVE_CDROM: u32 = 5;
pub const DRIVE_RAMDISK: u32 = 6;

// ============================================================================
// Win32 Cihaz Bildirim Sabitleri ve Yapıları
// ============================================================================

/// Yeni bir aygıt sisteme tanıtıldığında gönderilen bildirim kodu
pub const DBT_DEVICEARRIVAL: usize = 0x8000;

/// Bir aygıt sistemden çıkarıldığında gönderilen bildirim kodu
pub const DBT_DEVICEREMOVECOMPLETE: usize = 0x8004;

/// Bildirimin mantıksal bir depolama birimine (volume) ait olduğunu belirten tip
pub const DBT_DEVTYP_VOLUME: u32 = 0x00000002;

/// Win32 standart cihaz bildirim başlık yapısı
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DEV_BROADCAST_HDR {
    pub dbch_size: u32,
    pub dbch_devicetype: u32,
    pub dbch_reserved: u32,
}

/// Win32 mantıksal depolama birimi bildirim yapısı
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DEV_BROADCAST_VOLUME {
    pub dbcv_size: u32,
    pub dbcv_devicetype: u32,
    pub dbcv_reserved: u32,
    pub dbcv_unitmask: u32,
    pub dbcv_flags: u16,
}

// Global durum değişkenleri (Atomic & Thread-Safe)
static GLOBAL_HWND: AtomicIsize = AtomicIsize::new(0);
static AUTO_SUPPRESS_EXPLORER: AtomicBool = AtomicBool::new(true);
static QUERY_CANCEL_AUTOPLAY_MSG: AtomicU32 = AtomicU32::new(0);
static IS_CLI_MODE: AtomicBool = AtomicBool::new(true);

// Güvenlik boru hattı (Pipeline) çağrı göstericisi (AtomicPtr ile güvenli yönetim)
pub type PipelineCallback = fn(&str);
static PIPELINE_CALLBACK: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

#[derive(Debug, Clone)]
pub enum DeviceEvent {
    Arrival(String),
    Removal(String),
}

pub type DeviceEventCallback = Box<dyn Fn(DeviceEvent) + Send + Sync + 'static>;
static DEVICE_EVENT_CALLBACK: std::sync::RwLock<Option<DeviceEventCallback>> = std::sync::RwLock::new(None);

pub fn set_device_event_callback<F>(callback: F)
where
    F: Fn(DeviceEvent) + Send + Sync + 'static,
{
    if let Ok(mut lock) = DEVICE_EVENT_CALLBACK.write() {
        *lock = Some(Box::new(callback));
    }
}

/// UTF-8 dizgisini null sonlandırmalı UTF-16 vektörüne dönüştürür
pub fn to_wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Bit maskesini (unitmask) sürücü harflerine ('A'..'Z') dönüştürür.
/// Tek bir maske birden fazla bölüm/harf içerebilir.
pub fn unitmask_to_drive_letters(mask: u32) -> Vec<char> {
    let mut letters = Vec::new();
    for i in 0..26 {
        if (mask >> i) & 1 == 1 {
            letters.push((b'A' + i as u8) as char);
        }
    }
    letters
}

/// Belirtilen sürücü harfinin çıkarılabilir (USB / Removable) olup olmadığını doğrular
pub fn is_removable_drive(drive_letter: char) -> bool {
    let path = format!("{}:\\", drive_letter);
    let wide_path = to_wide_string(&path);

    #[cfg(windows)]
    unsafe {
        let drive_type = GetDriveTypeW(wide_path.as_ptr());
        drive_type == DRIVE_REMOVABLE
    }

    #[cfg(not(windows))]
    false
}

/// Sürücü tipinin insan tarafından okunabilir açıklamasını döndürür
pub fn get_drive_type_description(drive_letter: char) -> &'static str {
    let path = format!("{}:\\", drive_letter);
    let wide_path = to_wide_string(&path);

    #[cfg(windows)]
    unsafe {
        match GetDriveTypeW(wide_path.as_ptr()) {
            DRIVE_REMOVABLE => "Çıkarılabilir Disk (USB Flash Bellek)",
            DRIVE_FIXED => "Sabit Disk (HDD/SSD/NVMe)",
            DRIVE_REMOTE => "Ağ Paylaşım Sürücüsü (Network Drive)",
            DRIVE_CDROM => "Optik Sürücü (CD/DVD-ROM)",
            DRIVE_RAMDISK => "Sanal RAM Diski",
            DRIVE_NO_ROOT_DIR => "Kök Dizin Bulunamadı",
            _ => "Bilinmeyen Sürücü Türü",
        }
    }

    #[cfg(not(windows))]
    "Desteklenmeyen Platform"
}

/// Sistemde şu anda takılı olan tüm çıkarılabilir (USB) sürücüleri listeler
pub fn enumerate_removable_drives() -> Vec<String> {
    let mut removable_drives = Vec::new();

    #[cfg(windows)]
    unsafe {
        let drives_mask = GetLogicalDrives();
        for i in 0..26 {
            if (drives_mask >> i) & 1 == 1 {
                let letter = (b'A' + i as u8) as char;
                if is_removable_drive(letter) {
                    removable_drives.push(format!("{}:\\", letter));
                }
            }
        }
    }

    removable_drives
}

/// Sistemde mevcut olan tüm mantıksal sürücüleri ve türlerini döndürür
pub fn enumerate_all_drives() -> Vec<(String, &'static str, bool)> {
    let mut results = Vec::new();

    #[cfg(windows)]
    unsafe {
        let drives_mask = GetLogicalDrives();
        for i in 0..26 {
            if (drives_mask >> i) & 1 == 1 {
                let letter = (b'A' + i as u8) as char;
                let path = format!("{}:\\", letter);
                let desc = get_drive_type_description(letter);
                let is_removable = is_removable_drive(letter);
                results.push((path, desc, is_removable));
            }
        }
    }

    results
}

/// Pipeline callback fonksiyonunu tetikler
fn dispatch_pipeline(drive_path: &str) {
    let ptr = PIPELINE_CALLBACK.load(Ordering::SeqCst);
    if !ptr.is_null() {
        let cb: PipelineCallback = unsafe { std::mem::transmute(ptr) };
        cb(drive_path);
    } else {
        println!("[*] [Pipeline] Tetiklendi -> Sürücü: {}", drive_path);
    }
}

// ============================================================================
// Win32 Pencere ve Mesaj İşleyici (Window Procedure)
// ============================================================================

#[cfg(windows)]
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // AutoPlay / Windows Gezgini otomatik açılışını baskılama
    let query_cancel = QUERY_CANCEL_AUTOPLAY_MSG.load(Ordering::SeqCst);
    if query_cancel != 0 && msg == query_cancel {
        if AUTO_SUPPRESS_EXPLORER.load(Ordering::SeqCst) {
            println!("[!] [AutoPlay] Windows Gezgini otomatik açılış talebi yakalandı ve engellendi (QueryCancelAutoPlay).");
            // Windows Shell'e AutoPlay'i iptal etmesi için TRUE (1) döndür
            return 1;
        }
    }

    match msg {
        WM_DEVICECHANGE => {
            let event_type = wparam as usize;

            if event_type == DBT_DEVICEARRIVAL && lparam != 0 {
                let hdr = *(lparam as *const DEV_BROADCAST_HDR);
                if hdr.dbch_size as usize >= std::mem::size_of::<DEV_BROADCAST_VOLUME>()
                    && hdr.dbch_devicetype == DBT_DEVTYP_VOLUME
                {
                    let vol = *(lparam as *const DEV_BROADCAST_VOLUME);
                    let drive_letters = unitmask_to_drive_letters(vol.dbcv_unitmask);

                    for drive_letter in drive_letters {
                        let drive_path = format!("{}:\\", drive_letter);
                        if is_removable_drive(drive_letter) {
                            println!("\n========================================================");
                            println!("[!] [DONANIM TESPİTİ] Yeni Çıkarılabilir USB Sürücü Takıldı: {}", drive_path);
                            println!("[*] [Sürücü Türü] {}", get_drive_type_description(drive_letter));
                            println!("========================================================");

                            dispatch_pipeline(&drive_path);

                            if let Ok(lock) = DEVICE_EVENT_CALLBACK.read() {
                                if let Some(cb) = lock.as_ref() {
                                    cb(DeviceEvent::Arrival(drive_path.clone()));
                                }
                            }
                        } else {
                            println!(
                                "[*] [DONANIM BİLGİSİ] Çıkarılabilir olmayan birim takıldı (Atlandı): {} ({})",
                                drive_path,
                                get_drive_type_description(drive_letter)
                            );
                        }
                    }
                }
            } else if event_type == DBT_DEVICEREMOVECOMPLETE && lparam != 0 {
                let hdr = *(lparam as *const DEV_BROADCAST_HDR);
                if hdr.dbch_size as usize >= std::mem::size_of::<DEV_BROADCAST_VOLUME>()
                    && hdr.dbch_devicetype == DBT_DEVTYP_VOLUME
                {
                    let vol = *(lparam as *const DEV_BROADCAST_VOLUME);
                    let drive_letters = unitmask_to_drive_letters(vol.dbcv_unitmask);
                    for drive_letter in drive_letters {
                        let drive_path = format!("{}:\\", drive_letter);
                        println!("[-] [DONANIM TESPİTİ] USB Sürücü Çıkarıldı: {}", drive_path);
                        if let Ok(lock) = DEVICE_EVENT_CALLBACK.read() {
                            if let Some(cb) = lock.as_ref() {
                                cb(DeviceEvent::Removal(drive_path));
                            }
                        }
                    }
                } else {
                    println!("[-] [DONANIM TESPİTİ] Donanım aygıtının bağlantısı kesildi.");
                }
            }
            0
        }
        WM_CLOSE => {
            println!("[*] [Sentry] Pencere kapatma bildirimi alındı, temizlik yapılıyor...");
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            println!("[*] [Sentry] Olay döngüsü sonlandırıldı.");
            GLOBAL_HWND.store(0, Ordering::SeqCst);
            if IS_CLI_MODE.load(Ordering::SeqCst) {
                PostQuitMessage(0);
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Konsol kapatma (Ctrl+C veya pencere kapatma) sinyalini yakalar
#[cfg(windows)]
unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        0 /* CTRL_C_EVENT */ | 2 /* CTRL_CLOSE_EVENT */ => {
            println!("\n[*] [Sentry] Kapatma sinyali (Ctrl+C / Close) yakalandı. Temiz çıkış yapılıyor...");
            let hwnd = GLOBAL_HWND.load(Ordering::SeqCst);
            if hwnd != 0 {
                PostMessageW(hwnd as HWND, WM_CLOSE, 0, 0);
            }
            1
        }
        _ => 0,
    }
}

// ============================================================================
// Sentry Modu Giriş Noktası
// ============================================================================

/// Sentry Modunu CLI için başlatır (Ctrl+C yakalama aktif)
pub fn start_sentry_loop(config: &Config, pipeline_callback: PipelineCallback) -> Result<(), String> {
    IS_CLI_MODE.store(true, Ordering::SeqCst);
    start_sentry_loop_internal(config, Some(pipeline_callback), true)
}

/// Sentry Modunu GUI için başlatır (Arka plan daemon thread'i, konsol sinyalleri yok)
pub fn start_sentry_loop_gui(config: &Config) -> Result<(), String> {
    IS_CLI_MODE.store(false, Ordering::SeqCst);
    start_sentry_loop_internal(config, None, false)
}

fn start_sentry_loop_internal(
    config: &Config,
    pipeline_callback: Option<PipelineCallback>,
    is_cli: bool,
) -> Result<(), String> {
    #[cfg(windows)]
    unsafe {
        if let Some(cb) = pipeline_callback {
            PIPELINE_CALLBACK.store(cb as *mut (), Ordering::SeqCst);
        } else {
            PIPELINE_CALLBACK.store(std::ptr::null_mut(), Ordering::SeqCst);
        }

        AUTO_SUPPRESS_EXPLORER.store(config.auto_suppress_explorer, Ordering::SeqCst);

        // AutoPlay iptal mesajını Windows Shell'e kaydet
        let query_cancel_name = to_wide_string("QueryCancelAutoPlay");
        let query_cancel_msg = RegisterWindowMessageW(query_cancel_name.as_ptr());
        if query_cancel_msg != 0 {
            QUERY_CANCEL_AUTOPLAY_MSG.store(query_cancel_msg, Ordering::SeqCst);
            if config.auto_suppress_explorer && is_cli {
                println!("[+] [Sentry] AutoPlay baskılama aktif (QueryCancelAutoPlay ID: 0x{:X})", query_cancel_msg);
            }
        }

        if is_cli {
            // Konsol kontrol işleyicisini bağla (Ctrl+C yakalama)
            SetConsoleCtrlHandler(Some(console_ctrl_handler), 1);
        }

        let h_instance = GetModuleHandleW(std::ptr::null());
        let class_name_str = "CoreSyncGatekeeperListenerWindow";
        let class_name = to_wide_string(class_name_str);

        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: h_instance,
            hIcon: 0 as _,
            hCursor: 0 as _,
            hbrBackground: 0 as _,
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: 0 as _,
        };

        let atom = RegisterClassExW(&wc);
        if atom == 0 {
            return Err("Win32 pencere sınıfı kaydedilemedi (RegisterClassExW başarısız).".to_string());
        }

        // Görünmez, 0 boyutlu üst düzey pencere:
        // WM_DEVICECHANGE doğrudan broadcast edildiği için HWND_MESSAGE yerine görünmez top-level pencere şarttır.
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            WS_OVERLAPPED,
            0, 0, 0, 0,
            0 as _,
            0 as _,
            h_instance,
            std::ptr::null(),
        );

        if hwnd == 0 as HWND {
            UnregisterClassW(class_name.as_ptr(), h_instance);
            return Err("Win32 dinleyici penceresi oluşturulamadı (CreateWindowExW başarısız).".to_string());
        }

        GLOBAL_HWND.store(hwnd as isize, Ordering::SeqCst);

        if is_cli {
            println!("[+] [Sentry] Win32 Donanım Olay Dinleyicisi hazır.");
            println!("[*] [Sentry] Durum: USB aygıtı takılması bekleniyor... (Durdurmak için Ctrl+C)");
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, hwnd, 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Temizlik adımları: Eğer döngüden beklenmeyen şekilde çıkıldıysa pencereyi kapat ve sınıfı kaldır
        let remaining_hwnd = GLOBAL_HWND.swap(0, Ordering::SeqCst);
        if remaining_hwnd != 0 {
            DestroyWindow(remaining_hwnd as HWND);
        }
        UnregisterClassW(class_name.as_ptr(), h_instance);

        if is_cli {
            println!("[+] [Sentry] Dinleyici başarıyla kapatıldı. Kaynaklar serbest bırakıldı.");
        }
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = config;
        let _ = pipeline_callback;
        let _ = is_cli;
        Err("Sentry modu yalnızca Windows platformunda desteklenmektedir.".to_string())
    }
}
