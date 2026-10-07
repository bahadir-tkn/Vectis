//! ============================================================================
//! Vectis Removable Media Defense - Faz 5: Kompakt VPN Stili Görev Çubuğu Arayüzü
//! ----------------------------------------------------------------------------
//! Mimari: Air-Gapped (Çevrimdışı, Sıfır Dış Ağ Erişimi), Saf Rust
//! - Windows Görev Çubuğu Sağ Alt Köşesi (Flyout / Popup Mini Pencere)
//! - Sade, Genel Kullanıcı Kitlesine Hitap Eden Tek Tıkla Savunma Arayüzü
//! - Bilgisayara (C:\ vb.) Kalıcı Değişiklik Yapmayan Güvenli & Geri Alınabilir Mimari
//! ============================================================================

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, VecModel};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, MouseButton, TrayIconBuilder, TrayIconEvent,
};

use crate::cleaner::clean_shortcut_worm;
use crate::config::{get_config_path, load_config, save_config};
use crate::detector::{
    enumerate_all_drives, set_device_event_callback, start_sentry_loop_gui, DeviceEvent,
};
use crate::immunizer::{
    check_immunization_status, deimmunize_drive, immunize_drive, DEFAULT_SHARED_FOLDER,
};
use crate::quarantine::{delete_quarantined_record, list_quarantine, quarantine_file, restore_file};
use crate::scanner::{StaticScanner, ThreatLevel};

// Slint derlenen modülleri içeri aktar
slint::include_modules!();

// ============================================================================
// GÖMÜLÜ SİSTEM TEPSİSİ KALKAN İKONU (AIR-GAPPED - SAF RUST PİKSEL MOTORU)
// ============================================================================

/// 32x32 boyutunda RGBA piksel tamponu ile bellek içinde Kalkan (Shield) ikonu üretir.
pub fn create_shield_icon(is_active: bool) -> Icon {
    let width = 32u32;
    let height = 32u32;
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);

    for y in 0..height {
        for x in 0..width {
            let fx = x as f32;
            let fy = y as f32;

            let dx = (fx - 15.5).abs();
            let in_shield = if fy < 4.0 || fy > 28.0 {
                false
            } else if fy <= 14.0 {
                dx <= 12.0
            } else {
                let factor = 1.0 - ((fy - 14.0) / 14.0);
                dx <= (12.0 * factor)
            };

            let is_border = if in_shield {
                if fy <= 5.0 || fy >= 27.0 {
                    true
                } else if fy <= 14.0 {
                    dx >= 10.0
                } else {
                    let factor = 1.0 - ((fy - 14.0) / 14.0);
                    dx >= (10.0 * factor)
                }
            } else {
                false
            };

            if in_shield {
                if is_border {
                    if is_active {
                        rgba.extend_from_slice(&[5, 150, 105, 255]); // Koyu Zümrüt
                    } else {
                        rgba.extend_from_slice(&[51, 65, 85, 255]); // Koyu Slate Gri
                    }
                } else {
                    if is_active {
                        rgba.extend_from_slice(&[16, 185, 129, 255]); // Neon Emerald
                    } else {
                        rgba.extend_from_slice(&[148, 163, 184, 255]); // Açık Slate Gri
                    }
                }
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]); // Şeffaf
            }
        }
    }

    Icon::from_rgba(rgba, width, height).expect("Piksel tamponundan ikon oluşturulamadı")
}

// ============================================================================
// WIN32 SAĞ ALT KÖŞE (TASKBAR FLYOUT) KONUMLANDIRMA FONKSİYONU
// ============================================================================

/// Pencereyi Windows görev çubuğunun hemen sağ üst köşesine (VPN pop-up stili) yerleştirir
#[cfg(windows)]
pub fn position_window_to_bottom_right(title: &str) {
    use windows_sys::Win32::Foundation::{HWND, RECT};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, GetWindowRect, SetForegroundWindow, SetWindowPos, SystemParametersInfoW,
        HWND_TOP, SPI_GETWORKAREA, SWP_NOSIZE, SWP_SHOWWINDOW,
    };

    let title_wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let hwnd = FindWindowW(std::ptr::null(), title_wide.as_ptr());
        if hwnd != 0 as HWND {
            let mut work_area: RECT = std::mem::zeroed();
            let mut win_rect: RECT = std::mem::zeroed();
            if SystemParametersInfoW(
                SPI_GETWORKAREA,
                0,
                &mut work_area as *mut RECT as *mut _,
                0,
            ) != 0
                && GetWindowRect(hwnd, &mut win_rect as *mut RECT as *mut _) != 0
            {
                let win_w = win_rect.right - win_rect.left;
                let win_h = win_rect.bottom - win_rect.top;
                let margin = 12;
                let mut x = work_area.right - win_w - margin;
                let mut y = work_area.bottom - win_h - margin;
                if x < work_area.left {
                    x = work_area.left;
                }
                if y < work_area.top {
                    y = work_area.top;
                }

                SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW);
                SetForegroundWindow(hwnd);
            }
        }
    }
}

// ============================================================================
// VERİ MODELİ DÖNÜŞTÜRÜCÜLERİ
// ============================================================================

/// Sistemdeki çıkarılabilir USB diskleri tarar ve Slint DriveItem listesi oluşturur
pub fn query_drives_model() -> (Vec<DriveItem>, String, DriveItem) {
    let raw_drives = enumerate_all_drives();
    let mut items = Vec::new();

    let mut default_path = String::new();
    let mut default_item = DriveItem {
        path: slint::SharedString::from(""),
        description: slint::SharedString::from("USB Bekleniyor"),
        is_removable: false,
        is_immunized: false,
        fs_type: slint::SharedString::from("-"),
    };

    let mut found_removable = false;

    for (path, desc, is_rem) in raw_drives {
        // Yalnızca çıkarılabilir USB bellekleri kullanıcıya öncelikli sun
        if is_rem {
            let imm_status = check_immunization_status(&path);
            let item = DriveItem {
                path: slint::SharedString::from(&path),
                description: slint::SharedString::from(desc),
                is_removable: true,
                is_immunized: imm_status.is_immunized,
                fs_type: slint::SharedString::from(imm_status.fs_type.as_str()),
            };

            if !found_removable {
                default_path = path.clone();
                default_item = item.clone();
                found_removable = true;
            }

            items.push(item);
        }
    }

    (items, default_path, default_item)
}

/// Sürücüdeki .sentry_quarantine havuzunu listeler ve Slint QuarantineItem vektörü döner
pub fn query_quarantine_model(drive_path: &str) -> Vec<QuarantineItem> {
    if drive_path.is_empty() {
        return Vec::new();
    }

    match list_quarantine(drive_path) {
        Ok(records) => records
            .into_iter()
            .map(|r| {
                let sha256_short = if r.sha256.len() > 12 {
                    format!("{}...", &r.sha256[..12])
                } else {
                    r.sha256
                };

                QuarantineItem {
                    id: slint::SharedString::from(&r.id),
                    original_path: slint::SharedString::from(&r.original_file_name),
                    threat_level: slint::SharedString::from(&r.threat_level),
                    threat_reason: slint::SharedString::from(&r.reason),
                    quarantined_at: slint::SharedString::from(&r.quarantined_at),
                    sha256_short: slint::SharedString::from(&sha256_short),
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

// ============================================================================
// GRAFİK ARAYÜZ (GUI) VE SİSTEM TEPSİSİ ANA GİRİŞ NOKTASI
// ============================================================================

/// Kompakt VPN stili Slint GUI motorunu başlatır
pub fn run_gui() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let log_step = |step: &str| {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("debug_vectis.log") {
            let _ = writeln!(f, "[GUI] {}", step);
        }
    };
    log_step("Starting run_gui()");
    let app = AppWindow::new()?;
    log_step("AppWindow::new() OK");

    // 1. Yapılandırma ve Başlangıç Durumu
    let config = load_config();
    let sentry_running = Arc::new(AtomicBool::new(config.background_monitoring));

    app.set_auto_protect(config.background_monitoring);
    app.set_cfg_background_monitoring(config.background_monitoring);
    app.set_cfg_auto_suppress_explorer(config.auto_suppress_explorer);
    app.set_cfg_enable_ntfs_immunization(config.enable_ntfs_immunization);
    app.set_cfg_create_portable_rescue(config.create_portable_rescue);

    // 2. Sürücü Listesini Yükle
    let (drives_list, default_path, default_item) = query_drives_model();
    app.set_drives(ModelRc::new(VecModel::from(drives_list)));
    app.set_selected_drive_path(slint::SharedString::from(&default_path));
    app.set_current_drive(default_item);

    // Karantina havuzunu yükle
    let q_items = query_quarantine_model(&default_path);
    app.set_quarantine_list(ModelRc::new(VecModel::from(q_items)));

    // 3. Windows Sistem Tepsisi (Tray Icon) ve Menü Yapılandırması
    let tray_menu = Menu::new();
    let item_open = MenuItem::new("Vectis'i Göster", true, None);
    let item_settings = MenuItem::new("Ayarlar", true, None);
    let item_quick_scan = MenuItem::new("Hızlı Tara ve Koru", true, None);
    let item_separator = PredefinedMenuItem::separator();
    let item_quit = MenuItem::new("Çıkış", true, None);

    let id_open = item_open.id().clone();
    let id_settings = item_settings.id().clone();
    let id_quick_scan = item_quick_scan.id().clone();
    let id_quit = item_quit.id().clone();

    let _ = tray_menu.append(&item_open);
    let _ = tray_menu.append(&item_settings);
    let _ = tray_menu.append(&item_quick_scan);
    let _ = tray_menu.append(&item_separator);
    let _ = tray_menu.append(&item_quit);

    #[cfg(windows)]
    unsafe {
        #[link(name = "ole32")]
        extern "system" {
            fn CoInitialize(pvReserved: *mut std::ffi::c_void) -> i32;
        }
        let _ = CoInitialize(std::ptr::null_mut());
    }

    let active_icon = create_shield_icon(config.background_monitoring);
    let tray_res = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("Vectis - USB Güvenliği")
        .with_icon(active_icon)
        .build();

    let tray_icon = match tray_res {
        Ok(ti) => Some(Rc::new(RefCell::new(ti))),
        Err(_) => None,
    };

    // 4. Pencere Kapatma (X) Tıklandığında Kapanmak Yerine Tepsiye Küçül
    app.window().on_close_requested({
        let ui_w = app.as_weak();
        move || {
            if let Some(ui) = ui_w.upgrade() {
                let _ = ui.hide();
            }
            slint::CloseRequestResponse::KeepWindowShown
        }
    });

    // 5. Callback: Tepsiye Küçült Butonu
    app.on_minimize_to_tray_requested({
        let ui_w = app.as_weak();
        move || {
            if let Some(ui) = ui_w.upgrade() {
                let _ = ui.hide();
            }
        }
    });

    // 6. Callback: Sürücü Listesini Yenile
    app.on_refresh_drives_requested({
        let ui_w = app.as_weak();
        move || {
            let (new_drives, sel_path, sel_item) = query_drives_model();
            if let Some(ui) = ui_w.upgrade() {
                ui.set_drives(ModelRc::new(VecModel::from(new_drives)));
                ui.set_selected_drive_path(slint::SharedString::from(&sel_path));
                ui.set_current_drive(sel_item);
                let q_list = query_quarantine_model(&sel_path);
                ui.set_quarantine_list(ModelRc::new(VecModel::from(q_list)));
            }
        }
    });

    // 7. Callback: TEK TIKLA TARA VE KORU (Ana Aksiyon Butonu)
    app.on_quick_action_requested({
        let ui_w = app.as_weak();
        move |drive_path| {
            let dp = drive_path.to_string();
            if dp.is_empty() {
                return;
            }
            let ui_w_clone = ui_w.clone();

            if let Some(ui) = ui_w.upgrade() {
                let mut s = ui.get_scan_summary();
                s.is_running = true;
                s.status_text = slint::SharedString::from(format!("{} taranıyor ve korunuyor...", dp));
                ui.set_scan_summary(s);
            }

            std::thread::spawn(move || {
                run_pipeline_background(&dp, ui_w_clone);
            });
        }
    });

    // 8. Callback: Korumayı Aç / Kaldır Toggle (Geri Alınabilir Kilit)
    app.on_toggle_protection_requested({
        let ui_w = app.as_weak();
        move |drive_path| {
            let dp = drive_path.to_string();
            if dp.is_empty() {
                return;
            }
            let ui_w_clone = ui_w.clone();

            std::thread::spawn(move || {
                let cur_status = check_immunization_status(&dp);
                if cur_status.is_immunized {
                    // Bağışıklığı kaldır (Geri al)
                    match deimmunize_drive(&dp) {
                        Ok(rep) => {
                            let _ = slint::invoke_from_event_loop({
                                let ui_w_inner = ui_w_clone.clone();
                                let msg = rep.message.clone();
                                move || {
                                    if let Some(ui) = ui_w_inner.upgrade() {
                                        let mut s = ui.get_scan_summary();
                                        s.status_text = slint::SharedString::from(msg);
                                        ui.set_scan_summary(s);
                                        let (new_drives, _, cur_item) = query_drives_model();
                                        ui.set_drives(ModelRc::new(VecModel::from(new_drives)));
                                        ui.set_current_drive(cur_item);
                                    }
                                }
                            });
                        }
                        Err(err) => {
                            let _ = slint::invoke_from_event_loop({
                                let ui_w_inner = ui_w_clone.clone();
                                move || {
                                    if let Some(ui) = ui_w_inner.upgrade() {
                                        let mut s = ui.get_scan_summary();
                                        s.status_text = slint::SharedString::from(format!("Hata: {}", err));
                                        ui.set_scan_summary(s);
                                    }
                                }
                            });
                        }
                    }
                } else {
                    // Bağışıklığı uygula
                    match immunize_drive(&dp, Some(DEFAULT_SHARED_FOLDER)) {
                        Ok(rep) => {
                            let _ = slint::invoke_from_event_loop({
                                let ui_w_inner = ui_w_clone.clone();
                                let msg = rep.message.clone();
                                move || {
                                    if let Some(ui) = ui_w_inner.upgrade() {
                                        let mut s = ui.get_scan_summary();
                                        s.status_text = slint::SharedString::from(msg);
                                        ui.set_scan_summary(s);
                                        let (new_drives, _, cur_item) = query_drives_model();
                                        ui.set_drives(ModelRc::new(VecModel::from(new_drives)));
                                        ui.set_current_drive(cur_item);
                                    }
                                }
                            });
                        }
                        Err(err) => {
                            let _ = slint::invoke_from_event_loop({
                                let ui_w_inner = ui_w_clone.clone();
                                move || {
                                    if let Some(ui) = ui_w_inner.upgrade() {
                                        let mut s = ui.get_scan_summary();
                                        s.status_text = slint::SharedString::from(format!("Hata: {}", err));
                                        ui.set_scan_summary(s);
                                    }
                                }
                            });
                        }
                    }
                }
            });
        }
    });

    // 9. Callback: Gizli Klasörleri Kurtar (Solucan Virüsü Onarımı)
    app.on_clean_shortcuts_requested({
        let ui_w = app.as_weak();
        move |drive_path| {
            let dp = drive_path.to_string();
            let ui_w_clone = ui_w.clone();

            std::thread::spawn(move || {
                let report = clean_shortcut_worm(&dp);
                let _ = slint::invoke_from_event_loop({
                    let ui_w_inner = ui_w_clone.clone();
                    let unhidden = report.directories_restored.len();
                    let deleted = report.shortcuts_removed.len();
                    move || {
                        if let Some(ui) = ui_w_inner.upgrade() {
                            let mut s = ui.get_scan_summary();
                            s.status_text = slint::SharedString::from(format!(
                                "{} gizli klasör kurtarıldı, {} sahte kısayol temizlendi.",
                                unhidden, deleted
                            ));
                            ui.set_scan_summary(s);
                        }
                    }
                });
            });
        }
    });

    // 10. Callback: Karantinadan Geri Yükle (Restore)
    app.on_restore_quarantine_requested({
        let ui_w = app.as_weak();
        move |drive_path, item_id| {
            let dp = drive_path.to_string();
            let id = item_id.to_string();
            let ui_w_clone = ui_w.clone();

            std::thread::spawn(move || {
                match restore_file(&dp, &id) {
                    Ok(rec) => {
                        let _ = slint::invoke_from_event_loop({
                            let dp_clone = dp.clone();
                            let orig_name = rec.original_file_name.clone();
                            let ui_w_inner = ui_w_clone.clone();
                            move || {
                                if let Some(ui) = ui_w_inner.upgrade() {
                                    let mut s = ui.get_scan_summary();
                                    s.status_text = slint::SharedString::from(format!(
                                        "'{}' başarıyla kurtarıldı.", orig_name
                                    ));
                                    ui.set_scan_summary(s);
                                    let q_list = query_quarantine_model(&dp_clone);
                                    ui.set_quarantine_list(ModelRc::new(VecModel::from(q_list)));
                                }
                            }
                        });
                    }
                    Err(err) => {
                        let _ = slint::invoke_from_event_loop({
                            let ui_w_inner = ui_w_clone.clone();
                            move || {
                                if let Some(ui) = ui_w_inner.upgrade() {
                                    let mut s = ui.get_scan_summary();
                                    s.status_text = slint::SharedString::from(format!("Kurtarma hatası: {}", err));
                                    ui.set_scan_summary(s);
                                }
                            }
                        });
                    }
                }
            });
        }
    });

    // 11. Callback: Karantinadan Kalıcı Olarak Sil
    app.on_delete_quarantine_requested({
        let ui_w = app.as_weak();
        move |drive_path, item_id| {
            let dp = drive_path.to_string();
            let id = item_id.to_string();
            let ui_w_clone = ui_w.clone();

            std::thread::spawn(move || {
                match delete_quarantined_record(&dp, &id) {
                    Ok(_) => {
                        let _ = slint::invoke_from_event_loop({
                            let dp_clone = dp.clone();
                            let ui_w_inner = ui_w_clone.clone();
                            move || {
                                if let Some(ui) = ui_w_inner.upgrade() {
                                    let mut s = ui.get_scan_summary();
                                    s.status_text = slint::SharedString::from("Karantina kaydı kalıcı silindi.");
                                    ui.set_scan_summary(s);
                                    let q_list = query_quarantine_model(&dp_clone);
                                    ui.set_quarantine_list(ModelRc::new(VecModel::from(q_list)));
                                }
                            }
                        });
                    }
                    Err(err) => {
                        let _ = slint::invoke_from_event_loop({
                            let ui_w_inner = ui_w_clone.clone();
                            move || {
                                if let Some(ui) = ui_w_inner.upgrade() {
                                    let mut s = ui.get_scan_summary();
                                    s.status_text = slint::SharedString::from(format!("Silme hatası: {}", err));
                                    ui.set_scan_summary(s);
                                }
                            }
                        });
                    }
                }
            });
        }
    });

    // 12. Callback: Otomatik Koruma Toggle
    app.on_toggle_auto_protect_requested({
        let sentry_running_clone = sentry_running.clone();
        let tray_icon_clone = tray_icon.clone();
        move |enabled| {
            sentry_running_clone.store(enabled, Ordering::SeqCst);
            let mut cfg = load_config();
            cfg.background_monitoring = enabled;
            let cfg_path = get_config_path();
            let _ = save_config(&cfg, &cfg_path);

            let new_icon = create_shield_icon(enabled);
            if let Some(ref ti) = tray_icon_clone {
                let _ = ti.borrow_mut().set_icon(Some(new_icon));
            }
        }
    });

    // 12b. Callback: Kurumsal Güvenlik & Davranış Ayarları Güncelleme
    app.on_update_config_requested({
        let sentry_running_clone = sentry_running.clone();
        let tray_icon_clone = tray_icon.clone();
        move |bg_mon, auto_supp, ntfs_imm, port_rescue| {
            sentry_running_clone.store(bg_mon, Ordering::SeqCst);
            let mut cfg = load_config();
            cfg.background_monitoring = bg_mon;
            cfg.auto_suppress_explorer = auto_supp;
            cfg.enable_ntfs_immunization = ntfs_imm;
            cfg.create_portable_rescue = port_rescue;
            let cfg_path = get_config_path();
            let _ = save_config(&cfg, &cfg_path);

            let new_icon = create_shield_icon(bg_mon);
            if let Some(ref ti) = tray_icon_clone {
                let _ = ti.borrow_mut().set_icon(Some(new_icon));
            }
        }
    });

    // 13. Win32 WM_DEVICECHANGE Olay Dinleyicisi (MPSC Event Bus İle)
    let (device_event_tx, device_event_rx) = std::sync::mpsc::channel::<DeviceEvent>();
    let device_event_tx = Arc::new(Mutex::new(device_event_tx));

    let tx_clone = device_event_tx.clone();
    set_device_event_callback(move |event| {
        if let Ok(tx) = tx_clone.lock() {
            let _ = tx.send(event);
        }
    });

    // Arka planda Win32 WM_DEVICECHANGE dinleyicisini çalıştıran daemon thread
    std::thread::spawn(|| {
        let cfg = load_config();
        let _ = start_sentry_loop_gui(&cfg);
    });

    // 14. Sistem Tepsisi ve Cihaz Olay Döngüsü Zamanlayıcısı (Slint Timer - Her 100 ms)
    let tray_timer = slint::Timer::default();
    let ui_w_timer = app.as_weak();
    let sentry_running_timer = sentry_running.clone();
    let mut startup_position_count = 0;

    tray_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(100),
        move || {
            // İlk açılışta pencereyi sağ alt köşeye sabitle (Flyout yerleşimi)
            if startup_position_count < 3 {
                startup_position_count += 1;
                #[cfg(windows)]
                position_window_to_bottom_right("Vectis - USB Güvenliği");
            }

            // A) Donanım Cihaz Bildirimlerini (Arrival/Removal) İşle
            while let Ok(event) = device_event_rx.try_recv() {
                if let Some(ui) = ui_w_timer.upgrade() {
                    let is_sentry = sentry_running_timer.load(Ordering::SeqCst);
                    match event {
                        DeviceEvent::Arrival(dp) => {
                            let (new_drives, _, cur_item) = query_drives_model();
                            ui.set_drives(ModelRc::new(VecModel::from(new_drives)));
                            ui.set_selected_drive_path(slint::SharedString::from(&dp));
                            ui.set_current_drive(cur_item);

                            let q_list = query_quarantine_model(&dp);
                            ui.set_quarantine_list(ModelRc::new(VecModel::from(q_list)));

                            // USB takıldığında pencereyi sağ altta öne getir
                            let _ = ui.show();
                            ui.window().set_minimized(false);
                            #[cfg(windows)]
                            position_window_to_bottom_right("Vectis - USB Güvenliği");

                            if is_sentry {
                                let mut s = ui.get_scan_summary();
                                s.is_running = true;
                                s.status_text = slint::SharedString::from(format!("USB algılandı ({}): Otomatik korunuyor...", dp));
                                ui.set_scan_summary(s);

                                let ui_w_pipeline = ui_w_timer.clone();
                                let dp_run = dp.clone();
                                std::thread::spawn(move || {
                                    run_pipeline_background(&dp_run, ui_w_pipeline);
                                });
                            }
                        }
                        DeviceEvent::Removal(dp) => {
                            let (new_drives, sel_p, cur_item) = query_drives_model();
                            ui.set_drives(ModelRc::new(VecModel::from(new_drives)));
                            ui.set_selected_drive_path(slint::SharedString::from(&sel_p));
                            ui.set_current_drive(cur_item);
                            let q_list = query_quarantine_model(&sel_p);
                            ui.set_quarantine_list(ModelRc::new(VecModel::from(q_list)));

                            let mut s = ui.get_scan_summary();
                            s.status_text = slint::SharedString::from(format!("USB Sürücü Çıkarıldı ({})", dp));
                            ui.set_scan_summary(s);
                        }
                    }
                }
            }

            // B) Sistem Tepsisi Menü Olaylarını Yokla
            if let Ok(event) = MenuEvent::receiver().try_recv() {
                if event.id == id_open {
                    if let Some(ui) = ui_w_timer.upgrade() {
                        let _ = ui.show();
                        ui.window().set_minimized(false);
                        #[cfg(windows)]
                        position_window_to_bottom_right("Vectis - USB Güvenliği");
                    }
                } else if event.id == id_settings {
                    if let Some(ui) = ui_w_timer.upgrade() {
                        ui.set_active_view(2);
                        let _ = ui.show();
                        ui.window().set_minimized(false);
                        #[cfg(windows)]
                        position_window_to_bottom_right("Vectis - USB Güvenliği");
                    }
                } else if event.id == id_quick_scan {
                    if let Some(ui) = ui_w_timer.upgrade() {
                        let dp = ui.get_selected_drive_path().to_string();
                        if !dp.is_empty() {
                            let ui_w_bg = ui_w_timer.clone();
                            std::thread::spawn(move || {
                                run_pipeline_background(&dp, ui_w_bg);
                            });
                        }
                    }
                } else if event.id == id_quit {
                    std::process::exit(0);
                }
            }

            // C) Sistem Tepsisi Tıklama Olaylarını Yokla
            if let Ok(event) = TrayIconEvent::receiver().try_recv() {
                match event {
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        ..
                    }
                    | TrayIconEvent::DoubleClick { .. } => {
                        if let Some(ui) = ui_w_timer.upgrade() {
                            let _ = ui.show();
                            ui.window().set_minimized(false);
                            #[cfg(windows)]
                            position_window_to_bottom_right("Vectis - USB Güvenliği");
                        }
                    }
                    _ => {}
                }
            }
        },
    );

    // 15. Pencereyi Göster, Sağ Alt Köşeye Konumlandır ve Event Loop'u Başlat
    app.show()?;
    log_step("app.show() OK");

    #[cfg(windows)]
    position_window_to_bottom_right("Vectis - USB Güvenliği");
    log_step("position_window OK");

    log_step("Calling slint::run_event_loop()...");
    let loop_res = slint::run_event_loop();
    log_step(&format!("slint::run_event_loop() exited: {:?}", loop_res));

    Ok(())
}

// ============================================================================
// ARKA PLAN GÜVENLİK BORU HATTI
// ============================================================================

fn run_pipeline_background(drive_path: &str, ui_weak: slint::Weak<AppWindow>) {
    let dp = drive_path.to_string();
    let config = load_config();
    let scanner = StaticScanner::new(&config);

    // Adım 1: Statik Tarama
    let summary = scanner.scan_drive(&dp);

    // Adım 2: Tehditleri İzole Et (Karantina)
    if summary.critical_count > 0 || summary.suspicious_count > 0 {
        for r in &summary.results {
            if r.threat_level != ThreatLevel::Clean {
                let reason = if !r.yara_matches.is_empty() {
                    format!("YARA: {}", r.yara_matches[0].rule_name)
                } else if !r.pe_anomalies.is_empty() {
                    format!("PE: {}", r.pe_anomalies[0])
                } else if !r.flags.is_empty() {
                    r.flags[0].clone()
                } else {
                    "Heuristic Anomali".to_string()
                };

                let _ = quarantine_file(
                    &dp,
                    &r.path,
                    &r.relative_path,
                    &r.sha256,
                    r.threat_level.as_str(),
                    &reason,
                );
            }
        }
    }

    // Adım 3: Solucan Onarımı (Gizli Klasörleri Görünür Kıl)
    let _ = clean_shortcut_worm(&dp);

    // Adım 4: USB Kök Dizin Bağışıklama (Kök Kilidi / Autorun Aşısı)
    if config.enable_ntfs_immunization {
        let _ = immunize_drive(&dp, Some(DEFAULT_SHARED_FOLDER));
    }

    // Arayüzü Güncelle
    let _ = slint::invoke_from_event_loop({
        let ui_w = ui_weak.clone();
        let dp_clone = dp.clone();
        let total = summary.total_files_scanned;
        let threat_count = summary.critical_count + summary.suspicious_count;
        move || {
            if let Some(ui) = ui_w.upgrade() {
                let mut s = ui.get_scan_summary();
                s.is_running = false;
                s.total_scanned = total as i32;
                s.clean_count = summary.clean_count as i32;
                s.suspicious_count = summary.suspicious_count as i32;
                s.critical_count = summary.critical_count as i32;
                s.status_text = slint::SharedString::from(if threat_count > 0 {
                    format!("{} tehdit izole edildi! Sürücü başarıyla korundu.", threat_count)
                } else {
                    format!("{} dosya temiz. USB sürücü koruma altında.", total)
                });
                ui.set_scan_summary(s);

                let (new_drives, _, cur_item) = query_drives_model();
                ui.set_drives(ModelRc::new(VecModel::from(new_drives)));
                ui.set_current_drive(cur_item);

                let q_list = query_quarantine_model(&dp_clone);
                ui.set_quarantine_list(ModelRc::new(VecModel::from(q_list)));
            }
        }
    });
}
