//! ============================================================================
//! CoreSync USB Gatekeeper - PE (Portable Executable) Statik Başlık & Anomali Analizcisi
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Sıfır Harici Kütüphane / C Bağımlılığı)
//!
//! Bu modül:
//! 1. MZ ve PE imza bütünlüğünü doğrular.
//! 2. Şüpheli paketleyici bölüm isimlerini (UPX, ASPack, Themida, VMProtect vb.) yakalar.
//! 3. W+X (Hem Yazılabilir Hem Çalıştırılabilir) bellek anomalilerini (Self-modifying code) tespit eder.
//! 4. Giriş noktası (Entry Point) sapmalarını ve ham veri vs sanal boyut tutarsızlıklarını inceler.
//! 5. Sahte uzantı maskelemesini (örn: .jpg veya .pdf görünümlü PE ikilileri) deşifre eder.
//! ============================================================================

use crate::entropy::calculate_entropy;
use std::fs::File;
use std::io::Read;
use std::path::Path;

// Win32 PE Bölüm Bayrakları
pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

// Bilinen zararlı veya packer/crypter bölüm adları
const KNOWN_PACKER_SECTIONS: &[&str] = &[
    "UPX0", "UPX1", "UPX2", "!UPX", "UPX!",
    ".aspack", ".adata", "ASPack",
    "PEC2", "PECompact2",
    "FSG!", "MEW", ".pcle",
    ".themida", "Themida",
    ".vmp0", ".vmp1", ".vmp2",
    "Enigma", ".nsp0", ".nsp1",
    ".MPRESS1", ".MPRESS2",
    ".petite", ".boom", "yoda",
    "pebundle", "pespin",
];

/// PE Bölüm Detayı
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_ptr: u32,
    pub characteristics: u32,
    pub entropy: f64,
    pub is_writable: bool,
    pub is_executable: bool,
    pub is_writable_and_executable: bool,
    pub is_packer_section: bool,
}

/// PE Başlık ve Anomali Analiz Raporu
#[derive(Debug, Clone)]
pub struct PeReport {
    pub is_pe: bool,
    pub is_64bit: bool,
    pub machine_type: String,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub entry_point_rva: u32,
    pub entry_point_section: Option<String>,
    pub entry_point_in_last_section: bool,
    pub sections: Vec<SectionInfo>,
    pub detected_anomalies: Vec<String>,
    pub is_suspicious: bool,
    pub masquerading_detected: bool,
}

impl Default for PeReport {
    fn default() -> Self {
        Self {
            is_pe: false,
            is_64bit: false,
            machine_type: "Unknown".to_string(),
            number_of_sections: 0,
            timestamp: 0,
            entry_point_rva: 0,
            entry_point_section: None,
            entry_point_in_last_section: false,
            sections: Vec::new(),
            detected_anomalies: Vec::new(),
            is_suspicious: false,
            masquerading_detected: false,
        }
    }
}

/// Ham bayt dizisinin geçerli bir MZ başlığı taşıyıp taşımadığını kontrol eder
pub fn has_mz_magic(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'M' && data[1] == b'Z'
}

/// Bayt dizisini PE yapısı yönünden derinlemesine çözümler
pub fn parse_pe_bytes(data: &[u8], file_extension: Option<&str>) -> PeReport {
    let mut report = PeReport::default();

    // 1. DOS Başlığı (MZ) Doğrulaması
    if !has_mz_magic(data) {
        return report;
    }

    if data.len() < 64 {
        report.detected_anomalies.push("Geçersiz DOS Başlığı: Dosya 64 bayttan küçük.".to_string());
        return report;
    }

    // Sahte uzantı denetimi: Dosya MZ başlığı içeriyor fakat uzantısı zararsız bir doküman veya medya ise
    if let Some(ext) = file_extension {
        let clean_ext = ext.trim_start_matches('.').to_lowercase();
        let harmless_exts = [
            "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt",
            "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4",
            "txt", "csv", "zip", "rar", "7z", "iso"
        ];
        if harmless_exts.contains(&clean_ext.as_str()) {
            report.masquerading_detected = true;
            report.is_suspicious = true;
            report.detected_anomalies.push(format!(
                "KRİTİK MASKELEME (Masquerading): Dosya uzantısı '.{}' olmasına rağmen ikili PE (MZ/EXE) başlığı taşıyor!",
                clean_ext
            ));
        }
    }

    // e_lfanew: PE başlığına işaret eden ofset (0x3C konumundaki 4 bayt)
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    if e_lfanew + 24 > data.len() {
        report.detected_anomalies.push(format!(
            "Bozuk PE Ofseti: e_lfanew (0x{:X}) dosya sınırlarını aşıyor.",
            e_lfanew
        ));
        return report;
    }

    // 2. PE İmza Doğrulaması ('P', 'E', 0x00, 0x00)
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return report;
    }

    report.is_pe = true;

    // 3. COFF Dosya Başlığı
    let coff_offset = e_lfanew + 4;
    let machine = u16::from_le_bytes([data[coff_offset], data[coff_offset + 1]]);
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]);
    let timestamp = u32::from_le_bytes([
        data[coff_offset + 4],
        data[coff_offset + 5],
        data[coff_offset + 6],
        data[coff_offset + 7],
    ]);
    let size_of_opt_header = u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    report.number_of_sections = num_sections;
    report.timestamp = timestamp;
    report.machine_type = match machine {
        0x014c => "x86 (32-bit Intel)".to_string(),
        0x8664 => "x64 (64-bit AMD/Intel)".to_string(),
        0x01c0 => "ARM".to_string(),
        0xaa64 => "ARM64".to_string(),
        other => format!("Bilinmeyen Mimari (0x{:04X})", other),
    };

    if num_sections == 0 {
        report.detected_anomalies.push("Anomali: Bölüm sayısı sıfır (0 sections).".to_string());
        report.is_suspicious = true;
    } else if num_sections > 20 {
        report.detected_anomalies.push(format!(
            "Şüpheli: Olağandışı yüksek bölüm sayısı ({} bölüm).",
            num_sections
        ));
        report.is_suspicious = true;
    }

    // 4. İsteğe Bağlı Başlık (Optional Header) & Giriş Noktası
    let opt_offset = coff_offset + 20;
    if size_of_opt_header >= 28 && opt_offset + size_of_opt_header <= data.len() {
        let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
        report.is_64bit = opt_magic == 0x020b; // 0x10b = PE32, 0x20b = PE32+
        let entry_point = u32::from_le_bytes([
            data[opt_offset + 16],
            data[opt_offset + 17],
            data[opt_offset + 18],
            data[opt_offset + 19],
        ]);
        report.entry_point_rva = entry_point;
    }

    // 5. Bölüm Başlıkları (Section Headers) Analizi
    let sections_start = opt_offset + size_of_opt_header;
    let section_header_size = 40;

    let mut parsed_sections = Vec::new();
    let mut ep_section_name: Option<String> = None;

    for i in 0..num_sections as usize {
        let sec_offset = sections_start + (i * section_header_size);
        if sec_offset + section_header_size > data.len() {
            report.detected_anomalies.push(format!(
                "Bozuk Bölüm Tablosu: Bölüm {} dosya boyutunun ötesinde.",
                i
            ));
            report.is_suspicious = true;
            break;
        }

        // 8 Baytlık Bölüm Adı
        let name_bytes = &data[sec_offset..sec_offset + 8];
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name_str = String::from_utf8_lossy(&name_bytes[..name_len]).to_string();

        let virtual_size = u32::from_le_bytes([
            data[sec_offset + 8],
            data[sec_offset + 9],
            data[sec_offset + 10],
            data[sec_offset + 11],
        ]);
        let virtual_address = u32::from_le_bytes([
            data[sec_offset + 12],
            data[sec_offset + 13],
            data[sec_offset + 14],
            data[sec_offset + 15],
        ]);
        let raw_data_size = u32::from_le_bytes([
            data[sec_offset + 16],
            data[sec_offset + 17],
            data[sec_offset + 18],
            data[sec_offset + 19],
        ]);
        let raw_data_ptr = u32::from_le_bytes([
            data[sec_offset + 20],
            data[sec_offset + 21],
            data[sec_offset + 22],
            data[sec_offset + 23],
        ]);
        let characteristics = u32::from_le_bytes([
            data[sec_offset + 36],
            data[sec_offset + 37],
            data[sec_offset + 38],
            data[sec_offset + 39],
        ]);

        let is_executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        let is_wx = is_executable && is_writable;

        // Bölüm Entropisi Hesaplama (Ham verisi mevcutsa)
        let sec_entropy = if raw_data_ptr as usize + raw_data_size as usize <= data.len()
            && raw_data_size > 0
        {
            let sec_bytes = &data[raw_data_ptr as usize..(raw_data_ptr + raw_data_size) as usize];
            calculate_entropy(sec_bytes)
        } else {
            0.0
        };

        // Bilinen paketleyici bölüm adı kontrolü
        let mut is_packer = false;
        for &known in KNOWN_PACKER_SECTIONS {
            if name_str.eq_ignore_ascii_case(known) {
                is_packer = true;
                break;
            }
        }

        // Giriş Noktası (Entry Point) bu bölüme mi denk geliyor?
        if report.entry_point_rva >= virtual_address
            && report.entry_point_rva < virtual_address.saturating_add(virtual_size.max(raw_data_size))
        {
            ep_section_name = Some(name_str.clone());
            if i == (num_sections as usize - 1) && num_sections > 1 {
                report.entry_point_in_last_section = true;
            }
        }

        // Anomali Taramaları:
        // A) W+X Anomali (Hem Yazılabilir Hem Çalıştırılabilir)
        if is_wx {
            report.is_suspicious = true;
            report.detected_anomalies.push(format!(
                "KRİTİK GÜVENLİK İHLALİ (W+X): '{}' bölümü hem YAZILABİLİR hem ÇALIŞTIRILABİLİR (Self-Modifying Code / Shellcode Dropper).",
                name_str
            ));
        }

        // B) Packer Bölüm Adı Tespiti
        if is_packer {
            report.is_suspicious = true;
            report.detected_anomalies.push(format!(
                "PAKETLEYİCİ TESPİTİ (Packer/Crypter): Şüpheli bölüm adı algılandı: '{}'.",
                name_str
            ));
        }

        // C) Ham Veri Boyut Tutarsızlığı (SizeOfRawData == 0 ve VirtualSize > 0 -> tipik UPX unpacking alanı)
        if raw_data_size == 0 && virtual_size > 0 {
            report.detected_anomalies.push(format!(
                "Bellek Şişirme Anomalisi: '{}' bölümünün disk boyutu 0 fakat sanal boyutu {} bayt (Unpacking alanı).",
                name_str, virtual_size
            ));
            report.is_suspicious = true;
        }

        // D) Yüksek Bölüm Entropisi (> 7.2)
        if sec_entropy >= 7.2 && raw_data_size > 512 {
            report.detected_anomalies.push(format!(
                "ŞÜPHELİ ENTROPİ: '{}' bölümünün entropisi {:.2}/8.0 (Şifrelenmiş veya sıkıştırılmış zararlı kod yükü).",
                name_str, sec_entropy
            ));
            report.is_suspicious = true;
        }

        parsed_sections.push(SectionInfo {
            name: name_str,
            virtual_size,
            virtual_address,
            raw_data_size,
            raw_data_ptr,
            characteristics,
            entropy: sec_entropy,
            is_writable,
            is_executable,
            is_writable_and_executable: is_wx,
            is_packer_section: is_packer,
        });
    }

    report.entry_point_section = ep_section_name;

    // Giriş noktası son bölümde ise (Tipik packer davranışı: Orijinal kod son bölümde açılır ve oradan çalışır)
    if report.entry_point_in_last_section {
        report.detected_anomalies.push(
            "GİRİŞ NOKTASI ANOMALİSİ: İkili dosyanın giriş noktası (OEP/EP) son bölüme yönlendirilmiş (Packer stager işareti).".to_string()
        );
        report.is_suspicious = true;
    }

    report.sections = parsed_sections;
    report
}

/// Dosyayı okuyarak PE analizini tamamlar
pub fn analyze_pe_file<P: AsRef<Path>>(path: P) -> Result<PeReport, std::io::Error> {
    let p = path.as_ref();
    let mut file = File::open(p)?;
    let mut buffer = Vec::new();
    // PE başlıkları ve ilk bölümler için ilk 1 MB veya tüm dosya yeterlidir
    let max_read = 2 * 1024 * 1024;
    file.by_ref().take(max_read).read_to_end(&mut buffer)?;

    let ext = p.extension().and_then(|e| e.to_str());
    Ok(parse_pe_bytes(&buffer, ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_pe_file() {
        let data = b"Hello, this is a plain text file, not a PE.";
        let rep = parse_pe_bytes(data, Some("txt"));
        assert!(!rep.is_pe);
        assert!(!rep.is_suspicious);
    }

    #[test]
    fn test_masquerading_detection() {
        let mut fake_pdf = vec![0u8; 128];
        fake_pdf[0] = b'M';
        fake_pdf[1] = b'Z';
        // e_lfanew points to 0x40
        fake_pdf[0x3C] = 0x40;
        fake_pdf[0x40] = b'P';
        fake_pdf[0x41] = b'E';
        fake_pdf[0x42] = 0;
        fake_pdf[0x43] = 0;

        let rep = parse_pe_bytes(&fake_pdf, Some("pdf"));
        assert!(rep.is_pe);
        assert!(rep.masquerading_detected);
        assert!(rep.is_suspicious);
    }
}
