//! ============================================================================
//! CoreSync USB Gatekeeper - Shannon Entropi Hesaplayıcısı ve Anomali Dedektörü
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Sıfır Bağımlılık)
//!
//! Shannon Entropisi: H(X) = - SUM( p(x) * log2(p(x)) )
//! Normal derlenmiş PE dosyaları 5.0 - 6.8 arasında entropiye sahipken; UPX,
//! ASPack, Themida gibi paketleyiciler veya şifrelenmiş/zararlı yükler (crypter)
//! genellikle 7.2'nin üzerinde rastgelelik/entropi üretir.
//! ============================================================================

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Varsayılan şüpheli entropi eşiği (7.2 üzeri paketlenmiş/şifrelenmiş zararlı kabul edilir)
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 7.2;

/// Entropi analiz sonucu
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyReport {
    /// 0.0 ile 8.0 arasında hesaplanan Shannon entropi değeri
    pub value: f64,
    /// Eşik değerini aşıp aşmadığı
    pub is_suspicious: bool,
    /// İnsan tarafından anlaşılır risk değerlendirmesi
    pub evaluation: &'static str,
    /// İncelenen toplam bayt sayısı
    pub total_bytes: u64,
}

/// Verilen bayt dizisinin Shannon entropisini hesaplar (0.0 - 8.0 aralığı)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0usize; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequencies {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Dosyayı belleğe tek seferde yüklemeden, 64 KB akış blokları halinde okuyarak
/// frekans tablosu üzerinden dosya entropisini hesaplar (Sıfır RAM şişmesi)
pub fn calculate_file_entropy<P: AsRef<Path>>(path: P) -> Result<f64, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(65536, file);
    let mut frequencies = [0u64; 256];
    let mut total_bytes = 0u64;
    let mut buffer = [0u8; 65536];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total_bytes += n as u64;
        for &byte in &buffer[..n] {
            frequencies[byte as usize] += 1;
        }
    }

    if total_bytes == 0 {
        return Ok(0.0);
    }

    let total = total_bytes as f64;
    let mut entropy = 0.0;

    for &count in &frequencies {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    Ok(entropy)
}

/// Entropi değerini değerlendirir ve rapor nesnesi üretir
pub fn evaluate_entropy(entropy: f64, total_bytes: u64, threshold: f64) -> EntropyReport {
    let is_suspicious = entropy >= threshold;
    let evaluation = match entropy {
        e if e < 1.0 => "Son derece düşük (Tekdüze / Sıfır Dolgulu Blok)",
        e if e < 5.0 => "Düşük (Düz Metin / Yapılandırılmış Doküman)",
        e if e < 6.8 => "Normal (Standart Derlenmiş İkili / Kod)",
        e if e < threshold => "Yüksek (Sıkıştırılmış / Yoğun Veri)",
        _ => "KRİTİK ANOMALİ: Şifrelenmiş veya Paketlenmiş (Packer / Malware / Crypter)",
    };

    EntropyReport {
        value: entropy,
        is_suspicious,
        evaluation,
        total_bytes,
    }
}

/// Dosyayı analiz ederek doğrudan tam rapor döndürür
pub fn analyze_file_entropy<P: AsRef<Path>>(
    path: P,
    threshold: Option<f64>,
) -> Result<EntropyReport, std::io::Error> {
    let p = path.as_ref();
    let meta = std::fs::metadata(p)?;
    let file_size = meta.len();
    let entropy = calculate_file_entropy(p)?;
    let thresh = threshold.unwrap_or(DEFAULT_ENTROPY_THRESHOLD);
    Ok(evaluate_entropy(entropy, file_size, thresh))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let data = [0u8; 1000];
        let ent = calculate_entropy(&data);
        assert_eq!(ent, 0.0);
    }

    #[test]
    fn test_maximum_entropy() {
        // Her 256 bayttan tam olarak 4 adet (toplam 1024) -> düzgün dağılım (maksimum 8.0)
        let mut data = Vec::with_capacity(1024);
        for _ in 0..4 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let ent = calculate_entropy(&data);
        assert!((ent - 8.0).abs() < 1e-6);
    }

    #[test]
    fn test_threshold_flagging() {
        let rep_low = evaluate_entropy(4.5, 1024, 7.2);
        assert!(!rep_low.is_suspicious);

        let rep_high = evaluate_entropy(7.45, 1024, 7.2);
        assert!(rep_high.is_suspicious);
    }
}
