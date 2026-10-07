//! ============================================================================
//! CoreSync USB Gatekeeper - Gömülü YARA ve İmza Motoru
//! ----------------------------------------------------------------------------
//! Lisans: MIT | Mimari: Saf Rust (Air-Gapped, Harici C/libyara Bağımlılığı Yoktur)
//!
//! Bu modül:
//! 1. `include_str!` ile `rules/usb_threats.yar` kural dosyasını binary'e derleme zamanında gömer.
//! 2. Standart YARA sözdizimini (meta, strings, condition) bellek içinde derler.
//! 3. Büyük/küçük harf duyarsız metin (nocase), UTF-16LE geniş metin ve jokerli (??) hex kalıplarını destekler.
//! 4. Mantıksal koşul ağacını (and, or, not, any/all of them) mikrosaniyeler içinde değerlendirir.
//! ============================================================================

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Derleme zamanında gömülen varsayılan YARA kuralları
pub const DEFAULT_YARA_RULES: &str = include_str!("rules/usb_threats.yar");

/// Kalıp türü (Metin, Geniş UTF-16 veya Jokerli Hex)
#[derive(Debug, Clone)]
pub enum PatternKind {
    /// ASCII Metin (büyük/küçük harf duyarsız seçeneği ile)
    Ascii { pattern: Vec<u8>, nocase: bool },
    /// Jokerli Hex bayt dizisi (None = ?? jokeri)
    Hex { pattern: Vec<Option<u8>> },
}

/// YARA Kural İçindeki Bir Kalıp Tanımı
#[derive(Debug, Clone)]
pub struct YaraPattern {
    pub id: String,
    pub kind: PatternKind,
}

/// YARA Koşul İfadesi AST (Soyut Sözdizimi Ağacı)
#[derive(Debug, Clone)]
pub enum ConditionNode {
    Variable(String),
    AnyOfThem,
    AllOfThem,
    Not(Box<ConditionNode>),
    And(Box<ConditionNode>, Box<ConditionNode>),
    Or(Box<ConditionNode>, Box<ConditionNode>),
}

/// Derlenmiş Tek Bir YARA Kuralı
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub name: String,
    pub meta: HashMap<String, String>,
    pub patterns: Vec<YaraPattern>,
    pub condition: ConditionNode,
}

/// Bir Kural Eşleştiğinde Üretilen Sonuç
#[derive(Debug, Clone, PartialEq)]
pub struct YaraMatch {
    pub rule_name: String,
    pub severity: String,
    pub threat_type: String,
    pub description: String,
    pub matched_strings: Vec<(String, usize)>, // (Kalıp ID, Bulunduğu Ofset)
}

/// Gömülü YARA Motoru
#[derive(Debug, Clone)]
pub struct YaraEngine {
    pub rules: Vec<CompiledRule>,
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::load_embedded().unwrap_or_else(|err| {
            eprintln!("[-] [YARA] Gömülü kurallar derlenirken hata: {}", err);
            Self { rules: Vec::new() }
        })
    }
}

impl YaraEngine {
    /// Derleme zamanında gömülen varsayılan kuralları yükler
    pub fn load_embedded() -> Result<Self, String> {
        Self::compile_str(DEFAULT_YARA_RULES)
    }

    /// YARA kural metnini derler
    pub fn compile_str(source: &str) -> Result<Self, String> {
        let mut rules = Vec::new();
        let chunks = source.split("rule ");

        for chunk in chunks {
            let trimmed = chunk.trim();
            if trimmed.is_empty() || trimmed.starts_with("/*") && !trimmed.contains('{') {
                continue;
            }

            // Kural adını ayıkla
            let open_brace = trimmed.find('{').ok_or_else(|| {
                format!("Kuralda açılış parantezi bulunamadı: {}", trimmed)
            })?;
            let rule_name = trimmed[..open_brace].trim().to_string();

            let close_brace = trimmed.rfind('}').ok_or_else(|| {
                format!("'{}' kuralında kapanış parantezi bulunamadı", rule_name)
            })?;
            let body = &trimmed[open_brace + 1..close_brace];

            let compiled = parse_rule_body(&rule_name, body)?;
            rules.push(compiled);
        }

        Ok(Self { rules })
    }

    /// Bellekteki bayt dizisini tüm derlenmiş kurallarla tarar
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<YaraMatch> {
        let mut matches = Vec::new();

        for rule in &self.rules {
            let mut pattern_hits: HashMap<String, Vec<usize>> = HashMap::new();

            // Tüm kalıpları veri üzerinde ara
            for pat in &rule.patterns {
                let hits = search_pattern(data, &pat.kind);
                if !hits.is_empty() {
                    pattern_hits.insert(pat.id.clone(), hits);
                }
            }

            // Koşulu değerlendir
            if evaluate_condition(&rule.condition, &pattern_hits, rule.patterns.len()) {
                let mut matched_strings = Vec::new();
                for (id, offsets) in &pattern_hits {
                    for &offset in offsets {
                        matched_strings.push((id.clone(), offset));
                    }
                }
                // Ofsete göre sırala
                matched_strings.sort_by_key(|&(_, off)| off);

                let severity = rule
                    .meta
                    .get("severity")
                    .cloned()
                    .unwrap_or_else(|| "MEDIUM".to_string());
                let threat_type = rule
                    .meta
                    .get("threat_type")
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string());
                let description = rule
                    .meta
                    .get("description")
                    .cloned()
                    .unwrap_or_else(|| "Gömülü YARA kuralı ile eşleşti.".to_string());

                matches.push(YaraMatch {
                    rule_name: rule.name.clone(),
                    severity,
                    threat_type,
                    description,
                    matched_strings,
                });
            }
        }

        matches
    }

    /// Dosyayı okuyarak tarar (Maksimum 64 MB ile RAM güvenliğini korur)
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<YaraMatch>, std::io::Error> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        let max_size = 64 * 1024 * 1024; // 64 MB sınır
        file.by_ref().take(max_size).read_to_end(&mut buffer)?;
        Ok(self.scan_bytes(&buffer))
    }
}

// ============================================================================
// KALIP VE ARAMA YARDIMCILARI
// ============================================================================

fn search_pattern(data: &[u8], kind: &PatternKind) -> Vec<usize> {
    let mut offsets = Vec::new();
    if data.is_empty() {
        return offsets;
    }

    match kind {
        PatternKind::Ascii { pattern, nocase } => {
            if pattern.is_empty() || pattern.len() > data.len() {
                return offsets;
            }

            if *nocase {
                // Hem ASCII hem UTF-16LE varyantını tara (Windows ortamında komutlar UTF-16 da olabilir)
                let pat_lower: Vec<u8> = pattern.iter().map(|b| b.to_ascii_lowercase()).collect();
                let plen = pat_lower.len();

                // ASCII Arama
                for i in 0..=(data.len() - plen) {
                    let mut matched = true;
                    for j in 0..plen {
                        if data[i + j].to_ascii_lowercase() != pat_lower[j] {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        offsets.push(i);
                    }
                }

                // UTF-16LE Arama (örn: p\0o\0w\0e\0r\0s\0h\0e\0l\0l)
                let mut wide_lower = Vec::with_capacity(plen * 2);
                for &b in &pat_lower {
                    wide_lower.push(b);
                    wide_lower.push(0);
                }
                let wlen = wide_lower.len();
                if wlen <= data.len() {
                    for i in 0..=(data.len() - wlen) {
                        let mut matched = true;
                        for j in (0..wlen).step_by(2) {
                            if data[i + j].to_ascii_lowercase() != wide_lower[j]
                                || data[i + j + 1] != 0
                            {
                                matched = false;
                                break;
                            }
                        }
                        if matched {
                            offsets.push(i);
                        }
                    }
                }
            } else {
                let plen = pattern.len();
                for i in 0..=(data.len() - plen) {
                    if &data[i..i + plen] == pattern.as_slice() {
                        offsets.push(i);
                    }
                }
            }
        }
        PatternKind::Hex { pattern } => {
            let plen = pattern.len();
            if plen == 0 || plen > data.len() {
                return offsets;
            }

            for i in 0..=(data.len() - plen) {
                let mut matched = true;
                for j in 0..plen {
                    if let Some(expected) = pattern[j] {
                        if data[i + j] != expected {
                            matched = false;
                            break;
                        }
                    }
                }
                if matched {
                    offsets.push(i);
                }
            }
        }
    }

    offsets
}

// ============================================================================
// YARA GÖVDE VE KOŞUL AYIKLAYICI
// ============================================================================

/// YARA dizgi kaçış karakterlerini (örn: \\, \", \n, \r, \t) çözer
fn unescape_yara_string(raw: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    '\\' => {
                        bytes.push(b'\\');
                        chars.next();
                        continue;
                    }
                    '"' => {
                        bytes.push(b'"');
                        chars.next();
                        continue;
                    }
                    't' => {
                        bytes.push(b'\t');
                        chars.next();
                        continue;
                    }
                    'r' => {
                        bytes.push(b'\r');
                        chars.next();
                        continue;
                    }
                    'n' => {
                        bytes.push(b'\n');
                        chars.next();
                        continue;
                    }
                    _ => {
                        bytes.push(b'\\');
                        continue;
                    }
                }
            }
        }
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        bytes.extend_from_slice(s.as_bytes());
    }
    bytes
}

fn parse_rule_body(rule_name: &str, body: &str) -> Result<CompiledRule, String> {
    let mut meta = HashMap::new();
    let mut patterns = Vec::new();
    let mut condition_str = String::new();

    let mut current_section = "";

    for line in body.lines() {
        let clean = line.trim();
        if clean.is_empty() || clean.starts_with("//") {
            continue;
        }

        if clean.starts_with("meta:") {
            current_section = "meta";
            continue;
        } else if clean.starts_with("strings:") {
            current_section = "strings";
            continue;
        } else if clean.starts_with("condition:") {
            current_section = "condition";
            continue;
        }

        match current_section {
            "meta" => {
                if let Some(eq_pos) = clean.find('=') {
                    let key = clean[..eq_pos].trim().to_string();
                    let val = clean[eq_pos + 1..]
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    meta.insert(key, val);
                }
            }
            "strings" => {
                if let Some(eq_pos) = clean.find('=') {
                    let id = clean[..eq_pos].trim().to_string();
                    let rest = clean[eq_pos + 1..].trim();

                    if rest.starts_with('"') {
                        // Metin Kalıbı: "..." [nocase]
                        let last_quote = rest.rfind('"').ok_or_else(|| {
                            format!("'{}' kalıbında kapanış tırnağı yok: {}", id, rest)
                        })?;
                        let content = &rest[1..last_quote];
                        let flags = &rest[last_quote + 1..].trim();
                        let nocase = flags.contains("nocase");

                        patterns.push(YaraPattern {
                            id,
                            kind: PatternKind::Ascii {
                                pattern: unescape_yara_string(content),
                                nocase,
                            },
                        });
                    } else if rest.starts_with('{') {
                        // Hex Kalıbı: { 4C 00 ?? FF }
                        let close_bracket = rest.rfind('}').ok_or_else(|| {
                            format!("'{}' kalıbında kapanış köşeli ayraç yok: {}", id, rest)
                        })?;
                        let hex_str = &rest[1..close_bracket].trim();
                        let mut hex_bytes = Vec::new();

                        for token in hex_str.split_whitespace() {
                            if token == "??" || token == "?" {
                                hex_bytes.push(None);
                            } else if let Ok(byte) = u8::from_str_radix(token, 16) {
                                hex_bytes.push(Some(byte));
                            } else {
                                return Err(format!("Geçersiz hex bayt: '{}'", token));
                            }
                        }

                        patterns.push(YaraPattern {
                            id,
                            kind: PatternKind::Hex { pattern: hex_bytes },
                        });
                    }
                }
            }
            "condition" => {
                condition_str.push_str(clean);
                condition_str.push(' ');
            }
            _ => {}
        }
    }

    if condition_str.trim().is_empty() {
        return Err(format!("'{}' kuralında 'condition' bulunamadı", rule_name));
    }

    let condition = parse_condition(condition_str.trim())?;

    Ok(CompiledRule {
        name: rule_name.to_string(),
        meta,
        patterns,
        condition,
    })
}

// ============================================================================
// KOŞUL AST AYRIŞTIRICISI VE ÇÖZÜCÜSÜ
// ============================================================================

fn parse_condition(input: &str) -> Result<ConditionNode, String> {
    let tokens = tokenize_condition(input)?;
    let mut pos = 0;
    parse_or_expr(&tokens, &mut pos)
}

#[derive(Debug, PartialEq, Clone)]
enum Token {
    Ident(String),
    And,
    Or,
    Not,
    LParen,
    RParen,
    AnyOfThem,
    AllOfThem,
}

fn tokenize_condition(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }

        if c == '(' {
            tokens.push(Token::LParen);
            chars.next();
        } else if c == ')' {
            tokens.push(Token::RParen);
            chars.next();
        } else {
            // Kelime tokeni oku
            let mut word = String::new();
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() || ch == '(' || ch == ')' {
                    break;
                }
                word.push(ch);
                chars.next();
            }

            let lower = word.to_lowercase();
            match lower.as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                _ => {
                    // "any of them" kalıbı kontrolü
                    if lower == "any" {
                        // "of them" takip ediyor mu kontrol et
                        tokens.push(Token::AnyOfThem);
                    } else if lower == "all" {
                        tokens.push(Token::AllOfThem);
                    } else if lower == "of" || lower == "them" {
                        // "any of them" veya "all of them" sonrası gelen ara kelimeler (yutulur)
                    } else {
                        tokens.push(Token::Ident(word));
                    }
                }
            }
        }
    }

    Ok(tokens)
}

fn parse_or_expr(tokens: &[Token], pos: &mut usize) -> Result<ConditionNode, String> {
    let mut left = parse_and_expr(tokens, pos)?;

    while *pos < tokens.len() && tokens[*pos] == Token::Or {
        *pos += 1;
        let right = parse_and_expr(tokens, pos)?;
        left = ConditionNode::Or(Box::new(left), Box::new(right));
    }

    Ok(left)
}

fn parse_and_expr(tokens: &[Token], pos: &mut usize) -> Result<ConditionNode, String> {
    let mut left = parse_unary_expr(tokens, pos)?;

    while *pos < tokens.len() && tokens[*pos] == Token::And {
        *pos += 1;
        let right = parse_unary_expr(tokens, pos)?;
        left = ConditionNode::And(Box::new(left), Box::new(right));
    }

    Ok(left)
}

fn parse_unary_expr(tokens: &[Token], pos: &mut usize) -> Result<ConditionNode, String> {
    if *pos < tokens.len() && tokens[*pos] == Token::Not {
        *pos += 1;
        let child = parse_unary_expr(tokens, pos)?;
        return Ok(ConditionNode::Not(Box::new(child)));
    }
    parse_primary_expr(tokens, pos)
}

fn parse_primary_expr(tokens: &[Token], pos: &mut usize) -> Result<ConditionNode, String> {
    if *pos >= tokens.len() {
        return Err("Beklenmeyen koşul sonu (Tokens bitti)".to_string());
    }

    match &tokens[*pos] {
        Token::LParen => {
            *pos += 1;
            let node = parse_or_expr(tokens, pos)?;
            if *pos < tokens.len() && tokens[*pos] == Token::RParen {
                *pos += 1;
                Ok(node)
            } else {
                Err("Eşleşmeyen parantez: ')' bekleniyordu".to_string())
            }
        }
        Token::AnyOfThem => {
            *pos += 1;
            Ok(ConditionNode::AnyOfThem)
        }
        Token::AllOfThem => {
            *pos += 1;
            Ok(ConditionNode::AllOfThem)
        }
        Token::Ident(name) => {
            let res = ConditionNode::Variable(name.clone());
            *pos += 1;
            Ok(res)
        }
        other => Err(format!("Beklenmeyen token: {:?}", other)),
    }
}

fn evaluate_condition(
    node: &ConditionNode,
    hits: &HashMap<String, Vec<usize>>,
    total_patterns: usize,
) -> bool {
    match node {
        ConditionNode::Variable(name) => hits.contains_key(name),
        ConditionNode::AnyOfThem => !hits.is_empty(),
        ConditionNode::AllOfThem => hits.len() == total_patterns && total_patterns > 0,
        ConditionNode::Not(child) => !evaluate_condition(child, hits, total_patterns),
        ConditionNode::And(left, right) => {
            evaluate_condition(left, hits, total_patterns)
                && evaluate_condition(right, hits, total_patterns)
        }
        ConditionNode::Or(left, right) => {
            evaluate_condition(left, hits, total_patterns)
                || evaluate_condition(right, hits, total_patterns)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_rules_compile() {
        let engine = YaraEngine::load_embedded();
        assert!(engine.is_ok(), "Gömülü kurallar derlenemedi!");
        let e = engine.unwrap();
        assert!(!e.rules.is_empty(), "Kural listesi boş!");
    }

    #[test]
    fn test_shortcut_dropper_detection() {
        let engine = YaraEngine::load_embedded().unwrap();

        // Sahte LNK başlığı + powershell + -windowstyle hidden içeren test verisi
        let mut sample = vec![
            0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, // LNK header
        ];
        sample.extend_from_slice(b"C:\\Windows\\System32\\powershell.exe -windowstyle hidden -enc AAAA");

        let matches = engine.scan_bytes(&sample);
        assert!(!matches.is_empty(), "LNK dropper tespit edilemedi!");
        assert_eq!(matches[0].rule_name, "USB_Shortcut_Dropper_LNK");
    }

    #[test]
    fn test_rtlo_spoofing_detection() {
        let engine = YaraEngine::load_embedded().unwrap();

        // U+202E içeren test dizisi
        let sample = "document\u{202E}fdp.exe".as_bytes();
        let matches = engine.scan_bytes(sample);
        assert!(
            matches.iter().any(|m| m.rule_name == "USB_RTLO_Filename_Spoofing"),
            "RTLO karakteri tespit edilemedi!"
        );
    }

    #[test]
    fn test_eicar_rule_detection() {
        let engine = YaraEngine::load_embedded().unwrap();
        let eicar_sample = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let matches = engine.scan_bytes(eicar_sample);
        assert!(
            matches.iter().any(|m| m.rule_name == "EICAR_Standard_Test_File"),
            "EICAR kuralı tespit edilemedi!"
        );
        let m = matches.iter().find(|m| m.rule_name == "EICAR_Standard_Test_File").unwrap();
        assert_eq!(m.severity, "CRITICAL");
    }
}
