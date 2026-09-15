//! MAC address → vendor, from the IEEE MA-L registry embedded at build time
//! (data/oui.txt, regenerate with scripts/update_oui.sh).

use std::collections::HashMap;
use std::sync::OnceLock;

static TABLE: &str = include_str!("../data/oui.txt");

fn table() -> &'static HashMap<&'static str, &'static str> {
    static T: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    T.get_or_init(|| TABLE.lines().filter_map(|l| l.split_once('\t')).collect())
}

pub fn vendor(mac: &str) -> String {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if hex.len() < 6 {
        return String::new();
    }
    if let Some(v) = table().get(&hex[..6]) {
        return v.to_string();
    }
    // Locally administered bit set → randomized MAC (phones, laptops with privacy on).
    match u8::from_str_radix(&hex[..2], 16) {
        Ok(b) if b & 0x02 != 0 => "(private MAC)".into(),
        _ => String::new(),
    }
}
