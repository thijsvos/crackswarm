/// Common hash mode constants for quick reference.
/// Full list: <https://hashcat.net/wiki/doku.php?id=example_hashes>
pub mod modes {
    pub const MD5: u32 = 0;
    pub const SHA1: u32 = 100;
    pub const SHA256: u32 = 1400;
    pub const SHA512: u32 = 1700;
    pub const NTLM: u32 = 1000;
    pub const NET_NTLMV1: u32 = 5500;
    pub const NET_NTLMV2: u32 = 5600;
    pub const WPA_PMKID: u32 = 22000;
    pub const WPA_EAPOL: u32 = 22000;
    pub const BCRYPT: u32 = 3200;
    pub const KERBEROS_TGS_REP: u32 = 13100;
    pub const KERBEROS_AS_REP: u32 = 18200;
    pub const MSCACHEV2: u32 = 2100;
}

/// Hashcat attack modes.
pub mod attack_modes {
    pub const DICTIONARY: u32 = 0;
    pub const COMBINATOR: u32 = 1;
    pub const BRUTE_FORCE: u32 = 3;
    pub const HYBRID_WORDLIST_MASK: u32 = 6;
    pub const HYBRID_MASK_WORDLIST: u32 = 7;
}

/// JSON status output from `hashcat --status-json`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct HashcatStatus {
    pub session: Option<String>,
    pub guess: Option<GuessInfo>,
    pub status: Option<i32>,
    pub target: Option<String>,
    pub progress: Option<Vec<u64>>,
    pub restore_point: Option<u64>,
    pub recovered_hashes: Option<Vec<u64>>,
    pub recovered_salts: Option<Vec<u64>>,
    pub rejected: Option<u64>,
    pub devices: Option<Vec<DeviceStatus>>,
    pub time_start: Option<u64>,
    pub estimated_stop: Option<u64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct GuessInfo {
    pub guess_base: Option<String>,
    pub guess_base_count: Option<u64>,
    pub guess_base_offset: Option<u64>,
    pub guess_mod: Option<String>,
    pub guess_mod_count: Option<u64>,
    pub guess_mod_offset: Option<u64>,
    pub guess_mode: Option<u32>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct DeviceStatus {
    pub device_id: Option<u32>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub speed: Option<u64>,
    pub temp: Option<i32>,
    pub util: Option<i32>,
}

impl HashcatStatus {
    /// Calculate aggregate speed across all devices.
    pub fn total_speed(&self) -> u64 {
        self.devices
            .as_ref()
            .map(|devs| devs.iter().filter_map(|d| d.speed).sum())
            .unwrap_or(0)
    }

    /// Calculate progress percentage.
    pub fn progress_pct(&self) -> f64 {
        match &self.progress {
            Some(p) if p.len() >= 2 && p[1] > 0 => (p[0] as f64 / p[1] as f64) * 100.0,
            _ => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_status(
        devices: Option<Vec<DeviceStatus>>,
        progress: Option<Vec<u64>>,
    ) -> HashcatStatus {
        HashcatStatus {
            session: None,
            guess: None,
            status: None,
            target: None,
            progress,
            restore_point: None,
            recovered_hashes: None,
            recovered_salts: None,
            rejected: None,
            devices,
            time_start: None,
            estimated_stop: None,
        }
    }

    fn make_device(speed: Option<u64>) -> DeviceStatus {
        DeviceStatus {
            device_id: Some(1),
            device_name: Some("GPU".to_string()),
            device_type: Some("GPU".to_string()),
            speed,
            temp: None,
            util: None,
        }
    }

    // ── total_speed ──

    #[test]
    fn total_speed_no_devices() {
        let s = make_status(None, None);
        assert_eq!(s.total_speed(), 0);
    }

    #[test]
    fn total_speed_empty_devices() {
        let s = make_status(Some(vec![]), None);
        assert_eq!(s.total_speed(), 0);
    }

    #[test]
    fn total_speed_mixed() {
        let s = make_status(
            Some(vec![
                make_device(Some(1_000_000)),
                make_device(None),
                make_device(Some(2_000_000)),
            ]),
            None,
        );
        assert_eq!(s.total_speed(), 3_000_000);
    }

    // ── progress_pct ──

    #[test]
    fn progress_pct_none() {
        let s = make_status(None, None);
        assert!((s.progress_pct() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_pct_empty() {
        let s = make_status(None, Some(vec![]));
        assert!((s.progress_pct() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_pct_one_element() {
        let s = make_status(None, Some(vec![50]));
        assert!((s.progress_pct() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_pct_zero_total() {
        let s = make_status(None, Some(vec![0, 0]));
        assert!((s.progress_pct() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_pct_half() {
        let s = make_status(None, Some(vec![50, 100]));
        assert!((s.progress_pct() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn progress_pct_complete() {
        let s = make_status(None, Some(vec![100, 100]));
        assert!((s.progress_pct() - 100.0).abs() < f64::EPSILON);
    }
}
