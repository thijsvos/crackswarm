use anyhow::{anyhow, Context};
use crack_common::hashcat::HashcatStatus;
use crack_common::models::DeviceInfo;
use tokio::process::Command;

/// Try to parse a line of hashcat output as a JSON status object.
///
/// Hashcat interleaves plain-text progress lines with JSON status blobs when
/// `--status-json` is enabled.  Lines that are not valid JSON are silently
/// ignored (returns `None`).
pub fn parse_status_line(line: &str) -> Option<HashcatStatus> {
    let trimmed = line.trim();
    if !trimmed.starts_with('{') {
        return None;
    }
    serde_json::from_str::<HashcatStatus>(trimmed).ok()
}

/// Parse a line from the hashcat outfile (format=1,2 with tab separator:
/// `hash\tplaintext`).
///
/// Returns `(hash, plaintext)` or `None` if the line doesn't contain a
/// separator.
pub fn parse_outfile_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    // outfile-format=1,2 with --separator=\t produces "hash\tplaintext"
    let (hash, plain) = trimmed.split_once('\t')?;
    Some((hash.to_string(), plain.to_string()))
}

/// Detect hashcat by running `<path> --version` and returning the version
/// string (e.g. `"v6.2.6"`).
pub async fn detect_hashcat(path: &str) -> anyhow::Result<String> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .await
        .with_context(|| format!("failed to execute '{path}' -- is hashcat installed?"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "hashcat --version exited with {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.is_empty() {
        return Err(anyhow!("hashcat --version returned empty output"));
    }
    Ok(version)
}

/// Run `hashcat -I` and parse basic device information.
///
/// This is intentionally simplified: we extract device IDs, names, and types
/// from the semi-structured output.  A production implementation might use
/// `--machine-readable` when available.
pub async fn get_devices(hashcat_path: &str) -> anyhow::Result<Vec<DeviceInfo>> {
    let output = Command::new(hashcat_path)
        .arg("-I")
        .output()
        .await
        .with_context(|| format!("failed to run '{hashcat_path} -I'"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut devices = Vec::new();
    let mut current_id: Option<u32> = None;
    let mut current_name: Option<String> = None;
    let mut current_type: Option<String> = None;

    for line in stdout.lines() {
        let line = line.trim();

        // Lines like "Backend Device ID #1"
        if let Some(rest) = line.strip_prefix("Backend Device ID #") {
            // Flush previous device
            if let (Some(id), Some(name)) = (current_id, current_name.take()) {
                devices.push(DeviceInfo {
                    id,
                    name,
                    device_type: current_type.take().unwrap_or_else(|| "unknown".into()),
                    speed: None,
                });
            }
            current_id = rest
                .trim_end_matches(|c: char| !c.is_ascii_digit())
                .parse::<u32>()
                .ok();
            current_name = None;
            current_type = None;
        }

        // "Name...........: NVIDIA GeForce RTX 3090"
        if line.starts_with("Name") {
            if let Some((_, val)) = line.split_once(':') {
                current_name = Some(val.trim().to_string());
            }
        }

        // "Type...........: GPU"
        if line.starts_with("Type") {
            if let Some((_, val)) = line.split_once(':') {
                current_type = Some(val.trim().to_string());
            }
        }
    }

    // Flush last device
    if let (Some(id), Some(name)) = (current_id, current_name) {
        devices.push(DeviceInfo {
            id,
            name,
            device_type: current_type.unwrap_or_else(|| "unknown".into()),
            speed: None,
        });
    }

    Ok(devices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status_line_valid() {
        let json = r#"{"session":"test","status":5,"progress":[50,100],"devices":[{"device_id":1,"speed":1000000}]}"#;
        let status = parse_status_line(json);
        assert!(status.is_some());
        let s = status.unwrap();
        assert_eq!(s.progress_pct(), 50.0);
        assert_eq!(s.total_speed(), 1_000_000);
    }

    #[test]
    fn test_parse_status_line_non_json() {
        assert!(parse_status_line("Session..........: hashcat").is_none());
        assert!(parse_status_line("").is_none());
        assert!(parse_status_line("Progress.........: 100/200").is_none());
    }

    #[test]
    fn test_parse_outfile_line() {
        let (hash, plain) =
            parse_outfile_line("5f4dcc3b5aa765d61d8327deb882cf99\tpassword").unwrap();
        assert_eq!(hash, "5f4dcc3b5aa765d61d8327deb882cf99");
        assert_eq!(plain, "password");
    }

    #[test]
    fn test_parse_outfile_line_empty() {
        assert!(parse_outfile_line("").is_none());
        assert!(parse_outfile_line("   ").is_none());
    }

    #[test]
    fn test_parse_outfile_line_no_separator() {
        assert!(parse_outfile_line("no_separator_here").is_none());
    }

    #[test]
    fn test_parse_outfile_line_colon_in_plaintext() {
        // Colons in the plaintext should not cause a split (we use tab separator)
        let (hash, plain) =
            parse_outfile_line("5f4dcc3b5aa765d61d8327deb882cf99\tpass:word").unwrap();
        assert_eq!(hash, "5f4dcc3b5aa765d61d8327deb882cf99");
        assert_eq!(plain, "pass:word");
    }
}
