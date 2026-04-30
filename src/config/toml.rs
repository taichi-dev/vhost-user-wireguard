// SPDX-License-Identifier: MIT OR Apache-2.0

//! TOML file loader for [`crate::config::Config`].

use crate::config::Config;
use crate::error::ConfigError;
use std::path::Path;

/// Read and parse a TOML configuration file.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    let config = toml::from_str::<Config>(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const VALID_TOML: &str = r#"
[wireguard]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
listen_port = 51820

[[wireguard.peers]]
name = "peer1"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
endpoint = "1.2.3.4:51820"
allowed_ips = ["10.0.0.0/24"]

[vhost_user]
socket = "/tmp/vhu.sock"
queue_size = 256
num_queues = 2

[dhcp]
decline_probation_secs = 86400
checkpoint_secs = 60
reservations = []

[dhcp.pool]
start = "10.0.0.2"
end = "10.0.0.2"

[network]
subnet = "10.0.0.0/30"
gateway = "10.0.0.1"
dns = ["8.8.8.8"]

[vm]
mtu = 1420
mac = "52:54:00:12:34:56"
ip = "10.0.0.2"
"#;

    fn write_temp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    #[test]
    fn test_load_valid_toml() {
        let f = write_temp(VALID_TOML);
        let result = load(f.path());
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        let cfg = result.unwrap();
        assert_eq!(cfg.wireguard.listen_port, 51820);
        assert_eq!(cfg.vhost_user.queue_size, 256);
    }

    #[test]
    fn test_load_missing_file() {
        let path = std::path::Path::new("/nonexistent/path/config.toml");
        let result = load(path);
        assert!(
            matches!(result, Err(ConfigError::FileRead { .. })),
            "expected FileRead error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_load_invalid_toml() {
        let f = write_temp("this is not valid toml ][[[");
        let result = load(f.path());
        assert!(
            matches!(result, Err(ConfigError::TomlParse(_))),
            "expected TomlParse error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_load_unknown_field() {
        let bad = format!("{}\nunknown_key = \"oops\"\n", VALID_TOML);
        let f = write_temp(&bad);
        let result = load(f.path());
        assert!(
            matches!(result, Err(ConfigError::TomlParse(_))),
            "expected TomlParse error for unknown field, got: {:?}",
            result
        );
    }
}
