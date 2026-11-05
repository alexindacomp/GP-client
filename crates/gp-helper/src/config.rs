//! Reading the launch config written by the app. The file lives in the user's %TEMP%, so the
//! helper (running as administrator) treats it as hostile: no reparse points, size cap, the hash
//! from the command line must match, the JSON must be a valid [`HelperConfig`], and only then is
//! the file deleted — through the handle that was read, so a swapped path can never make the
//! administrator delete some other file.

use std::io::Read;
use std::path::Path;

use gp_elevate::helper_protocol::{HelperConfig, MAX_CONFIG_BYTES, ct_eq, sha256_hex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The file does not match the hash from the command line.
    Hash,
    /// Unreadable, too large, not a regular file or not a valid config.
    Invalid(String),
}

/// Verifies `bytes` against `sha256` and parses them.
pub fn parse_and_verify(bytes: &[u8], sha256: &str) -> Result<HelperConfig, ConfigError> {
    if !ct_eq(sha256_hex(bytes).as_bytes(), sha256.as_bytes()) {
        return Err(ConfigError::Hash);
    }
    let cfg: HelperConfig =
        serde_json::from_slice(bytes).map_err(|e| ConfigError::Invalid(format!("invalid config: {e}")))?;
    cfg.check_format().map_err(ConfigError::Invalid)?;
    Ok(cfg)
}

fn invalid(e: impl std::fmt::Display) -> ConfigError {
    ConfigError::Invalid(e.to_string())
}

/// Reads, verifies and deletes the config file.
pub fn load(path: &Path, sha256: &str) -> Result<HelperConfig, ConfigError> {
    let mut file = platform::open(path).map_err(invalid)?;
    let md = file.metadata().map_err(invalid)?;
    if !md.is_file() || md.file_type().is_symlink() {
        return Err(ConfigError::Invalid("config is not a regular file".into()));
    }
    if md.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Invalid("config is too large".into()));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::Invalid("config is too large".into()));
    }
    let cfg = parse_and_verify(&bytes, sha256)?;
    // The token must not stay on disk.
    platform::delete(&file, path).map_err(invalid)?;
    Ok(cfg)
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)] // SetFileInformationByHandle on our own handle.

    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_DISPOSITION_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FileDispositionInfo,
        SetFileInformationByHandle,
    };

    /// Opens the entry itself (never a reparse-point target) with DELETE access; others may only
    /// read while we hold it, so it cannot be replaced or renamed in between.
    pub(super) fn open(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    pub(super) fn delete(file: &File, _path: &Path) -> io::Result<()> {
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        let size = u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).unwrap_or(u32::MAX);
        // SAFETY: valid handle opened with DELETE access; `info` outlives the call.
        let ok = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&raw const info).cast(),
                size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    //! Non-Windows stand-in so the logic is testable everywhere (the helper only runs on Windows).

    use std::fs::{File, OpenOptions};
    use std::io;
    use std::path::Path;

    pub(super) fn open(path: &Path) -> io::Result<File> {
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(io::Error::other("config is a symlink"));
        }
        OpenOptions::new().read(true).open(path)
    }

    pub(super) fn delete(_file: &File, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests {
    use gp_elevate::helper_protocol::PIPE_PREFIX;

    use super::*;

    fn sample() -> Vec<u8> {
        serde_json::to_vec(&HelperConfig {
            pipe: format!("{PIPE_PREFIX}{}", "1".repeat(32)),
            token: "2".repeat(64),
            binary: r"C:\Program Files\OpenConnect\openconnect.exe".into(),
            args: vec!["--protocol=gp".into()],
            script: None,
            server_pid: 42,
        })
        .unwrap()
    }

    #[test]
    fn loads_verifies_and_deletes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("helper.json");
        let bytes = sample();
        std::fs::write(&p, &bytes).unwrap();
        let cfg = load(&p, &sha256_hex(&bytes)).unwrap();
        assert_eq!(cfg.token, "2".repeat(64));
        assert!(!p.exists());
    }

    #[test]
    fn keeps_a_file_whose_hash_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("helper.json");
        std::fs::write(&p, sample()).unwrap();
        assert_eq!(load(&p, &"0".repeat(64)), Err(ConfigError::Hash));
        assert!(p.exists());
    }

    #[test]
    fn never_deletes_a_file_that_is_not_a_config_even_with_the_right_hash() {
        // An attacker launching the helper could pass the hash of some other file.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("important.dll");
        std::fs::write(&p, b"MZ not a config").unwrap();
        let r = load(&p, &sha256_hex(b"MZ not a config"));
        assert!(matches!(r, Err(ConfigError::Invalid(_))), "{r:?}");
        assert!(p.exists());
    }

    #[test]
    fn rejects_oversized_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.json");
        let big = vec![b' '; usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1];
        std::fs::write(&p, &big).unwrap();
        assert!(matches!(
            load(&p, &sha256_hex(&big)),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            load(&dir.path().join("missing.json"), &"0".repeat(64)),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_invalid_fields_after_a_matching_hash() {
        let mut v: serde_json::Value = serde_json::from_slice(&sample()).unwrap();
        v["pipe"] = "evil".into();
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(matches!(
            parse_and_verify(&bytes, &sha256_hex(&bytes)),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_config() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let bytes = sample();
        std::fs::write(&target, &bytes).unwrap();
        let link = dir.path().join("helper.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            load(&link, &sha256_hex(&bytes)),
            Err(ConfigError::Invalid(_))
        ));
        assert!(target.exists());
    }
}
