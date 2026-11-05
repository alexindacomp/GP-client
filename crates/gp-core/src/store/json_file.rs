//! Atomic, private JSON files.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use crate::clock::{Clock, SystemClock};

#[derive(Debug, thiserror::Error)]
pub enum JsonFileError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Parse(#[from] serde_json::Error),
}

/// Reads JSON; `Ok(None)` when the file does not exist. Fails on corrupt JSON.
pub fn read_json_file(file: &Path) -> Result<Option<Value>, JsonFileError> {
    let raw = match fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(serde_json::from_str(&raw)?))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if getrandom::fill(&mut buf).is_err() {
        // Uniqueness only matters against concurrent writers; `create_new` still refuses clashes.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        return format!("{:016x}", nanos.as_nanos());
    }
    crate::util::hex(&buf)
}

pub(crate) fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Atomic, durable write: exclusive random temp file (0600) + fsync + rename. Pretty-printed with
/// two-space indentation and a trailing newline, like `JSON.stringify(data, null, 2)`.
pub fn write_json_file<T: Serialize + ?Sized>(file: &Path, data: &T) -> io::Result<()> {
    if let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) {
        create_private_dir_all(dir)?;
    }
    let mut text = serde_json::to_string_pretty(data).map_err(io::Error::other)?;
    text.push('\n');
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", random_hex(8)));
    let tmp = PathBuf::from(tmp);

    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp)?;
    let written = f.write_all(text.as_bytes()).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, file) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Moves an unreadable file aside (`<file>.corrupt-<epoch ms>`) so the app can start with
/// defaults. Returns the new path.
pub fn quarantine_file(file: &Path) -> Option<PathBuf> {
    quarantine_file_at(file, SystemClock.now_ms())
}

pub(crate) fn quarantine_file_at(file: &Path, now_ms: i64) -> Option<PathBuf> {
    let mut target = file.as_os_str().to_owned();
    target.push(format!(".corrupt-{now_ms}"));
    let target = PathBuf::from(target);
    fs::rename(file, &target).ok().map(|()| target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn writes_atomically_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sub").join("settings.json");
        write_json_file(&file, &json!({"a": 1})).unwrap();
        write_json_file(&file, &json!({"a": 2})).unwrap();
        assert_eq!(read_json_file(&file).unwrap(), Some(json!({"a": 2})));
        let names: Vec<_> = fs::read_dir(file.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["settings.json"]);
        assert_eq!(fs::read_to_string(&file).unwrap(), "{\n  \"a\": 2\n}\n");
    }

    #[cfg(unix)]
    #[test]
    fn creates_the_file_0600_and_its_directory_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sub").join("settings.json");
        write_json_file(&file, &json!({"a": 1})).unwrap();
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(file.parent().unwrap()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn missing_file_is_none_and_corrupt_json_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read_json_file(&dir.path().join("missing.json"))
                .unwrap()
                .is_none()
        );
        let bad = dir.path().join("bad.json");
        fs::write(&bad, "{\"a\":").unwrap();
        assert!(matches!(read_json_file(&bad), Err(JsonFileError::Parse(_))));
    }

    #[test]
    fn failed_rename_removes_the_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("settings.json");
        fs::create_dir(&file).unwrap(); // a directory where the file should be
        let blocker = file.join("x");
        fs::write(&blocker, "x").unwrap();
        assert!(write_json_file(&file, &json!({})).is_err());
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["settings.json"]);
    }

    #[test]
    fn quarantine_moves_the_file_aside() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("p.json");
        fs::write(&file, "garbage").unwrap();
        let moved = quarantine_file_at(&file, 42).unwrap();
        assert!(moved.ends_with("p.json.corrupt-42"));
        assert_eq!(fs::read_to_string(moved).unwrap(), "garbage");
        assert!(quarantine_file(&file).is_none());
    }
}
