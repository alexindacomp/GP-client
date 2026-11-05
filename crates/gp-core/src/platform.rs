//! Target platform, named like Node's `process.platform` (the wire value of `SystemInfo.platform`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Win32,
    Darwin,
    Linux,
}

impl Platform {
    pub const ALL: [Platform; 3] = [Platform::Win32, Platform::Darwin, Platform::Linux];

    /// Platform this binary was built for. Other Unixes behave like Linux.
    pub const fn current() -> Platform {
        if cfg!(windows) {
            Platform::Win32
        } else if cfg!(target_os = "macos") {
            Platform::Darwin
        } else {
            Platform::Linux
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Win32 => "win32",
            Platform::Darwin => "darwin",
            Platform::Linux => "linux",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
