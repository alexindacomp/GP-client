//! Minimal environment for the elevated openconnect. The helper's own environment comes from the
//! user's profile (HKCU\Environment is user-writable: PATH, COMSPEC, TEMP, OPENSSL_CONF,
//! SSL_CERT_FILE, *_PROXY, …), so none of it is passed on. Every value here is derived from
//! system APIs ([`SystemPaths`]) or created by the helper (the admin-only temp directory).

/// Values read from system APIs (never from the inherited environment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPaths {
    /// `GetSystemWindowsDirectoryW`, e.g. `C:\Windows`.
    pub system_root: String,
    /// `GetSystemDirectoryW`, e.g. `C:\Windows\System32`.
    pub system32: String,
    /// Known folder `FOLDERID_ProgramData`, e.g. `C:\ProgramData`.
    pub program_data: String,
    /// `GetNativeSystemInfo().wProcessorArchitecture`.
    pub processor_architecture: u16,
    pub number_of_processors: u32,
}

/// `PROCESSOR_ARCHITECTURE` value for a `PROCESSOR_ARCHITECTURE_*` constant.
pub fn processor_architecture_name(arch: u16) -> &'static str {
    match arch {
        9 => "AMD64",
        12 => "ARM64",
        5 => "ARM",
        0 => "x86",
        _ => "UNKNOWN",
    }
}

/// Executable extensions resolved without one (cmd, WScript).
pub const PATHEXT: &str = ".COM;.EXE;.BAT;.CMD;.JS";

/// The complete environment of openconnect (and the vpnc/HIP scripts it runs).
pub fn minimal_env(sys: &SystemPaths, openconnect_dir: &str, temp_dir: &str) -> Vec<(String, String)> {
    let drive: String = sys.system_root.chars().take(2).collect();
    let path = format!(
        "{openconnect_dir};{s32};{root};{s32}\\Wbem",
        s32 = sys.system32,
        root = sys.system_root
    );
    [
        ("SystemRoot", sys.system_root.clone()),
        ("windir", sys.system_root.clone()),
        ("SystemDrive", drive),
        ("ComSpec", format!("{}\\cmd.exe", sys.system32)),
        ("PATH", path),
        ("PATHEXT", PATHEXT.to_string()),
        ("TEMP", temp_dir.to_string()),
        ("TMP", temp_dir.to_string()),
        ("ProgramData", sys.program_data.clone()),
        ("ALLUSERSPROFILE", sys.program_data.clone()),
        (
            "PROCESSOR_ARCHITECTURE",
            processor_architecture_name(sys.processor_architecture).to_string(),
        ),
        ("NUMBER_OF_PROCESSORS", sys.number_of_processors.to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

/// Names in [`minimal_env`] (upper-case, as Windows compares them case-insensitively).
pub fn minimal_env_names() -> Vec<String> {
    let sys = SystemPaths {
        system_root: String::new(),
        system32: String::new(),
        program_data: String::new(),
        processor_architecture: 0,
        number_of_processors: 0,
    };
    minimal_env(&sys, "", "")
        .into_iter()
        .map(|(k, _)| k.to_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys() -> SystemPaths {
        SystemPaths {
            system_root: r"C:\Windows".into(),
            system32: r"C:\Windows\System32".into(),
            program_data: r"C:\ProgramData".into(),
            processor_architecture: 9,
            number_of_processors: 8,
        }
    }

    #[test]
    fn builds_only_the_minimal_environment_from_system_values() {
        let env = minimal_env(
            &sys(),
            r"C:\Program Files\OpenConnect",
            r"C:\ProgramData\GP-Connect-ab",
        );
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(
            get("PATH"),
            Some(r"C:\Program Files\OpenConnect;C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem")
        );
        assert_eq!(get("ComSpec"), Some(r"C:\Windows\System32\cmd.exe"));
        assert_eq!(get("SystemDrive"), Some("C:"));
        assert_eq!(get("TEMP"), Some(r"C:\ProgramData\GP-Connect-ab"));
        assert_eq!(get("TMP"), get("TEMP"));
        assert_eq!(get("ALLUSERSPROFILE"), Some(r"C:\ProgramData"));
        assert_eq!(get("PROCESSOR_ARCHITECTURE"), Some("AMD64"));
        assert_eq!(get("NUMBER_OF_PROCESSORS"), Some("8"));
        assert_eq!(get("PATHEXT"), Some(".COM;.EXE;.BAT;.CMD;.JS"));
        assert_eq!(env.len(), 12);
        for (k, _) in &env {
            let k = k.to_uppercase();
            assert!(
                !(k.starts_with("OPENSSL")
                    || k.starts_with("GNUTLS")
                    || k.starts_with("SSL_")
                    || k.ends_with("_PROXY")
                    || k == "USERPROFILE"
                    || k == "APPDATA"),
                "{k}"
            );
        }
    }

    #[test]
    fn names_processor_architectures() {
        assert_eq!(processor_architecture_name(9), "AMD64");
        assert_eq!(processor_architecture_name(12), "ARM64");
        assert_eq!(processor_architecture_name(0), "x86");
        assert_eq!(processor_architecture_name(99), "UNKNOWN");
        assert!(minimal_env_names().contains(&"SYSTEMROOT".to_string()));
    }
}
