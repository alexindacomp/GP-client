//! Command line of `gp-connect-helper.exe`: `--config <path> --sha256 <hex>` (both exactly once).

use std::ffi::OsString;
use std::path::PathBuf;

use gp_elevate::helper_protocol::is_valid_sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    pub config: PathBuf,
    pub sha256: String,
}

/// Parses the arguments after the program name.
pub fn parse_cli(args: &[OsString]) -> Result<Cli, String> {
    let mut config = None;
    let mut sha256 = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("missing value for {}", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--config") if config.is_none() => config = Some(PathBuf::from(value)),
            Some("--sha256") if sha256.is_none() => {
                let v = value
                    .to_str()
                    .filter(|v| is_valid_sha256(v))
                    .ok_or("invalid --sha256")?;
                sha256 = Some(v.to_string());
            }
            _ => return Err(format!("unexpected argument {}", flag.to_string_lossy())),
        }
    }
    match (config, sha256) {
        (Some(config), Some(sha256)) if !config.as_os_str().is_empty() => Ok(Cli { config, sha256 }),
        _ => Err("usage: gp-connect-helper --config <path> --sha256 <hex>".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_config_and_hash_in_any_order() {
        let h = "a".repeat(64);
        let want = Cli {
            config: PathBuf::from(r"C:\Temp\x\helper.json"),
            sha256: h.clone(),
        };
        assert_eq!(
            parse_cli(&os(&["--config", r"C:\Temp\x\helper.json", "--sha256", &h])),
            Ok(want.clone())
        );
        assert_eq!(
            parse_cli(&os(&["--sha256", &h, "--config", r"C:\Temp\x\helper.json"])),
            Ok(want)
        );
    }

    #[test]
    fn rejects_everything_else() {
        let h = "a".repeat(64);
        for bad in [
            os(&[]),
            os(&["--config", "x"]),
            os(&["--config", "x", "--sha256"]),
            os(&["--config", "x", "--sha256", "XYZ"]),
            os(&["--config", "x", "--sha256", &"A".repeat(64)]),
            os(&["--config", "x", "--sha256", &h, "--config", "y"]),
            os(&["--config", "x", "--sha256", &h, "--extra", "1"]),
            os(&["--config", "", "--sha256", &h]),
        ] {
            assert!(parse_cli(&bad).is_err(), "{bad:?}");
        }
    }
}
