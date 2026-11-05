//! Log lines describing the openconnect discovery result, emitted only when the result changes
//!: discovery runs on startup, on every
//! `system.info()` and before every connect — the same facts must not flood the log.

use std::sync::Mutex;

use super::locate::LocateResult;
use super::version::major_version;
use crate::logging::{LogLevel, Logger};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryLine {
    pub level: LogLevel,
    pub msg: String,
}

pub fn discovery_lines(found: Option<&LocateResult>, version: Option<&str>) -> Vec<DiscoveryLine> {
    let Some(found) = found else {
        return vec![DiscoveryLine {
            level: LogLevel::Warn,
            msg: "openconnect not found".into(),
        }];
    };
    let mut lines = Vec::new();
    if !found.trusted {
        lines.push(DiscoveryLine {
            level: LogLevel::Warn,
            msg: format!(
                "{} is not admin-owned (user-writable); it will not be run with administrator rights",
                found.path
            ),
        });
    }
    lines.push(DiscoveryLine {
        level: LogLevel::Info,
        msg: format!(
            "Using {} ({}), version {}",
            found.path,
            found.source.as_str(),
            version.unwrap_or("unknown")
        ),
    });
    if let (Some(major), Some(v)) = (major_version(version), version)
        && major < 9
    {
        lines.push(DiscoveryLine {
            level: LogLevel::Warn,
            msg: format!("openconnect {v} is older than 9; GlobalProtect support may be incomplete"),
        });
    }
    lines
}

/// Forwards discovery lines to the log only when they differ from the previous report.
#[derive(Debug, Default)]
pub struct DiscoveryReporter {
    last: Mutex<Option<Vec<DiscoveryLine>>>,
}

impl DiscoveryReporter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the lines that should be logged now (empty when nothing changed).
    pub fn report(&self, found: Option<&LocateResult>, version: Option<&str>) -> Vec<DiscoveryLine> {
        let lines = discovery_lines(found, version);
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.as_ref() == Some(&lines) {
            return Vec::new();
        }
        *last = Some(lines.clone());
        lines
    }

    /// [`Self::report`] and write the new lines to `logger` (source `openconnect`).
    pub fn report_to(&self, logger: &Logger, found: Option<&LocateResult>, version: Option<&str>) {
        for l in self.report(found, version) {
            logger.write(l.level, "openconnect", &l.msg);
        }
    }
}

/// Cached outcome of openconnect discovery (`path = None`: not found).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub path: Option<String>,
    pub version: Option<String>,
    pub trusted: Option<bool>,
}

/// The openconnect part of `SystemInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenconnectInfo {
    pub openconnect_found: bool,
    pub openconnect_version: Option<String>,
    pub openconnect_path: Option<String>,
    pub openconnect_trusted: Option<bool>,
}

pub fn openconnect_system_info(r: &DiscoveryResult) -> OpenconnectInfo {
    match &r.path {
        None => OpenconnectInfo {
            openconnect_found: false,
            openconnect_version: None,
            openconnect_path: None,
            openconnect_trusted: None,
        },
        Some(p) => OpenconnectInfo {
            openconnect_found: true,
            openconnect_version: r.version.clone(),
            openconnect_path: Some(p.clone()),
            openconnect_trusted: Some(r.trusted == Some(true)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openconnect::locate::OpenconnectSource;

    fn untrusted() -> LocateResult {
        LocateResult {
            path: "C:\\Users\\a\\oc\\openconnect.exe".into(),
            source: OpenconnectSource::Settings,
            trusted: false,
        }
    }

    #[test]
    fn logs_each_result_once_and_again_only_when_it_changes() {
        let logger = Logger::in_memory();
        let r = DiscoveryReporter::new();
        r.report_to(&logger, Some(&untrusted()), None);
        r.report_to(&logger, Some(&untrusted()), None);
        r.report_to(&logger, Some(&untrusted()), None);
        let lines = logger.lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("WARN  [openconnect]") && lines[0].contains("is not admin-owned"));
        assert!(lines[1].ends_with(
            "INFO  [openconnect] Using C:\\Users\\a\\oc\\openconnect.exe (settings), version unknown"
        ));
        let trusted = LocateResult {
            trusted: true,
            ..untrusted()
        };
        r.report_to(&logger, Some(&trusted), Some("9.12"));
        assert_eq!(logger.lines().len(), 3);
        assert!(logger.lines()[2].ends_with("version 9.12"));
    }

    #[test]
    fn describes_missing_and_old_binaries() {
        assert_eq!(
            discovery_lines(None, None),
            [DiscoveryLine {
                level: LogLevel::Warn,
                msg: "openconnect not found".into()
            }]
        );
        let found = LocateResult {
            path: "/usr/sbin/openconnect".into(),
            source: OpenconnectSource::WellKnown,
            trusted: true,
        };
        let last = discovery_lines(Some(&found), Some("8.20")).pop().unwrap();
        assert_eq!(last.level, LogLevel::Warn);
        assert!(last.msg.contains("older than 9"));
    }

    #[test]
    fn system_info_reports_path_and_trust_or_omits_them() {
        let r = DiscoveryResult {
            path: Some("C:\\Users\\a\\openconnect.exe".into()),
            version: Some("9.12".into()),
            trusted: Some(false),
        };
        assert_eq!(
            openconnect_system_info(&r),
            OpenconnectInfo {
                openconnect_found: true,
                openconnect_version: Some("9.12".into()),
                openconnect_path: Some("C:\\Users\\a\\openconnect.exe".into()),
                openconnect_trusted: Some(false),
            }
        );
        let r = DiscoveryResult {
            path: Some("/usr/sbin/openconnect".into()),
            version: None,
            trusted: Some(true),
        };
        let info = openconnect_system_info(&r);
        assert_eq!(
            (info.openconnect_version, info.openconnect_trusted),
            (None, Some(true))
        );
        let none = openconnect_system_info(&DiscoveryResult::default());
        assert!(
            !none.openconnect_found && none.openconnect_path.is_none() && none.openconnect_trusted.is_none()
        );
    }
}
