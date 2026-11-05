use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use super::*;
use crate::clock::Clock;
use crate::openconnect::windows_acl::{AceType, AclEntry, AclItem, WindowsProbeResult};

#[derive(Clone, Copy)]
struct Node {
    uid: u32,
    mode: u32,
    dir: bool,
}

const ROOT_DIR: Node = Node {
    uid: 0,
    mode: 0o40755,
    dir: true,
};

fn file(uid: u32, mode: u32) -> Node {
    Node {
        uid,
        mode,
        dir: false,
    }
}

/// In-memory filesystem: path → owner/mode, plus symlinks.
struct FakeFs {
    nodes: HashMap<String, Node>,
    links: HashMap<String, String>,
    realpath_calls: AtomicUsize,
}

fn fake_fs(nodes: &[(&str, Node)], links: &[(&str, &str)]) -> Arc<FakeFs> {
    Arc::new(FakeFs {
        nodes: nodes.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
        links: links
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        realpath_calls: AtomicUsize::new(0),
    })
}

#[async_trait]
impl TrustFs for FakeFs {
    async fn realpath(&self, p: &str) -> io::Result<String> {
        self.realpath_calls.fetch_add(1, Ordering::SeqCst);
        let target = self.links.get(p).cloned().unwrap_or_else(|| p.to_string());
        if self.nodes.contains_key(&target) {
            Ok(target)
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "ENOENT"))
        }
    }
    async fn stat(&self, p: &str) -> io::Result<TrustStat> {
        let n = self
            .nodes
            .get(p)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("ENOENT {p}")))?;
        Ok(TrustStat {
            uid: n.uid,
            mode: n.mode,
            is_file: !n.dir,
            is_dir: n.dir,
        })
    }
}

fn linux_tree() -> Vec<(&'static str, Node)> {
    vec![
        ("/", ROOT_DIR),
        ("/usr", ROOT_DIR),
        ("/usr/sbin", ROOT_DIR),
        ("/usr/sbin/openconnect", file(0, 0o100_755)),
        ("/usr/sbin/groupw", file(0, 0o100_775)),
        ("/home", ROOT_DIR),
        (
            "/home/alice",
            Node {
                uid: 1000,
                mode: 0o40755,
                dir: true,
            },
        ),
        ("/home/alice/openconnect", file(1000, 0o100_755)),
        ("/home/alice/rootowned", file(0, 0o100_755)),
        ("/opt", ROOT_DIR),
        (
            "/opt/homebrew",
            Node {
                uid: 501,
                mode: 0o40755,
                dir: true,
            },
        ),
        (
            "/opt/homebrew/bin",
            Node {
                uid: 501,
                mode: 0o40755,
                dir: true,
            },
        ),
        ("/opt/homebrew/bin/openconnect", file(501, 0o100_755)),
        (
            "/tmp",
            Node {
                uid: 0,
                mode: 0o41777,
                dir: true,
            },
        ),
        ("/tmp/oc", file(0, 0o100_755)),
    ]
}

fn unix_opts() -> TrustOptions {
    TrustOptions {
        platform: Platform::Linux,
        fs: fake_fs(
            &linux_tree(),
            &[
                ("/usr/bin/openconnect", "/usr/sbin/openconnect"),
                ("/usr/local/bin/oc", "/home/alice/openconnect"),
            ],
        ),
        windows_probe: None,
    }
}

#[tokio::test]
async fn unix_accepts_root_owned_files_and_returns_the_real_path() {
    let opts = unix_opts();
    assert_eq!(
        verify_trusted_file("/usr/sbin/openconnect", &opts).await.unwrap(),
        "/usr/sbin/openconnect"
    );
    assert_eq!(
        verify_trusted_file("/usr/bin/openconnect", &opts).await.unwrap(),
        "/usr/sbin/openconnect"
    );
}

#[tokio::test]
async fn unix_rejects_user_owned_writable_missing_and_relative_paths() {
    let opts = unix_opts();
    for (path, reason) in [
        ("/home/alice/openconnect", "not owned by root"),
        ("/home/alice/rootowned", "/home/alice is not owned by root"),
        ("/opt/homebrew/bin/openconnect", "not owned by root"),
        ("/usr/sbin/groupw", "writable by group or others"),
        ("/tmp/oc", "/tmp is writable"),
        ("/usr/local/bin/oc", "not owned by root"),
        ("/nope", "does not exist"),
        ("relative/openconnect", "absolute"),
        ("/usr/sbin", "not a regular file"),
    ] {
        let e = verify_trusted_file(path, &opts).await.unwrap_err();
        assert!(e.message.contains(reason), "{path}: {}", e.message);
        let v: VpnError = e.into();
        assert_eq!(v.code, VpnErrorCode::PrivilegesDenied);
        assert!(!is_trusted_file(path, &opts).await);
    }
}

#[tokio::test]
async fn homebrew_paths_get_the_homebrew_hint() {
    let opts = unix_opts();
    let e = verify_trusted_file("/opt/homebrew/bin/openconnect", &opts)
        .await
        .unwrap_err();
    assert_eq!(e.hint, VpnErrorHint::UntrustedHomebrew);
    assert!(e.message.contains("MacPorts"));
    let e = verify_trusted_file("/home/alice/openconnect", &opts)
        .await
        .unwrap_err();
    assert_eq!(e.hint, VpnErrorHint::UntrustedBinary);
}

struct BrokenStat;

#[async_trait]
impl TrustFs for BrokenStat {
    async fn realpath(&self, p: &str) -> io::Result<String> {
        Ok(p.to_string())
    }
    async fn stat(&self, _: &str) -> io::Result<TrustStat> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "EACCES"))
    }
}

#[tokio::test]
async fn unexpected_fs_errors_become_untrusted_path_errors() {
    let opts = TrustOptions {
        platform: Platform::Linux,
        fs: Arc::new(BrokenStat),
        windows_probe: None,
    };
    let e = verify_trusted_file("/usr/sbin/openconnect", &opts)
        .await
        .unwrap_err();
    assert!(e.message.contains("EACCES"));
}

// ------------------------------------------------------------------ Windows

const SYSTEM: &str = "S-1-5-18";
const ADMINS: &str = "S-1-5-32-544";
const TI: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const USERS: &str = "S-1-5-32-545";
const AUTH_USERS: &str = "S-1-5-11";
const ME: &str = "S-1-5-21-1-2-3-1001";
const FULL: u32 = 0x1f_01ff;
const RX: u32 = 0x12_00a9;
const MODIFY: u32 = 0x13_01bf;

fn ace(sid: &str, rights: u32, ace_type: AceType, inherit_only: bool) -> AclEntry {
    AclEntry {
        sid: sid.into(),
        rights,
        ace_type,
        inherit_only,
    }
}

fn admin_only(p: &str) -> AclItem {
    AclItem {
        path: p.into(),
        owner_sid: TI.into(),
        entries: vec![
            ace(SYSTEM, FULL, AceType::Allow, false),
            ace(ADMINS, FULL, AceType::Allow, false),
            ace(USERS, RX, AceType::Allow, false),
            // CREATOR OWNER template: does not apply to the object itself
            ace("S-1-3-0", 0x1000_0000, AceType::Allow, true),
        ],
    }
}

/// Fake registry + ACLs: everything admin-only except the overrides.
struct FakeProbe {
    overrides: HashMap<String, AclItem>,
    calls: Mutex<Vec<Vec<String>>>,
    fail: Option<&'static str>,
}

fn probe(overrides: Vec<AclItem>) -> Arc<FakeProbe> {
    Arc::new(FakeProbe {
        overrides: overrides.into_iter().map(|i| (i.path.clone(), i)).collect(),
        calls: Mutex::new(vec![]),
        fail: None,
    })
}

#[async_trait]
impl WindowsSecurityProbe for FakeProbe {
    async fn probe(&self, paths: &[String]) -> Result<WindowsProbeResult, String> {
        if let Some(f) = self.fail {
            return Err(f.into());
        }
        self.calls.lock().unwrap().push(paths.to_vec());
        Ok(WindowsProbeResult {
            program_files: vec!["C:\\Program Files".into(), "C:\\Program Files (x86)".into()],
            items: paths
                .iter()
                .map(|p| self.overrides.get(p).cloned().unwrap_or_else(|| admin_only(p)))
                .collect(),
        })
    }
}

fn win_files() -> Arc<FakeFs> {
    let f = file(0, 0);
    fake_fs(
        &[
            ("C:\\Program Files\\OpenConnect-GUI\\openconnect.exe", f),
            (
                "C:\\Program Files\\GP Connect\\resources\\bin\\win32\\openconnect.exe",
                f,
            ),
            ("C:\\Program Files\\Loose\\openconnect.exe", f),
            ("C:\\Program Files\\Mine\\openconnect.exe", f),
            ("C:\\Windows\\Temp\\openconnect.exe", f),
            ("C:\\Windows\\System32\\openconnect.exe", f),
            (
                "C:\\Users\\alice\\AppData\\Local\\Programs\\GP Connect\\openconnect.exe",
                f,
            ),
            ("C:\\Program Files Evil\\openconnect.exe", f),
        ],
        &[],
    )
}

fn win_opts(p: Arc<FakeProbe>) -> TrustOptions {
    TrustOptions {
        platform: Platform::Win32,
        fs: win_files(),
        windows_probe: Some(p),
    }
}

#[tokio::test]
async fn windows_accepts_admin_only_files_and_checks_every_parent() {
    for f in [
        "C:\\Program Files\\OpenConnect-GUI\\openconnect.exe",
        "C:\\Program Files\\GP Connect\\resources\\bin\\win32\\openconnect.exe",
    ] {
        let p = probe(vec![]);
        assert_eq!(verify_trusted_file(f, &win_opts(p.clone())).await.unwrap(), f);
        let calls = p.calls.lock().unwrap();
        let chain = calls.last().unwrap();
        assert_eq!(chain.first().unwrap(), f);
        assert_eq!(chain.last().unwrap(), "C:\\Program Files");
    }
}

#[tokio::test]
async fn windows_rejects_paths_outside_program_files_unc_and_relative() {
    for (f, reason) in [
        ("C:\\Windows\\Temp\\openconnect.exe", "Program Files"),
        ("C:\\Windows\\System32\\openconnect.exe", "Program Files"),
        (
            "C:\\Users\\alice\\AppData\\Local\\Programs\\GP Connect\\openconnect.exe",
            "Program Files",
        ),
        ("C:\\Program Files Evil\\openconnect.exe", "Program Files"),
        ("\\\\server\\share\\openconnect.exe", "local absolute path"),
        ("relative\\openconnect.exe", "local absolute path"),
    ] {
        let e = verify_trusted_file(f, &win_opts(probe(vec![])))
            .await
            .unwrap_err();
        assert!(e.message.contains(reason), "{f}: {}", e.message);
    }
}

#[tokio::test]
async fn windows_rejects_writable_files_and_parents() {
    for (acl_path, sid, rights) in [
        ("C:\\Program Files\\Loose", USERS, MODIFY),
        ("C:\\Program Files\\Loose\\openconnect.exe", AUTH_USERS, 0x2),
        ("C:\\Program Files\\Loose\\openconnect.exe", ME, FULL),
        ("C:\\Program Files\\Loose", "S-1-1-0", 0x4000_0000),
    ] {
        let mut item = admin_only(acl_path);
        item.entries.push(ace(sid, rights, AceType::Allow, false));
        let e = verify_trusted_file(
            "C:\\Program Files\\Loose\\openconnect.exe",
            &win_opts(probe(vec![item])),
        )
        .await
        .unwrap_err();
        assert!(e.message.contains(&format!("writable by {sid}")), "{}", e.message);
    }
}

#[tokio::test]
async fn windows_rejects_a_user_owned_file() {
    let f = "C:\\Program Files\\Mine\\openconnect.exe";
    let mut item = admin_only(f);
    item.owner_sid = ME.into();
    let e = verify_trusted_file(f, &win_opts(probe(vec![item])))
        .await
        .unwrap_err();
    assert!(e.message.contains("owned by S-1-5-21-1-2-3-1001"));
}

#[tokio::test]
async fn windows_ignores_deny_and_inherit_only_entries() {
    let f = "C:\\Program Files\\Loose\\openconnect.exe";
    let mut item = admin_only(f);
    item.entries.push(ace(USERS, FULL, AceType::Deny, false));
    item.entries.push(ace(USERS, FULL, AceType::Allow, true));
    assert_eq!(
        verify_trusted_file(f, &win_opts(probe(vec![item])))
            .await
            .unwrap(),
        f
    );
}

#[tokio::test]
async fn windows_fails_closed_when_the_probe_fails_or_is_missing() {
    let f = "C:\\Program Files\\OpenConnect-GUI\\openconnect.exe";
    let broken = Arc::new(FakeProbe {
        overrides: HashMap::new(),
        calls: Mutex::new(vec![]),
        fail: Some("probe missing"),
    });
    let e = verify_trusted_file(f, &win_opts(broken)).await.unwrap_err();
    assert!(e.message.contains("probe missing"));
    let opts = TrustOptions {
        platform: Platform::Win32,
        fs: win_files(),
        windows_probe: None,
    };
    assert!(
        verify_trusted_file(f, &opts)
            .await
            .unwrap_err()
            .message
            .contains("ACL check is not available")
    );
}

#[tokio::test]
async fn windows_never_derives_roots_from_the_environment() {
    // The only roots are the ones returned by the (registry) probe; %ProgramFiles% is not read.
    let e = verify_trusted_file("C:\\Windows\\Temp\\openconnect.exe", &win_opts(probe(vec![]))).await;
    assert!(e.is_err());
}

#[test]
fn simplifies_only_verbatim_local_drive_paths() {
    assert_eq!(
        strip_verbatim_prefix(r"\\?\C:\Program Files\x.exe"),
        r"C:\Program Files\x.exe"
    );
    assert_eq!(strip_verbatim_prefix(r"\\?\d:\x"), r"d:\x");
    for unchanged in [
        r"\\?\UNC\srv\share\x",
        r"\\?\Volume{0b1c2d3e-0000-0000-0000-100000000000}\x.exe",
        r"\\?\GLOBALROOT\Device\HarddiskVolume3\x.exe",
        r"\\?\C:",
        r"\\?\C:relative",
        r"\\.\C:\x.exe",
        r"\\.\pipe\x",
        r"\\server\share\x",
        r"C:\Program Files\x.exe",
        "/usr/sbin/openconnect",
        "",
    ] {
        assert_eq!(strip_verbatim_prefix(unchanged), unchanged);
    }
}

#[tokio::test]
async fn windows_accepts_verbatim_local_paths_and_returns_the_plain_form() {
    // What Tauri's resource dir yields for the bundled openconnect.exe in an installed app.
    let f = "C:\\Program Files\\GP Connect\\resources\\bin\\win32\\openconnect.exe";
    let p = probe(vec![]);
    let verbatim = format!("\\\\?\\{f}");
    assert_eq!(
        verify_trusted_file(&verbatim, &win_opts(p.clone()))
            .await
            .unwrap(),
        f
    );
    assert_eq!(p.calls.lock().unwrap().last().unwrap().first().unwrap(), f);
}

#[tokio::test]
async fn windows_keeps_rejecting_device_unc_and_volume_paths() {
    for f in [
        r"\\?\UNC\server\share\openconnect.exe",
        r"\\?\Volume{0b1c2d3e-0000-0000-0000-100000000000}\openconnect.exe",
        r"\\?\GLOBALROOT\Device\HarddiskVolume3\openconnect.exe",
        r"\\.\C:\Program Files\OpenConnect-GUI\openconnect.exe",
        r"\\server\share\openconnect.exe",
    ] {
        let e = verify_trusted_file(f, &win_opts(probe(vec![])))
            .await
            .unwrap_err();
        assert!(e.message.contains("local absolute path"), "{f}: {}", e.message);
    }
}

/// The real `canonicalize` on Windows returns `\\?\C:\…`; `StdTrustFs` must hand out the plain
/// form, for plain and verbatim input alike.
#[cfg(windows)]
#[tokio::test]
async fn std_fs_realpath_returns_plain_local_paths_on_windows() {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let exe = format!(r"{root}\System32\cmd.exe");
    for input in [exe.clone(), format!(r"\\?\{exe}")] {
        let real = StdTrustFs.realpath(&input).await.unwrap();
        assert!(!real.starts_with(r"\\"), "{input} → {real}");
        assert!(real.eq_ignore_ascii_case(&exe), "{input} → {real}");
    }
}

// ------------------------------------------------------------------ cache

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn cache_memoises_by_path_and_mtime_for_the_ttl_only() {
    let fs = fake_fs(&linux_tree(), &[]);
    let opts = TrustOptions {
        platform: Platform::Linux,
        fs: fs.clone(),
        windows_probe: None,
    };
    let clock = Arc::new(TestClock(AtomicI64::new(0)));
    let mtime = Arc::new(AtomicI64::new(1));
    let m = mtime.clone();
    let cache = TrustCache::with(
        opts,
        1000,
        clock.clone(),
        Arc::new(move |_| Ok(m.load(Ordering::SeqCst))),
    );
    assert!(cache.check("/usr/sbin/openconnect").await);
    assert!(cache.check("/usr/sbin/openconnect").await);
    assert_eq!(fs.realpath_calls.load(Ordering::SeqCst), 1);
    mtime.store(2, Ordering::SeqCst); // file replaced → re-checked
    cache.check("/usr/sbin/openconnect").await;
    assert_eq!(fs.realpath_calls.load(Ordering::SeqCst), 2);
    clock.0.store(1001, Ordering::SeqCst); // TTL expired → re-checked
    cache.check("/usr/sbin/openconnect").await;
    assert_eq!(fs.realpath_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn cache_reports_missing_files_as_untrusted() {
    let opts = TrustOptions {
        platform: Platform::Linux,
        fs: fake_fs(&linux_tree(), &[]),
        windows_probe: None,
    };
    let cache = TrustCache::with(
        opts,
        1000,
        Arc::new(TestClock(AtomicI64::new(0))),
        Arc::new(|_| Err(io::Error::new(io::ErrorKind::NotFound, "ENOENT"))),
    );
    assert!(!cache.check("/nope").await);
}

#[cfg(unix)]
#[tokio::test]
async fn real_filesystem_rejects_a_user_owned_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("openconnect");
    std::fs::write(&f, "x").unwrap();
    let opts = TrustOptions::new(Platform::Linux, None);
    let e = verify_trusted_file(f.to_str().unwrap(), &opts).await.unwrap_err();
    assert!(
        e.message.contains("not owned by root") || e.message.contains("writable"),
        "{}",
        e.message
    );
}

/// Directory listing for `verify_windows_install_dir`.
struct ListingFs(Vec<&'static str>);

#[async_trait]
impl TrustFs for ListingFs {
    async fn realpath(&self, p: &str) -> io::Result<String> {
        Ok(p.into())
    }
    async fn stat(&self, _p: &str) -> io::Result<TrustStat> {
        Err(io::Error::other("unused"))
    }
    async fn read_dir(&self, p: &str) -> io::Result<Vec<String>> {
        assert_eq!(p, "C:\\Program Files\\OC");
        Ok(self.0.iter().map(|s| (*s).to_string()).collect())
    }
}

fn listing_opts(names: Vec<&'static str>, p: Arc<FakeProbe>) -> TrustOptions {
    TrustOptions {
        platform: Platform::Win32,
        fs: Arc::new(ListingFs(names)),
        windows_probe: Some(p),
    }
}

const OC_EXE: &str = "C:\\Program Files\\OC\\openconnect.exe";

#[tokio::test]
async fn install_dir_checks_dlls_executables_and_scripts_next_to_openconnect() {
    let names = vec![
        "openconnect.exe",
        "libgnutls-30.DLL",
        "vpnc-script-win.js",
        "README.txt",
    ];
    let p = probe(vec![]);
    verify_windows_install_dir(OC_EXE, &listing_opts(names.clone(), p.clone()))
        .await
        .unwrap();
    assert_eq!(
        p.calls.lock().unwrap().last().unwrap(),
        &vec![
            "C:\\Program Files\\OC\\libgnutls-30.DLL".to_string(),
            "C:\\Program Files\\OC\\openconnect.exe".to_string(),
            "C:\\Program Files\\OC\\vpnc-script-win.js".to_string(),
        ]
    );
    let mut script = admin_only("C:\\Program Files\\OC\\vpnc-script-win.js");
    script.entries.push(ace(USERS, MODIFY, AceType::Allow, false));
    let e = verify_windows_install_dir(OC_EXE, &listing_opts(names, probe(vec![script])))
        .await
        .unwrap_err();
    assert!(
        e.message
            .contains("vpnc-script-win.js is writable by S-1-5-32-545"),
        "{}",
        e.message
    );
}

#[tokio::test]
async fn install_dir_check_fails_closed_and_is_a_no_op_off_windows() {
    // Default `read_dir` of a TrustFs that cannot list → refused.
    let e = verify_windows_install_dir(OC_EXE, &win_opts(probe(vec![])))
        .await
        .unwrap_err();
    assert!(e.message.contains("cannot list"), "{}", e.message);
    let mut o = listing_opts(vec!["x.dll"], probe(vec![]));
    o.windows_probe = None;
    assert!(verify_windows_install_dir(OC_EXE, &o).await.is_err());
    assert!(
        verify_windows_install_dir("/usr/sbin/openconnect", &unix_opts())
            .await
            .is_ok()
    );
}
