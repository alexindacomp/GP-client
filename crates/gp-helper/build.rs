//! Link flags for `gp-connect-helper.exe` (runs as administrator).

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os == "windows" && env == "msvc" {
        // LOAD_LIBRARY_SEARCH_SYSTEM32 for the static imports: the loader never looks in the
        // working directory or PATH for the helper's own DLL dependencies.
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
