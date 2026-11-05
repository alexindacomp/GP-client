//! `gp-connect-helper.exe` — see the gp_helper library docs. GUI subsystem on Windows: no console
//! window of its own (openconnect gets a hidden console, see `send_ctrl_c`).
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    std::process::exit(gp_helper::run());
}
