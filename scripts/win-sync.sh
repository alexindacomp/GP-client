#!/usr/bin/env bash
# Dev helper (WSL only): mirror the working tree to the Windows checkout used for native
# Windows builds (Rust MSVC toolchain, Tauri, WebView2). The WSL tree is the source of truth.
# Usage: scripts/win-sync.sh            # sync
#        scripts/win-sync.sh run "<cmd>" # sync, then run <cmd> in the Windows checkout via cmd.exe
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
WIN_DIR_WSL="/mnt/c/dev projects/Global Protect VPN"
WIN_DIR='C:\dev projects\Global Protect VPN'

rsync -a --delete \
  --exclude node_modules --exclude target --exclude out --exclude dist --exclude dist-renderer \
  --exclude coverage --exclude '*.tsbuildinfo' --exclude 'src-tauri/gen' --exclude 'src-tauri/resources/bin/win32' --exclude 'src-tauri/binaries' \
  "$SRC/" "$WIN_DIR_WSL/"

if [[ "${1:-}" == "run" ]]; then
  shift
  # Write a temp .cmd (avoids cmd.exe quoting issues with the space in the path).
  RUN_WSL="/mnt/c/Users/$(cmd.exe /c 'echo %USERNAME%' 2>/dev/null | tr -d '\r')/AppData/Local/Temp/gp-win-run-$$.cmd"
  {
    printf '@echo off\r\nchcp 65001 >nul\r\n'
    printf 'set "PATH=%%USERPROFILE%%\\.cargo\\bin;%%PATH%%"\r\n'
    printf 'cd /d "%s"\r\n' "$WIN_DIR"
    printf '%s\r\n' "$*"
  } > "$RUN_WSL"
  cd /mnt/c
  cmd.exe /c "$(wslpath -w "$RUN_WSL")" 2>&1 | tr -d '\r'
  rc=${PIPESTATUS[0]}
  rm -f "$RUN_WSL"
  exit "$rc"
fi
