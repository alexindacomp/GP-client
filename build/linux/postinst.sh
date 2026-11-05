#!/bin/sh
# GP Connect .deb postinst: (re)installs the polkit action for openconnect (auth_admin).
#
# The policy is shipped twice: at its final path (owned by this package, so it is removed with
# it) and as a pristine copy under /usr/lib/gp-connect. Upgrading from the old Electron-based
# package runs that package's postrm *after* this package was unpacked, and the old postrm
# deletes /usr/share/polkit-1/actions/com.gpconnect.openconnect.policy; the copy restores it.
set -e

SRC=/usr/lib/gp-connect/com.gpconnect.openconnect.policy
DEST=/usr/share/polkit-1/actions/com.gpconnect.openconnect.policy

if [ "$1" = "configure" ] && [ -f "$SRC" ]; then
  mkdir -p /usr/share/polkit-1/actions
  install -m 0644 "$SRC" "$DEST"
fi

exit 0
