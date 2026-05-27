#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo:"
  echo "  sudo $0"
  exit 1
fi

TARGET_USER="${SUDO_USER:-$(id -un)}"
if [ "$TARGET_USER" = "root" ]; then
  echo "Could not determine the non-root user to grant capture access to."
  exit 1
fi

BPF_GROUP="access_bpf"
BPF_DAEMON="/Library/LaunchDaemons/com.reliquary-archiver.chmod-bpf.plist"
RPMUXD_PLIST="/Library/Apple/System/Library/LaunchDaemons/com.apple.rpmuxd.plist"

if ! dscl . -read "/Groups/$BPF_GROUP" >/dev/null 2>&1; then
  dseditgroup -q -o create "$BPF_GROUP"
fi

dseditgroup -q -o edit -a "$TARGET_USER" -t user "$BPF_GROUP"

cat > "$BPF_DAEMON" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.reliquary-archiver.chmod-bpf</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>chgrp access_bpf /dev/bpf* 2>/dev/null || true; chmod g+rw /dev/bpf* 2>/dev/null || true</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
PLIST

chown root:wheel "$BPF_DAEMON"
chmod 644 "$BPF_DAEMON"

chgrp "$BPF_GROUP" /dev/bpf* 2>/dev/null || true
chmod g+rw /dev/bpf* 2>/dev/null || true

if ! launchctl print system/com.reliquary-archiver.chmod-bpf >/dev/null 2>&1; then
  launchctl bootstrap system "$BPF_DAEMON" 2>/dev/null || true
fi
launchctl kickstart -k system/com.reliquary-archiver.chmod-bpf 2>/dev/null || true

if [ -f "$RPMUXD_PLIST" ] && ! launchctl print system/com.apple.rpmuxd >/dev/null 2>&1; then
  launchctl bootstrap system "$RPMUXD_PLIST" 2>/dev/null || true
fi

echo "Installed capture permissions for $TARGET_USER."
echo "Open a new terminal window before running reliquary-archiver without sudo."
