#!/bin/sh
# Rackhand installer for Linux (design 7.3.12, D105). Run as root:
#
#   curl -fsSL https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<X>/install.sh \
#     | sudo sh -s -- --ticket <ticket> --token <token> [--monitor] [--remote] [--role <role>]
#
# It checks rackhand-verify against the SHA-256 below, then has the verifier check every other file against the two
# pinned release keys, and installs nothing until all of them pass. The release fills in the two values below.
set -eu

VERSION="__VERSION__"
VERIFY_SHA256="__VERIFY_SHA256__"
RELEASE_URL="https://github.com/StrangeMatterStudio/Rackhand/releases/download/v$VERSION"

die() {
  echo "rackhand install: $*" >&2
  exit 1
}

TICKET="" TOKEN="" ACCESS=managed MODE="" ROLE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ticket) TICKET="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --monitor) ACCESS=monitor; shift ;;
    --remote) MODE=--remote; shift ;;
    --role) ROLE="$2"; shift 2 ;;
    --release-url) RELEASE_URL="$2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$TICKET" ] && [ -n "$TOKEN" ] || die "usage: install.sh --ticket <ticket> --token <token> [--monitor] [--remote] [--role <role>]"
[ "$(id -u)" = 0 ] || die "run it as root"

case "$(uname -m)" in
  x86_64) TARGET=x86_64-unknown-linux-musl ;;
  aarch64 | arm64) TARGET=aarch64-unknown-linux-musl ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  INIT=systemd
elif command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
  INIT=openrc
else
  die "neither systemd nor OpenRC is running"
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  else
    wget -q -O "$2" "$1"
  fi || die "download failed: $1"
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

# 1. the verifier, checked against this script's own SHA-256 for it
fetch "$RELEASE_URL/rackhand-verify-$TARGET" "$WORK/rackhand-verify"
[ "$(sha256sum "$WORK/rackhand-verify" | cut -d' ' -f1)" = "$VERIFY_SHA256" ] \
  || die "rackhand-verify doesn't match this installer; nothing was installed"
chmod 0700 "$WORK/rackhand-verify"

# 2. everything else, checked against the pinned release keys
case "$INIT" in
  systemd) UNITS="rackhand-probe.service rackhand-probe-helper.service" ;;
  openrc) UNITS="rackhand-probe.openrc rackhand-probe-helper.openrc" ;;
esac
for f in "rackhand-probe-$TARGET" $UNITS; do
  fetch "$RELEASE_URL/$f" "$WORK/$f"
  fetch "$RELEASE_URL/$f.minisig" "$WORK/$f.minisig"
  "$WORK/rackhand-verify" "$WORK/$f" "$WORK/$f.minisig" >/dev/null \
    || die "$f isn't signed by a pinned release key; nothing was installed"
done

# 3. what a managed machine's accounts need
if [ "$ACCESS" = managed ]; then
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache sudo bash >/dev/null || die "apk add sudo bash failed"
  elif ! command -v visudo >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q sudo >/dev/null || die "apt-get install sudo failed"
  fi
fi

# 4. the binary, the wrapper and the probe user, laid out as 7.3.3 says
install -d -m 0755 /usr/local/lib/rackhand /etc/rackhand-probe /etc/rackhand
install -d -m 0700 /var/lib/rackhand-run
install -m 0755 "$WORK/rackhand-probe-$TARGET" /usr/local/lib/rackhand/rackhand-probe
install -m 0755 "$WORK/rackhand-probe-$TARGET" /usr/local/lib/rackhand/run
add_system_user() { # name
  id "$1" >/dev/null 2>&1 && return 0
  if command -v useradd >/dev/null 2>&1; then
    useradd -r -U -M -s /usr/sbin/nologin "$1"
  else
    addgroup -S "$1" && adduser -S -D -H -s /sbin/nologin -G "$1" "$1"
  fi
}
add_system_user rackhand-probe
install -d -o rackhand-probe -g rackhand-probe -m 0700 /var/lib/rackhand-probe

# 5. the join
set -- --ticket "$TICKET" --token "$TOKEN"
[ "$ACCESS" = monitor ] && set -- "$@" --monitor
[ -n "$MODE" ] && set -- "$@" "$MODE"
[ -n "$ROLE" ] && set -- "$@" --role "$ROLE"
JOINED=$(/usr/local/lib/rackhand/rackhand-probe enroll "$@") || die "the join failed"
chown rackhand-probe:rackhand-probe /var/lib/rackhand-probe/node.key
MACHINE_ID=$(echo "$JOINED" | sed -n 's/^machine_id=//p')
ASSISTANT=$(echo "$JOINED" | sed -n 's/^assistant=//p')

# 6. a managed machine's accounts (7.3.7)
if [ "$ACCESS" = managed ]; then
  E=/var/lib/rackhand-run/enroll
  visudo -c -f "$E/sudoers" >/dev/null || die "the hub's sudoers didn't pass visudo -c"
  add_account() { # name shell
    if ! id "$1" >/dev/null 2>&1; then
      if command -v useradd >/dev/null 2>&1; then
        useradd -m -s "$2" "$1"
      else
        adduser -D -s "$2" "$1"
      fi
    fi
    # key-only login: no password, but not a locked account (sshd refuses locked ones without PAM)
    echo "$1:*" | chpasswd -e
    home=$(getent passwd "$1" | cut -d: -f6)
    install -d -o "$1" -g "$1" -m 0700 "$home/.ssh"
    install -o "$1" -g "$1" -m 0600 "$E/$1.authorized_keys" "$home/.ssh/authorized_keys"
  }
  add_account rackhand /bin/sh
  if [ "$ASSISTANT" = true ]; then
    add_account rackhand-ai /bin/bash
    install -d -m 0700 /var/log/rackhand/sudo-io
  fi
  install -d -m 0750 /etc/sudoers.d
  install -m 0440 "$E/sudoers" /etc/sudoers.d/rackhand
  visudo -c >/dev/null || { rm -f /etc/sudoers.d/rackhand; die "sudoers didn't pass visudo -c"; }
  rm -rf "$E"
fi

# 7. the services: the helper first (root), then the probe (its own user)
case "$INIT" in
  systemd)
    install -m 0644 "$WORK/rackhand-probe-helper.service" /etc/systemd/system/rackhand-probe-helper.service
    install -m 0644 "$WORK/rackhand-probe.service" /etc/systemd/system/rackhand-probe.service
    systemctl daemon-reload
    systemctl enable --now rackhand-probe-helper.service rackhand-probe.service >/dev/null 2>&1 \
      || die "the services didn't start"
    ;;
  openrc)
    install -m 0755 "$WORK/rackhand-probe-helper.openrc" /etc/init.d/rackhand-probe-helper
    install -m 0755 "$WORK/rackhand-probe.openrc" /etc/init.d/rackhand-probe
    rc-update add rackhand-probe-helper default >/dev/null
    rc-update add rackhand-probe default >/dev/null
    rc-service rackhand-probe-helper start >/dev/null && rc-service rackhand-probe start >/dev/null \
      || die "the services didn't start"
    ;;
esac
echo "Rackhand: enrolled as machine $MACHINE_ID ($ACCESS)."
