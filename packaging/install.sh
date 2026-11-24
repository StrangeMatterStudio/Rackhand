#!/bin/sh
# Rackhand installer for Linux (design 7.3.12, D105). Run as root:
#
#   curl -fsSL https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<X>/install.sh \
#     | sudo sh -s -- --ticket <ticket> --token <token> [--monitor] [--remote] [--role <role>]
#
# or, to make this machine a site's hub (7.7.4, Debian 12 or later):
#
#   curl -fsSL https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<X>/install.sh | sudo sh -s -- --hub
#
# It checks rackhand-verify against the SHA-256 below, then has the verifier check every other file against the two
# pinned release keys, and installs nothing until all of them pass. The release fills in the two values below.
#
# The dashboard's offline variant runs it from the hub with `--release-url https://<hub>:8443/release --self-signed`:
# the hub's HTTPS certificate is its own, so the downloads don't check it; the SHA-256 and signatures above still do.
set -eu

VERSION="__VERSION__"
VERIFY_SHA256_X86_64="__VERIFY_SHA256_X86_64__"
VERIFY_SHA256_AARCH64="__VERIFY_SHA256_AARCH64__"
RELEASE_URL="https://github.com/StrangeMatterStudio/Rackhand/releases/download/v$VERSION"

die() {
  echo "rackhand install: $*" >&2
  exit 1
}

TICKET="" TOKEN="" ACCESS=managed MODE="" ROLE="" SELF_SIGNED="" HUB=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ticket) TICKET="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --monitor) ACCESS=monitor; shift ;;
    --remote) MODE=--remote; shift ;;
    --role) ROLE="$2"; shift 2 ;;
    --release-url) RELEASE_URL="$2"; shift 2 ;;
    --self-signed) SELF_SIGNED=1; shift ;;
    --hub) HUB=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$HUB" ] || { [ -n "$TICKET" ] && [ -n "$TOKEN" ]; } \
  || die "usage: install.sh --ticket <ticket> --token <token> [--monitor] [--remote] [--role <role>], or install.sh --hub"
[ "$(id -u)" = 0 ] || die "run it as root"

case "$(uname -m)" in
  x86_64) TARGET=x86_64-unknown-linux-musl; VERIFY_SHA256="$VERIFY_SHA256_X86_64" ;;
  aarch64 | arm64) TARGET=aarch64-unknown-linux-musl; VERIFY_SHA256="$VERIFY_SHA256_AARCH64" ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  INIT=systemd
elif command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
  INIT=openrc
else
  die "neither systemd nor OpenRC is running"
fi

# a hub needs Debian 12 or later and systemd (7.7.4); said before anything is downloaded
if [ -n "$HUB" ]; then
  # read in subshells: os-release names VERSION too
  OS_ID=$( [ -r /etc/os-release ] && . /etc/os-release && echo "${ID:-}" )
  OS_NAME=$( [ -r /etc/os-release ] && . /etc/os-release && echo "${PRETTY_NAME:-}" )
  OS_VERSION=$( [ -r /etc/os-release ] && . /etc/os-release && echo "${VERSION_ID:-}" )
  [ "$OS_ID" = debian ] || die "a hub installs on Debian 12 or later; this is ${OS_NAME:-not Debian}"
  case "$OS_VERSION" in
    '' | *[!0-9.]*) die "a hub installs on Debian 12 or later; this is Debian ${OS_VERSION:-of an unknown version}" ;;
  esac
  [ "${OS_VERSION%%.*}" -ge 12 ] || die "a hub installs on Debian 12 or later; this is Debian $OS_VERSION"
  [ "$INIT" = systemd ] || die "a hub runs under systemd"
  command -v curl >/dev/null 2>&1 || die "a hub's installer needs curl"
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    if [ -n "$SELF_SIGNED" ]; then curl -fsSLk "$1" -o "$2"; else curl -fsSL "$1" -o "$2"; fi
  elif [ -n "$SELF_SIGNED" ]; then
    wget -q --no-check-certificate -O "$2" "$1"
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

# A site's hub (7.7.4): the hub and its updater from the release, checked like everything else, the binary in its slots
# (7.5.7), `rackhand hub init` the first time, and the units. It prints the dashboard's address and the one-time setup code.
if [ -n "$HUB" ]; then
  for f in "rackhand-$TARGET" rackhand-hub.service rackhand-updater.path rackhand-updater.service manifest.json; do
    fetch "$RELEASE_URL/$f" "$WORK/$f"
    fetch "$RELEASE_URL/$f.minisig" "$WORK/$f.minisig"
    "$WORK/rackhand-verify" "$WORK/$f" "$WORK/$f.minisig" >/dev/null \
      || die "$f isn't signed by a pinned release key; nothing was installed"
  done
  S=/usr/local/lib/rackhand-server
  install -d -m 0755 "$S" /etc/rackhand
  install -m 0755 "$WORK/rackhand-$TARGET" "$S/rackhand-a"
  ln -sfn rackhand-a "$S/rackhand"
  ln -sfn "$S/rackhand" /usr/local/bin/rackhand
  id rackhand-hub >/dev/null 2>&1 || useradd -r -U -M -d /var/lib/rackhand -s /usr/sbin/nologin rackhand-hub
  INIT_OUT=""
  if [ ! -f /etc/rackhand/master.key ]; then
    INIT_OUT=$(/usr/local/bin/rackhand hub init) || die "rackhand hub init failed"
  fi
  install -d -m 0750 -o rackhand-hub -g rackhand-hub /var/lib/rackhand
  chown -R rackhand-hub:rackhand-hub /var/lib/rackhand
  chown rackhand-hub:rackhand-hub /etc/rackhand/node.key
  chown root:rackhand-hub /etc/rackhand/hub.toml
  # what the self-watch checks this binary against (10)
  install -m 0644 "$WORK/manifest.json" /etc/rackhand/release-manifest.json
  install -m 0644 "$WORK/manifest.json.minisig" /etc/rackhand/release-manifest.json.minisig
  for u in rackhand-hub.service rackhand-updater.path rackhand-updater.service; do
    install -m 0644 "$WORK/$u" "/etc/systemd/system/$u"
  done
  systemctl daemon-reload
  systemctl enable --now rackhand-hub.service rackhand-updater.path >/dev/null 2>&1 || die "the hub's services didn't start"
  i=0
  until curl -fsk --max-time 5 https://127.0.0.1:8443/healthz 2>/dev/null | grep -q ok; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || die "the hub didn't answer on https://127.0.0.1:8443/healthz; see journalctl -u rackhand-hub"
    sleep 1
  done
  ADDR=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo "Rackhand: the hub runs. Dashboard: https://${ADDR:-this-machine}:8443/"
  if [ -n "$INIT_OUT" ]; then
    echo "$INIT_OUT" | grep -E '^(Setup code|Recovery code)'
  else
    echo "This machine had a hub already: its keys and database were kept."
  fi
  exit 0
fi

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
# the services run the probe through a link to one of two slots, so that an update goes into the other slot and the guard
# switches the link (7.3.3)
install -m 0755 "$WORK/rackhand-probe-$TARGET" /usr/local/lib/rackhand/probe-a
ln -sfn probe-a /usr/local/lib/rackhand/rackhand-probe
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

# 6b. a monitor machine has no hub account (7.3.12, D89): a machine changing from managed to monitor loses them, with
# their keys, the sudoers file and the command list. Nothing else is touched: other users and files stay.
if [ "$ACCESS" = monitor ]; then
  for name in rackhand rackhand-ai; do
    id "$name" >/dev/null 2>&1 || continue
    if command -v userdel >/dev/null 2>&1; then
      userdel --force --remove "$name" >/dev/null 2>&1 || userdel -f -r "$name" >/dev/null 2>&1 || true
    else
      deluser --remove-home "$name" >/dev/null 2>&1 || true
    fi
  done
  rm -f /etc/sudoers.d/rackhand /etc/rackhand/commands.json
  rm -rf /var/lib/rackhand-run/enroll
fi

# 7. the services: the helper first (root), then the probe (its own user). A machine changing level has them running
# already, and they read their configuration at start.
case "$INIT" in
  systemd)
    install -m 0644 "$WORK/rackhand-probe-helper.service" /etc/systemd/system/rackhand-probe-helper.service
    install -m 0644 "$WORK/rackhand-probe.service" /etc/systemd/system/rackhand-probe.service
    systemctl daemon-reload
    systemctl enable rackhand-probe-helper.service rackhand-probe.service >/dev/null 2>&1 \
      && systemctl restart rackhand-probe-helper.service && systemctl restart rackhand-probe.service \
      || die "the services didn't start"
    ;;
  openrc)
    install -m 0755 "$WORK/rackhand-probe-helper.openrc" /etc/init.d/rackhand-probe-helper
    install -m 0755 "$WORK/rackhand-probe.openrc" /etc/init.d/rackhand-probe
    rc-update add rackhand-probe-helper default >/dev/null
    rc-update add rackhand-probe default >/dev/null
    rc-service rackhand-probe-helper restart >/dev/null && rc-service rackhand-probe restart >/dev/null \
      || die "the services didn't start"
    ;;
esac
echo "Rackhand: enrolled as machine $MACHINE_ID ($ACCESS)."
