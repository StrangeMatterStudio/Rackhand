#!/bin/sh
# A site's hub in a Debian LXC on a Proxmox host (design 7.7.4). Run as root on the host:
#
#   curl -fsSL https://github.com/StrangeMatterStudio/Rackhand/releases/download/v<X>/rackhand-lxc.sh | sudo sh
#
# It downloads the newest Debian 12 template if the host doesn't have one, creates an unprivileged container (2 vCPU,
# 1 GB RAM, 20 GB disk, DHCP on vmbr0, nesting on for systemd, started at boot), starts it, and runs the hub installer
# inside it (`install.sh --hub`, which checks every file against the pinned release keys). The installer prints the
# dashboard's address and the one-time setup code.
#
# Options: --vmid <n> (the next free id), --hostname <name> (rackhand), --storage <id> (local-lvm), --bridge <name>
# (vmbr0), --template-storage <id> (local), --release-url <url> (this release).
set -eu

VERSION="__VERSION__"
RELEASE_URL="https://github.com/StrangeMatterStudio/Rackhand/releases/download/v$VERSION"
VMID="" HOSTNAME_="rackhand" STORAGE="local-lvm" BRIDGE="vmbr0" TEMPLATE_STORAGE="local"

die() {
  echo "rackhand-lxc: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --vmid) VMID="$2"; shift 2 ;;
    --hostname) HOSTNAME_="$2"; shift 2 ;;
    --storage) STORAGE="$2"; shift 2 ;;
    --bridge) BRIDGE="$2"; shift 2 ;;
    --template-storage) TEMPLATE_STORAGE="$2"; shift 2 ;;
    --release-url) RELEASE_URL="$2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run it as root on the Proxmox host"
command -v pct >/dev/null 2>&1 || die "pct isn't here: run it on a Proxmox host"
case "$VMID" in
  '') VMID=$(pvesh get /cluster/nextid) || die "no free container id" ;;
  *[!0-9]*) die "--vmid is a number" ;;
esac
case "$HOSTNAME_" in
  '' | *[!a-zA-Z0-9-]*) die "--hostname is letters, digits and dashes" ;;
esac

# the newest Debian 12 template, downloaded once
pveam update >/dev/null 2>&1 || true
TEMPLATE=$(pveam list "$TEMPLATE_STORAGE" | awk '{print $1}' | grep -E 'debian-12-standard_.*\.tar\.zst$' | sort -V | tail -1)
if [ -z "$TEMPLATE" ]; then
  NAME=$(pveam available --section system | awk '{print $2}' | grep -E '^debian-12-standard_.*\.tar\.zst$' | sort -V | tail -1)
  [ -n "$NAME" ] || die "no Debian 12 template is available from pveam"
  pveam download "$TEMPLATE_STORAGE" "$NAME" >/dev/null || die "pveam download $NAME failed"
  TEMPLATE="$TEMPLATE_STORAGE:vztmpl/$NAME"
fi

pct create "$VMID" "$TEMPLATE" \
  --hostname "$HOSTNAME_" \
  --cores 2 \
  --memory 1024 \
  --swap 512 \
  --rootfs "$STORAGE:20" \
  --net0 "name=eth0,bridge=$BRIDGE,ip=dhcp" \
  --unprivileged 1 \
  --features nesting=1 \
  --onboot 1 \
  || die "pct create failed"
pct start "$VMID" || die "pct start $VMID failed"

# the container's network, then curl and the hub installer
i=0
until pct exec "$VMID" -- sh -c 'ip -4 route show default | grep -q default' >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -lt 60 ] || die "container $VMID has no network after a minute"
  sleep 1
done
pct exec "$VMID" -- sh -c 'apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q curl ca-certificates >/dev/null' \
  || die "installing curl in container $VMID failed"
pct exec "$VMID" -- sh -c "curl -fsSL '$RELEASE_URL/install.sh' | sh -s -- --hub --release-url '$RELEASE_URL'" \
  || die "the hub installer failed in container $VMID"
echo "rackhand-lxc: container $VMID ($HOSTNAME_) runs the hub."
