#!/bin/bash
# Installs Proxmox VE on a lab Debian machine (plan L1), following Proxmox's "Install Proxmox VE on Debian" guides.
# Usage: sudo proxmox.sh <phase 1|2> <major 8|9> <site address> <prefix> <site MAC> <ct address> <vm address>
# Phase 1: repository and the Proxmox kernel (then reboot). Phase 2: proxmox-ve, vmbr0 on the site NIC, a ZFS pool on
# the extra disk, and the test guests ct-test (100, unprivileged LXC) and vm-test (200, small Alpine VM).
set -euxo pipefail
phase="$1"; major="$2"; address="$3"; prefix="$4"; mac="$5"; ct_ip="$6"; vm_ip="$7"
export DEBIAN_FRONTEND=noninteractive
host="$(hostname -s)"

if [ "$phase" = 1 ]; then
  sed -i "/[[:space:]]$host\$/d; /[[:space:]]$host[[:space:]]/d" /etc/hosts
  echo "$address $host.lab.invalid $host" >> /etc/hosts
  # DNS that survives the switch to ifupdown2 and vmbr0 in phase 2: QEMU user-mode networking's resolver.
  systemctl disable --now systemd-resolved 2>/dev/null || true
  rm -f /etc/resolv.conf
  echo "nameserver 10.0.2.3" > /etc/resolv.conf
  # Proxmox's grub-pc asks for the install device; answer for the lab disk.
  echo "grub-pc grub-pc/install_devices multiselect /dev/vda" | debconf-set-selections
  if [ "$major" = 8 ]; then
    curl -fsSL https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg -o /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg
    echo "7da6fe34168adc6e479327ba517796d4702fa2f8b4f0a9833f5ea6e6b48f6507a6da403a274fe201595edc86a84463d50383d07f64bdde2e3658108db7d6dc87  /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg" | sha512sum -c -
    echo "deb [arch=amd64] http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-install-repo.list
  else
    curl -fsSL https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg -o /usr/share/keyrings/proxmox-archive-keyring.gpg
    echo "136673be77aba35dcce385b28737689ad64fd785a797e57897589aed08db6e45  /usr/share/keyrings/proxmox-archive-keyring.gpg" | sha256sum -c -
    cat > /etc/apt/sources.list.d/pve-install-repo.sources <<EOF
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
  fi
  apt-get update
  apt-get -y full-upgrade
  apt-get install -y proxmox-default-kernel
  exit 0
fi

# Phase 2
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
echo "postfix postfix/mailname string $host.lab.invalid" | debconf-set-selections
apt-get install -y proxmox-ve postfix open-iscsi chrony
apt-get remove -y os-prober || true
apt-get remove -y 'linux-image-*cloud*' 'linux-image-amd64' || true
update-grub

nic=""
uplink=""
for dev in /sys/class/net/*; do
  name="$(basename "$dev")"
  [ -e "$dev/device" ] || continue
  if [ "$(cat "$dev/address")" = "$mac" ]; then nic="$name"; else uplink="$name"; fi
done
[ -n "$nic" ] && [ -n "$uplink" ]
rm -f /etc/netplan/*.yaml /etc/network/interfaces.d/50-cloud-init
cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

# QEMU user-mode networking's fixed addresses; static because the cloud images ship no dhclient for ifupdown2.
auto $uplink
iface $uplink inet static
    address 10.0.2.15/24
    gateway 10.0.2.2

iface $nic inet manual

auto vmbr0
iface vmbr0 inet static
    address $address/$prefix
    bridge-ports $nic
    bridge-stp off
    bridge-fd 0
EOF
systemctl disable --now systemd-networkd 2>/dev/null || true
ifreload -a || systemctl restart networking

# ZFS pool on the extra disk for guests (and for the S11 ARC reading)
if ! zpool list tank >/dev/null 2>&1; then
  zpool create -f tank /dev/vdb
fi
pvesm status | grep -q '^tank ' || pvesm add zfspool tank --pool tank --content rootdir,images

# Test guests
pveam update
template="$(pveam available --section system | awk '/alpine-3\.[0-9]+-default/ {print $2}' | sort -V | tail -1)"
[ -f "/var/lib/vz/template/cache/$template" ] || pveam download local "$template"
if ! pct status 100 >/dev/null 2>&1; then
  pct create 100 "local:vztmpl/$template" --hostname ct-test --unprivileged 1 --memory 256 --swap 0 \
    --net0 "name=eth0,bridge=vmbr0,ip=$ct_ip/$prefix" --rootfs tank:2 --ssh-public-keys /root/lab.pub --onboot 1
fi
pct start 100 || true

if ! qm status 200 >/dev/null 2>&1; then
  qm create 200 --name vm-test --memory 384 --cores 1 --net0 virtio,bridge=vmbr0 --scsihw virtio-scsi-pci \
    --serial0 socket --vga serial0 --ostype l26 --onboot 1
  qm importdisk 200 /root/alpine.qcow2 tank >/dev/null
  qm set 200 --scsi0 tank:vm-200-disk-0 --boot order=scsi0 --ide2 tank:cloudinit \
    --ipconfig0 "ip=$vm_ip/$prefix" --ciuser lab --sshkeys /root/lab.pub
fi
if [ -w /dev/kvm ] && grep -qE 'vmx|svm' /proc/cpuinfo; then
  echo hardware > /root/rackhand-lab-nested
else
  qm set 200 --kvm 0
  echo emulation > /root/rackhand-lab-nested
fi
qm start 200 || true
echo "proxmox $major ready: $(pveversion)"
