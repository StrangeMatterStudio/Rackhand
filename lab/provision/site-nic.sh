#!/bin/sh
# Gives the lab site NIC with MAC $1 the static address $2/$3 (plan L1). Runs once from cloud-init.
# Works with netplan (Ubuntu, Debian 13) and ifupdown (Debian 12, Alpine).
set -eu
mac="$1"; address="$2"; prefix="$3"
nic=""
for dev in /sys/class/net/*; do
  if [ "$(cat "$dev/address" 2>/dev/null)" = "$mac" ]; then nic="$(basename "$dev")"; fi
done
[ -n "$nic" ] || { echo "no NIC with MAC $mac" >&2; exit 1; }
if command -v netplan >/dev/null 2>&1 && [ -d /etc/netplan ]; then
  cat > /etc/netplan/60-rackhand-lab.yaml <<EOF
network:
  version: 2
  ethernets:
    $nic:
      dhcp4: false
      dhcp6: false
      addresses: [$address/$prefix]
EOF
  chmod 600 /etc/netplan/60-rackhand-lab.yaml
  netplan apply
else
  mkdir -p /etc/network
  cat >> /etc/network/interfaces <<EOF

auto $nic
iface $nic inet static
    address $address/$prefix
EOF
  ip link set "$nic" up
  ip addr add "$address/$prefix" dev "$nic" 2>/dev/null || true
fi
echo "$nic $address/$prefix" > /etc/rackhand-lab-site-nic
