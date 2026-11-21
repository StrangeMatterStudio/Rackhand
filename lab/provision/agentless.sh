#!/bin/sh
# agentless (plan L3): an SNMP appliance with no probe. snmpd answers v2c with the lab's community on every address;
# the live tests add it through the dashboard's SNMP form.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends snmpd
cat > /etc/snmp/snmpd.conf <<'CONF'
agentAddress udp:161
rocommunity rackhand-lab default
sysLocation lab site a
sysContact lab
CONF
systemctl enable snmpd
systemctl restart snmpd
