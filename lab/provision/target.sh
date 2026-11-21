#!/bin/sh
# target (plan L3): the machine the live tests measure. No unattended upgrades: they install packages and restart
# services (networking among them) in the middle of a test. The package lists still refresh, so pending updates are
# still reported.
set -eu
systemctl disable --now apt-daily-upgrade.timer
systemctl disable --now unattended-upgrades.service
