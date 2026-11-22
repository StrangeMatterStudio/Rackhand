# A machine to patch (plan T59): Debian 12 with systemd, OpenSSH, sudo and the hub's accounts as in `executor`, whose
# only package source is a repository on its own disk with one newer package. Its install takes as long as
# /srv/ctl/seconds says, fails with /srv/ctl/fail, and asks for a reboot with /srv/ctl/reboot; apt is the real one.
# /sbin/reboot is a stand-in that records who ran it: a container can't reboot.
FROM debian:12-slim
ENV container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv sudo procps openssh-server dbus \
 && rm -rf /var/lib/apt/lists/* /etc/apt/sources.list /etc/apt/sources.list.d/* \
 && useradd -m -s /bin/sh rackhand \
 && useradd -m -s /bin/bash rackhand-ai \
 && install -d -m 0700 -o rackhand -g rackhand /home/rackhand/.ssh \
 && install -d -m 0700 -o rackhand-ai -g rackhand-ai /home/rackhand-ai/.ssh \
 && mkdir -p /usr/local/lib/rackhand /etc/rackhand /etc/rackhand-probe /srv/ctl /srv/repo \
 && echo 'rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run' > /etc/sudoers.d/rackhand \
 && chmod 0440 /etc/sudoers.d/rackhand && visudo -c \
 && printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/rackhand.conf \
 && rm -f /sbin/reboot && printf '#!/bin/sh\nid -un >> /root/rebooted\n' > /sbin/reboot && chmod 0755 /sbin/reboot \
 && systemctl enable ssh
RUN set -e; for v in 1.0 2.0; do \
      d=/tmp/rackhand-demo-$v; mkdir -p $d/DEBIAN $d/usr/share/rackhand-demo; \
      printf 'Package: rackhand-demo\nVersion: %s\nArchitecture: all\nMaintainer: Rackhand tests <tests@example.invalid>\nDescription: a package to update\n' $v > $d/DEBIAN/control; \
      echo $v > $d/usr/share/rackhand-demo/version; \
      printf '#!/bin/sh\nset -e\n[ "$1" = configure ] || exit 0\n[ -n "$2" ] || exit 0\ni=$(cat /srv/ctl/seconds 2>/dev/null || echo 0)\nwhile [ "$i" -gt 0 ]; do echo "installing, $i s left"; sleep 1; i=$((i-1)); done\n[ ! -e /srv/ctl/fail ] || exit 1\n[ ! -e /srv/ctl/reboot ] || touch /run/reboot-required\n' > $d/DEBIAN/postinst; \
      chmod 0755 $d/DEBIAN/postinst; dpkg-deb --root-owner-group -b $d /tmp/rackhand-demo_$v.deb; \
    done; \
    dpkg -i /tmp/rackhand-demo_1.0.deb; \
    cp /tmp/rackhand-demo_2.0.deb /srv/repo/; cd /srv/repo; \
    { dpkg-deb -f rackhand-demo_2.0.deb; \
      echo "Filename: ./rackhand-demo_2.0.deb"; \
      echo "Size: $(stat -c %s rackhand-demo_2.0.deb)"; \
      echo "SHA256: $(sha256sum rackhand-demo_2.0.deb | cut -d' ' -f1)"; echo; } > Packages; \
    echo 'deb [trusted=yes] file:/srv/repo ./' > /etc/apt/sources.list
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
