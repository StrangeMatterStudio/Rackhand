# Detached steps under systemd (plan T52) and the hub's unit (T41): Debian 12 with systemd as PID 1, sudo, curl
# and the automation user.
FROM debian:12-slim
ENV container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv sudo procps curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/sh rackhand \
 && mkdir -p /usr/local/lib/rackhand /etc/rackhand /etc/rackhand-probe \
 && echo 'rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run' > /etc/sudoers.d/rackhand \
 && chmod 0440 /etc/sudoers.d/rackhand && visudo -c \
 && printf '#!/bin/sh\nfor i in $(seq 1 "$1"); do echo "line $i"; sleep 1; done\necho done\n' > /usr/local/bin/slow-echo \
 && chmod 0755 /usr/local/bin/slow-echo
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
