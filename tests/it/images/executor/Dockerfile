# The Executor against a managed machine (plan T55, T63): Debian 12 with systemd as PID 1, OpenSSH, sudo, both hub
# accounts and the automation user's one sudo rule, plus what the diagnostics run (7.8.3). Docker itself isn't here:
# a stand-in prints what `docker` would, so the docker diagnostics' templates and the wrapper path are what is tested.
# The test installs the keys, the wrapper and a signed command list.
FROM debian:12-slim
ENV container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv sudo procps openssh-server iproute2 curl \
    iputils-ping dbus \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/sh rackhand \
 && useradd -m -s /bin/bash rackhand-ai \
 && install -d -m 0700 -o rackhand -g rackhand /home/rackhand/.ssh \
 && install -d -m 0700 -o rackhand-ai -g rackhand-ai /home/rackhand-ai/.ssh \
 && mkdir -p /usr/local/lib/rackhand /etc/rackhand /etc/rackhand-probe \
 && echo 'rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run' > /etc/sudoers.d/rackhand \
 && chmod 0440 /etc/sudoers.d/rackhand && visudo -c \
 && printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/rackhand.conf \
 && printf '#!/bin/sh\nfor i in $(seq 1 "$1"); do echo "line $i"; sleep 1; done\necho done\n' > /usr/local/bin/slow-echo \
 && chmod 0755 /usr/local/bin/slow-echo \
 && printf '#!/bin/sh\ncase "$1" in\n  ps) echo "CONTAINER ID   IMAGE   STATUS";;\n  compose) echo "NAME   STATUS   CONFIG FILES";;\n  logs) echo "a log line";;\n  *) exit 1;;\nesac\n' > /usr/bin/docker \
 && chmod 0755 /usr/bin/docker \
 && touch /var/log/wtmp \
 && systemctl enable ssh
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
