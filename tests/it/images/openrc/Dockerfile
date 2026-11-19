# Detached steps on OpenRC (plan T52): Alpine 3.20 with OpenRC's start-stop-daemon, sudo and the automation user.
FROM alpine:3.20
RUN apk add --no-cache openrc sudo bash coreutils procps \
 && adduser -D -s /bin/sh rackhand \
 && mkdir -p /usr/local/lib/rackhand /etc/rackhand /etc/rackhand-probe \
 && echo 'rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run' > /etc/sudoers.d/rackhand \
 && chmod 0440 /etc/sudoers.d/rackhand && visudo -c \
 && printf '#!/bin/sh\nfor i in $(seq 1 "$1"); do echo "line $i"; sleep 1; done\necho done\n' > /usr/local/bin/slow-echo \
 && chmod 0755 /usr/local/bin/slow-echo
CMD ["sleep", "infinity"]
