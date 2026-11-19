# The hub's SSH identities (plan T53): Debian 12 with OpenSSH and the two hub accounts; the test installs the keys.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/sh rackhand \
 && useradd -m -s /bin/bash rackhand-ai \
 && install -d -m 0700 -o rackhand -g rackhand /home/rackhand/.ssh \
 && install -d -m 0700 -o rackhand-ai -g rackhand-ai /home/rackhand-ai/.ssh \
 && mkdir -p /run/sshd \
 && printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/rackhand.conf
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
