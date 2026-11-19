# A git server for the library mirror (plan T56): OpenSSH with git-shell and a bare repository that refuses
# non-fast-forward pushes.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /usr/bin/git-shell git \
 && install -d -m 0700 -o git -g git /home/git/.ssh \
 && mkdir -p /srv/git /run/sshd \
 && git init -q --bare -b main /srv/git/rackhand.git \
 && git --git-dir=/srv/git/rackhand.git config receive.denyNonFastForwards true \
 && chown -R git:git /srv/git \
 && printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/rackhand.conf
CMD ["/usr/sbin/sshd", "-D", "-e"]
