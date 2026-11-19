# The command wrapper's sudo entry (plan T51): a Debian machine with the automation user and its one sudo rule.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/sh rackhand \
 && mkdir -p /usr/local/lib/rackhand /etc/rackhand /etc/rackhand-probe \
 && echo 'rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run' > /etc/sudoers.d/rackhand \
 && chmod 0440 /etc/sudoers.d/rackhand \
 && visudo -c
CMD ["sleep", "infinity"]
