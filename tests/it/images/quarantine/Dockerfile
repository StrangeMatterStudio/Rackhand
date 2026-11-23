# The in-guest quarantine's machine (plan T72): the wrapper's sudo entry, nftables, and what the tests probe with
# (ping, Python for TCP and UDP listeners and clients). Run privileged so the container may load nftables rules.
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo nftables iproute2 iputils-ping python3 procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/sh rackhand \
 && mkdir -p /usr/local/lib/rackhand /etc/rackhand /etc/rackhand-probe \
 && echo 'rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run' > /etc/sudoers.d/rackhand \
 && chmod 0440 /etc/sudoers.d/rackhand \
 && visudo -c
CMD ["sleep", "infinity"]
