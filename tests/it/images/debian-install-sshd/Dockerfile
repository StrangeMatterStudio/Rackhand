# The installer's Debian machine with OpenSSH running (plan T49): what the hub's SSH test after a managed machine's
# first report logs in to. Debian 12 with systemd as PID 1, D-Bus, sudo, curl and OpenSSH; no Rackhand users. The offline
# test (plan T97) runs a hub in it and counts what it sends with nftables, routing the outside with iproute2.
FROM debian:12-slim
ENV container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus sudo procps curl ca-certificates openssh-server nftables \
    iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/rackhand.conf
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
