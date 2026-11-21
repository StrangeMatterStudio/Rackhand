# The installer's Debian machine (plan T44): Debian 12 with systemd as PID 1, D-Bus, sudo and curl; no Rackhand users.
FROM debian:12-slim
ENV container=docker
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus sudo procps curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
