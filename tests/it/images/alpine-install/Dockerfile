# The installer's Alpine machine (plan T44): Alpine 3.20 with OpenRC; no sudo, bash or Rackhand users (the installer
# adds them). OpenRC runs its services here without being PID 1: `rc_sys=docker` and the network and loopback taken
# as provided, as a booted machine would have them.
FROM alpine:3.20
RUN apk add --no-cache openrc coreutils \
 && sed -i 's/^#rc_sys=""/rc_sys="docker"/; s/^#rc_provide="!net"/rc_provide="loopback net"/' /etc/rc.conf \
 && mkdir -p /run/openrc && touch /run/openrc/softlevel
# the default runlevel, as a booted machine has it, then stay up
CMD ["sh", "-c", "openrc default >/dev/null 2>&1; exec sleep infinity"]
