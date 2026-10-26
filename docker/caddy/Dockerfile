# syntax=docker/dockerfile:1.6@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021

# Always run the builder on the host arch (BUILDPLATFORM) and let xcaddy
# cross-compile Caddy for the target arch via GOOS/GOARCH. This avoids QEMU
# emulation when producing the linux/arm64 image on an x86 GitHub runner —
# native cross-compilation is several times faster.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build
COPY docker/caddy/go.mod docker/caddy/go.sum docker/caddy/build.sh docker/caddy/update-compatibility-pins.sh ./

# Every module version comes from go.mod. Dependabot updates that file weekly;
# the compatibility updater derives cel-go from the pinned Caddy release, and
# go.sum authenticates the module metadata used to resolve the build.
RUN sh ./update-compatibility-pins.sh
RUN XCADDY_VERSION="$(go list -m -f '{{.Version}}' github.com/caddyserver/xcaddy)" && \
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@"${XCADDY_VERSION}"
RUN sh ./build.sh

FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944

# Accept build args for user/group IDs to support rootless operation
# Using 10000 as default to avoid conflicts with system users
ARG PUID=10000
ARG PGID=10000

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy caddy binary from builder
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Create caddy user and directories with configurable IDs for rootless operation
# Remove any existing users/groups with the same UID/GID to avoid conflicts
RUN (getent group ${PGID} && groupdel $(getent group ${PGID} | cut -d: -f1) || true) && \
    (getent passwd ${PUID} && userdel $(getent passwd ${PUID} | cut -d: -f1) || true) && \
    groupadd -g ${PGID} caddy && \
    useradd -r -u ${PUID} -g caddy -m -d /home/caddy caddy && \
    mkdir -p /data /config /logs /acme-ca && \
    chown -R caddy:caddy /data /config /logs /home/caddy && \
    chmod 0777 /acme-ca

COPY --chown=caddy:caddy docker/caddy/Caddyfile /etc/caddy/Caddyfile

EXPOSE 80 443 2019

# Set environment variables to use /data and /config like official Caddy image
ENV XDG_CONFIG_HOME=/config
ENV XDG_DATA_HOME=/data

# Run as non-root user (fully rootless)
USER caddy

CMD ["caddy", "run", "--resume", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
