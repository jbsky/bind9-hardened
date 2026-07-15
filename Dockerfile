# ============================================================================
# BIND9 Hardened -- FROM scratch multi-stage build
# ISC BIND 9.20.x DNS server with Go init binary, tini PID 1, zero shell.
#
# Tier: Platine (FROM scratch, non-root, setcap, binary healthcheck)
# ============================================================================
# ALPINE_VERSION / GO_VERSION kept for check-versions.sh reference only --
# the FROM lines below pin tag+digest together as a literal so a version
# bump requires deliberately re-resolving the digest, not a silent drift
# if these ARGs change without the pins being updated to match.
ARG ALPINE_VERSION=3.21
ARG BIND_VERSION=9.20.24
ARG GO_VERSION=1.26

# ============================================================================
# Stage 1: builder -- compile BIND from ISC source with hardening flags
# ============================================================================
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS builder

ARG BIND_VERSION

# Compiler hardening flags (Full RELRO, PIE, SSP, FORTIFY_SOURCE)
ENV CFLAGS="-O2 -fstack-protector-strong -fstack-clash-protection -fPIE -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security" \
    CXXFLAGS="-O2 -fstack-protector-strong -fstack-clash-protection -fPIE -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security" \
    LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack -pie"

# Proxy-aware CA injection (BuildKit secret, never baked into image)
RUN --mount=type=secret,id=ca-certs,required=false \
    if [ -f /run/secrets/ca-certs ]; then \
        cat /run/secrets/ca-certs >> /etc/ssl/certs/ca-certificates.crt; \
    fi

# HTTP repos for proxy compatibility (SSL Bump)
RUN sed -i 's|https://|http://|g' /etc/apk/repositories

# Build dependencies -- split for proxy timeout resilience
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        build-base \
        pkgconf \
        perl \
        linux-headers \
        gnupg

RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        openssl-dev \
        libuv-dev \
        userspace-rcu-dev

RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        libxml2-dev \
        json-c-dev \
        jemalloc-dev \
        zlib-dev \
        libcap-dev

# Download BIND source + PGP detached signature (ISC official tarball)
ADD https://downloads.isc.org/isc/bind9/${BIND_VERSION}/bind-${BIND_VERSION}.tar.xz /tmp/bind.tar.xz
ADD https://downloads.isc.org/isc/bind9/${BIND_VERSION}/bind-${BIND_VERSION}.tar.xz.asc /tmp/bind.tar.xz.asc
COPY keys/isc-keyblock.asc /tmp/isc-keyblock.asc

# Verify tarball authenticity against ISC's pinned code-signing keys
# (key block fetched from https://www.isc.org/docs/isc-keyblock.asc, committed to repo)
RUN gpg --import /tmp/isc-keyblock.asc && \
    gpg --verify /tmp/bind.tar.xz.asc /tmp/bind.tar.xz && \
    tar -xf /tmp/bind.tar.xz -C /tmp && \
    rm -rf /tmp/bind.tar.xz /tmp/bind.tar.xz.asc /tmp/isc-keyblock.asc /root/.gnupg

WORKDIR /tmp/bind-${BIND_VERSION}

# Detect build system and compile
# BIND 9.20: autoconf (configure). BIND 9.21+: meson. Handle both.
RUN if [ -f configure ]; then \
        echo "=== Building BIND ${BIND_VERSION} with autoconf ===" && \
        ./configure \
            --prefix=/usr \
            --sysconfdir=/etc/bind \
            --localstatedir=/var \
            --with-openssl \
            --with-libxml2 \
            --with-json-c \
            --with-zlib \
            --with-jemalloc \
            --disable-doh \
            --disable-static \
            --without-gssapi \
            --without-libidn2 \
            --without-readline \
            --without-cmocka && \
        make -j$(nproc) && \
        make install DESTDIR=/out; \
    elif [ -f meson.build ]; then \
        echo "=== Building BIND ${BIND_VERSION} with meson ===" && \
        apk add --no-cache meson ninja python3 && \
        meson setup build \
            --prefix=/usr \
            --sysconfdir=/etc/bind \
            --localstatedir=/var \
            -Dgssapi=disabled && \
        ninja -C build && \
        DESTDIR=/out ninja -C build install; \
    else \
        echo "ERROR: No recognized build system (configure or meson.build) found" && exit 1; \
    fi

# Strip binaries and shared libraries
# (.la libtool archives are plain text, not ELF -- delete before strip, not after)
RUN find /out -type f \( -name '*.a' -o -name '*.la' \) -delete && \
    find /out -type f \( -executable -o -name '*.so*' \) -exec strip --strip-unneeded {} +

# Remove unnecessary binaries (keep only named + named-checkconf)
RUN rm -f \
    /out/usr/bin/nsupdate /out/usr/bin/dig /out/usr/bin/host \
    /out/usr/bin/nslookup /out/usr/bin/delv /out/usr/bin/mdig \
    /out/usr/bin/arpaname /out/usr/bin/named-rrchecker \
    /out/usr/bin/ddns-confgen /out/usr/bin/tsig-keygen \
    /out/usr/sbin/rndc /out/usr/sbin/rndc-confgen \
    /out/usr/sbin/nsupdate /out/usr/sbin/dig /out/usr/sbin/delv \
    /out/usr/sbin/ddns-confgen /out/usr/sbin/tsig-keygen \
    /out/usr/bin/dnssec-cds /out/usr/bin/dnssec-dsfromkey \
    /out/usr/bin/dnssec-importkey /out/usr/bin/dnssec-keyfromlabel \
    /out/usr/bin/dnssec-keygen /out/usr/bin/dnssec-revoke \
    /out/usr/bin/dnssec-settime /out/usr/bin/dnssec-signzone \
    /out/usr/bin/dnssec-verify \
    /out/usr/sbin/dnssec-cds /out/usr/sbin/dnssec-dsfromkey \
    /out/usr/sbin/dnssec-importkey /out/usr/sbin/dnssec-keyfromlabel \
    /out/usr/sbin/dnssec-keygen /out/usr/sbin/dnssec-revoke \
    /out/usr/sbin/dnssec-settime /out/usr/sbin/dnssec-signzone \
    /out/usr/sbin/dnssec-verify \
    /out/usr/bin/named-journalprint /out/usr/sbin/named-journalprint \
    /out/usr/bin/named-compilezone /out/usr/sbin/named-compilezone

# Remove headers, man pages, docs, pkgconfig
RUN rm -rf /out/usr/include /out/usr/share/man /out/usr/share/doc \
    /out/usr/lib/pkgconfig /out/usr/lib/cmake

# ============================================================================
# Stage 2: Go builder -- init binary (healthcheck + entrypoint + setup-dirs)
# ============================================================================
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS gobuilder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod init.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags='-s -w' -trimpath -o /init .

# ============================================================================
# Stage 3: prep -- assemble complete runtime filesystem
# ============================================================================
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS prep

ARG BIND_VERSION

# Proxy-aware
RUN --mount=type=secret,id=ca-certs,required=false \
    if [ -f /run/secrets/ca-certs ]; then \
        cat /run/secrets/ca-certs >> /etc/ssl/certs/ca-certificates.crt; \
    fi
RUN sed -i 's|https://|http://|g' /etc/apk/repositories

# Runtime libraries + tools
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        tini-static \
        tzdata \
        ca-certificates \
        libcap-utils \
        libuv \
        libcrypto3 \
        libssl3 \
        libxml2 \
        json-c \
        jemalloc \
        zlib \
        libcap2 \
        userspace-rcu

# Create non-root user (UID 5300, mnemonic for port 53)
RUN addgroup -g 5300 -S named && \
    adduser -u 5300 -G named -D -H -s /sbin/nologin named

# Copy BIND binaries and internal shared libraries from builder
COPY --from=builder /out/ /

# Set file capability for binding port 53 as non-root
RUN setcap 'cap_net_bind_service+ep' /usr/sbin/named

# Copy Go init binary
COPY --from=gobuilder /init /usr/local/bin/init

# Verify named works
# hadolint ignore=DL4006
RUN /usr/sbin/named -V 2>&1 | head -5

# Create runtime directories via init
RUN /usr/local/bin/init --setup-dirs

# Clean up build-only tools (won't be in FROM scratch anyway)
RUN rm -rf /var/cache/apk/* /usr/lib/pkgconfig /usr/lib/cmake

# ============================================================================
# Stage 4: FROM scratch -- final hardened image
# ============================================================================
FROM scratch

ARG BIND_VERSION

# OCI labels
LABEL org.opencontainers.image.title="bind9-hardened" \
      org.opencontainers.image.description="ISC BIND 9 DNS server -- FROM scratch, non-root, zero shell" \
      org.opencontainers.image.vendor="jbsky" \
      org.opencontainers.image.licenses="MPL-2.0" \
      org.opencontainers.image.source="https://github.com/jbsky/bind9-hardened" \
      org.opencontainers.image.version="${BIND_VERSION}" \
      security.hardening.tier="platine" \
      versions="bind=${BIND_VERSION}"

# 1. System identity files
COPY --link --from=prep /etc/passwd /etc/group /etc/

# 2. TLS root certificates + timezone data
COPY --link --from=prep /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --link --from=prep /usr/share/zoneinfo/ /usr/share/zoneinfo/

# 3. Dynamic linker (musl) -- copy whole dir: filename is arch-specific
# (ld-musl-x86_64.so.1 vs ld-musl-aarch64.so.1), needed for multi-platform builds
COPY --link --from=prep /lib/ /lib/

# 4. Runtime shared libraries (system deps + BIND internal libs)
COPY --link --from=prep /usr/lib/ /usr/lib/

# 5. BIND binaries (named + named-checkconf only)
COPY --link --from=prep /usr/sbin/named /usr/sbin/
COPY --link --from=prep /usr/bin/named-checkconf /usr/bin/

# 6. tini-static as PID 1 (signal forwarding + zombie reaping)
COPY --link --from=prep /sbin/tini-static /sbin/tini

# 7. Go init binary (entrypoint + healthcheck + setup-dirs)
COPY --link --from=gobuilder /init /usr/local/bin/init

# 8. Create runtime directories
RUN ["/usr/local/bin/init", "--setup-dirs"]

# Runtime configuration
ENV TZ=Europe/Paris

USER 5300:5300

EXPOSE 53/tcp 53/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/init", "--healthcheck"]

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/init"]
CMD ["named", "-g", "-4", "-c", "/etc/bind/named.conf"]
