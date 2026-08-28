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
ARG ALPINE_VERSION=3.24
ARG BIND_VERSION=9.20.27
ARG GO_VERSION=1.26
# jemalloc est compile depuis les sources, pas installe via apk : voir la note
# devant sa compilation dans le stage builder.
ARG JEMALLOC_VERSION=5.3.1
ARG JEMALLOC_SHA256=3826bc80232f22ed5c4662f3034f799ca316e819103bdc7bb99018a421706f92
# Bibliotheques runtime compilees depuis les sources. Chacune est verifiee par
# la signature detachee de son amont, contre une empreinte epinglee ici : les
# cles sont committees dans keys/, et importer une cle puis verifier avec cette
# meme cle ne prouverait rien -- l'empreinte est le seul ancrage.
ARG ZLIB_VERSION=1.3.2
ARG ZLIB_FPR=5ED46A6721D365587791E2AA783FCD8E58BCAFBA
ARG XZ_VERSION=5.8.3
ARG XZ_FPR=3690C240CE51B4670D30AD1C38EE757D69184620
ARG URCU_VERSION=0.15.6
ARG URCU_FPR=2A0B4ED915F2D3FA45F5B16217280A9781186ACF
ARG LIBCAP_VERSION=2.78
ARG LIBCAP_FPR=38A644698C69787344E954CE29EE848AE2CCF3F4

# ============================================================================
# Stage 1: builder -- compile BIND from ISC source with hardening flags
# ============================================================================
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS builder

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

# hadolint ignore=DL3059
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        openssl-dev \
        libuv-dev \
        userspace-rcu-dev

# hadolint ignore=DL3059
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        libxml2-dev \
        json-c-dev \
        zlib-dev \
        libcap-dev \
        curl

# --- jemalloc, compile depuis les sources ---
#
# Le paquet Alpine est construit avec le support C++ (surcharges de new/delete),
# ce qui fait de libjemalloc le SEUL consommateur de libstdc++ de cette image :
# 2,8 Mo de C++ embarques pour un allocateur ecrit en C. `--disable-cxx` les
# supprime, et libgcc_s part avec puisque plus rien ne l'appelle.
#
# jemalloc s'installe NON STRIPPE (il compile en -g3 par defaut) : 6,1 Mo au
# lieu de 818 Ko. Une bibliotheque compilee depuis les sources n'herite
# d'aucun strip, contrairement a un paquet Alpine -- le faire explicitement.
#
# jemalloc ne publie ni signature ni hash amont : le sha256 est epingle ici,
# comme pour les autres tarballs non signes. Le canal a ete valide en
# comparant le sha512 de la 5.3.0 telechargee sur GitHub a celui qu'Alpine
# verifie de son cote -- identique octet pour octet.
#
# CFLAGS/LDFLAGS sont redefinis pour cette compilation seule : le stage porte
# `-fPIE` et `-pie` pour les executables de BIND, mais jemalloc produit une
# bibliotheque PARTAGEE. `-pie` sur un lien `-shared` fait tirer Scrt1.o au
# linker, qui reclame alors un `main` inexistant. -fPIC suffit et est correct
# des deux cotes.
ARG JEMALLOC_VERSION
ARG JEMALLOC_SHA256
WORKDIR /tmp/jemalloc
RUN export CFLAGS="-O2 -fstack-protector-strong -fstack-clash-protection -fPIC -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security" \
 && export LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack" \
 && curl -fsSL "https://github.com/jemalloc/jemalloc/releases/download/${JEMALLOC_VERSION}/jemalloc-${JEMALLOC_VERSION}.tar.bz2" \
      -o /tmp/jemalloc.tar.bz2 \
 && printf '%s  /tmp/jemalloc.tar.bz2\n' "${JEMALLOC_SHA256}" > /tmp/jemalloc.sha256 \
 && sha256sum -c /tmp/jemalloc.sha256 \
 && tar -xjf /tmp/jemalloc.tar.bz2 -C /tmp/jemalloc --strip-components=1 \
 && ./configure --prefix=/usr --disable-cxx --disable-static --disable-doc \
 && make -j"$(nproc)" \
 && make install \
 && test ! -e /usr/lib/libjemalloc.a \
 && strip --strip-unneeded /usr/lib/libjemalloc.so.2 \
 && rm -rf /tmp/jemalloc /tmp/jemalloc.tar.bz2 /tmp/jemalloc.sha256

# --- Bibliotheques runtime, compilees depuis les sources ---
#
# `cd` a l'interieur du RUN plutot que WORKDIR : un WORKDIR resterait le
# repertoire courant des etapes suivantes, ce qui a deja fait extraire un
# tarball au mauvais endroit ailleurs dans le parc.
#
# Les flags PIE du stage sont neutralises pour ces compilations : ce sont des
# bibliotheques PARTAGEES, et `-pie` sur un lien `-shared` fait tirer Scrt1.o
# au linker, qui reclame alors un `main` inexistant. -fPIC est correct partout.
#
# `strip` explicite a chaque fois : une bibliotheque compilee depuis les
# sources n'herite d'aucun strip, contrairement a un paquet Alpine.
COPY keys/zlib-madler.gpg.asc keys/xz-tukaani.gpg.asc \
     keys/urcu-efficios.gpg.asc keys/libcap-kernel.gpg.asc /tmp/keys/

ARG ZLIB_VERSION
ARG ZLIB_FPR
ARG XZ_VERSION
ARG XZ_FPR
ARG URCU_VERSION
ARG URCU_FPR
ARG LIBCAP_VERSION
ARG LIBCAP_FPR

# strip_inplace : `strip` s'appuie sur libbfd, qui lie libz.so.1 -- stripper
# une bibliotheque EN PLACE alors que strip l'a mappee reecrit le fichier sous
# ses propres pieds et le fait tomber en Segmentation fault. Constate sur zlib.
# Ecrire ailleurs puis renommer evite la classe entiere : rename(2) ne touche
# pas l'inode que les processus en cours ont deja ouvert.
COPY strip-inplace.sh /usr/local/bin/strip_inplace

ENV SRCLIB_CFLAGS="-O2 -fstack-protector-strong -fstack-clash-protection -fPIC -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security" \
    SRCLIB_LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack"

# zlib
# hadolint ignore=DL3003
RUN --mount=type=secret,id=ca-certs,required=false \
    if [ -f /run/secrets/ca-certs ]; then cat /run/secrets/ca-certs >> /etc/ssl/certs/ca-certificates.crt; fi \
 && export CFLAGS="$SRCLIB_CFLAGS" LDFLAGS="$SRCLIB_LDFLAGS" \
 && curl -fsSL "https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz" -o /tmp/zlib.tar.gz \
 && curl -fsSL "https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz.asc" -o /tmp/zlib.tar.gz.asc \
 && GNUPGHOME="$(mktemp -d)" && export GNUPGHOME \
 && gpg --batch --import /tmp/keys/zlib-madler.gpg.asc \
 && gpg --batch --list-keys "${ZLIB_FPR}" > /dev/null \
 && gpg --batch --verify /tmp/zlib.tar.gz.asc /tmp/zlib.tar.gz \
 && gpgconf --kill gpg-agent && rm -rf "$GNUPGHOME" /tmp/zlib.tar.gz.asc \
 && mkdir -p /tmp/zlib && tar -xzf /tmp/zlib.tar.gz -C /tmp/zlib --strip-components=1 \
 && cd /tmp/zlib && ./configure --prefix=/usr --libdir=/usr/lib \
 && make -j"$(nproc)" && make install \
 && rm -f /usr/lib/libz.a \
 && strip_inplace /usr/lib/libz.so.1.* \
 && rm -rf /tmp/zlib /tmp/zlib.tar.gz

# xz (liblzma) -- signature GPG obligatoire ici : apres la porte derobee de
# 2024, un sha256 calcule soi-meme sur un tarball qu'on vient de telecharger
# serait la verification la plus faible sur le projet ou elle compte le plus.
# hadolint ignore=DL3003
RUN --mount=type=secret,id=ca-certs,required=false \
    if [ -f /run/secrets/ca-certs ]; then cat /run/secrets/ca-certs >> /etc/ssl/certs/ca-certificates.crt; fi \
 && export CFLAGS="$SRCLIB_CFLAGS" LDFLAGS="$SRCLIB_LDFLAGS" \
 && XZ_URL="https://github.com/tukaani-project/xz/releases/download/v${XZ_VERSION}" \
 && curl -fsSL "${XZ_URL}/xz-${XZ_VERSION}.tar.gz" -o /tmp/xz.tar.gz \
 && curl -fsSL "${XZ_URL}/xz-${XZ_VERSION}.tar.gz.sig" -o /tmp/xz.tar.gz.sig \
 && GNUPGHOME="$(mktemp -d)" && export GNUPGHOME \
 && gpg --batch --import /tmp/keys/xz-tukaani.gpg.asc \
 && gpg --batch --list-keys "${XZ_FPR}" > /dev/null \
 && gpg --batch --verify /tmp/xz.tar.gz.sig /tmp/xz.tar.gz \
 && gpgconf --kill gpg-agent && rm -rf "$GNUPGHOME" /tmp/xz.tar.gz.sig \
 && mkdir -p /tmp/xz && tar -xzf /tmp/xz.tar.gz -C /tmp/xz --strip-components=1 \
 && cd /tmp/xz \
 && ./configure --prefix=/usr --libdir=/usr/lib --disable-static \
      --disable-xz --disable-xzdec --disable-lzmadec --disable-lzmainfo \
      --disable-scripts --disable-doc --disable-nls \
 && make -j"$(nproc)" && make install \
 && strip_inplace /usr/lib/liblzma.so.5.* \
 && rm -rf /tmp/xz /tmp/xz.tar.gz

# userspace-rcu
# hadolint ignore=DL3003
RUN --mount=type=secret,id=ca-certs,required=false \
    if [ -f /run/secrets/ca-certs ]; then cat /run/secrets/ca-certs >> /etc/ssl/certs/ca-certificates.crt; fi \
 && export CFLAGS="$SRCLIB_CFLAGS" LDFLAGS="$SRCLIB_LDFLAGS" \
 && curl -fsSL "https://lttng.org/files/urcu/userspace-rcu-${URCU_VERSION}.tar.bz2" -o /tmp/urcu.tar.bz2 \
 && curl -fsSL "https://lttng.org/files/urcu/userspace-rcu-${URCU_VERSION}.tar.bz2.asc" -o /tmp/urcu.tar.bz2.asc \
 && GNUPGHOME="$(mktemp -d)" && export GNUPGHOME \
 && gpg --batch --import /tmp/keys/urcu-efficios.gpg.asc \
 && gpg --batch --list-keys "${URCU_FPR}" > /dev/null \
 && gpg --batch --verify /tmp/urcu.tar.bz2.asc /tmp/urcu.tar.bz2 \
 && gpgconf --kill gpg-agent && rm -rf "$GNUPGHOME" /tmp/urcu.tar.bz2.asc \
 && mkdir -p /tmp/urcu && tar -xjf /tmp/urcu.tar.bz2 -C /tmp/urcu --strip-components=1 \
 && cd /tmp/urcu \
 && ./configure --prefix=/usr --libdir=/usr/lib --disable-static --disable-examples \
 && make -j"$(nproc)" && make install \
 && strip_inplace /usr/lib/liburcu*.so.*.* \
 && rm -rf /tmp/urcu /tmp/urcu.tar.bz2

# libcap -- kernel.org signe le tar NON compresse, d'ou la decompression avant
# verification. Makefile pur, pas d'autotools : les chemins passent en variables.
#
# Cible `install-shared-cap` et non `install` : la cible par defaut est
# `install-static`, et un `make` complet construit aussi progs/ (capsh, setcap)
# dont le generateur mkcapshdoc.sh porte un shebang #!/bin/bash absent de
# l'image. On ne veut ni les programmes ni l'archive statique, juste la
# bibliotheque partagee. PTHREADS=no evite libpsx, que rien ne reclame ici.
#
# Pas de `-j` : le Makefile de libcap ne declare pas la dependance vers
# cap_names.h, qu'il genere lui-meme, et un build parallele compile cap_magic.o
# avant que l'en-tete existe. La bibliotheque est minuscule, le serie ne coute
# rien.
# hadolint ignore=DL3003
RUN --mount=type=secret,id=ca-certs,required=false \
    if [ -f /run/secrets/ca-certs ]; then cat /run/secrets/ca-certs >> /etc/ssl/certs/ca-certificates.crt; fi \
 && LIBCAP_URL="https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2" \
 && curl -fsSL "${LIBCAP_URL}/libcap-${LIBCAP_VERSION}.tar.xz" -o /tmp/libcap.tar.xz \
 && curl -fsSL "${LIBCAP_URL}/libcap-${LIBCAP_VERSION}.tar.sign" -o /tmp/libcap.tar.sign \
 && xz -dc /tmp/libcap.tar.xz > /tmp/libcap.tar \
 && GNUPGHOME="$(mktemp -d)" && export GNUPGHOME \
 && gpg --batch --import /tmp/keys/libcap-kernel.gpg.asc \
 && gpg --batch --list-keys "${LIBCAP_FPR}" > /dev/null \
 && gpg --batch --verify /tmp/libcap.tar.sign /tmp/libcap.tar \
 && gpgconf --kill gpg-agent && rm -rf "$GNUPGHOME" /tmp/libcap.tar.sign /tmp/libcap.tar.xz \
 && mkdir -p /tmp/libcap && tar -xf /tmp/libcap.tar -C /tmp/libcap --strip-components=1 \
 && cd /tmp/libcap \
 && make -C libcap \
      CFLAGS="$SRCLIB_CFLAGS" LDFLAGS="$SRCLIB_LDFLAGS" \
      SHARED=yes PTHREADS=no GOLANG=no \
      prefix=/usr lib=lib install-shared-cap \
 && strip_inplace /usr/lib/libcap.so.2.* \
 && rm -rf /tmp/libcap /tmp/libcap.tar /tmp/keys

# Download BIND source + PGP detached signature (ISC official tarball)
ADD https://downloads.isc.org/isc/bind9/${BIND_VERSION}/bind-${BIND_VERSION}.tar.xz /tmp/bind.tar.xz
ADD https://downloads.isc.org/isc/bind9/${BIND_VERSION}/bind-${BIND_VERSION}.tar.xz.asc /tmp/bind.tar.xz.asc
COPY keys/isc-keyblock.asc /tmp/isc-keyblock.asc

# Verify tarball authenticity against ISC's pinned code-signing keys
# (key block fetched from https://www.isc.org/docs/isc-keyblock.asc, committed to repo)
RUN gpg --import /tmp/isc-keyblock.asc && \
    gpg --verify /tmp/bind.tar.xz.asc /tmp/bind.tar.xz && \
    gpgconf --kill gpg-agent && \
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
        make -j"$(nproc)" && \
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

# Remove unnecessary binaries (keep only named + named-checkconf), then
# headers/man pages/docs/pkgconfig
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
    /out/usr/bin/named-compilezone /out/usr/sbin/named-compilezone \
    && rm -rf /out/usr/include /out/usr/share/man /out/usr/share/doc \
    /out/usr/lib/pkgconfig /out/usr/lib/cmake

# ============================================================================
# Stage 2: Go builder -- init binary (healthcheck + entrypoint + setup-dirs)
# ============================================================================
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS gobuilder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod init.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags='-s -w' -trimpath -o /init .

# ============================================================================
# Stage 3: prep -- assemble complete runtime filesystem
# ============================================================================
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS prep

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
        json-c

# Create non-root user (UID 5300, mnemonic for port 53)
RUN addgroup -g 5300 -S named && \
    adduser -u 5300 -G named -D -H -s /sbin/nologin named

# Copy BIND binaries and internal shared libraries from builder
COPY --from=builder /out/ /
# Bibliotheques compilees dans le builder (voir les notes la-bas), pas
# installees par apk ici : elles doivent etre reprises explicitement.
#
# Cette copie vient APRES l'`apk add` a dessein : les paquets encore non portes
# tirent certaines de ces bibliotheques en dependance transitive (libxml2 amene
# zlib et xz-libs), et la copie ecrase alors les exemplaires d'Alpine. Meme
# SONAME, meme version amont -- c'est bien la version compilee ici qui part
# dans la cloture.
COPY --from=builder /usr/lib/libjemalloc.so* /usr/lib/
COPY --from=builder /usr/lib/libz.so* /usr/lib/
COPY --from=builder /usr/lib/liblzma.so* /usr/lib/
COPY --from=builder /usr/lib/liburcu*.so* /usr/lib/
COPY --from=builder /usr/lib/libcap.so* /usr/lib/

# Set file capability for binding port 53 as non-root
RUN setcap 'cap_net_bind_service+ep' /usr/sbin/named

# Copy Go init binary
COPY --from=gobuilder /init /usr/local/bin/init

# Verify named works
# hadolint ignore=DL4006
RUN /usr/sbin/named -V 2>&1 | head -5

# Create runtime directories via init
RUN /usr/local/bin/init --setup-dirs

# Clean up build-only tools (won't be in FROM scratch anyway). Kept as its
# own step (not merged with the verify/setup-dirs RUNs above) so a failure
# in any one of the three points at exactly which failed.
# hadolint ignore=DL3059
RUN rm -rf /var/cache/apk/* /usr/lib/pkgconfig /usr/lib/cmake

# Collect exactly the shared objects that ship, instead of copying /lib and
# /usr/lib whole into the final stage. The wholesale copy carried whatever apk
# had installed -- including /lib/apk/db/installed and libapk.so, a package
# inventory and the package manager's own library, in an image that advertises
# having neither.
#
# lddtree -l prints the binary, its transitive dependencies, symlinks together
# with their targets, and the real loader for the architecture being built, so
# nothing here hardcodes ld-musl-x86_64.so.1 and arm64 keeps working.
#
# The "Not found" guard is not decoration: lddtree reports a missing library on
# stderr and still EXITS 0. Without it, a library that stops being installed --
# jemalloc now comes from the builder rather than from apk, exactly this case --
# would ship a closure with a hole in it, and the failure would only surface at
# container start.
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache lddtree \
 && mkdir -p /rootfs \
 && lddtree -l /usr/sbin/named /usr/bin/named-checkconf \
      > /tmp/closure.list 2> /tmp/closure.err \
 && if grep -q 'Not found' /tmp/closure.list /tmp/closure.err; then \
      echo "closure incomplete -- a dependency is missing from this stage:" >&2; \
      grep 'Not found' /tmp/closure.list /tmp/closure.err >&2; \
      exit 1; \
    fi \
 && sort -u /tmp/closure.list -o /tmp/closure.list \
 && tar -cf /tmp/closure.tar -T /tmp/closure.list \
 && tar -xf /tmp/closure.tar -C /rootfs \
 && rm -f /tmp/closure.list /tmp/closure.err /tmp/closure.tar

# OpenSSL providers are opened with dlopen, so no dependency closure lists
# them. Kept deliberately: DNSSEC only needs the built-in default provider
# today, but a missing provider fails at first validation, not at startup.
# The 1.x engines (engines-3/) and the BIND query plugins (/usr/lib/bind/,
# no `plugin` clause in our named.conf) are left out on purpose.
RUN mkdir -p /rootfs/usr/lib \
 && cp -a /usr/lib/ossl-modules /rootfs/usr/lib/

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

# 3. Runtime closure: loader, shared libraries and their symlinks, resolved
#    at build time by lddtree in the prep stage -- not /lib and /usr/lib whole
COPY --link --from=prep /rootfs/ /

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
