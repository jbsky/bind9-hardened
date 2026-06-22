# BIND9 Hardened

[![Build](https://github.com/jbsky/bind9-hardened/actions/workflows/build-push.yml/badge.svg)](https://github.com/jbsky/bind9-hardened/actions/workflows/build-push.yml)
[![Docker Hub](https://img.shields.io/docker/v/jbsky/bind9-hardened?sort=semver&label=Docker%20Hub)](https://hub.docker.com/r/jbsky/bind9-hardened)
[![Hardening](https://img.shields.io/badge/hardening-platine-blueviolet)](https://github.com/jbsky/bind9-hardened#security--verification)

Image Docker ISC BIND 9.20.24 hardenee (FROM scratch, Go init, tini PID 1), optimisee pour deploiement VyOS Podman.

## Features

| Feature | Detail |
|---------|--------|
| FROM scratch | Zero shell, zero package manager, zero attack surface |
| Non-root | UID 5300 avec file capability (`cap_net_bind_service+ep`) |
| Compiler hardening | RELRO, PIE, SSP, FORTIFY_SOURCE, NX, stack-clash |
| Go static init | Healthcheck DNS query + named-checkconf validation |
| tini PID 1 | Signal forwarding + zombie reaping |
| 19 MB | vs ~150 MB image Ubuntu upstream |
| DNSSEC validation | Trust anchors compiles dans le binaire |

## Image

| Registry | Tag | Taille |
|----------|-----|--------|
| `docker.io/jbsky/bind9-hardened` | `9.20.24` | 19 MB |
| `ghcr.io/jbsky/bind9-hardened` | `9.20.24` | 19 MB |

## Usage rapide

```bash
docker run -d --name bind9 \
  --cap-add NET_BIND_SERVICE \
  -v /path/to/config:/etc/bind \
  -v /path/to/cache:/var/cache/bind \
  -p 53:53/udp -p 53:53/tcp \
  jbsky/bind9-hardened:9.20.24
```

## Configuration

| Variable d'env | Default | Description |
|---------------|---------|-------------|
| `NAMED_CONF` | `/etc/bind/named.conf` | Chemin du fichier de config |
| `TZ` | `UTC` | Timezone |

## Healthcheck

Le Go init effectue une **requete DNS UDP reelle** vers `127.0.0.1:53` (CH TXT version.bind). Contrairement a un TCP connect, cela prouve que le pipeline DNS complet fonctionne.

Accepte toute reponse DNS valide (QR=1), meme REFUSED (quand `version "not disclosed"` est configure).

## Architecture du repo

```
bind9-hardened/
├── Dockerfile          # Multi-stage 4 stages (builder → gobuilder → prep → scratch)
├── go.mod + init.go    # Go static init (healthcheck DNS + checkconf + entrypoint)
└── .dockerignore
```

## Build multi-stage

```
Stage 1: builder      → Compile ISC BIND 9.20.24 from source (autoconf, hardening flags)
Stage 2: gobuilder    → CGO_ENABLED=0 Go static init binary
Stage 3: prep         → Runtime libs + tini + user 5300 + setcap cap_net_bind_service
Stage 4: FROM scratch → Assemblage final (named + named-checkconf + init + tini = 19 MB)
```

### Configure flags

```
--prefix=/usr --sysconfdir=/etc/bind --localstatedir=/var
--with-openssl --with-libxml2 --with-json-c --with-zlib --with-jemalloc
--disable-doh --disable-static
--without-gssapi --without-libidn2 --without-readline --without-cmocka
```

## Deploiement VyOS

```
set container name bind9 image docker.io/jbsky/bind9-hardened:9.20.24
set container name bind9 capability net-bind-service
set container name bind9 network bind9 address 172.20.2.10
set container name bind9 volume bind-conf source /config/containers/bind9
set container name bind9 volume bind-conf destination /etc/bind
set container name bind9 volume bind-cache source /config/containers/bind9-cache
set container name bind9 volume bind-cache destination /var/cache/bind
```

## Security & Verification

```bash
# Verifier la signature cosign (OIDC keyless)
cosign verify ghcr.io/jbsky/bind9-hardened:9.20.24 \
  --certificate-identity-regexp '^https://github.com/jbsky/bind9-hardened/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Licence

MPL-2.0 (ISC BIND) / MIT (init.go)
