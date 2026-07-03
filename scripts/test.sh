#!/usr/bin/env bash
# Smoke tests for bind9-hardened.
#
# Usage: scripts/test.sh [image] [udp-port]
#   image     Image to test (default: bind9-hardened:test)
#   udp-port  Host UDP port to publish container's :53 on (default: 15353)
#
# Starts a throwaway container with a minimal named.conf, exercises it from
# the host, then tears everything down. Requires docker + python3.
set -euo pipefail

IMAGE="${1:-bind9-hardened:test}"
PORT="${2:-15353}"
CONTAINER="bind9-smoketest-$$"
WORKDIR=$(mktemp -d)

PASS=0
FAIL=0

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run --rm -v "$WORKDIR:/data" alpine:3.21 rm -rf /data/cache >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

check() {
  local desc="$1"
  shift
  if "$@" >/tmp/bind9-test-out.$$ 2>&1; then
    echo "PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $desc"
    sed 's/^/    /' /tmp/bind9-test-out.$$
    FAIL=$((FAIL + 1))
  fi
  rm -f /tmp/bind9-test-out.$$
}

mkdir -p "$WORKDIR/conf" "$WORKDIR/cache" "$WORKDIR/bad-conf"

cat > "$WORKDIR/conf/named.conf" <<'EOF'
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { none; };
    recursion no;
    version "not disclosed";
};
EOF

cat > "$WORKDIR/bad-conf/named.conf" <<'EOF'
options {
    this is not valid bind syntax
};
EOF

# Container runs as UID 5300 -- the bind-mounted cache dir must be owned accordingly
docker run --rm -v "$WORKDIR/cache:/data" alpine:3.21 chown -R 5300:5300 /data

echo "=== bind9-hardened smoke tests ($IMAGE) ==="

docker run -d --name "$CONTAINER" \
  -v "$WORKDIR/conf:/etc/bind:ro" \
  -v "$WORKDIR/cache:/var/cache/bind" \
  -p "${PORT}:53/udp" \
  "$IMAGE" >/dev/null

check "container starts and stays running" \
  bash -c "sleep 2 && docker ps --filter name=^${CONTAINER}\$ --filter status=running --format '{{.Names}}' | grep -q ."

check "named-checkconf accepts the valid config" \
  docker exec "$CONTAINER" /usr/bin/named-checkconf /etc/bind/named.conf

check "named-checkconf rejects an invalid config" \
  bash -c "! docker run --rm --entrypoint /usr/bin/named-checkconf -v '$WORKDIR/bad-conf:/etc/bind:ro' '$IMAGE' /etc/bind/named.conf"

check "container reports healthy" \
  bash -c '
    for _ in $(seq 1 15); do
      status=$(docker inspect "$1" --format "{{.State.Health.Status}}" 2>/dev/null || true)
      [ "$status" = "healthy" ] && exit 0
      sleep 2
    done
    exit 1
  ' _ "$CONTAINER"

check "init --healthcheck exits 0 from inside the container" \
  docker exec "$CONTAINER" /usr/local/bin/init --healthcheck

check "DNS UDP query (CH TXT version.bind) gets a valid response" \
  python3 - "$PORT" <<'PYEOF'
import socket, struct, sys

port = int(sys.argv[1])
query = bytes([
    0xBE, 0x9D, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    7, ord('v'), ord('e'), ord('r'), ord('s'), ord('i'), ord('o'), ord('n'),
    4, ord('b'), ord('i'), ord('n'), ord('d'),
    0x00, 0x00, 0x10, 0x00, 0x03,
])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(query, ("127.0.0.1", port))
data, _ = sock.recvfrom(512)
resp_id, flags = struct.unpack(">HH", data[0:4])
assert resp_id == 0xBE9D, f"unexpected response ID: {resp_id:#04x}"
assert flags >> 15 == 1, f"QR bit not set: flags={flags:#04x}"
PYEOF

echo "=== $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
