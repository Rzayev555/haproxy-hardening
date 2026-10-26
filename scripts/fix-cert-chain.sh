#!/bin/bash
# fix-cert-chain.sh - insert a missing intermediate certificate into an HAProxy PEM bundle.
#
# Symptom this fixes: browsers on the internet work, but clients that cannot fetch the
# intermediate themselves (isolated networks, Java, curl, older Windows/schannel) hang or
# fail the TLS handshake.
#
#   sudo ./fix-cert-chain.sh <bundle.pem> <intermediate.pem> [sha256-fingerprint]
#
# Backs up the bundle, places the intermediate right after the leaf, verifies the chain
# with openssl, runs haproxy -c and rolls back on any failure. Does NOT reload.
set -u
PEM=${1:?bundle pem}
INT=${2:?intermediate pem}
FP_EXPECTED=${3:-}
CFG=${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}

subjects() {
    local t; t=$(mktemp)
    sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$1" > "$t"
    openssl crl2pkcs7 -nocrl -certfile "$t" | openssl pkcs7 -print_certs -noout | grep subject
    rm -f "$t"
}

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
[ -f "$PEM" ] && [ -f "$INT" ] || { echo "file not found"; exit 1; }

if [ -n "$FP_EXPECTED" ]; then
    FP=$(openssl x509 -in "$INT" -noout -fingerprint -sha256 | cut -d= -f2)
    [ "$FP" = "$FP_EXPECTED" ] || { echo "intermediate fingerprint mismatch: $FP"; exit 1; }
    echo "OK: intermediate fingerprint matches"
fi

ISUBJ=$(openssl x509 -in "$INT" -noout -subject)
if subjects "$PEM" | grep -qF "${ISUBJ#subject=}"; then
    echo "intermediate already present - nothing to do"; exit 0
fi

BK="$PEM.bak-$(date +%F-%H%M%S)"
cp -a "$PEM" "$BK" || exit 1
echo "backup: $BK"

TMP=$(mktemp "$(dirname "$PEM")/.pemfix.XXXXXX")
awk -v ic="$INT" '
  { print }
  /-----END CERTIFICATE-----/ && !done { while ((getline l < ic) > 0) print l; done=1 }
' "$PEM" > "$TMP"
chmod --reference="$PEM" "$TMP"; chown --reference="$PEM" "$TMP"

echo "certificates in the new bundle:"
subjects "$TMP" | sed 's/^/  /'

LEAF=$(mktemp); CHAIN=$(mktemp)
awk '/BEGIN CERT/{n++} n==1' "$TMP" | sed -n '/BEGIN/,/END/p' > "$LEAF"
awk '/BEGIN CERT/{n++} n>=2' "$TMP" | sed -n '/BEGIN CERT/,/END CERT/p' > "$CHAIN"
if ! openssl verify -untrusted "$CHAIN" "$LEAF" >/dev/null 2>&1; then
    echo "chain does not verify - NOT applied"; rm -f "$TMP" "$LEAF" "$CHAIN"; exit 1
fi
rm -f "$LEAF" "$CHAIN"
echo "OK: chain verifies"

mv "$TMP" "$PEM"
if haproxy -c -q -f "$CFG"; then
    echo "OK: haproxy -c passed. NOT reloaded."
    echo "reload:   systemctl reload haproxy"
    echo "rollback: cp -a $BK $PEM && systemctl reload haproxy"
else
    cp -a "$BK" "$PEM"
    echo "haproxy -c failed - bundle restored"; exit 1
fi
