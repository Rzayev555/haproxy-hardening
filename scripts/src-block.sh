#!/bin/bash
# src-block.sh - reject IPs at TCP accept time (before TLS), without reloading HAProxy.
#
#   sudo ./src-block.sh 203.0.113.7 [198.51.100.0/24 ...]
#
# First run: creates the list and adds two lines after the first "bind ... ssl" of the
# given frontend (FRONTEND env, default first frontend), validates, rolls back on error.
# Later runs: appends to the list AND pushes the entries into the running process
# through the runtime API - effective immediately, no reload.
#
# Note: this matches the TCP peer. Clients behind a CDN must be blocked at the CDN
# (or by real-IP ACLs - see haproxy-guard).
set -u
CFG=${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}
L=/etc/haproxy/blocked_src.lst
SOCK=${HAPROXY_SOCK:-/run/haproxy/admin.sock}

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
[ $# -ge 1 ] || { echo "usage: $0 <ip|cidr> ..."; exit 1; }

public() { python3 -c "import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1], strict=False); sys.exit(1 if (n.is_private or n.is_loopback) else 0)" "$1" 2>/dev/null; }
for ip in "$@"; do public "$ip" || { echo "'$ip' is not a public address - refusing"; exit 1; }; done

rt() { python3 -c "import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall((sys.argv[2]+'\n').encode());print(s.makefile().read().strip())" "$SOCK" "$1"; }

touch "$L"; chmod 644 "$L"
for ip in "$@"; do grep -qxF "$ip" "$L" || echo "$ip" >> "$L"; done

if grep -q "blocked_src.lst" "$CFG"; then
    for ip in "$@"; do r=$(rt "add acl $L $ip"); echo "  $ip ${r:-added}"; done
    exit 0
fi

BK="$CFG.bak-$(date +%F-%H%M%S)"
cp -a "$CFG" "$BK" || exit 1
python3 - "$CFG" "${FRONTEND:-}" <<'PY'
import re, sys
path, want = sys.argv[1], sys.argv[2]
t = open(path, encoding="latin-1").read()
pat = rf"^frontend\s+{re.escape(want)}\b" if want else r"^frontend\s+\S+"
m = re.search(pat, t, re.M)
if not m:
    sys.exit("frontend not found")
b = re.compile(r"^\s*bind\b[^\n]*\n", re.M).search(t, m.end())
if not b:
    sys.exit("no bind line")
block = ("\tacl bad_src src -f /etc/haproxy/blocked_src.lst\n"
         "\ttcp-request connection reject if bad_src\n")
open(path, "w", encoding="latin-1").write(t[:b.end()] + block + t[b.end():])
PY
if haproxy -c -q -f "$CFG"; then
    echo "rule added. reload once: systemctl reload haproxy   (rollback: cp -a $BK $CFG)"
else
    cp -a "$BK" "$CFG"; echo "haproxy -c failed - restored"; exit 1
fi
