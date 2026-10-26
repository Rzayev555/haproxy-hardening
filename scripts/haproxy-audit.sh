#!/bin/bash
# haproxy-audit.sh - read-only security/operations audit of an HAProxy host.
# Changes nothing. Exit code = number of FAIL findings.
#   sudo ./haproxy-audit.sh [/etc/haproxy/haproxy.cfg]
set -u
CFG=${1:-/etc/haproxy/haproxy.cfg}
FAILS=0; WARNS=0
if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[1m'; N=$'\e[0m'; else R= Y= G= B= N=; fi
pass() { printf '%s[PASS]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$Y" "$N" "$*"; WARNS=$((WARNS + 1)); }
fail() { printf '%s[FAIL]%s %s\n' "$R" "$N" "$*"; FAILS=$((FAILS + 1)); }
hdr()  { printf '\n%s== %s%s\n' "$B" "$*" "$N"; }

[ -r "$CFG" ] || { echo "cannot read $CFG (run with sudo?)"; exit 1; }
# strip comments once; everything below greps this
C=$(sed -e 's/#.*$//' "$CFG")

# seconds from an HAProxy time value (10s, 5m, 1h, 3000 = ms)
to_sec() {
    local v=$1
    case $v in
        *ms) echo $(( ${v%ms} / 1000 )) ;;
        *s)  echo "${v%s}" ;;
        *m)  echo $(( ${v%m} * 60 )) ;;
        *h)  echo $(( ${v%h} * 3600 )) ;;
        *d)  echo $(( ${v%d} * 86400 )) ;;
        *)   echo $(( v / 1000 )) ;;
    esac
}

hdr "version"
V=$(haproxy -v 2>/dev/null | head -1)
echo "$V"
haproxy -c -q -f "$CFG" >/dev/null 2>&1 && pass "config is valid (haproxy -c)" || fail "haproxy -c reports errors"

hdr "slow-client protection (Slowloris)"
HR=$(echo "$C" | awk '$1=="timeout" && $2=="http-request" {print $3}' | head -1)
if [ -z "$HR" ]; then
    fail "timeout http-request not set - a client can hold a connection open forever sending headers slowly"
elif [ "$(to_sec "$HR")" -gt 30 ]; then
    fail "timeout http-request = $HR (recommend 10s-15s)"
else
    pass "timeout http-request = $HR"
fi
KA=$(echo "$C" | awk '$1=="timeout" && $2=="http-keep-alive" {print $3}' | head -1)
[ -n "$KA" ] && pass "timeout http-keep-alive = $KA" || warn "timeout http-keep-alive not set (falls back to http-request)"
GLOBAL=$(echo "$C" | awk '/^[a-z]/{g=($1=="global")} g')
echo "$GLOBAL" | grep -qE '^\s*maxconn\s+[0-9]+' && pass "global maxconn is set" || warn "no global maxconn (derived from ulimit - can be huge or tiny)"

hdr "stats page"
if echo "$C" | grep -qE '^\s*stats\s+(enable|uri)'; then
    STATS_BIND=$(echo "$C" | awk '/^(listen|frontend)/{s=$0} /stats (enable|uri)/{print s}' | sort -u)
    echo "$STATS_BIND" | sed 's/^/  section: /'
    if echo "$C" | grep -qE 'stats\s+auth\s+\S+:(admin|password|123456|12345678|qwerty|haproxy|stats|changeme)\b'; then
        fail "stats auth uses a well-known weak password"
    fi
    echo "$C" | grep -qE 'stats\s+admin\s+if\s+TRUE' && fail "'stats admin if TRUE' - anyone who logs in can disable servers"
    # whole text of every section that serves stats
    SEC=$(echo "$C" | awk '/^[a-z]/{if (buf ~ /stats (enable|uri)/) printf "%s", buf; buf=""} {buf=buf $0 "\n"} END{if (buf ~ /stats (enable|uri)/) printf "%s", buf}')
    if echo "$SEC" | grep -qE '(http-request|tcp-request connection)\s+(deny|reject|allow|accept).*\bsrc\b' \
       || { echo "$SEC" | grep -qE '^\s*acl\s+\S+\s+src\b' && echo "$SEC" | grep -qE '(http-request|tcp-request connection)\s+(deny|reject|allow|accept)\s+(if|unless)'; } \
       || echo "$SEC" | grep -qE '^\s*bind\s+(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost|\[::1\])'; then
        pass "stats access restricted by source address"
    else
        fail "stats reachable from any source address"
    fi
    echo "$C" | grep -qE 'stats\s+hide-version' && pass "stats hide-version" || warn "stats page shows HAProxy version"
else
    pass "no stats page configured"
fi

hdr "TLS"
if echo "$C" | grep -qE 'ssl-default-bind-options.*ssl-min-ver\s+TLSv1\.[23]'; then
    pass "ssl-min-ver TLSv1.2+ set globally"
elif echo "$C" | grep -qE '^\s*bind\s.*\bssl\b'; then
    v=$(haproxy -vv 2>/dev/null | awk '/^HAProxy version/{print $3}')
    warn "no global ssl-min-ver (HAProxy $v default may still allow TLS 1.0/1.1 depending on OpenSSL)"
fi
for pem in $(echo "$C" | grep -oE 'crt\s+\S+' | awk '{print $2}' | sort -u); do
    [ -d "$pem" ] && files=$(ls "$pem"/*.pem 2>/dev/null) || files=$pem
    for f in $files; do
        [ -r "$f" ] || { warn "cannot read $f"; continue; }
        end=$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | cut -d= -f2)
        cn=$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
        days=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
        if [ "$days" -lt 0 ]; then fail "$f ($cn) EXPIRED $end"
        elif [ "$days" -lt 14 ]; then fail "$f ($cn) expires in $days days"
        elif [ "$days" -lt 30 ]; then warn "$f ($cn) expires in $days days"
        else pass "$f ($cn) valid for $days days"; fi
        n=$(grep -c 'BEGIN CERTIFICATE' "$f")
        if [ "$n" -lt 2 ]; then
            warn "$f contains only the leaf certificate - clients without AIA fetching (no internet, Java, curl) will fail"
        else
            t=$(mktemp); l=$(mktemp)
            awk '/BEGIN CERT/{n++} n==1' "$f" | sed -n '/BEGIN/,/END/p' > "$l"
            awk '/BEGIN CERT/{n++} n>=2' "$f" | sed -n '/BEGIN CERT/,/END CERT/p' > "$t"
            openssl verify -untrusted "$t" "$l" >/dev/null 2>&1 && pass "$f chain verifies" \
                || fail "$f chain does not verify (missing/wrong intermediate?)"
            rm -f "$t" "$l"
        fi
    done
done

hdr "information leakage"
echo "$C" | grep -qE 'http-response\s+del-header\s+Server' && pass "Server header removed" || warn "backend Server header passed to clients"
echo "$C" | grep -qE 'http-response\s+del-header\s+X-Powered-By' && pass "X-Powered-By removed" || warn "X-Powered-By passed to clients (leaks PHP/ASP.NET versions)"

hdr "logging"
if [ -f /etc/logrotate.d/haproxy ]; then
    if grep -q 'systemctl reload rsyslog' /etc/logrotate.d/haproxy && ! systemctl cat rsyslog 2>/dev/null | grep -q ExecReload; then
        fail "logrotate runs 'systemctl reload rsyslog' but rsyslog has no ExecReload - rsyslog keeps writing to the ROTATED file (use /usr/lib/rsyslog/rsyslog-rotate)"
    else
        pass "logrotate postrotate looks fine"
    fi
fi
LOG=/var/log/haproxy.log
if [ -f "$LOG" ]; then
    newest=$(ls -t /var/log/haproxy.log* 2>/dev/null | head -1)
    if [ "$newest" != "$LOG" ]; then
        fail "newest HAProxy log is $newest, not $LOG - logs go to a rotated file"
    else
        pass "$LOG is the active log"
    fi
fi
if [ -d /etc/rsyslog.d ]; then
    dup=$(grep -rlE 'local0' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | wc -l)
    [ "$dup" -gt 1 ] && warn "local0 is referenced in $dup rsyslog files - check for duplicated log lines"
fi

hdr "runtime / service"
echo "$C" | grep -qE 'stats\s+socket\s+\S+.*level\s+admin' && pass "runtime API socket (level admin) available" || warn "no admin runtime socket - no live ACL/map updates"
if [ -d /etc/needrestart ]; then
    if grep -rqsE 'haproxy|keepalived' /etc/needrestart/conf.d/ 2>/dev/null; then
        pass "needrestart has an override for haproxy/keepalived"
    else
        warn "needrestart may auto-restart haproxy/keepalived during unattended upgrades (VIP failover / dropped connections)"
    fi
fi
ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E '(0\.0\.0\.0|\*|\[::\]):' | sed 's/^/  listening: /'

hdr "summary"
printf '%s FAIL, %s WARN\n' "$FAILS" "$WARNS"
exit "$FAILS"
