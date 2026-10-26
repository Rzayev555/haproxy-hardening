<div align="center">

# 🔐 haproxy-hardening

**A field-tested checklist, audit script and config snippets for running HAProxy at the edge.**

[![ci](https://github.com/Rzayev555/haproxy-hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/Rzayev555/haproxy-hardening/actions/workflows/ci.yml)
![HAProxy](https://img.shields.io/badge/HAProxy-2.x%20|%203.x-106da9?logo=haproxy)
![Shell](https://img.shields.io/badge/bash-read--only%20audit-4EAA25?logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

Every item here came from a real production proxy, not from a vendor blog post. Each one either
broke something or would have.

## ⚡ Run the audit (read-only)

```bash
curl -fsSLO https://raw.githubusercontent.com/Rzayev555/haproxy-hardening/main/scripts/haproxy-audit.sh
sudo bash haproxy-audit.sh            # changes nothing; exit code = number of FAILs
```

```text
== slow-client protection (Slowloris)
[FAIL] timeout http-request = 55555s (recommend 10s-15s)
== stats page
[FAIL] stats auth uses a well-known weak password
[FAIL] 'stats admin if TRUE' - anyone who logs in can disable servers
[FAIL] stats reachable from any source address
== TLS
[FAIL] /etc/haproxy/certs/site.pem (*.example.com) expires in 10 days
[PASS] /etc/haproxy/certs/site.pem chain verifies
== logging
[FAIL] logrotate runs 'systemctl reload rsyslog' but rsyslog has no ExecReload -
       rsyslog keeps writing to the ROTATED file (use /usr/lib/rsyslog/rsyslog-rotate)
== summary
6 FAIL, 5 WARN
```
*(example output: findings from a real production proxy before hardening, hostnames anonymised)*

## ✅ The checklist

### 1. Slow clients (Slowloris)
- [ ] `timeout http-request 10s` — the time allowed to send the request **headers**. I have seen this
      set to `55555s` in production, which lets a single laptop hold thousands of sockets open.
- [ ] `timeout http-keep-alive` set explicitly.
- [ ] `option http-buffer-request` if you want the same limit on POST bodies.
- [ ] a global `maxconn` that your RAM can actually hold.

→ [`snippets/defaults-timeouts.cfg`](snippets/defaults-timeouts.cfg)

### 2. The stats page
- [ ] not bound to `0.0.0.0` / not reachable from the internet (scanners find `:8404/stats` within days)
- [ ] no default/weak password
- [ ] `stats admin` only for an ops subnet, **never** `if TRUE`
- [ ] `stats hide-version`

→ [`snippets/stats-locked.cfg`](snippets/stats-locked.cfg)

### 3. TLS
- [ ] `ssl-min-ver TLSv1.2` globally, modern ciphers
- [ ] **full chain in the PEM** (leaf + intermediates). Browsers on the internet quietly download a
      missing intermediate (AIA fetching), so the site *looks* fine. Clients on an isolated network, Java
      or curl will fail with nothing more than a generic handshake error.
      → [`scripts/fix-cert-chain.sh`](scripts/fix-cert-chain.sh)
- [ ] certificate expiry monitored (the audit fails below 14 days)

→ [`snippets/global-tls.cfg`](snippets/global-tls.cfg)

### 4. "TLS hangs, but only from building B"
Before you blame the firewall or SSL inspection, check **path MTU**. One network segment could reach
the proxy, but every 1500-byte packet was silently dropped, and so was ICMP *fragmentation needed*.
The TCP handshake and the small ClientHello succeeded. The server's certificate flight did not.
`tcpdump` showed SACK gaps and retransmits of exactly the large segments.
Fix: MSS clamping (`1360`) on the router. HTTPS started working within a minute.

```bash
tcpdump -ni any host <client> and port 443     # look for retransmits of full-size segments
ping -M do -s 1472 <proxy>                     # from the client side: does 1500 pass?
```

### 5. Logging that silently stops
- [ ] On Ubuntu 22.04+ `rsyslog.service` has **no `ExecReload`**, so a logrotate `postrotate` of
      `systemctl reload rsyslog || true` does nothing. rsyslog keeps writing into
      `haproxy.log-<date>` forever and `haproxy.log` stays empty. Use `/usr/lib/rsyslog/rsyslog-rotate`.
- [ ] `local0` handled in exactly one place. Otherwise every line is written twice, which on one host
      filled the root filesystem to 100%.
- [ ] log the **real client IP** when behind a CDN (`http-request capture`).

### 6. Unattended upgrades vs. HA pairs
- [ ] `needrestart` will happily restart `keepalived` during an unattended upgrade, which moves your
      VIP to the other node in the middle of the day. Pin it:
```bash
echo '$nrconf{override_rc}{qr(^(keepalived|haproxy)\.service$)} = 0;' > /etc/needrestart/conf.d/edge.conf
```

### 7. Hygiene
- [ ] drop `TRACE`, `PROPFIND`, WebDAV methods; deny `Host:` = bare IP
- [ ] internal tools (Zabbix, Grafana, Redmine…) behind source ACLs even if they have logins
- [ ] strip `Server`, `X-Powered-By`, `X-AspNet-Version`
- [ ] block scanners and brute force → **[haproxy-guard](https://github.com/Rzayev555/haproxy-guard)**

→ [`snippets/frontend-hygiene.cfg`](snippets/frontend-hygiene.cfg)

### 8. Change safety
Every script in this repo follows the same pattern, and so should yours:
**backup → edit by anchor text (never by line number) → `haproxy -c` → rollback on failure → reload explicitly.**

## 🧰 Scripts

| script | what it does |
|---|---|
| [`haproxy-audit.sh`](scripts/haproxy-audit.sh) | read-only audit: timeouts, stats exposure, weak creds, TLS version, cert expiry + chain, header leaks, logrotate/rsyslog bug, needrestart |
| [`fix-cert-chain.sh`](scripts/fix-cert-chain.sh) | inserts a missing intermediate after the leaf, verifies with `openssl verify`, `haproxy -c`, rollback |
| [`src-block.sh`](scripts/src-block.sh) | rejects IPs at TCP accept (pre-TLS); after the first run updates the live process via the runtime API, **no reload** |

## License

MIT
