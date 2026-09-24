# WRAITH — DNS Passive Recon Scanner

> Passive DNS reconnaissance for IP ranges. No port scanning. No active probing. Just DNS.

---

## What is WRAITH?

**WRAITH** walks through an IP range, queries reverse DNS (PTR records) for every address, then validates each discovered hostname resolves back to the same IP (Forward-confirmed reverse DNS check).

Servers that moved, misconfigured mail relays, hijacked PTR records, and zone transfer exposure - all surface quietly, without touching a single open port.

The name comes from Scottish folklore: a wraith appears silently, leaves no trace, and sees what is hidden. That's the idea.

---

## What it finds

| Finding | Description |
|---------|-------------|
| **PTR records** | Hostnames mapped to IPs in the scanned range |
| **FCrDNS MATCH** | Hostname resolves back to the same IP - correctly configured |
| **FCrDNS MISMATCH** | Hostname resolves to a *different* IP - server moved, broken relay, misconfigured record |
| **Unique domains** | Base domains extracted from discovered hostnames |
| **Wildcard PTR** | Detected before scan — warns if all responses may be synthetic |
| **AXFR exposure** | (`-X`) Nameservers that allow full zone transfer, leaking all DNS records |

---

## Usage

```bash
# Scan a /24
bash wraith.sh 192.168.1.0/24

# Scan a specific range
bash wraith.sh 192.168.1.1 192.168.1.90

# Custom resolver, 4 workers
bash wraith.sh 10.0.0.0/24 -t 4 -r 8.8.8.8

# Full scan with zone transfer check
bash wraith.sh 192.168.1.0/24 -X

# Resume a previous scan
bash wraith.sh 192.168.1.0/24 -R
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t N` | Parallel workers per phase | `3` |
| `-T N` | Timeout per DNS query (seconds) | `3` |
| `-r IP` | Custom DNS resolver | system |
| `-o dir` | Output base directory | `./wraith_scans` |
| `-R` | Resume last scan of the same range | - |
| `-X` | Phase 3: AXFR zone transfer ⚠️ | disabled |

---

## Output

Each scan saves to a timestamped directory - previous scans are never overwritten.

```
wraith_scans/192.168.1.1-254_20260917-2100/
├── ips.txt        - scanned IP list
├── ptrs.tsv       - IP → PTR hostname
├── hosts.tsv      - IP → hostname → A-record → MATCH / MISMATCH / NORESOLVE
├── domains.txt    - unique base domains discovered
├── summary.txt    - scan metadata
└── axfr_*.txt     - zone dumps (only if -X and transfer was allowed)
```

### Example hosts.tsv

```
192.168.1.111    smtp1.test-data.net      192.168.1.11    MATCH
192.168.12.92    smtp.test.com            192.168.12.92   MISMATCH
192.168.12.111   test.com             -                   NORESOLVE
```

---

## How it works

```
Phase 1 - PTR queries
  For each IP in range → dig -x IP → PTR hostname
  Findings stream live to the terminal

Phase 2 - FCrDNS validation
  For each discovered hostname → dig A hostname → compare to original IP
  MISMATCH = hostname points elsewhere (real finding)
  NORESOLVE = no forward record (ISP noise, silently counted)

Phase 3 - AXFR (optional, -X)
  For each discovered domain → query NS records → attempt AXFR
  Successful transfer = full zone saved to axfr_domain.txt
```

---

## Requirements

| Platform | Install |
|----------|---------|
| **Termux (Android)** | `pkg install dnsutils` |
| **Debian / Ubuntu / Kali** | `apt install dnsutils` |
| **CentOS / RHEL / Fedora** | `dnf install bind-utils` |
| **macOS** | `brew install bind` |

Requires: `bash 5.x` · `dig` · `awk` · `sed`

---

## Notes

**Is it passive?**  
PTR and A queries go through your resolver to the target's authoritative nameserver — your IP (or your resolver's IP) appears in their DNS logs. No TCP connections are opened to target services. Most methodologies classify this as passive or semi-passive recon.

**AXFR (`-X`)**  
Zone transfer requests are logged by the target's nameserver. This flag is disabled by default. Only use it on networks you are authorized to test.

**Termux / Android**  
Keep `-t` at 3–5. Android 12+ limits background child processes system-wide; higher values may cause silent kills.

---

## Author

**romandoro** · [github.com/romandoro/WRAITH](https://github.com/romandoro/WRAITH)
