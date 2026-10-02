# saumyaprakashrana_cybersecurity

A collection of Python security tools for reconnaissance and repository hygiene.

## Tools

| Tool | Purpose |
|------|---------|
| [`auto-recon.py`](auto-recon.py) | Discover subdomains for a target domain |
| [`secret_scanner.py`](secret_scanner.py) | Scan a git repo for accidentally committed secrets |

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## auto-recon.py

Subdomain enumeration using passive sources and optional DNS brute-force.

**Sources**
- Certificate Transparency logs ([crt.sh](https://crt.sh))
- HackerTarget passive DNS API
- Optional DNS brute-force with a built-in or custom wordlist

**Usage**

```bash
python auto-recon.py -d example.com
python auto-recon.py -d example.com --brute
python auto-recon.py -d example.com --brute --wordlist wordlist.txt
python auto-recon.py -d example.com --passive-only
python auto-recon.py -d example.com -o results.csv
```

**Options**

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain (required) |
| `--brute` | Enable DNS brute-force |
| `--wordlist` | Custom wordlist file for brute-force |
| `--passive-only` | Use passive sources only |
| `--threads` | Concurrent threads (default: 50) |
| `-o`, `--output` | Save results to CSV |
| `--no-resolve` | Skip live-host DNS verification |

## secret_scanner.py

Scans a git repository for leaked credentials using regex patterns and entropy analysis.

**Detects**
- Cloud keys (AWS, GCP, Azure)
- Version-control and CI tokens (GitHub, GitLab)
- Payment and messaging API keys (Stripe, Slack, Twilio, etc.)
- High-entropy strings that may indicate secrets

**Usage**

```bash
python secret_scanner.py .
python secret_scanner.py /path/to/repo --history
python secret_scanner.py . --output results.json
python secret_scanner.py . --entropy 4.0
python secret_scanner.py . --severity HIGH
```

**Options**

| Flag | Description |
|------|-------------|
| `repo` | Path to the git repository (default: `.`) |
| `--history` | Scan full git commit history |
| `--entropy` | Entropy threshold for detection (default: 4.5) |
| `--output` | Write JSON report to file |
| `--severity` | Filter by severity: `HIGH`, `MEDIUM`, or `LOW` |

## Legal notice

Use these tools only on systems and repositories you own or have explicit permission to test. Unauthorized scanning or access may be illegal.
