#!/usr/bin/env python3
"""
secret_scanner.py - Find secrets accidentally committed in a git repository.

Usage:
    python secret_scanner.py [repo_path] [options]

Examples:
    python secret_scanner.py .
    python secret_scanner.py /path/to/repo --history
    python secret_scanner.py . --output results.json
    python secret_scanner.py . --entropy 4.0
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# Secret patterns (regex, label, severity)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    # Cloud providers
    ("AWS Access Key ID",          r"AKIA[0-9A-Z]{16}",                              "HIGH"),
    ("AWS Secret Access Key",      r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "HIGH"),
    ("GCP API Key",                r"AIza[0-9A-Za-z\-_]{35}",                        "HIGH"),
    ("Azure Storage Key",          r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "HIGH"),

    # Version control / CI tokens
    ("GitHub Personal Token",      r"ghp_[0-9a-zA-Z]{36}",                           "HIGH"),
    ("GitHub OAuth Token",         r"gho_[0-9a-zA-Z]{36}",                           "HIGH"),
    ("GitHub Actions Token",       r"ghs_[0-9a-zA-Z]{36}",                           "HIGH"),
    ("GitHub Refresh Token",       r"ghr_[0-9a-zA-Z]{36}",                           "HIGH"),
    ("GitLab Personal Token",      r"glpat-[0-9a-zA-Z\-_]{20}",                      "HIGH"),

    # Payment / finance
    ("Stripe Secret Key",          r"sk_live_[0-9a-zA-Z]{24,}",                      "HIGH"),
    ("Stripe Publishable Key",     r"pk_live_[0-9a-zA-Z]{24,}",                      "MEDIUM"),
    ("PayPal BraintreeToken",      r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "HIGH"),
    ("Square Access Token",        r"sq0atp-[0-9A-Za-z\-_]{22}",                     "HIGH"),

    # Communication services
    ("Twilio API Key",             r"SK[0-9a-fA-F]{32}",                              "HIGH"),
    ("Twilio Account SID",        r"AC[0-9a-fA-F]{32}",                              "MEDIUM"),
    ("SendGrid API Key",           r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",   "HIGH"),
    ("Mailgun API Key",            r"key-[0-9a-zA-Z]{32}",                            "HIGH"),

    # Social / third-party
    ("Slack Token",                r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",               "HIGH"),
    ("Slack Webhook",              r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+", "MEDIUM"),
    ("Heroku API Key",             r"[hH]eroku.{0,20}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "HIGH"),
    ("Firebase URL",               r"https://[a-z0-9-]+\.firebaseio\.com",            "LOW"),
    ("NPM Auth Token",             r"//registry\.npmjs\.org/:_authToken=[0-9a-fA-F\-]{36}", "HIGH"),

    # Cryptographic / auth
    ("RSA Private Key",            r"-----BEGIN RSA PRIVATE KEY-----",                "HIGH"),
    ("EC Private Key",             r"-----BEGIN EC PRIVATE KEY-----",                 "HIGH"),
    ("PGP Private Key",            r"-----BEGIN PGP PRIVATE KEY BLOCK-----",          "HIGH"),
    ("OpenSSH Private Key",        r"-----BEGIN OPENSSH PRIVATE KEY-----",            "HIGH"),
    ("JWT Token",                  r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*", "MEDIUM"),

    # Database / connection strings
    ("Generic DB URL (with creds)",r"(?i)(postgres|mysql|mongodb|redis|mssql)://[^:]+:[^@]+@[^\s\"']+", "HIGH"),
    ("Generic Password Field",     r"(?i)(password|passwd|pwd|secret|token|api_?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "MEDIUM"),
    ("Basic Auth in URL",          r"https?://[^:@\s]+:[^:@\s]+@[^\s]+",             "MEDIUM"),
]

# File extensions to skip entirely
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".tar", ".gz",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".wasm",
    ".lock", ".sum",  # dependency lock files — very noisy
    ".min.js", ".min.css",
}

# Paths/directories to ignore
SKIP_PATHS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "vendor", "third_party",
}

# Lines likely to be false positives
FALSE_POSITIVE_PATTERNS = [
    re.compile(r"(?i)example|placeholder|your[_-]?key|dummy|fake|test|sample|xxx+|<.*>|\$\{"),
]


# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


HIGH_ENTROPY_RE = re.compile(
    r"""(?x)
    (?:
        [0-9a-fA-F]{40,}   |   # hex strings (SHA-like)
        [A-Za-z0-9+/]{32,}=*   # base64-like
    )
    """
)

def find_high_entropy_strings(line: str, threshold: float = 4.5) -> list[str]:
    candidates = []
    for match in HIGH_ENTROPY_RE.finditer(line):
        token = match.group()
        if len(token) >= 20 and shannon_entropy(token) >= threshold:
            candidates.append(token)
    return candidates


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule:     str
    severity: str
    file:     str
    line_no:  int
    line:     str
    match:    str
    commit:   str = ""

    def key(self) -> str:
        return f"{self.rule}:{self.file}:{self.match}"


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class SecretScanner:
    def __init__(self, repo_path: str, entropy_threshold: float = 4.5, scan_history: bool = False):
        self.repo_path = Path(repo_path).resolve()
        self.entropy_threshold = entropy_threshold
        self.scan_history = scan_history
        self._compiled = [(label, re.compile(pattern), sev) for label, pattern, sev in SECRET_PATTERNS]
        self._seen: set[str] = set()

    # ------------------------------------------------------------------
    # File helpers
    # ------------------------------------------------------------------

    def _should_skip_path(self, path: Path) -> bool:
        parts = set(path.parts)
        if parts & SKIP_PATHS:
            return True
        suffix = "".join(path.suffixes).lower()
        return suffix in SKIP_EXTENSIONS or path.suffix.lower() in SKIP_EXTENSIONS

    def _iter_repo_files(self) -> Iterator[Path]:
        for root, dirs, files in os.walk(self.repo_path):
            root_path = Path(root)
            dirs[:] = [d for d in dirs if d not in SKIP_PATHS]
            for fname in files:
                fpath = root_path / fname
                if not self._should_skip_path(fpath.relative_to(self.repo_path)):
                    yield fpath

    # ------------------------------------------------------------------
    # Pattern matching
    # ------------------------------------------------------------------

    def _is_false_positive(self, text: str) -> bool:
        return any(p.search(text) for p in FALSE_POSITIVE_PATTERNS)

    def _scan_line(self, line: str, file_str: str, line_no: int, commit: str = "") -> list[Finding]:
        findings: list[Finding] = []
        stripped = line.strip()

        if self._is_false_positive(stripped):
            return findings

        # Regex-based patterns
        for label, pattern, severity in self._compiled:
            for m in pattern.finditer(stripped):
                finding = Finding(
                    rule=label, severity=severity,
                    file=file_str, line_no=line_no,
                    line=stripped[:200], match=m.group()[:120],
                    commit=commit,
                )
                key = finding.key()
                if key not in self._seen:
                    self._seen.add(key)
                    findings.append(finding)

        # Entropy-based detection
        for token in find_high_entropy_strings(stripped, self.entropy_threshold):
            if not self._is_false_positive(token):
                finding = Finding(
                    rule="High-Entropy String", severity="MEDIUM",
                    file=file_str, line_no=line_no,
                    line=stripped[:200], match=token[:120],
                    commit=commit,
                )
                key = finding.key()
                if key not in self._seen:
                    self._seen.add(key)
                    findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # Working-tree scan
    # ------------------------------------------------------------------

    def scan_files(self) -> list[Finding]:
        all_findings: list[Finding] = []
        for fpath in self._iter_repo_files():
            rel = str(fpath.relative_to(self.repo_path))
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                all_findings.extend(self._scan_line(line, rel, i))
        return all_findings

    # ------------------------------------------------------------------
    # Git history scan
    # ------------------------------------------------------------------

    def _git(self, *args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.repo_path,
            capture_output=True, text=True,
        )
        return result.stdout

    def _iter_commits(self) -> list[str]:
        output = self._git("log", "--format=%H", "--all")
        return [h.strip() for h in output.splitlines() if h.strip()]

    def scan_history(self) -> list[Finding]:
        all_findings: list[Finding] = []
        commits = self._iter_commits()
        total = len(commits)
        print(f"  Scanning {total} commits in history...", flush=True)
        for idx, commit in enumerate(commits, start=1):
            if idx % 50 == 0:
                print(f"  [{idx}/{total}]", flush=True)
            diff = self._git("show", "--unified=0", "--no-color", commit)
            current_file = ""
            line_no = 0
            for line in diff.splitlines():
                if line.startswith("+++ b/"):
                    current_file = line[6:]
                    line_no = 0
                elif line.startswith("@@ "):
                    m = re.search(r"\+(\d+)", line)
                    line_no = int(m.group(1)) if m else 0
                elif line.startswith("+") and not line.startswith("+++"):
                    line_no += 1
                    if current_file:
                        rel = current_file
                        ext = Path(current_file).suffix.lower()
                        if ext not in SKIP_EXTENSIONS:
                            all_findings.extend(
                                self._scan_line(line[1:], rel, line_no, commit=commit[:12])
                            )
                else:
                    line_no += 1
        return all_findings

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        print(f"\n[*] Scanning working tree: {self.repo_path}")
        findings.extend(self.scan_files())

        if self.scan_history:
            print("[*] Scanning git history...")
            findings.extend(self.scan_history())

        return findings


# ---------------------------------------------------------------------------
# Output / reporting
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_COLOR = {
    "HIGH":   "\033[91m",  # red
    "MEDIUM": "\033[93m",  # yellow
    "LOW":    "\033[94m",  # blue
}
RESET = "\033[0m"

def _color(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if sys.stdout.isatty() else text


def print_report(findings: list[Finding]) -> None:
    if not findings:
        print("\n[+] No secrets found.")
        return

    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file))

    counts: dict[str, int] = defaultdict(int)
    for f in sorted_findings:
        counts[f.severity] += 1

    print(f"\n{'='*70}")
    print(f"  FINDINGS SUMMARY: {len(findings)} potential secret(s) found")
    print(f"{'='*70}")
    for sev in ("HIGH", "MEDIUM", "LOW"):
        if counts[sev]:
            label = _color(f"{sev:<8}", SEVERITY_COLOR[sev])
            print(f"  {label} {counts[sev]}")
    print(f"{'='*70}\n")

    for f in sorted_findings:
        sev_label = _color(f"[{f.severity}]", SEVERITY_COLOR.get(f.severity, ""))
        print(f"{sev_label} {f.rule}")
        print(f"  File   : {f.file}:{f.line_no}")
        if f.commit:
            print(f"  Commit : {f.commit}")
        print(f"  Match  : {f.match}")
        print(f"  Line   : {f.line}")
        print()


def write_json(findings: list[Finding], output_path: str) -> None:
    data = [asdict(f) for f in findings]
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"[+] Results written to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a git repository for accidentally committed secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("repo", nargs="?", default=".", help="Path to the git repository (default: .)")
    parser.add_argument("--history", action="store_true", help="Also scan the full git commit history")
    parser.add_argument("--entropy", type=float, default=4.5, metavar="THRESHOLD",
                        help="Shannon entropy threshold for high-entropy detection (default: 4.5)")
    parser.add_argument("--output", metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--severity", choices=["HIGH", "MEDIUM", "LOW"], default=None,
                        help="Only show findings at this severity level or higher")
    args = parser.parse_args()

    repo_path = Path(args.repo).resolve()
    if not (repo_path / ".git").exists():
        print(f"[!] Warning: {repo_path} does not appear to be a git repository root.")

    scanner = SecretScanner(
        repo_path=str(repo_path),
        entropy_threshold=args.entropy,
        scan_history=args.history,
    )

    findings = scanner.run()

    # Filter by severity if requested
    if args.severity:
        cutoff = SEVERITY_ORDER[args.severity]
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 9) <= cutoff]

    print_report(findings)

    if args.output:
        write_json(findings, args.output)

    # Exit code 1 if any HIGH findings, 0 otherwise (useful in CI)
    return 1 if any(f.severity == "HIGH" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
