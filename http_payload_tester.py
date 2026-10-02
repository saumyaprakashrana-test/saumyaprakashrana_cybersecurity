#!/usr/bin/env python3
"""
http_payload_tester.py — Send payloads from a file over HTTP and analyze responses.

Usage:
    python http_payload_tester.py --url "https://example.com/search?q={payload}" --payloads payloads.txt
    python http_payload_tester.py --url "https://example.com/api" --payloads payloads.txt --method POST --param q --inject body
    python http_payload_tester.py --url "https://example.com/" --payloads payloads.txt --inject path --match "error|syntax"
"""

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

try:
    import requests
except ImportError:
    print("Missing dependency: pip install requests", file=sys.stderr)
    sys.exit(1)

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

PLACEHOLDER = "{payload}"


@dataclass
class TestResult:
    index: int
    payload: str
    url: str
    method: str
    status_code: int | None
    response_time_ms: float
    content_length: int
    matched: bool
    match_detail: str
    error: str
    body_preview: str


def banner() -> None:
    print(
        f"""{CYAN}{BOLD}
  ██╗  ██╗████████╗████████╗██████╗     ██████╗  █████╗ ██╗   ██╗██╗      ██████╗  █████╗ ██████╗
  ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ██╔══██╗██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗██╔══██╗██╔══██╗
  ███████║   ██║      ██║   ██████╔╝    ██████╔╝███████║ ╚████╔╝ ██║     ██║   ██║███████║██║  ██║
  ██╔══██║   ██║      ██║   ██╔═══╝     ██╔═══╝ ██╔══██║  ╚██╔╝  ██║     ██║   ██║██╔══██║██║  ██║
  ██║  ██║   ██║      ██║   ██║         ██║     ██║  ██║   ██║   ███████╗╚██████╔╝██║  ██║██████╔╝
  ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝
                         HTTP Payload Tester{RESET}
"""
    )


def load_payloads(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"Payload file not found: {path}")

    payloads: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        payloads.append(line)

    if not payloads:
        raise ValueError(f"No payloads found in {path}")

    return payloads


def load_headers(path: Path | None) -> dict[str, str]:
    if path is None:
        return {"User-Agent": "http-payload-tester/1.0"}

    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return {"User-Agent": "http-payload-tester/1.0"}

    if path.suffix.lower() == ".json":
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Header JSON must be an object of key/value pairs.")
        return {str(k): str(v) for k, v in data.items()}

    headers: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"Invalid header line (expected 'Name: value'): {line}")
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def build_request(
    base_url: str,
    payload: str,
    method: str,
    inject: str,
    param: str | None,
) -> tuple[str, dict[str, Any] | None, dict[str, str] | None]:
    method = method.upper()
    extra_headers: dict[str, str] | None = None
    data: dict[str, Any] | None = None
    json_body: dict[str, Any] | None = None
    params: dict[str, str] | None = None

    if inject == "placeholder":
        if PLACEHOLDER not in base_url:
            raise ValueError(f"URL must contain {PLACEHOLDER} when --inject placeholder is used.")
        url = base_url.replace(PLACEHOLDER, payload)
        return url, None, None

    if inject == "path":
        url = urljoin(base_url.rstrip("/") + "/", payload.lstrip("/"))
        return url, None, None

    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {base_url}")

    if inject == "query":
        if not param:
            raise ValueError("--param is required for query injection.")
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = payload
        url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        return url, None, None

    if inject == "body":
        if not param:
            raise ValueError("--param is required for body injection.")
        url = urlunparse(parsed)
        if method in {"POST", "PUT", "PATCH"}:
            data = {param: payload}
        else:
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query[param] = payload
            url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        return url, data, None

    if inject == "json":
        if not param:
            raise ValueError("--param is required for json injection.")
        url = urlunparse(parsed)
        json_body = {param: payload}
        return url, json_body, None

    if inject == "header":
        if not param:
            raise ValueError("--param is required for header injection.")
        url = urlunparse(parsed)
        extra_headers = {param: payload}
        return url, None, extra_headers

    raise ValueError(f"Unsupported inject mode: {inject}")


def analyze_response(
    text: str,
    status_code: int,
    baseline_status: int | None,
    baseline_length: int | None,
    match_pattern: re.Pattern[str] | None,
    length_delta: int,
) -> tuple[bool, str]:
    reasons: list[str] = []

    if match_pattern and match_pattern.search(text):
        reasons.append("pattern match in body")

    if baseline_status is not None and status_code != baseline_status:
        reasons.append(f"status changed ({baseline_status} -> {status_code})")

    if baseline_length is not None and abs(len(text) - baseline_length) >= length_delta:
        diff = len(text) - baseline_length
        reasons.append(f"length delta {diff:+d} bytes")

    if reasons:
        return True, "; ".join(reasons)
    return False, ""


def send_payload(
    index: int,
    payload: str,
    args: argparse.Namespace,
    session: requests.Session,
    headers: dict[str, str],
    match_pattern: re.Pattern[str] | None,
    baseline_status: int | None,
    baseline_length: int | None,
) -> TestResult:
    try:
        url, body, extra_headers = build_request(
            args.url, payload, args.method, args.inject, args.param
        )
        req_headers = dict(headers)
        if extra_headers:
            req_headers.update(extra_headers)

        request_kwargs: dict[str, Any] = {
            "method": args.method.upper(),
            "url": url,
            "headers": req_headers,
            "timeout": args.timeout,
            "allow_redirects": args.follow_redirects,
            "verify": not args.insecure,
        }

        if isinstance(body, dict):
            if args.inject == "json":
                request_kwargs["json"] = body
            else:
                request_kwargs["data"] = body

        start = time.perf_counter()
        response = session.request(**request_kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000

        text = response.text
        matched, match_detail = analyze_response(
            text=text,
            status_code=response.status_code,
            baseline_status=baseline_status,
            baseline_length=baseline_length,
            match_pattern=match_pattern,
            length_delta=args.length_delta,
        )

        return TestResult(
            index=index,
            payload=payload,
            url=url,
            method=args.method.upper(),
            status_code=response.status_code,
            response_time_ms=round(elapsed_ms, 2),
            content_length=len(text),
            matched=matched,
            match_detail=match_detail,
            error="",
            body_preview=text[:args.preview],
        )
    except requests.RequestException as exc:
        return TestResult(
            index=index,
            payload=payload,
            url=args.url,
            method=args.method.upper(),
            status_code=None,
            response_time_ms=0.0,
            content_length=0,
            matched=True,
            match_detail="request error",
            error=str(exc),
            body_preview="",
        )


def print_result(result: TestResult, verbose: bool) -> None:
    if result.error:
        color = RED
        status = "ERROR"
    elif result.matched:
        color = YELLOW
        status = "MATCH"
    else:
        color = GREEN
        status = "OK"

    line = (
        f"{color}[{status}]{RESET} "
        f"#{result.index:04d} "
        f"{result.status_code if result.status_code is not None else '---'} "
        f"{result.response_time_ms:7.1f}ms "
        f"len={result.content_length:6d} "
        f"payload={result.payload[:80]}"
    )
    print(line)

    if result.error:
        print(f"       {RED}{result.error}{RESET}")
    elif result.matched and result.match_detail:
        print(f"       {YELLOW}{result.match_detail}{RESET}")

    if verbose and result.body_preview:
        preview = result.body_preview.replace("\n", "\\n")
        print(f"       body: {preview}")


def establish_baseline(
    args: argparse.Namespace,
    session: requests.Session,
    headers: dict[str, str],
) -> tuple[int | None, int | None]:
    if not args.baseline:
        return None, None

    probe = args.baseline_payload
    try:
        url, body, extra_headers = build_request(
            args.url, probe, args.method, args.inject, args.param
        )
        req_headers = dict(headers)
        if extra_headers:
            req_headers.update(extra_headers)

        request_kwargs: dict[str, Any] = {
            "method": args.method.upper(),
            "url": url,
            "headers": req_headers,
            "timeout": args.timeout,
            "allow_redirects": args.follow_redirects,
            "verify": not args.insecure,
        }
        if isinstance(body, dict):
            if args.inject == "json":
                request_kwargs["json"] = body
            else:
                request_kwargs["data"] = body

        response = session.request(**request_kwargs)
        print(
            f"{CYAN}Baseline:{RESET} status={response.status_code}, "
            f"length={len(response.text)} using probe '{probe}'"
        )
        return response.status_code, len(response.text)
    except requests.RequestException as exc:
        print(f"{YELLOW}Baseline request failed: {exc}{RESET}")
        return None, None


def save_results(path: Path, results: list[TestResult]) -> None:
    payload = [asdict(r) for r in results]
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    else:
        lines = [
            "index,payload,status_code,response_time_ms,content_length,matched,match_detail,error,url"
        ]
        for r in results:
            row = [
                str(r.index),
                json.dumps(r.payload),
                str(r.status_code if r.status_code is not None else ""),
                str(r.response_time_ms),
                str(r.content_length),
                str(r.matched),
                json.dumps(r.match_detail),
                json.dumps(r.error),
                json.dumps(r.url),
            ]
            lines.append(",".join(row))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read payloads from a text file, send HTTP requests, and inspect responses."
    )
    parser.add_argument("--url", required=True, help="Target URL. Use {payload} for placeholder mode.")
    parser.add_argument("--payloads", required=True, type=Path, help="Text file with one payload per line.")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET).")
    parser.add_argument(
        "--inject",
        choices=["placeholder", "query", "body", "json", "header", "path"],
        default="placeholder",
        help="Where to place each payload (default: placeholder).",
    )
    parser.add_argument("--param", help="Parameter/header name for query, body, json, or header injection.")
    parser.add_argument("--headers", type=Path, help="Optional headers file (.json or 'Name: value' lines).")
    parser.add_argument("--match", help="Regex to flag interesting response bodies.")
    parser.add_argument("--baseline", action="store_true", help="Compare responses against a baseline request.")
    parser.add_argument(
        "--baseline-payload",
        default="test",
        help="Probe payload used for baseline comparison (default: test).",
    )
    parser.add_argument(
        "--length-delta",
        type=int,
        default=50,
        help="Minimum body-length change from baseline to flag a match (default: 50).",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds.")
    parser.add_argument("--threads", type=int, default=1, help="Concurrent workers (default: 1).")
    parser.add_argument("--preview", type=int, default=120, help="Body preview length for verbose mode.")
    parser.add_argument("--output", type=Path, help="Save results to .json or .csv.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("--no-follow-redirects", action="store_true", help="Do not follow redirects.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print response body previews.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only print matches and errors.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.follow_redirects = not args.no_follow_redirects

    if not args.quiet:
        banner()

    try:
        payloads = load_payloads(args.payloads)
        headers = load_headers(args.headers)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"{RED}Error: {exc}{RESET}", file=sys.stderr)
        return 1

    match_pattern = re.compile(args.match, re.IGNORECASE) if args.match else None
    session = requests.Session()

    baseline_status, baseline_length = establish_baseline(args, session, headers)

    if not args.quiet:
        print(f"{CYAN}Loaded {len(payloads)} payload(s) from {args.payloads}{RESET}")
        print(f"{CYAN}Target:{RESET} {args.method.upper()} {args.url} [{args.inject}]")
        print("-" * 80)

    results: list[TestResult] = []
    matches = 0
    errors = 0

    def run_one(index_payload: tuple[int, str]) -> TestResult:
        index, payload = index_payload
        if args.delay > 0 and args.threads == 1 and index > 1:
            time.sleep(args.delay)
        return send_payload(
            index=index,
            payload=payload,
            args=args,
            session=session,
            headers=headers,
            match_pattern=match_pattern,
            baseline_status=baseline_status,
            baseline_length=baseline_length,
        )

    indexed_payloads = list(enumerate(payloads, start=1))

    if args.threads > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = [pool.submit(run_one, item) for item in indexed_payloads]
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if result.matched:
                    matches += 1
                if result.error:
                    errors += 1
                if not args.quiet or result.matched or result.error:
                    print_result(result, args.verbose)
    else:
        for item in indexed_payloads:
            result = run_one(item)
            results.append(result)
            if result.matched:
                matches += 1
            if result.error:
                errors += 1
            if not args.quiet or result.matched or result.error:
                print_result(result, args.verbose)

    results.sort(key=lambda r: r.index)

    print("-" * 80)
    print(
        f"{BOLD}Done.{RESET} tested={len(results)} matches={matches} errors={errors}"
    )

    if args.output:
        save_results(args.output, results)
        print(f"{CYAN}Saved results to {args.output}{RESET}")

    return 0 if errors == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
