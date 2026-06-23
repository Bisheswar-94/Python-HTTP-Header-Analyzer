"""HTTP header analyzer for security posture checks."""

from __future__ import annotations

import argparse
from typing import Mapping

import requests
from colorama import Fore, Style, init

init(autoreset=True)

REQUIRED_SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "strict-transport-security": "Strict-Transport-Security",
    "permissions-policy": "Permissions-Policy",
    "referrer-policy": "Referrer-Policy",
}
RISK_COLORS = {
    "Low": Fore.GREEN,
    "Medium": Fore.YELLOW,
    "High": Fore.RED,
}


def normalize_url(url: str) -> str:
    """Add https:// when a scheme is missing."""
    if url.startswith(("http://", "https://")):
        return url
    return f"https://{url}"


def analyze_headers(headers: Mapping[str, str]) -> dict[str, object]:
    """Analyze response headers and identify missing security protections."""
    normalized_headers = {key.lower(): value for key, value in headers.items()}

    present_security_headers = [
        header_name
        for lower_name, header_name in REQUIRED_SECURITY_HEADERS.items()
        if lower_name in normalized_headers
    ]
    missing_security_headers = [
        header_name
        for lower_name, header_name in REQUIRED_SECURITY_HEADERS.items()
        if lower_name not in normalized_headers
    ]

    missing_count = len(missing_security_headers)
    if missing_count == 0:
        risk_level = "Low"
    elif missing_count <= 2:
        risk_level = "Medium"
    else:
        risk_level = "High"

    return {
        "server": normalized_headers.get("server", "Not disclosed"),
        "content_type": normalized_headers.get("content-type", "Unknown"),
        "present_security_headers": present_security_headers,
        "missing_security_headers": missing_security_headers,
        "risk_level": risk_level,
    }


def print_banner() -> None:
    print(Fore.CYAN + r"""
 _   _ _____ _____ ____    _   _                _           
| | | |_   _|_   _|  _ \  | | | | ___  __ _  __| | ___ _ __ 
| |_| | | |   | | | |_) | | |_| |/ _ \/ _` |/ _` |/ _ \ '__|
|  _  | | |   | | |  __/  |  _  |  __/ (_| | (_| |  __/ |   
|_| |_| |_|   |_| |_|     |_| |_|\___|\__,_|\__,_|\___|_|   

               HTTP Header Analyzer
""" + Style.RESET_ALL)


def print_report(url: str, status_code: int, analysis: Mapping[str, object]) -> None:
    print(f"{Fore.GREEN}Target:{Style.RESET_ALL} {url}")
    print(f"{Fore.GREEN}Status:{Style.RESET_ALL} {status_code}")
    print(f"{Fore.GREEN}Server:{Style.RESET_ALL} {analysis['server']}")
    print(f"{Fore.GREEN}Content-Type:{Style.RESET_ALL} {analysis['content_type']}")

    present = analysis["present_security_headers"]
    missing = analysis["missing_security_headers"]

    print(f"\n{Fore.BLUE}Detected security headers:{Style.RESET_ALL}")
    if present:
        for header in present:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {header}")
    else:
        print(f"  {Fore.YELLOW}None{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Missing security headers:{Style.RESET_ALL}")
    if missing:
        for header in missing:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {header}")
    else:
        print(f"  {Fore.GREEN}None{Style.RESET_ALL}")

    risk_level = analysis["risk_level"]
    risk_color = RISK_COLORS.get(risk_level, Fore.WHITE)
    print(f"\n{Fore.MAGENTA}Risk level:{Style.RESET_ALL} {risk_color}{risk_level}{Style.RESET_ALL}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze HTTP response headers for security protections")
    parser.add_argument("url", help="Website URL (e.g. example.com or https://example.com)")
    args = parser.parse_args()

    url = normalize_url(args.url)
    print_banner()

    try:
        with requests.Session() as session:
            response = session.get(url, timeout=10, allow_redirects=False, verify=True)
    except requests.RequestException as exc:
        print(f"{Fore.RED}Request failed:{Style.RESET_ALL} {exc}")
        return 1

    analysis = analyze_headers(response.headers)
    print_report(url, response.status_code, analysis)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
