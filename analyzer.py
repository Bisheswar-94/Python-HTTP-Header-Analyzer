import requests
import time
from colorama import Fore, Style, init
from urllib.parse import urlparse

# Initialize colorama
init(autoreset=True)

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against SSL stripping attacks.",
    "Content-Security-Policy": "Prevents XSS and code injection attacks.",
    "X-Frame-Options": "Protects against clickjacking attacks.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "Referrer-Policy": "Controls referrer information sharing.",
    "Permissions-Policy": "Restricts browser features and APIs."
}


# Normalize URL
def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


# Main analyzer function
def analyze_headers(url):

    start = time.time()

    try:
        response = requests.get(url, timeout=10)

        parsed = urlparse(url)

        target = parsed.netloc
        protocol = parsed.scheme.upper()
        status_code = response.status_code

        server = response.headers.get("Server", "Not Disclosed")
        content_type = response.headers.get("Content-Type", "Unknown")

        # Banner
        print(Fore.CYAN + "=" * 50)
        print(Fore.GREEN + "        HTTP HEADER ANALYZER")
        print(Fore.CYAN + "=" * 50)

        # Target Information
        print(Fore.YELLOW + f"\n[+] Target         : {target}")
        print(Fore.YELLOW + f"[+] Protocol       : {protocol}")
        print(Fore.YELLOW + f"[+] Status Code    : {status_code}")

        # Header Information
        print(Fore.GREEN + f"[+] Server         : {server}")
        print(Fore.GREEN + f"[+] Content-Type   : {content_type}")

        # Display Headers
        print(Fore.CYAN + "\n" + "=" * 50)
        print(Fore.MAGENTA + "              HTTP HEADERS")
        print(Fore.CYAN + "=" * 50)

        for header, value in response.headers.items():
            print(Fore.WHITE + f"{header}: {value}")

        # Security Analysis
        print(Fore.CYAN + "\n" + "=" * 50)
        print(Fore.MAGENTA + "           SECURITY ANALYSIS")
        print(Fore.CYAN + "=" * 50)

        missing_headers = []

        for header, description in SECURITY_HEADERS.items():

            if header in response.headers:

                print(
                    Fore.GREEN +
                    f"[SECURE] {header} detected"
                )

            else:

                print(
                    Fore.RED +
                    f"[HIGH RISK] Missing: {header}"
                )

                print(
                    Fore.YELLOW +
                    f"  -> {description}\n"
                )

                missing_headers.append(header)

        # Final Result
        print(Fore.CYAN + "=" * 50)

        if not missing_headers:

            print(
                Fore.GREEN +
                "\n[+] Excellent! All major security headers detected."
            )

        else:

            print(
                Fore.RED +
                f"\n[-] Missing {len(missing_headers)} important security headers."
            )

        # Scan Time
        end = time.time()

        print(
            Fore.CYAN +
            f"\n[+] Scan completed in {round(end - start, 2)} seconds"
        )

        # Footer
        print(Fore.CYAN + "\n" + "=" * 50)
        print(Fore.GREEN + "      HTTP Header Analysis Completed")
        print(Fore.CYAN + "      Developed by Bisheswar-94")
        print(Fore.CYAN + "=" * 50)

    except requests.exceptions.RequestException as error:

        print(
            Fore.RED +
            f"\n[ERROR] {error}"
        )


# Main Program
def main():

    # ASCII Banner
    print(Fore.CYAN + r"""

██╗  ██╗████████╗████████╗██████╗ 
██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗
███████║   ██║      ██║   ██████╔╝
██╔══██║   ██║      ██║   ██╔═══╝ 
██║  ██║   ██║      ██║   ██║     
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     

██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ 
██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝
██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗
██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝

    """)

    print(Fore.GREEN + "Professional HTTP Security Header Analyzer\n")

    # User Input
    url = input(
        Fore.YELLOW +
        "Enter Website URL: "
    ).strip()

    url = normalize_url(url)

    analyze_headers(url)


# Run Program
if __name__ == "__main__":
    main()