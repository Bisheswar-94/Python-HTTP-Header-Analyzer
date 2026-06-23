# Python-HTTP-Header-Analyzer

Professional Python cybersecurity tool that analyzes HTTP response headers and detects missing security protections like CSP, HSTS, X-Frame-Options, and more.

## Features

- Colorful terminal output with `colorama`
- Professional ASCII banner
- Server and `Content-Type` header visibility
- Security risk analysis based on missing protections
- Fast website scanning with `requests`

## Security headers checked

- Content-Security-Policy
- X-Frame-Options
- Strict-Transport-Security
- Permissions-Policy
- Referrer-Policy

## Usage

```bash
pip install -r requirements.txt
python header_analyzer.py example.com
```
