# WAF IP Bypass Tool

## Description

This tool allows you to bypass Web Application Firewalls (WAF) and find the real IP address of a domain by using DNS lookups and OSINT sources. It utilizes various external services to gather information and tries to bypass WAF by accessing the domain via discovered IP addresses.

---

## Features

- **DNS Lookup**: Uses DNS queries to resolve the IP addresses of a domain.
- **OSINT**: Collects IP addresses from various OSINT sources (like Shodan, VirusTotal, and more).
- **WAF Bypass**: Attempts to bypass WAFs using the discovered IPs by sending HTTP requests with the `Host` header set to the original domain.
- **Support for Domain Lists**: Can scan multiple domains from a text file.

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/waf-ip-bypass-tool.git
   cd waf-ip-bypass-tool
