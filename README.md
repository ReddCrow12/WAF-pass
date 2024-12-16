# WAF IP Bypass Tool

## Description

This tool is designed to help security researchers and penetration testers find the real IP address of a domain by bypassing Web Application Firewalls (WAF). The tool uses two primary methods:

1. **DNS Lookup**: The tool performs a DNS query to resolve the domain to its associated IP addresses.
2. **OSINT Sources**: The tool collects information from various OSINT (Open Source Intelligence) platforms like Shodan, VirusTotal, Censys, and others to gather IP addresses that may not be directly visible via DNS queries.

The tool then attempts to bypass WAFs by making HTTP requests to the discovered IP addresses with the `Host` header set to the original domain. This technique helps to bypass WAF protections by accessing the web server directly through its IP, instead of the domain name that is typically protected by the WAF.

---

## How it bypasses WAF security

Web Application Firewalls (WAF) typically protect domains by filtering HTTP requests based on the `Host` header. The `Host` header is used to identify which domain the request is targeting, allowing the WAF to filter and block malicious traffic before it reaches the web server.

This tool uses a method known as **IP enumeration** to bypass this security:

1. **DNS Lookup**: The tool queries the DNS records of the domain to find IP addresses associated with it. WAFs often protect only the domain name, but the underlying IP might still be exposed to the public, allowing attackers to reach the server directly.

2. **OSINT Sources**: The tool collects IP addresses from multiple OSINT platforms such as Shodan, VirusTotal, and others. These platforms might provide historical data or even information about IP addresses that are not directly visible through DNS queries.

3. **WAF Bypass**: Once the tool has gathered potential IP addresses, it tries to access each IP directly by sending HTTP requests with the original domain in the `Host` header. By sending requests directly to the IP address, it bypasses any domain-based WAF protections, which typically block requests from unknown or untrusted IP addresses.

If successful, the tool will reveal the real IP of the domain, even if it is hidden behind a WAF.

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
   git clone https://github.com/ReddCrow12/WAF-pass.git
   cd WAF-pass
2. Downlaods requirements:
   
   ```bash
   pip install -r requirements.txt

   chmod +x wafpass.py
   sudo mv wafpass.py /usr/local/bin/wafpass

---

## Usage
### Command-Line Options

- **`-d <domain>`**: Specify a single domain to scan.
  - Example:
    ```bash
    wafpass -d example.com 
    ```

- **`-dlist <file>`**: Specify a text file containing a list of domains (one per line).
  - Example:
    ```bash
    wafpass -dlist domains.txt
    ```

- **`-dns`**: Use DNS method only for scanning.
  - Example:
    ```bash
    wafpass -d example.com -dns
    ```

- **`-osint`**: Use OSINT sources only for scanning.
  - Example:
    ```bash
    wafpass -d example.com -osint
    ```

- **`-all`**: Use both DNS and OSINT methods for scanning.
  - Example:
    ```bash
    wafpass -d example.com -all
    ```

---

כעת תוכל להעתיק את זה ולהוסיף אותו לקובץ ה-`README.md` שלך תחת החלק של ה-Usage. אם יש עוד משהו שצריך לשנות או להוסיף, אני כאן!
