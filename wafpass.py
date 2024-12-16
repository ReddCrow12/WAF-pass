import argparse
import socket
import requests # type: ignore
from dns import resolver # type: ignore
import subprocess
from termcolor import colored # type: ignore

# Banner
def print_banner():
    print(colored("""
 _    _   ___  ______                         
| |  | | / _ \ |  ___|                        
| |  | |/ /_\ \| |_    _ __    __ _  ___  ___ 
| |/\| ||  _  ||  _|  | '_ \  / _` |/ __|/ __|
\  /\  /| | | || |    | |_) || (_| |\__ \\\__ \\
 \/  \/ \_| |_/\_|    | .__/  \__,_||___/|___/
                      | |                     
                      |_|                     
""", "yellow"))
    print(colored("<created by Redd Crow>", "red"))

def fetch_ips_from_osint(domain):
    """
    Fetch IP addresses from OSINT sources.

    :param domain: The domain to search.
    :return: List of IP addresses from OSINT sources.
    """
    osint_ips = []
    sources = [
        f"https://api.shodan.io/dns/resolve?hostnames={domain}&key=YOUR_SHODAN_API_KEY",
        f"https://securitytrails.com/domain/{domain}",
        f"https://censys.io/ipv4/{domain}",
        f"https://viewdns.info/iphistory/?domain={domain}",
        f"https://ipinfo.io/{domain}",
        f"https://whois.domaintools.com/{domain}",
        f"https://www.robtex.com/dns-lookup/{domain}",
        f"https://www.binaryedge.io/api/v2/query/domains/{domain}",
        f"https://spyse.com/search/{domain}",
        f"https://www.virustotal.com/gui/domain/{domain}/relations"
    ]

    for source in sources:
        try:
            response = requests.get(source, timeout=10)
            if response.status_code == 200:
                osint_ips.extend(extract_ips_from_text(response.text))
        except Exception:
            pass

    return list(set(osint_ips))

def scan_ips(domain, method):
    """
    Scans for real IP of the domain bypassing WAF.

    :param domain: The domain to scan.
    :param method: Method to find IPs (dns, osint, all).
    """
    print(colored("\n[+] Scanning IPs...", "green"))

    ip_list = []

    if method in ["dns", "all"]:
        print(colored("[+] Using DNS lookup...", "green"))
        try:
            answers = resolver.resolve(domain, 'A')
            ip_list.extend([answer.to_text() for answer in answers])
        except Exception as e:
            print(f"[-] DNS lookup failed: {e}")

    if method in ["osint", "all"]:
        print(colored("[+] Using OSINT sources...", "green"))
        osint_ips = fetch_ips_from_osint(domain)
        ip_list.extend(osint_ips)

    # Remove duplicates
    ip_list = list(set(ip_list))

    if not ip_list:
        print("[-] No IPs found.")
        return

    print(colored("\nAll IPs that were found:", "yellow"))
    print(colored("===============", "yellow"))
    for ip in ip_list:
        print(colored(ip, "white"))

    print(colored("\n[+] Trying to bypass WAF...", "green"))
    for ip in ip_list:
        # Check for HTTP
        try:
            url = f"http://{ip}"
            response = requests.get(url, headers={"Host": domain}, timeout=5)
            if response.status_code == 200:
                print(colored(f"\nReal IP of {domain} found using HTTP:", "yellow"))
                print(colored("=================", "yellow"))
                print(colored(ip, "white"))
                return
        except Exception as e:
            pass

        # Check for HTTPS
        try:
            url = f"https://{ip}"
            response = requests.get(url, headers={"Host": domain}, timeout=5)
            if response.status_code == 200:
                print(colored(f"\nReal IP of {domain} found using HTTPS:", "yellow"))
                print(colored("=================", "yellow"))
                print(colored(ip, "white"))
                return
        except Exception as e:
            pass

    print("[-] Could not bypass the WAF with the given IPs.")


def extract_ips_from_text(text):
    """
    Extracts IP addresses from a text using regex.

    :param text: Text to search for IP addresses.
    :return: List of IP addresses.
    """
    import re
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(ip_pattern, text)

def main():
    parser = argparse.ArgumentParser(description="Tool to bypass WAF and find real IP of a domain.")
    parser.add_argument("-d", help="Specify a single domain.")
    parser.add_argument("-dlist", help="Specify a file containing list of domains.")
    parser.add_argument("-dns", action="store_true", help="Use DNS method only.")
    parser.add_argument("-osint", action="store_true", help="Use OSINT method only.")
    parser.add_argument("-all", action="store_true", help="Use both DNS and OSINT methods.")
    
    args = parser.parse_args()

    if not any([args.d, args.dlist]):
        print("[-] You must specify either a domain (-d) or a domain list (-dlist). Use -h for help.")
        return

    method = "all"
    if args.dns:
        method = "dns"
    elif args.osint:
        method = "osint"

    if args.d:
        domain = args.d
        scan_ips(domain, method)
    elif args.dlist:
        try:
            with open(args.dlist, "r") as file:
                domains = file.readlines()
                for domain in domains:
                    domain = domain.strip()
                    if domain:
                        scan_ips(domain, method)
        except Exception as e:
            print(f"[-] Failed to read domain list: {e}")

if __name__ == "__main__":
    print_banner()
    main()
