#!/usr/bin/env python3
"""
Advanced Port Scanner
Professional-grade scanner with banner grabbing, OS fingerprinting,
geolocation, CVE lookup, risk assessment and report export.
Author: [Jahid]
For authorised use only.
"""

import socket
import threading
import datetime
import requests
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Colours ───────────────────────────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    END    = '\033[0m'

# ── Port database ─────────────────────────────────────────────────────────────
PORT_DB = {
    21:    {"name": "FTP",          "risk": "HIGH",     "desc": "File transfer — credentials sent in plaintext"},
    22:    {"name": "SSH",          "risk": "LOW",      "desc": "Secure remote access"},
    23:    {"name": "Telnet",       "risk": "CRITICAL", "desc": "Unencrypted remote access — major security risk"},
    25:    {"name": "SMTP",         "risk": "MEDIUM",   "desc": "Email sending"},
    53:    {"name": "DNS",          "risk": "MEDIUM",   "desc": "Domain name resolution"},
    80:    {"name": "HTTP",         "risk": "MEDIUM",   "desc": "Unencrypted web traffic"},
    110:   {"name": "POP3",         "risk": "MEDIUM",   "desc": "Email retrieval — often unencrypted"},
    135:   {"name": "RPC",          "risk": "HIGH",     "desc": "Windows Remote Procedure Call"},
    139:   {"name": "NetBIOS",      "risk": "HIGH",     "desc": "Windows file sharing — frequently exploited"},
    143:   {"name": "IMAP",         "risk": "MEDIUM",   "desc": "Email access"},
    443:   {"name": "HTTPS",        "risk": "LOW",      "desc": "Encrypted web traffic"},
    445:   {"name": "SMB",          "risk": "CRITICAL", "desc": "File sharing — EternalBlue/WannaCry attack vector"},
    1433:  {"name": "MSSQL",        "risk": "HIGH",     "desc": "Microsoft SQL Server database"},
    1723:  {"name": "PPTP",         "risk": "HIGH",     "desc": "VPN — known vulnerabilities"},
    3306:  {"name": "MySQL",        "risk": "HIGH",     "desc": "MySQL database — should not be publicly exposed"},
    3389:  {"name": "RDP",          "risk": "CRITICAL", "desc": "Remote Desktop — frequent brute-force target"},
    5432:  {"name": "PostgreSQL",   "risk": "HIGH",     "desc": "PostgreSQL database"},
    5900:  {"name": "VNC",          "risk": "HIGH",     "desc": "Remote desktop — often misconfigured"},
    6379:  {"name": "Redis",        "risk": "CRITICAL", "desc": "Database — commonly exposed with no auth"},
    8080:  {"name": "HTTP-Alt",     "risk": "MEDIUM",   "desc": "Alternate HTTP — often used by web apps"},
    8443:  {"name": "HTTPS-Alt",    "risk": "LOW",      "desc": "Alternate HTTPS"},
    27017: {"name": "MongoDB",      "risk": "CRITICAL", "desc": "Database — frequently exposed with no auth"},
}

RISK_COLOURS = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.RED,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.GREEN,
    "UNKNOWN":  C.CYAN,
}

# ── CVE signature database ────────────────────────────────────────────────────
CVE_DB = {
    "vsftpd 2.3.4":       "CVE-2011-2523 — Backdoor command execution (CRITICAL)",
    "openssh 7.2":        "CVE-2016-6515 — DoS via long passwords",
    "openssh 7.7":        "CVE-2018-15473 — Username enumeration vulnerability",
    "apache 2.4.49":      "CVE-2021-41773 — Path traversal & Remote Code Execution",
    "apache 2.4.50":      "CVE-2021-42013 — Path traversal & Remote Code Execution",
    "microsoft-ds":       "CVE-2017-0144 — EternalBlue/WannaCry SMB exploit",
    "samba":              "CVE-2017-7494 — SambaCry Remote Code Execution",
    "redis":              "CVE-2022-0543 — Lua sandbox escape RCE",
    "mongodb":            "CVE-2019-2386 — Authentication bypass",
    "mysql 5.5":          "CVE-2016-6662 — Malicious config file overwrite",
    "mysql 5.6":          "CVE-2016-6662 — Malicious config file overwrite",
    "vnc":                "CVE-2019-15681 — Memory leak / credential exposure",
    "ms-wbt-server":      "CVE-2019-0708 — BlueKeep RDP pre-auth RCE (CRITICAL)",
    "proftpd 1.3.5":      "CVE-2015-3306 — Arbitrary file read/write via mod_copy",
    "openssl 1.0.1":      "CVE-2014-0160 — Heartbleed memory disclosure",
    "log4j":              "CVE-2021-44228 — Log4Shell Remote Code Execution (CRITICAL)",
}

# ── Scanner ───────────────────────────────────────────────────────────────────
class PortScanner:
    def __init__(self, target, start_port, end_port, threads=200, timeout=1):
        self.target       = target
        self.start_port   = start_port
        self.end_port     = end_port
        self.threads      = threads
        self.timeout      = timeout
        self.results      = []
        self.lock         = threading.Lock()
        self.resolved_ip  = None
        self.hostname     = None
        self.os_guess     = "Unknown"
        self.geo          = {}
        self.start_time   = None

    def resolve_target(self):
        try:
            self.resolved_ip = socket.gethostbyname(self.target)
            try:
                self.hostname = socket.gethostbyaddr(self.resolved_ip)[0]
            except:
                self.hostname = self.target
            return True
        except socket.gaierror:
            print(f"{C.RED}  [!] Could not resolve: {self.target}{C.END}")
            return False

    def grab_banner(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.resolved_ip, port))
            if port in [80, 8080]:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            return banner.split("\n")[0][:80] if banner else ""
        except:
            return ""

    def fingerprint_os(self):
        open_ports = [r["port"] for r in self.results]
        if 445 in open_ports and 135 in open_ports:
            self.os_guess = "Windows (SMB + RPC detected)"
        elif 3389 in open_ports:
            self.os_guess = "Windows (RDP detected)"
        elif 22 in open_ports and 445 not in open_ports and 135 not in open_ports:
            self.os_guess = "Linux/Unix (SSH present, no Windows ports)"
        elif 22 in open_ports and 80 in open_ports:
            self.os_guess = "Linux/Unix Web Server"
        else:
            self.os_guess = "Unknown"

    def geolocate(self):
        try:
            r = requests.get(
                f"http://ip-api.com/json/{self.resolved_ip}?fields=status,country,city,regionName,isp,org,as",
                timeout=5
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    self.geo = data
        except:
            self.geo = {}

    def check_cve(self, banner):
        if not banner:
            return None
        banner_lower = banner.lower()
        matches = []
        for sig, cve in CVE_DB.items():
            if sig in banner_lower:
                matches.append(cve)
        return matches if matches else None

    def scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.resolved_ip, port))
            s.close()
            if result == 0:
                banner = self.grab_banner(port)
                info   = PORT_DB.get(port, {"name": "Unknown", "risk": "UNKNOWN", "desc": "Unrecognised service"})
                cves   = self.check_cve(banner)
                finding = {
                    "port":   port,
                    "name":   info["name"],
                    "risk":   info["risk"],
                    "desc":   info["desc"],
                    "banner": banner,
                    "cves":   cves,
                }
                with self.lock:
                    self.results.append(finding)
                    rc = RISK_COLOURS.get(info["risk"], C.CYAN)
                    print(f"  {C.GREEN}[OPEN]{C.END}  Port {port:<6} {rc}{info['name']:<14}{C.END} Risk: {rc}{info['risk']}{C.END}")
                    if banner:
                        print(f"          {C.CYAN}Banner : {banner}{C.END}")
                    if cves:
                        for cve in cves:
                            print(f"          {C.RED}⚠  CVE  : {cve}{C.END}")
        except:
            pass

    def save_report(self):
        os.makedirs("scan_reports", exist_ok=True)
        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_reports/{self.target}_{ts}.txt"
        elapsed  = (datetime.datetime.now() - self.start_time).seconds

        with open(filename, "w") as f:
            f.write("=" * 60 + "\n")
            f.write("  ADVANCED PORT SCANNER — SCAN REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"  Target     : {self.target}\n")
            f.write(f"  IP Address : {self.resolved_ip}\n")
            f.write(f"  Hostname   : {self.hostname}\n")
            f.write(f"  OS Guess   : {self.os_guess}\n")
            if self.geo:
                f.write(f"  Location   : {self.geo.get('city','?')}, {self.geo.get('regionName','?')}, {self.geo.get('country','?')}\n")
                f.write(f"  ISP        : {self.geo.get('isp','?')}\n")
                f.write(f"  Org        : {self.geo.get('org','?')}\n")
            f.write(f"  Scan Time  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Port Range : {self.start_port} - {self.end_port}\n")
            f.write(f"  Duration   : {elapsed}s\n")
            f.write(f"  Open Ports : {len(self.results)}\n")
            f.write("=" * 60 + "\n\n")

            if self.results:
                f.write("OPEN PORTS\n")
                f.write("-" * 60 + "\n")
                for r in sorted(self.results, key=lambda x: x["port"]):
                    f.write(f"Port   : {r['port']} ({r['name']})\n")
                    f.write(f"Risk   : {r['risk']}\n")
                    f.write(f"Info   : {r['desc']}\n")
                    if r["banner"]:
                        f.write(f"Banner : {r['banner']}\n")
                    if r["cves"]:
                        for cve in r["cves"]:
                            f.write(f"CVE    : {cve}\n")
                    f.write("\n")

            # Risk summary
            critical = [r for r in self.results if r["risk"] == "CRITICAL"]
            high     = [r for r in self.results if r["risk"] == "HIGH"]
            cve_hits = [r for r in self.results if r["cves"]]

            f.write("RISK SUMMARY\n")
            f.write("-" * 60 + "\n")
            f.write(f"Critical Risk Ports : {len(critical)}\n")
            f.write(f"High Risk Ports     : {len(high)}\n")
            f.write(f"CVEs Detected       : {len(cve_hits)}\n")

            if not critical and not cve_hits:
                f.write("Overall Status      : No critical issues detected\n")
            else:
                f.write("Overall Status      : ACTION REQUIRED — review flagged ports\n")

        return filename

    def run(self):
        print(f"\n{C.BOLD}{'='*60}{C.END}")
        print(f"{C.BOLD}  ADVANCED PORT SCANNER{C.END}")
        print(f"{'='*60}")
        print(f"  For authorised use only.")
        print(f"  Scanning without permission is illegal.\n")

        if not self.resolve_target():
            return

        print(f"  Target    : {C.CYAN}{self.target}{C.END}")
        print(f"  IP        : {C.CYAN}{self.resolved_ip}{C.END}")
        print(f"  Hostname  : {C.CYAN}{self.hostname}{C.END}")

        print(f"\n  Geolocating target...")
        self.geolocate()
        if self.geo:
            print(f"  Location  : {C.CYAN}{self.geo.get('city','?')}, {self.geo.get('regionName','?')}, {self.geo.get('country','?')}{C.END}")
            print(f"  ISP       : {C.CYAN}{self.geo.get('isp','?')}{C.END}")
        else:
            print(f"  Location  : {C.YELLOW}Could not geolocate (private IP or no connection){C.END}")

        print(f"\n  Port Range: {self.start_port} - {self.end_port}")
        print(f"  Threads   : {self.threads}")
        print(f"  Started   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{'='*60}\n")

        self.start_time = datetime.datetime.now()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan_port, port): port
                for port in range(self.start_port, self.end_port + 1)
            }
            for future in as_completed(futures):
                pass

        self.fingerprint_os()
        elapsed = (datetime.datetime.now() - self.start_time).seconds

        # ── Summary ───────────────────────────────────────────────────────────
        print(f"\n{'='*60}")
        print(f"{C.BOLD}  SCAN COMPLETE{C.END}")
        print(f"{'='*60}")
        print(f"  Open Ports : {C.GREEN}{len(self.results)}{C.END}")
        print(f"  OS Guess   : {C.CYAN}{self.os_guess}{C.END}")
        print(f"  Duration   : {elapsed}s")

        critical = [r for r in self.results if r["risk"] == "CRITICAL"]
        high     = [r for r in self.results if r["risk"] == "HIGH"]
        cve_hits = [r for r in self.results if r["cves"]]

        if critical:
            print(f"\n  {C.RED}{C.BOLD}⚠  CRITICAL RISK PORTS ({len(critical)}):{C.END}")
            for r in critical:
                print(f"  {C.RED}  • Port {r['port']} ({r['name']}) — {r['desc']}{C.END}")

        if high:
            print(f"\n  {C.YELLOW}⚠  HIGH RISK PORTS ({len(high)}):{C.END}")
            for r in high:
                print(f"  {C.YELLOW}  • Port {r['port']} ({r['name']}) — {r['desc']}{C.END}")

        if cve_hits:
            print(f"\n  {C.RED}⚠  KNOWN CVEs DETECTED ({len(cve_hits)}):{C.END}")
            for r in cve_hits:
                for cve in r["cves"]:
                    print(f"  {C.RED}  • Port {r['port']} — {cve}{C.END}")

        if not critical and not cve_hits:
            print(f"\n  {C.GREEN}✅ No critical risks detected{C.END}")

        report = self.save_report()
        print(f"\n  📄 Report saved: {C.CYAN}{report}{C.END}")
        print(f"{'='*60}\n")


# ── Main ──────────────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"{C.BOLD}  ADVANCED PORT SCANNER{C.END}")
print(f"  Only scan systems you own or have permission to scan")
print(f"{'='*60}\n")

print("  Scan profiles:")
print("  [1] Quick    — Ports 1-100")
print("  [2] Standard — Ports 1-1000")
print("  [3] Full     — Ports 1-65535")
print("  [4] Custom   — Choose your own range\n")

try:
    profile = input("  Select profile (1/2/3/4): ").strip()
    target  = input("  Enter target IP or hostname: ").strip()

    if profile == "1":
        start, end = 1, 100
    elif profile == "2":
        start, end = 1, 1000
    elif profile == "3":
        start, end = 1, 65535
    elif profile == "4":
        start = int(input("  Start port: "))
        end   = int(input("  End port  : "))
    else:
        print("  Invalid profile, using Quick scan.")
        start, end = 1, 100

    scanner = PortScanner(target, start, end)
    scanner.run()

except KeyboardInterrupt:
    print(f"\n\n  Scan cancelled.\n")
    