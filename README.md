# Advanced Port Scanner

A professional-grade Python port scanner with banner grabbing, OS fingerprinting, CVE detection, geolocation and automated report export.

## Features
- Scans any IP or hostname for open ports
- Grabs service banners to identify running software
- Detects known CVEs from banner signatures
- Geolocates target IP with ISP information
- Fingerprints operating system from open ports
- Flags critical, high, medium and low risk ports
- Saves full scan report to a .txt file automatically
- Multi-threaded for fast scanning
- Colour coded terminal output

## Technologies
- Python 3
- socket, threading, concurrent.futures
- requests (geolocation)

## Usage
```bash
python scanner.py
```
Select a scan profile and enter a target IP or hostname.

> Only scan systems you own or have explicit permission to scan. Unauthorised scanning is illegal.

## Skills Demonstrated
- Network programming and socket communication
- Cybersecurity concepts: port scanning, banner grabbing, CVE awareness
- Multi-threading and concurrent programming
- API integration (geolocation)
- Professional report generation
