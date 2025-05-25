# Sigma-Scanner-
 Sigma Scanner: Black Hat Edition - Advanced Network Reconnaissance Toolkit 🔍
Description:
A comprehensive network scanning and reconnaissance tool with integrated vulnerability detection, IP tracing, and advanced scanning capabilities. Built for black hat hacking and penetration testing purposes.

Key Features:
🎯 Network Discovery - Identify live hosts in subnet ranges (CIDR notation supported)
🛡️ Vulnerability Scanning - Integrated with Nmap's vulners script for CVE detection
🌍 IP Geolocation - Detailed IP tracing with geo-mapping capabilities
🔧 OS Fingerprinting - Advanced operating system detection with confidence metrics
📊 Port Analysis - Comprehensive port scanning with service version detection
💻 Interactive Menu - User-friendly CLI interface with color-coded output

Installation:

Technical Requirements:

Python 3.8+

Nmap 7.80+

Root privileges for OS detection

Internet connection for IP tracing

# Requirements
sudo apt install nmap
pip3 install python-nmap requests

# Clone & Run
git clone https://github.com/[yourusername]/sigma-scanner.git
cd sigma-scanner
sudo python3 sigma_scanner.py

Usage Examples:

Full Network Recon

[SIGMA_GHOST] > 1
Enter subnet: 192.168.1.0/24

Targeted Vulnerability Scan

[SIGMA_GHOST] > 3
Enter target IP: 10.0.2.15

IP Tracing

[SIGMA_GHOST] > 5
Enter IP to trace: 8.8.8.8

Disclaimer:
⚠️ This tool is intended not for authorized security testing and educational purposes only. Always obtain proper authorization before scanning any network. The developers are is responsible for misuse of this software.
