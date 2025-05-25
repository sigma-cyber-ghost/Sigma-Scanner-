import nmap
import datetime
import sys
import time
import os
import ipaddress
import webbrowser
import requests

COLORS = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "reset": "\033[0m", "bold": "\033[1m"
}

# Configuration
TELEGRAM_CHANNEL = "https://web.telegram.org/k/#@Sigma_Ghost"
channel_opened = False

def display_banner():
    global channel_opened
    os.system('clear' if os.name == 'posix' else 'cls')
    print(COLORS["cyan"] + r"""
  _____  _____  _____ ___  ___  ___           _____  _   _  _____  _____  _____ 
 /  ___||_   _||  __ \|  \/  | / _ \         |  __ \| | | ||  _  |/  ___||_   _|
 \ `--.   | |  | |  \/| .  . |/ /_\ \        | |  \/| |_| || | | |\ `--.   | |  
  `--. \  | |  | | __ | |\/| ||  _  |        | | __ |  _  || | | | `--. \  | |  
 /\__/ / _| |_ | |_\ \| |  | || | | |        | |_\ \| | | |\ \_/ //\__/ /  | |  
 \____/  \___/  \____/\_|  |_/\_| |_/         \____/\_| |_/ \___/ \____/   \_/  
                                      ______                                    
                                     |______|                                   
""" + COLORS["reset"])
    print(COLORS["yellow"] + r"""
   ___  _               _                                 _                
  / __\| |  __ _   ___ | | __         /\  /\  __ _   ___ | | __  ___  _ __ 
 /__\//| | / _` | / __|| |/ /        / /_/ / / _` | / __|| |/ / / _ \| '__|
/ \/  \| || (_| || (__ |   <        / __  / | (_| || (__ |   < |  __/| |   
\_____/|_| \__,_| \___||_|\_\ _____ \/ /_/   \__,_| \___||_|\_\ \___||_|   
                             |_____|                                       
""" + COLORS["reset"])
    print(COLORS["green"] + "\n" + " " * 15 + "[+] Coded with <3 by SIGMA_GHOST | 2025 | BLACK HAT EDITION [+]")
    print(COLORS["green"] + " " * 18 + f"Telegram Channel: @Sigma_Ghost_Hacking01")
    print(COLORS["yellow"] + "-" * 75)
    print(COLORS["cyan"] + f" Scanning Start Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(COLORS["yellow"] + "-" * 75 + COLORS["reset"] + "\n")
    
    if not channel_opened:
        try:
            webbrowser.open(TELEGRAM_CHANNEL)
            print(COLORS["green"] + "[+] Opening SIGMA_GHOST Channel..." + COLORS["reset"])
            time.sleep(2)
            channel_opened = True
        except Exception as e:
            print(COLORS["red"] + f"[-] Error opening Telegram: {e}" + COLORS["reset"])

def validate_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

def show_donation():
    print(COLORS["cyan"] + "\n[+] Support SIGMA_GHOST Development:" + COLORS["reset"])
    print(COLORS["yellow"] + "┌────────────────────────────────────────────────────────┐")
    print("│ " + COLORS["green"] + "Cryptocurrency Donation Addresses" + COLORS["yellow"] + "                 │")
    print("├────────────────────────────────────────────────────────┤")
    print("│ " + COLORS["magenta"] + "Solana: " + COLORS["reset"] + "DRokH1Mhbzo4dGtA4wLUtjyVvNSyjVvCMikSbMRZr6k6  │")
    print("│ " + COLORS["magenta"] + "Ethereum: " + COLORS["reset"] + "0x155f7be52d38e7DCba45549aa2D94E6A2005EF7f       │")
    print("│ " + COLORS["magenta"] + "Bitcoin: " + COLORS["reset"] + "bc1ppzt0pn4plgtetlkar8p5j43udd2mh85cmtu9g23vxqfm6ayknpnsmgzcfr │")
    print("│ " + COLORS["magenta"] + "Base: " + COLORS["reset"] + "0x155f7be52d38e7DCba45549aa2D94E6A2005EF7f          │")
    print("└────────────────────────────────────────────────────────┘" + COLORS["reset"])

def trace_ip(target):
    try:
        if not validate_ip(target):
            print(COLORS["red"] + "[-] Invalid IP address format" + COLORS["reset"])
            return

        print(COLORS["yellow"] + f"\n[*] Tracing IP: {target}" + COLORS["reset"])
        
        # IP-API.com request
        try:
            response = requests.get(f"http://ip-api.com/json/{target}")
            data = response.json()
            
            if data.get('status') != 'success':
                print(COLORS["red"] + f"[-] Error: {data.get('message', 'Unknown error')}" + COLORS["reset"])
                return
                
            print(COLORS["green"] + "[+] Geolocation Results:" + COLORS["reset"])
            print(f"IP Address: {data.get('query', 'N/A')}")
            print(f"Country: {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
            print(f"Region: {data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})")
            print(f"City: {data.get('city', 'N/A')}")
            print(f"ZIP Code: {data.get('zip', 'N/A')}")
            print(f"Latitude/Longitude: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
            print(f"Timezone: {data.get('timezone', 'N/A')}")
            print(f"ISP: {data.get('isp', 'N/A')}")
            print(f"Organization: {data.get('org', 'N/A')}")
            print(f"AS Number: {data.get('as', 'N/A')}")
            print(f"Reverse DNS: {data.get('reverse', 'N/A')}")
            print(f"Map: https://www.google.com/maps/search/?api=1&query={data.get('lat','')},{data.get('lon','')}")
            
        except Exception as e:
            print(COLORS["red"] + f"[-] IP tracing error: {str(e)}" + COLORS["reset"])

    except Exception as e:
        print(COLORS["red"] + f"[-] General error: {str(e)}" + COLORS["reset"])

def network_discovery(target):
    try:
        if not validate_ip(target):
            print(COLORS["red"] + "[-] Invalid IP/subnet format" + COLORS["reset"])
            return []

        nm = nmap.PortScanner()
        print(COLORS["yellow"] + f"\n[*] Discovering network {target}..." + COLORS["reset"])
        nm.scan(hosts=target, arguments='-sn -T4')
        live_hosts = nm.all_hosts()
        
        if not live_hosts:
            print(COLORS["red"] + "[-] No live hosts found" + COLORS["reset"])
            return []
            
        print(COLORS["green"] + f"[+] Found {len(live_hosts)} live hosts:" + COLORS["reset"])
        for host in live_hosts:
            print(f" - {host}")
        return live_hosts
        
    except Exception as e:
        print(COLORS["red"] + f"[-] Network discovery failed: {str(e)}" + COLORS["reset"])
        return []

def comprehensive_scan(target, ports='1-1000'):
    try:
        nm = nmap.PortScanner()
        arguments = f'-p {ports} -sV -O --script vulners -T4 --min-rate=5000'
        print(COLORS["yellow"] + f"\n[*] Scanning {target} comprehensively..." + COLORS["reset"])
        nm.scan(target, arguments=arguments)
        
        if target not in nm.all_hosts():
            print(COLORS["red"] + "[-] Target not reachable" + COLORS["reset"])
            return None
            
        return nm[target]
    except Exception as e:
        print(COLORS["red"] + f"[-] Comprehensive scan failed: {str(e)}" + COLORS["reset"])
        return None

def process_scan_results(host, scan_data):
    if not scan_data:
        return
    
    # Port Results
    print(COLORS["green"] + f"[+] Open ports on {host}:" + COLORS["reset"])
    if 'tcp' in scan_data:
        open_ports = [port for port in scan_data['tcp'] if scan_data['tcp'][port]['state'] == 'open']
        for port in open_ports:
            service = scan_data['tcp'][port]['name']
            print(f" Port {port}/tcp: {service}")
    else:
        print(COLORS["red"] + "[-] No open ports found" + COLORS["reset"])
    
    # Vulnerability Results
    print(COLORS["yellow"] + f"\n[*] Checking vulnerabilities on {host}..." + COLORS["reset"])
    vuln_found = False
    if 'tcp' in scan_data:
        for port in scan_data['tcp']:
            if 'script' in scan_data['tcp'][port]:
                print(COLORS["red"] + f"[!] Vulnerabilities on port {port}:" + COLORS["reset"])
                print(scan_data['tcp'][port]['script'])
                vuln_found = True
    if not vuln_found:
        print(COLORS["green"] + "[+] No vulnerabilities found" + COLORS["reset"])
    
    # OS Results
    print(COLORS["yellow"] + f"\n[*] OS detection for {host}..." + COLORS["reset"])
    if 'osclass' in scan_data:
        print(COLORS["green"] + "[+] Detected OS:" + COLORS["reset"])
        for osclass in scan_data['osclass']:
            print(f" - {osclass['osfamily']} ({osclass['accuracy']}% confidence)")
    else:
        print(COLORS["red"] + "[-] OS detection failed" + COLORS["reset"])

def main_menu():
    while True:
        print(COLORS["magenta"] + """
    [1] Full Network Recon
    [2] Target IP Scan
    [3] Vulnerability Scan
    [4] OS Detection
    [5] IP Address Tracer
    [6] Donate
    [8] Exit
        """ + COLORS["reset"])
        
        try:
            choice = input(COLORS["green"] + "[SIGMA_GHOST] > " + COLORS["reset"]).strip()
            
            if choice == '1':
                target = input(COLORS["yellow"] + "[+] Enter subnet (e.g. 192.168.1.0/24): " + COLORS["reset"]).strip()
                hosts = network_discovery(target)
                for host in hosts:
                    scan_data = comprehensive_scan(host)
                    if scan_data:
                        process_scan_results(host, scan_data)
                    
            elif choice == '2':
                target = input(COLORS["yellow"] + "[+] Enter target IP: " + COLORS["reset"]).strip()
                ports = input(COLORS["yellow"] + "[+] Port range (default 1-1000): " + COLORS["reset"]).strip() or '1-1000'
                scan_data = comprehensive_scan(target, ports)
                if scan_data:
                    process_scan_results(target, scan_data)
                
            elif choice == '3':
                target = input(COLORS["yellow"] + "[+] Enter target IP: " + COLORS["reset"]).strip()
                scan_data = comprehensive_scan(target)
                if scan_data:
                    vuln_found = False
                    if 'tcp' in scan_data:
                        for port in scan_data['tcp']:
                            if 'script' in scan_data['tcp'][port]:
                                print(COLORS["red"] + f"[!] Vulnerabilities on port {port}:" + COLORS["reset"])
                                print(scan_data['tcp'][port]['script'])
                                vuln_found = True
                    if not vuln_found:
                        print(COLORS["green"] + "[+] No vulnerabilities found" + COLORS["reset"])
                
            elif choice == '4':
                target = input(COLORS["yellow"] + "[+] Enter target IP: " + COLORS["reset"]).strip()
                scan_data = comprehensive_scan(target)
                if scan_data:
                    if 'osclass' in scan_data:
                        print(COLORS["green"] + "[+] Detected OS:" + COLORS["reset"])
                        for osclass in scan_data['osclass']:
                            print(f" - {osclass['osfamily']} ({osclass['accuracy']}% confidence)")
                    else:
                        print(COLORS["red"] + "[-] OS detection failed" + COLORS["reset"])
                
            elif choice == '5':
                target = input(COLORS["yellow"] + "[+] Enter IP to trace: " + COLORS["reset"]).strip()
                trace_ip(target)
                
            elif choice == '6':
                show_donation()
                
            elif choice == '8':
                print(COLORS["red"] + "\n[!] Exiting..." + COLORS["reset"])
                time.sleep(1)
                sys.exit()
                
            else:
                print(COLORS["red"] + "\n[-] Invalid option!" + COLORS["reset"])
                time.sleep(1)
                
            input("\nPress Enter to continue...")
            display_banner()

        except KeyboardInterrupt:
            print(COLORS["red"] + "\n[!] Operation cancelled" + COLORS["reset"])
            sys.exit()

if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            print(COLORS["red"] + "[-] Requires root privileges! Use sudo." + COLORS["reset"])
            sys.exit(1)
            
        display_banner()
        main_menu()
    except KeyboardInterrupt:
        print(COLORS["red"] + "\n[!] Operation cancelled" + COLORS["reset"])
        sys.exit()
