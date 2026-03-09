#!/usr/bin/env python3
import subprocess
import os
import time
from tqdm import tqdm
from colorama import Fore, init
from fpdf import FPDF

# Initialize Colorama for terminal colors
init(autoreset=True)

class PriViHardenElite:
    def __init__(self):
        self.score = 100
        self.logs = []
        self.banner = (
            f"\n{Fore.CYAN}  ██████╗ ██████╗ ██╗██╗   ██╗██╗███████╗███████╗ ██████╗\n"
            f"{Fore.CYAN}  ██╔══██╗██╔══██╗██║██║   ██║██║██╔════╝██╔════╝██╔════╝\n"
            f"{Fore.CYAN}  ██████╔╝██████╔╝██║██║   ██║██║███████╗█████╗  ██║     \n"
            f"{Fore.CYAN}  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝ ██║╚════██║██╔══╝  ██║     \n"
            f"{Fore.CYAN}  ██║     ██║  ██║██║ ╚████╔╝  ██║███████║███████╗╚██████╗\n"
            f"{Fore.RED}  PriViSecurity 🛡️ | ELITE HARDEN v11.0 | VERBOSE AUDIT MODE\n"
        )

    def verbose_check(self, name, command, expected, deduction):
        """Runs a check with a dedicated progress bar for high visibility."""
        with tqdm(total=100, desc=f"{Fore.WHITE}Checking {name[:15].ljust(15)}", bar_format="{l_bar}{bar:20}{r_bar}") as pbar:
            pbar.update(30)
            # Capture both output and errors
            res = subprocess.getoutput(command).strip()
            time.sleep(0.4) # Visual delay for the 'vibe'
            pbar.update(70)
            
            # Logic to determine if the result matches the secure 'expected' string
            is_secure = expected in res.lower() if res else False
            
            if not is_secure:
                self.score -= deduction
                status = f"{Fore.RED}[VULNERABLE]"
            else:
                status = f"{Fore.GREEN}[SECURE]"
            
            msg = f"{status} {name}: Found '{res if res else 'None'}'"
            self.logs.append(msg.strip())
            print(f"  {msg}")

    def run_network_audit(self, target):
        """Runs an aggressive Nmap scan to identify service versions and CVEs."""
        print(f"\n{Fore.YELLOW}[*] Starting Network Perimeter Analysis on {target}...")
        with tqdm(total=100, desc=f"{Fore.CYAN}Nmap Scan", bar_format="{l_bar}{bar:20}{r_bar}") as pbar:
            pbar.update(40)
            # -sV: Version detection, --script vuln: Check for vulnerabilities
            cmd = ["nmap", "-sV", "--script", "vuln", "-T4", target]
            try:
                res = subprocess.check_output(cmd).decode('utf-8', 'ignore')
                pbar.update(60)
                
                open_ports = res.count("open")
                vulns = res.count("VULNERABLE")
                self.score -= (open_ports * 5) + (vulns * 20)
                
                self.logs.append("\n--- NETWORK SCAN RESULTS ---")
                self.logs.append(res)
                print(f"{Fore.GREEN}[+] Network Scan Finished. Found {open_ports} ports and {vulns} vulnerabilities.")
            except Exception as e:
                print(f"{Fore.RED}[!] Nmap Error: {e}")

    def world_writable_check(self):
        """Finds dangerous files that have 777 (world-writable) permissions."""
        print(f"\n{Fore.YELLOW}[*] Scanning for Dangerous File Permissions (777)...")
        cmd = "find ~ -type f -perm 0777 2>/dev/null | head -n 5"
        self.verbose_check("File Permissions", cmd, "none", 15)

    def generate_pdf(self):
        """Finalizes the PDF report using the latin-1 encoding fix."""
        print(f"\n{Fore.MAGENTA}[*] Finalizing Encoded PDF Report...")
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, f"PriViHarden Elite Audit Report - Score: {self.score}/100", ln=True)
        pdf.set_font("Arial", size=10)
        
        # Encoding Fix: Prevents crash when Nmap output contains special characters
        full_text = "\n".join(self.logs)
        safe_text = full_text.encode('latin-1', 'replace').decode('latin-1')
        
        pdf.multi_cell(0, 7, txt=safe_text)
        pdf.output("PriViHarden_Elite_Report.pdf")
        print(f"{Fore.GREEN}[+] Report Created: {os.path.abspath('PriViHarden_Elite_Report.pdf')}")

if __name__ == "__main__":
    auditor = PriViHardenElite()
    print(auditor.banner)
    
    # OS Governance Checks
    auditor.verbose_check("SSH Root Login", "grep '^PermitRootLogin' /etc/ssh/sshd_config", "no", 15)
    auditor.verbose_check("IP Forwarding", "sysctl net.ipv4.ip_forward", "0", 10)
    auditor.verbose_check("Password Min Age", "grep '^PASS_MIN_DAYS' /etc/login.defs", "1", 5)
    
    # Permission Audits
    auditor.world_writable_check()
    
    # Network Audits
    target = input(f"\n{Fore.WHITE}Enter Target Host (default: localhost): ").strip() or "localhost"
    auditor.run_network_audit(target)
    
    # Report Generation
    auditor.generate_pdf()
            
