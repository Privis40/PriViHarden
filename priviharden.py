#!/usr/bin/env python3
import subprocess
import os
import sys
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
        # Fixed branding: Changed PriViSecurity to PriViHarden
        self.banner = (
            f"\n{Fore.CYAN}  ██████╗ ██████╗ ██╗██╗   ██╗██╗███████╗███████╗ ██████╗\n"
            f"{Fore.CYAN}  ██╔══██╗██╔══██╗██║██║   ██║██║██╔════╝██╔════╝██╔════╝\n"
            f"{Fore.CYAN}  ██████╔╝██████╔╝██║██║   ██║██║███████╗█████╗  ██║     \n"
            f"{Fore.CYAN}  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝ ██║╚════██║██╔══╝  ██║     \n"
            f"{Fore.CYAN}  ██║     ██║  ██║██║ ╚████╔╝  ██║███████║███████╗╚██████╗\n"
            f"{Fore.RED}  PriViHarden 🛡️ | ELITE HARDEN v11.0 | VERBOSE AUDIT MODE\n"
        )

    def check_privileges(self):
        """Ensure the script is running as root."""
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Error: This audit requires root/sudo privileges to read system configs.")
            sys.exit(1)

    def verbose_check(self, name, command, expected, deduction):
        """Runs a check with a dedicated progress bar."""
        with tqdm(total=100, desc=f"{Fore.WHITE}Checking {name[:15].ljust(15)}", bar_format="{l_bar}{bar:20}{r_bar}") as pbar:
            pbar.update(30)
            # Use shell=True for complex pipes, though generally we'd prefer list-based for safety
            res = subprocess.getoutput(command).strip()
            time.sleep(0.3) 
            pbar.update(70)
            
            # Logic: Ensure the result exists and contains the expected secure value
            is_secure = expected in res.lower() if res else False
            
            if not is_secure:
                self.score -= deduction
                status = f"{Fore.RED}[VULNERABLE]"
            else:
                status = f"{Fore.GREEN}[SECURE]"
            
            clean_res = res.replace('\n', ' ') if res else 'Not Found'
            msg = f"{status} {name}: Result '{clean_res}'"
            self.logs.append(msg.strip())
            print(f"  {msg}")

    def run_network_audit(self, target):
        """Runs Nmap scan to identify service versions and CVEs."""
        # Check if nmap is installed first
        if subprocess.call(["which", "nmap"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) != 0:
            print(f"{Fore.RED}[!] Nmap not found. Skipping network audit.")
            return

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
        """Finds dangerous files that have 777 permissions."""
        print(f"\n{Fore.YELLOW}[*] Scanning for Dangerous File Permissions (777)...")
        # Optimized to only look in home and ignore permission denied errors
        cmd = "find /home -type f -perm 0777 2>/dev/null | head -n 5"
        self.verbose_check("World Writable", cmd, "none", 15)

    def generate_pdf(self):
        """Finalizes the PDF report."""
        print(f"\n{Fore.MAGENTA}[*] Finalizing Encoded PDF Report...")
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, "PriViHarden Elite Audit Report", ln=True, align='C')
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, f"Final Security Score: {max(self.score, 0)}/100", ln=True, align='C')
        pdf.ln(10)
        
        pdf.set_font("Arial", size=10)
        full_text = "\n".join(self.logs)
        safe_text = full_text.encode('latin-1', 'replace').decode('latin-1')
        
        pdf.multi_cell(0, 7, txt=safe_text)
        report_name = "PriViHarden_Elite_Report.pdf"
        pdf.output(report_name)
        print(f"{Fore.GREEN}[+] Report Created: {os.path.abspath(report_name)}")

if __name__ == "__main__":
    auditor = PriViHardenElite()
    print(auditor.banner)
    
    # 1. Check for root privileges
    auditor.check_privileges()
    
    # 2. OS Governance Checks
    # Improved grep to ignore commented lines (^[^#]*)
    auditor.verbose_check("SSH Root Login", "grep '^[^#]*PermitRootLogin' /etc/ssh/sshd_config", "no", 15)
    auditor.verbose_check("IP Forwarding", "sysctl net.ipv4.ip_forward", "0", 10)
    auditor.verbose_check("Password Min Age", "grep '^[^#]*PASS_MIN_DAYS' /etc/login.defs", "1", 5)
    
    # 3. Permission Audits
    auditor.world_writable_check()
    
    # 4. Network Audits
    target = input(f"\n{Fore.WHITE}Enter Target Host (default: localhost): ").strip() or "localhost"
    auditor.run_network_audit(target)
    
    # 5. Report Generation
    auditor.generate_pdf()
