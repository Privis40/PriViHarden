#!/usr/bin/env python3
import os
import subprocess
import time
import sys
from colorama import Fore, Style, init
from fpdf import FPDF
from datetime import datetime

init(autoreset=True)


class PriViHarden:
    def __init__(self):
        # BUG FIX #10: Removed emoji from banner — UnicodeEncodeError on latin-1 terminals.
        self.banner = (
            f"\n{Fore.CYAN}  ██████╗ ██████╗ ██╗██╗   ██╗██╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗\n"
            f"{Fore.CYAN}  ██╔══██╗██╔══██╗██║██║   ██║██║██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝\n"
            f"{Fore.CYAN}  ██████╔╝██████╔╝██║██║   ██║██║███████║███████║██████╔╝██║  ██║█████╗  \n"
            f"{Fore.CYAN}  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝ ██║██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  \n"
            f"{Fore.CYAN}  ██║     ██║  ██║██║ ╚████╔╝  ██║██║  ██║██║  ██║██║  ██║██████╔╝███████╗\n"
            f"{Fore.RED}  PriViSecurity | Hardening Auditor v2.0 | Developed by Prince Ubebe\n"
            f"{Fore.YELLOW}  {'=' * 82}\n"
        )
        self.results = []
        self.score = 100

    def progress_bar(self, task_name, duration=0.4):
        # BUG FIX #13: Reduced default duration from 1.5s to 0.4s per check.
        # 4 checks x 1.5s = 6 seconds of pure artificial waiting added nothing.
        sys.stdout.write(f"{Fore.WHITE}[*] {task_name.ljust(35)}")
        for i in range(21):
            time.sleep(duration / 20)
            sys.stdout.write(f"{Fore.CYAN}█")
            sys.stdout.flush()
        sys.stdout.write(f"{Fore.GREEN} Done!\n")

    def audit_ssh(self):
        self.progress_bar("Analyzing SSH Configuration")
        # Secure value expected for each directive
        checks = {
            "PermitRootLogin":        "no",
            "PasswordAuthentication": "no",
            "Protocol":               "2"
        }
        path = "/etc/ssh/sshd_config"
        # BUG FIX #6: Wrapped file open in try/except — PermissionError or
        # IOError previously crashed the entire audit with no message.
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
        except (PermissionError, IOError, FileNotFoundError) as e:
            self.results.append((f"SSH config unreadable: {e}", "WARN", 10))
            self.score -= 10
            return

        # BUG FIX #1: Original checked f"{key} {val}" against the whole file
        # content — this matched commented lines like "#PermitRootLogin no"
        # as passing even though they have no effect. Now only checks
        # non-commented, active directive lines.
        active = {}
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#') or not stripped:
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                active[parts[0]] = parts[1]

        for key, secure_val in checks.items():
            current = active.get(key, "").lower()
            if current == secure_val:
                self.results.append((f"SSH {key} is hardened", "PASS", 0))
            else:
                detail = f"(found: '{current}')" if current else "(not set — default applies)"
                self.results.append((f"SSH {key} weak {detail}", "FAIL", 15))
                self.score -= 15

    def audit_kernel(self):
        self.progress_bar("Auditing Kernel Parameters")
        # BUG FIX #2: Original accepted val == "0" OR "1" for BOTH params,
        # meaning insecure values could pass. Each param has its own correct value:
        # accept_redirects = 0 (disabled) is secure
        # icmp_echo_ignore_broadcasts = 1 (ignored) is secure
        params = {
            "net.ipv4.conf.all.accept_redirects":      "0",
            "net.ipv4.icmp_echo_ignore_broadcasts":    "1",
        }
        for param, secure_val in params.items():
            try:
                # BUG FIX #7: Validate sysctl output format before splitting.
                # Unexpected output (error message, empty) gave wrong result silently.
                raw = subprocess.getoutput(f"sysctl {param}")
                if '=' not in raw:
                    self.results.append((f"Kernel: {param} unreadable", "WARN", 5))
                    self.score -= 5
                    continue
                val = raw.split('=')[-1].strip()
                if val == secure_val:
                    self.results.append((f"Kernel {param}", "PASS", 0))
                else:
                    self.results.append((f"Kernel {param} = {val} (should be {secure_val})", "FAIL", 5))
                    self.score -= 5
            except Exception as e:
                self.results.append((f"Kernel check error: {e}", "WARN", 0))

    def audit_users(self):
        self.progress_bar("Deep Scanning for Ghost Admins")
        cmd = "awk -F: '($3 == 0) { print $1 }' /etc/passwd"
        output = subprocess.getoutput(cmd)
        # BUG FIX #8: strip() before split prevents trailing newline from
        # producing a phantom empty-string entry that triggered false CRITICAL.
        admins = [a for a in output.strip().split('\n') if a]
        if len(admins) > 1:
            self.results.append((f"Multiple UID 0 users: {', '.join(admins)}", "CRITICAL", 30))
            self.score -= 30
        else:
            self.results.append(("No shadow admin accounts found", "PASS", 0))

    def audit_ports(self):
        self.progress_bar("Checking Unauthorized Ports")
        output = subprocess.getoutput("ss -tulpn")
        # BUG FIX #3: Whole-string search matched "ftp" inside "sftp" (secure),
        # and "rsh" inside service names. Now checks for the service name followed
        # by a non-word boundary to avoid false positives.
        insecure = {
            "telnet":  23,
            "ftp":     21,
            "rlogin":  513,
            "rsh":     514,
            "rexec":   512,
        }
        found = False
        for service, port in insecure.items():
            # Match the port number directly — more reliable than service name substring
            if f":{port} " in output or f":{port}\t" in output:
                self.results.append((f"Insecure port open: {service} (:{port})", "FAIL", 20))
                self.score -= 20
                found = True
        if not found:
            self.results.append(("No insecure legacy services detected", "PASS", 0))

    def generate_pdf(self):
        # BUG FIX #9: Show final score in terminal too — previously max(0,...) only
        # applied inside PDF. User never saw their score printed to screen.
        final_score = max(0, self.score)
        color = Fore.GREEN if final_score >= 80 else Fore.YELLOW if final_score >= 50 else Fore.RED
        print(f"\n{color}[*] Final Security Score: {final_score}/100")
        print(f"{Fore.YELLOW}[*] Finalizing PDF Report...")

        pdf = FPDF()
        pdf.add_page()

        # Header
        pdf.set_font("Arial", "B", 20)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 15, "SYSTEM HARDENING AUDIT REPORT", ln=True, align="C")

        # Score
        score_color = (0, 150, 0) if final_score >= 80 else (200, 150, 0) if final_score >= 50 else (200, 0, 0)
        pdf.set_font("Arial", "B", 14)
        pdf.set_text_color(*score_color)
        pdf.cell(0, 10, f"Final Security Score: {final_score}/100", ln=True, align="C")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(10)

        # Table header
        pdf.set_font("Arial", "B", 10)
        pdf.set_fill_color(220, 220, 220)
        pdf.cell(120, 10, "Security Check", 1, fill=True)
        pdf.cell(35, 10, "Status", 1, fill=True)
        pdf.cell(35, 10, "Penalty", 1, ln=True, fill=True)

        # BUG FIX #5: Replaced pdf.cell() with pdf.multi_cell() for audit rows.
        # cell() silently clips text that exceeds 120pt width — long check names
        # were cut off. multi_cell() wraps text and keeps all content visible.
        # Because multi_cell resets X, we use a manual row approach instead.
        pdf.set_font("Arial", "", 9)
        for item, status, penalty in self.results:
            status_color = {
                "PASS": (0, 128, 0),
                "FAIL": (200, 0, 0),
                "WARN": (200, 140, 0),
                "CRITICAL": (180, 0, 0),
            }.get(status, (0, 0, 0))

            # Save Y position for row alignment
            y = pdf.get_y()
            pdf.set_xy(10, y)
            pdf.multi_cell(120, 8, item, border=1)
            row_h = pdf.get_y() - y

            pdf.set_xy(130, y)
            pdf.set_text_color(*status_color)
            pdf.cell(35, row_h, status, border=1)
            pdf.set_text_color(0, 0, 0)
            pdf.set_xy(165, y)
            pdf.cell(35, row_h, f"-{penalty}", border=1, ln=True)

        # Footer
        pdf.ln(10)
        pdf.set_font("Arial", "I", 8)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        # BUG FIX #4: Removed emoji from PDF footer — fpdf latin-1 encoding crash.
        pdf.cell(0, 10, "Powered by PriViSecurity | Developed by Prince Ubebe", ln=True, align="C")

        # BUG FIX #12: Added date to filename — time-only %H%M%S meant two scans
        # in the same second would overwrite each other.
        filename = f"PriViHarden_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf.output(filename)
        print(f"{Fore.GREEN}[+] Report saved: {filename}")


if __name__ == "__main__":
    auditor = PriViHarden()
    print(auditor.banner)

    if os.getuid() != 0:
        print(f"{Fore.RED}[!] ACCESS DENIED: Please run with 'sudo' for a deep system scan.")
        # BUG FIX #11: Added sys.exit(1) — without it execution falls through
        # to the audit calls below which then fail with permission errors.
        sys.exit(1)

    auditor.audit_ssh()
    auditor.audit_kernel()
    auditor.audit_users()
    auditor.audit_ports()
    auditor.generate_pdf()
    print(f"\n{Fore.CYAN}[*] Hardening Audit Complete. Stay Secure.")
                                                           
