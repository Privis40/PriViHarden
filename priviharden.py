#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       PriViHarden Linux Vulnerability Auditor v2.0               ║
║       Linux Hardening & Security Configuration Auditor           ║
║       Developed by Prince Ubebe | PriViSecurity                  ║
╚══════════════════════════════════════════════════════════════════╝

LEGAL NOTICE:
  This tool audits the local system's security configuration.
  It must be run on systems you own or have explicit written
  authorization to audit. PriViSecurity accepts no liability
  for unauthorized use.
"""

import os
import sys
import subprocess
import time
from datetime import datetime
from fpdf import FPDF

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.live import Live
from rich.layout import Layout

console = Console()

AUTHOR  = "Prince Ubebe"
BRAND   = "PriViSecurity"
VERSION = "2.0"
TOOL    = "PriViHarden Linux Auditor"


# ── HEADER ────────────────────────────────────────────────────────────────────

def print_header():
    os.system("clear")
    header = Text()
    header.append(
        "\n"
        "  ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗\n"
        "  ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║\n"
        "  ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║\n"
        "  ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║\n"
        "  ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║\n"
        "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝\n",
        style="bold cyan"
    )
    header.append(
        f"  {BRAND}  |  {TOOL} v{VERSION}  |  Linux Security Configuration Audit\n",
        style="dim white"
    )
    header.append(f"  Developer: {AUTHOR}  |  Authorized Use Only\n", style="dim red")
    console.print(Panel(header, border_style="blue"))


# ── HELPERS ───────────────────────────────────────────────────────────────────

def run_cmd(cmd: str) -> str:
    """Run a shell command and return stdout. Never raises."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


def file_read(path: str) -> str:
    """Read a file safely. Returns empty string on failure."""
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception:
        return ""


# ── CHECK ENGINE ──────────────────────────────────────────────────────────────

class CheckResult:
    def __init__(self, name: str, category: str, status: str,
                 detail: str, deduction: int, recommendation: str):
        self.name           = name
        self.category       = category
        self.status         = status        # "SECURE" | "VULNERABLE" | "WARNING" | "INFO"
        self.detail         = detail
        self.deduction      = deduction
        self.recommendation = recommendation


class PriViHarden:
    def __init__(self):
        self.score   = 100
        self.results = []

    def _add(self, name: str, category: str, status: str,
             detail: str, deduction: int, recommendation: str):
        if status == "VULNERABLE":
            self.score = max(0, self.score - deduction)
        elif status == "WARNING":
            self.score = max(0, self.score - (deduction // 2))
        self.results.append(CheckResult(
            name, category, status, detail, deduction, recommendation
        ))

    # ── SSH CONFIGURATION ─────────────────────────────────────────────────────

    def check_ssh_root_login(self):
        out = run_cmd("grep -i '^[^#]*PermitRootLogin' /etc/ssh/sshd_config")
        if not out:
            self._add(
                "SSH Root Login", "SSH Configuration", "WARNING",
                "PermitRootLogin not explicitly set — defaults may apply",
                8,
                "Add 'PermitRootLogin no' to /etc/ssh/sshd_config and restart sshd."
            )
        elif "no" in out.lower():
            self._add(
                "SSH Root Login", "SSH Configuration", "SECURE",
                f"PermitRootLogin disabled: {out}", 0,
                "No action required."
            )
        else:
            self._add(
                "SSH Root Login", "SSH Configuration", "VULNERABLE",
                f"Root login permitted: {out}", 15,
                "Set 'PermitRootLogin no' in /etc/ssh/sshd_config. "
                "Use a non-root account with sudo instead."
            )

    def check_ssh_password_auth(self):
        out = run_cmd("grep -i '^[^#]*PasswordAuthentication' /etc/ssh/sshd_config")
        if not out:
            self._add(
                "SSH Password Auth", "SSH Configuration", "WARNING",
                "PasswordAuthentication not explicitly configured",
                8,
                "Set 'PasswordAuthentication no' and enforce key-based authentication."
            )
        elif "no" in out.lower():
            self._add(
                "SSH Password Auth", "SSH Configuration", "SECURE",
                "Password authentication disabled — keys only", 0,
                "No action required."
            )
        else:
            self._add(
                "SSH Password Auth", "SSH Configuration", "VULNERABLE",
                f"Password authentication enabled: {out}", 12,
                "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config. "
                "Ensure all users have SSH keys configured before applying."
            )

    def check_ssh_max_auth_tries(self):
        out = run_cmd("grep -i '^[^#]*MaxAuthTries' /etc/ssh/sshd_config")
        if not out:
            self._add(
                "SSH MaxAuthTries", "SSH Configuration", "WARNING",
                "MaxAuthTries not set — default is 6 (too high)",
                5,
                "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config to limit brute-force attempts."
            )
        else:
            try:
                val = int(out.split()[-1])
                if val <= 3:
                    self._add(
                        "SSH MaxAuthTries", "SSH Configuration", "SECURE",
                        f"MaxAuthTries = {val} (acceptable)", 0,
                        "No action required."
                    )
                elif val <= 6:
                    self._add(
                        "SSH MaxAuthTries", "SSH Configuration", "WARNING",
                        f"MaxAuthTries = {val} (should be ≤ 3)", 5,
                        f"Reduce MaxAuthTries to 3 in /etc/ssh/sshd_config."
                    )
                else:
                    self._add(
                        "SSH MaxAuthTries", "SSH Configuration", "VULNERABLE",
                        f"MaxAuthTries = {val} (too high — brute-force risk)", 10,
                        "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config."
                    )
            except (ValueError, IndexError):
                self._add(
                    "SSH MaxAuthTries", "SSH Configuration", "INFO",
                    f"Could not parse MaxAuthTries value: {out}", 0,
                    "Manually verify MaxAuthTries setting."
                )

    def check_ssh_protocol(self):
        out = run_cmd("grep -i '^[^#]*Protocol' /etc/ssh/sshd_config")
        if out and "1" in out:
            self._add(
                "SSH Protocol Version", "SSH Configuration", "VULNERABLE",
                f"SSHv1 may be enabled: {out}", 20,
                "Remove or comment the 'Protocol' line — modern OpenSSH defaults "
                "to Protocol 2 only. Explicitly add 'Protocol 2' if needed."
            )
        else:
            self._add(
                "SSH Protocol Version", "SSH Configuration", "SECURE",
                "SSHv1 not explicitly enabled — SSHv2 in use", 0,
                "No action required."
            )

    # ── KERNEL & NETWORK HARDENING ────────────────────────────────────────────

    def check_ip_forwarding(self):
        out = run_cmd("sysctl net.ipv4.ip_forward")
        if "= 0" in out:
            self._add(
                "IP Forwarding", "Kernel Hardening", "SECURE",
                "IP forwarding disabled", 0,
                "No action required."
            )
        else:
            self._add(
                "IP Forwarding", "Kernel Hardening", "VULNERABLE",
                f"IP forwarding enabled: {out}", 10,
                "Set 'net.ipv4.ip_forward = 0' in /etc/sysctl.conf "
                "and run 'sysctl -p' unless this is a router/VPN gateway."
            )

    def check_icmp_redirects(self):
        out = run_cmd("sysctl net.ipv4.conf.all.accept_redirects")
        if "= 0" in out:
            self._add(
                "ICMP Redirects", "Kernel Hardening", "SECURE",
                "ICMP redirect acceptance disabled", 0,
                "No action required."
            )
        else:
            self._add(
                "ICMP Redirects", "Kernel Hardening", "VULNERABLE",
                f"ICMP redirects accepted: {out}", 8,
                "Set 'net.ipv4.conf.all.accept_redirects = 0' in /etc/sysctl.conf. "
                "Acceptance of ICMP redirects can be abused for MITM attacks."
            )

    def check_syn_cookies(self):
        out = run_cmd("sysctl net.ipv4.tcp_syncookies")
        if "= 1" in out:
            self._add(
                "SYN Cookies", "Kernel Hardening", "SECURE",
                "SYN cookies enabled — SYN flood protection active", 0,
                "No action required."
            )
        else:
            self._add(
                "SYN Cookies", "Kernel Hardening", "VULNERABLE",
                f"SYN cookies disabled: {out}", 8,
                "Set 'net.ipv4.tcp_syncookies = 1' in /etc/sysctl.conf "
                "to protect against SYN flood denial-of-service attacks."
            )

    def check_aslr(self):
        out = run_cmd("sysctl kernel.randomize_va_space")
        if "= 2" in out:
            self._add(
                "ASLR", "Kernel Hardening", "SECURE",
                "Full ASLR enabled (randomize_va_space = 2)", 0,
                "No action required."
            )
        elif "= 1" in out:
            self._add(
                "ASLR", "Kernel Hardening", "WARNING",
                "Partial ASLR only (randomize_va_space = 1)", 5,
                "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.conf "
                "for full ASLR including heap randomization."
            )
        else:
            self._add(
                "ASLR", "Kernel Hardening", "VULNERABLE",
                f"ASLR disabled or not configured: {out}", 12,
                "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.conf. "
                "ASLR is a critical memory exploitation mitigation."
            )

    def check_core_dumps(self):
        out = run_cmd("ulimit -c")
        sysctl_out = run_cmd("sysctl kernel.core_pattern")
        if out == "0":
            self._add(
                "Core Dumps", "Kernel Hardening", "SECURE",
                "Core dumps disabled for current session", 0,
                "Also set '* hard core 0' in /etc/security/limits.conf "
                "to persist across all sessions."
            )
        else:
            self._add(
                "Core Dumps", "Kernel Hardening", "WARNING",
                f"Core dumps may be enabled (ulimit -c: {out})", 5,
                "Add '* hard core 0' and '* soft core 0' to /etc/security/limits.conf. "
                "Core dumps can expose sensitive memory contents."
            )

    # ── USER & PASSWORD POLICY ────────────────────────────────────────────────

    def check_password_min_age(self):
        out = run_cmd("grep '^PASS_MIN_DAYS' /etc/login.defs")
        try:
            val = int(out.split()[-1])
            if val >= 1:
                self._add(
                    "Password Min Age", "Password Policy", "SECURE",
                    f"PASS_MIN_DAYS = {val} — minimum age enforced", 0,
                    "No action required."
                )
            else:
                self._add(
                    "Password Min Age", "Password Policy", "WARNING",
                    f"PASS_MIN_DAYS = {val} — no minimum age enforced", 5,
                    "Set 'PASS_MIN_DAYS 1' in /etc/login.defs to prevent "
                    "immediate password recycling."
                )
        except Exception:
            self._add(
                "Password Min Age", "Password Policy", "WARNING",
                "PASS_MIN_DAYS not configured in /etc/login.defs", 5,
                "Add 'PASS_MIN_DAYS 1' to /etc/login.defs."
            )

    def check_password_max_age(self):
        out = run_cmd("grep '^PASS_MAX_DAYS' /etc/login.defs")
        try:
            val = int(out.split()[-1])
            if val <= 90:
                self._add(
                    "Password Max Age", "Password Policy", "SECURE",
                    f"PASS_MAX_DAYS = {val} — rotation enforced", 0,
                    "No action required."
                )
            elif val <= 180:
                self._add(
                    "Password Max Age", "Password Policy", "WARNING",
                    f"PASS_MAX_DAYS = {val} — consider reducing to 90 days", 5,
                    "Set 'PASS_MAX_DAYS 90' in /etc/login.defs."
                )
            else:
                self._add(
                    "Password Max Age", "Password Policy", "VULNERABLE",
                    f"PASS_MAX_DAYS = {val} — passwords rarely rotated", 8,
                    "Set 'PASS_MAX_DAYS 90' in /etc/login.defs to enforce rotation."
                )
        except Exception:
            self._add(
                "Password Max Age", "Password Policy", "WARNING",
                "PASS_MAX_DAYS not configured", 5,
                "Add 'PASS_MAX_DAYS 90' to /etc/login.defs."
            )

    def check_password_complexity(self):
        pwquality = run_cmd("grep -r 'minlen' /etc/security/pwquality.conf 2>/dev/null")
        pam_check = run_cmd("grep -r 'pam_pwquality' /etc/pam.d/ 2>/dev/null")
        if pwquality or pam_check:
            self._add(
                "Password Complexity", "Password Policy", "SECURE",
                "pam_pwquality configured — complexity enforced", 0,
                "Verify minlen >= 12 and dcredit/ucredit/lcredit/ocredit are set."
            )
        else:
            self._add(
                "Password Complexity", "Password Policy", "VULNERABLE",
                "pam_pwquality not configured — no complexity requirements", 10,
                "Install libpam-pwquality and configure /etc/security/pwquality.conf. "
                "Set minlen=12, dcredit=-1, ucredit=-1, ocredit=-1, lcredit=-1."
            )

    def check_empty_passwords(self):
        out = run_cmd("awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null")
        if out:
            self._add(
                "Empty Passwords", "Password Policy", "VULNERABLE",
                f"Accounts with empty passwords: {out}", 20,
                f"Immediately set passwords for: {out}. "
                "Run: passwd <username> for each account listed."
            )
        else:
            self._add(
                "Empty Passwords", "Password Policy", "SECURE",
                "No accounts with empty passwords found", 0,
                "No action required."
            )

    # ── FILE SYSTEM SECURITY ──────────────────────────────────────────────────

    def check_world_writable(self):
        out = run_cmd(
            "find / -xdev -type f -perm -0002 "
            "! -path '/proc/*' ! -path '/sys/*' "
            "2>/dev/null | head -10"
        )
        if not out:
            self._add(
                "World-Writable Files", "File System", "SECURE",
                "No world-writable files found", 0,
                "No action required."
            )
        else:
            count = len(out.splitlines())
            self._add(
                "World-Writable Files", "File System", "VULNERABLE",
                f"{count} world-writable file(s) found — first results:\n{out[:200]}", 12,
                "Review and remove world-write permissions: chmod o-w <file>. "
                "World-writable files allow any user to modify critical content."
            )

    def check_suid_binaries(self):
        out = run_cmd(
            "find / -xdev -type f -perm -4000 "
            "! -path '/proc/*' ! -path '/sys/*' "
            "2>/dev/null"
        )
        known_safe = {
            "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
            "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
            "/usr/bin/chfn", "/bin/mount", "/bin/umount", "/bin/ping",
        }
        suid_files = [f for f in out.splitlines() if f.strip()]
        unexpected = [f for f in suid_files if f not in known_safe]

        if not unexpected:
            self._add(
                "SUID Binaries", "File System", "SECURE",
                f"{len(suid_files)} SUID binary(ies) found — all appear standard", 0,
                "Periodically audit SUID binaries with: "
                "find / -perm -4000 -type f 2>/dev/null"
            )
        else:
            self._add(
                "SUID Binaries", "File System", "WARNING",
                f"{len(unexpected)} unexpected SUID binary(ies):\n"
                + "\n".join(unexpected[:8]), 8,
                "Review unexpected SUID binaries and remove the bit if unnecessary: "
                "chmod u-s <file>. Unnecessary SUID binaries are a privilege escalation risk."
            )

    def check_passwd_permissions(self):
        out = run_cmd("stat -c '%a %U %G' /etc/passwd")
        if out.startswith("644"):
            self._add(
                "/etc/passwd Permissions", "File System", "SECURE",
                f"/etc/passwd permissions: {out}", 0,
                "No action required."
            )
        else:
            self._add(
                "/etc/passwd Permissions", "File System", "VULNERABLE",
                f"/etc/passwd has unexpected permissions: {out}", 10,
                "Run: chmod 644 /etc/passwd && chown root:root /etc/passwd"
            )

    def check_shadow_permissions(self):
        out = run_cmd("stat -c '%a %U %G' /etc/shadow")
        # Acceptable: 640 root:shadow or 000 root:root or 600 root:root
        acceptable = ["640", "600", "000", "400"]
        perms = out.split()[0] if out else ""
        if perms in acceptable:
            self._add(
                "/etc/shadow Permissions", "File System", "SECURE",
                f"/etc/shadow permissions: {out}", 0,
                "No action required."
            )
        else:
            self._add(
                "/etc/shadow Permissions", "File System", "VULNERABLE",
                f"/etc/shadow has overly permissive settings: {out}", 15,
                "Run: chmod 640 /etc/shadow && chown root:shadow /etc/shadow. "
                "Weak shadow permissions expose password hashes."
            )

    # ── SERVICES & FIREWALL ───────────────────────────────────────────────────

    def check_firewall(self):
        # Check UFW first, then iptables
        ufw_out = run_cmd("ufw status 2>/dev/null")
        if "active" in ufw_out.lower():
            self._add(
                "Firewall (UFW)", "Services & Firewall", "SECURE",
                "UFW firewall is active", 0,
                "No action required. Review rules with: ufw status verbose"
            )
            return

        ipt_out = run_cmd("iptables -L 2>/dev/null | grep -v '^Chain\\|^target\\|^$'")
        if ipt_out:
            self._add(
                "Firewall (iptables)", "Services & Firewall", "SECURE",
                "iptables rules are active", 0,
                "No action required. Verify rules with: iptables -L -v -n"
            )
        else:
            self._add(
                "Firewall", "Services & Firewall", "VULNERABLE",
                "No active firewall detected (UFW inactive, iptables empty)", 15,
                "Enable UFW: ufw enable && ufw default deny incoming && "
                "ufw allow ssh. A firewall is essential for any internet-facing system."
            )

    def check_telnet(self):
        out = run_cmd("systemctl is-active telnet 2>/dev/null || "
                      "service telnet status 2>/dev/null || "
                      "which telnetd 2>/dev/null")
        if "active" in out.lower() or "telnetd" in out.lower():
            self._add(
                "Telnet Service", "Services & Firewall", "VULNERABLE",
                "Telnet service appears active or installed", 15,
                "Disable and remove Telnet immediately: "
                "systemctl disable --now telnet && apt remove telnetd. "
                "Telnet transmits credentials in plaintext."
            )
        else:
            self._add(
                "Telnet Service", "Services & Firewall", "SECURE",
                "Telnet service not active", 0,
                "No action required."
            )

    def check_rsh_rlogin(self):
        rsh  = run_cmd("which rsh 2>/dev/null")
        rlog = run_cmd("which rlogin 2>/dev/null")
        if rsh or rlog:
            self._add(
                "rsh / rlogin", "Services & Firewall", "VULNERABLE",
                f"Legacy r-tools present: rsh={rsh or 'not found'}, "
                f"rlogin={rlog or 'not found'}", 12,
                "Remove rsh and rlogin: apt remove rsh-client rsh-server. "
                "These tools transmit credentials in plaintext and have no legitimate use."
            )
        else:
            self._add(
                "rsh / rlogin", "Services & Firewall", "SECURE",
                "rsh and rlogin not installed", 0,
                "No action required."
            )

    def check_cron_permissions(self):
        out = run_cmd("stat -c '%a %U %G' /etc/cron.d 2>/dev/null")
        if not out:
            self._add(
                "Cron Permissions", "Services & Firewall", "INFO",
                "/etc/cron.d not found or not accessible", 0,
                "Verify cron directory permissions manually."
            )
            return
        perms = out.split()[0] if out else ""
        if perms in ["700", "755", "750"]:
            self._add(
                "Cron Permissions", "Services & Firewall", "SECURE",
                f"/etc/cron.d permissions: {out}", 0,
                "No action required."
            )
        else:
            self._add(
                "Cron Permissions", "Services & Firewall", "WARNING",
                f"/etc/cron.d has unexpected permissions: {out}", 5,
                "Run: chmod 755 /etc/cron.d && chown root:root /etc/cron.d. "
                "Loose cron permissions allow unprivileged users to inject jobs."
            )

    # ── LOGGING & AUDITING ────────────────────────────────────────────────────

    def check_auditd(self):
        out = run_cmd("systemctl is-active auditd 2>/dev/null")
        if "active" in out.lower():
            self._add(
                "auditd", "Logging & Auditing", "SECURE",
                "auditd is running — system call auditing active", 0,
                "No action required. Review rules with: auditctl -l"
            )
        else:
            self._add(
                "auditd", "Logging & Auditing", "WARNING",
                f"auditd not running: {out}", 5,
                "Install and enable auditd: apt install auditd && "
                "systemctl enable --now auditd. "
                "auditd provides critical forensic logging capability."
            )

    def check_syslog(self):
        rsyslog = run_cmd("systemctl is-active rsyslog 2>/dev/null")
        syslogd = run_cmd("systemctl is-active syslog 2>/dev/null")
        if "active" in rsyslog.lower() or "active" in syslogd.lower():
            self._add(
                "Syslog", "Logging & Auditing", "SECURE",
                "Syslog daemon is active — system events being logged", 0,
                "No action required."
            )
        else:
            self._add(
                "Syslog", "Logging & Auditing", "VULNERABLE",
                "No active syslog daemon detected", 8,
                "Install and enable rsyslog: apt install rsyslog && "
                "systemctl enable --now rsyslog. "
                "Without syslog, system events and errors are not captured."
            )

    # ── RUN ALL CHECKS ────────────────────────────────────────────────────────

    def run_all(self):
        checks = [
            # SSH
            self.check_ssh_root_login,
            self.check_ssh_password_auth,
            self.check_ssh_max_auth_tries,
            self.check_ssh_protocol,
            # Kernel
            self.check_ip_forwarding,
            self.check_icmp_redirects,
            self.check_syn_cookies,
            self.check_aslr,
            self.check_core_dumps,
            # Password
            self.check_password_min_age,
            self.check_password_max_age,
            self.check_password_complexity,
            self.check_empty_passwords,
            # File system
            self.check_world_writable,
            self.check_suid_binaries,
            self.check_passwd_permissions,
            self.check_shadow_permissions,
            # Services & firewall
            self.check_firewall,
            self.check_telnet,
            self.check_rsh_rlogin,
            self.check_cron_permissions,
            # Logging
            self.check_auditd,
            self.check_syslog,
        ]

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=35, style="cyan"),
            TextColumn("[bold white]{task.percentage:>3.0f}%"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "[cyan]Running security checks...", total=len(checks)
            )
            for check_fn in checks:
                progress.update(
                    task,
                    description=f"[cyan]Checking: {check_fn.__name__.replace('check_', '').replace('_', ' ').title()}"
                )
                check_fn()
                progress.advance(task)
                time.sleep(0.05)


# ── SCORING ───────────────────────────────────────────────────────────────────

def get_grade(score: int) -> tuple:
    if score >= 85:
        return "A — LOW RISK",      "bold green"
    elif score >= 70:
        return "B — MODERATE RISK", "bold yellow"
    elif score >= 50:
        return "C — HIGH RISK",     "bold red"
    else:
        return "D — CRITICAL RISK", "bold red"


# ── DISPLAY ───────────────────────────────────────────────────────────────────

def display_results(auditor: PriViHarden):
    score = max(0, auditor.score)
    grade, color = get_grade(score)

    # Score panel
    score_text = Text()
    score_text.append(f"\n  Security Score:  ", style="bold white")
    score_text.append(f"{score}/100\n", style=color)
    score_text.append(f"  Grade:          ", style="bold white")
    score_text.append(f"{grade}\n\n", style=color)

    vulns   = sum(1 for r in auditor.results if r.status == "VULNERABLE")
    warnings = sum(1 for r in auditor.results if r.status == "WARNING")
    secure  = sum(1 for r in auditor.results if r.status == "SECURE")

    score_text.append(f"  Vulnerable:  {vulns}  |  ", style="bold red")
    score_text.append(f"Warnings:  {warnings}  |  ", style="bold yellow")
    score_text.append(f"Secure:  {secure}\n", style="bold green")

    console.print(Panel(score_text, border_style="blue",
                        title="[bold cyan]Audit Score[/bold cyan]"))

    # Group by category
    categories = {}
    for r in auditor.results:
        categories.setdefault(r.category, []).append(r)

    status_styles = {
        "SECURE":     "[bold green]SECURE[/bold green]",
        "VULNERABLE": "[bold red]VULNERABLE[/bold red]",
        "WARNING":    "[bold yellow]WARNING[/bold yellow]",
        "INFO":       "[dim]INFO[/dim]",
    }

    for cat, checks in categories.items():
        table = Table(
            title=f"[bold cyan]{cat}[/bold cyan]",
            border_style="blue", show_lines=True
        )
        table.add_column("Check",   style="bold white", width=28)
        table.add_column("Status",  width=14)
        table.add_column("-Pts",    style="dim red",    width=6)
        table.add_column("Detail",  style="dim white")

        for r in checks:
            detail = r.detail.replace("\n", " ")[:80]
            table.add_row(
                r.name,
                status_styles.get(r.status, r.status),
                str(r.deduction) if r.status == "VULNERABLE" else
                str(r.deduction // 2) if r.status == "WARNING" else "0",
                detail
            )
        console.print(table)

    # Recommendations for non-secure checks
    non_secure = [r for r in auditor.results if r.status in ("VULNERABLE", "WARNING")]
    if non_secure:
        rec_text = Text()
        rec_text.append("Remediation Recommendations\n\n", style="bold white")
        for i, r in enumerate(non_secure, 1):
            rec_text.append(f"  {i}. [{r.status}] {r.name}\n", style="bold yellow")
            rec_text.append(f"     {r.recommendation}\n\n", style="white")
        console.print(Panel(rec_text, border_style="green",
                            title="[bold green]Recommendations[/bold green]"))


# ── PDF REPORT ────────────────────────────────────────────────────────────────

class HardenReport(FPDF):
    def header(self):
        self.set_fill_color(26, 26, 46)
        self.rect(0, 0, 210, 38, "F")
        self.set_xy(10, 8)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "PriViHarden Linux Security Audit Report", ln=True)
        self.set_xy(10, 20)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(180, 180, 180)
        self.cell(0, 8,
                  f"PriViSecurity  |  Analyst: {AUTHOR}  |  {TOOL} v{VERSION}",
                  ln=True)
        self.ln(18)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(
            0, 10,
            f"Page {self.page_no()}  —  Confidential: Authorized Use Only  —  PriViSecurity",
            align="C"
        )

    def section_title(self, title: str):
        self.set_fill_color(196, 30, 58)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", fill=True, ln=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)


def generate_pdf(auditor: PriViHarden) -> str:
    score     = max(0, auditor.score)
    grade, _  = get_grade(score)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname  = run_cmd("hostname")
    filename  = f"PriViHarden_Audit_{hostname}_{timestamp}.pdf"

    pdf = HardenReport()
    pdf.add_page()

    # Summary
    pdf.section_title("1. Audit Summary")
    pdf.set_font("Helvetica", "", 9)
    rows = [
        ("Host",         hostname),
        ("Audit Date",   datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Analyst",      AUTHOR),
        ("Tool",         f"{TOOL} v{VERSION}"),
        ("Total Checks", str(len(auditor.results))),
        ("Vulnerable",   str(sum(1 for r in auditor.results if r.status == "VULNERABLE"))),
        ("Warnings",     str(sum(1 for r in auditor.results if r.status == "WARNING"))),
        ("Secure",       str(sum(1 for r in auditor.results if r.status == "SECURE"))),
        ("Score",        f"{score}/100"),
        ("Grade",        grade),
    ]
    for k, v in rows:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(50, 7, f"  {k}:", ln=False)
        pdf.set_font("Helvetica", "", 9)
        is_risk = k == "Grade" and "CRITICAL" in v or "HIGH" in v
        pdf.set_text_color(196, 30, 58) if is_risk else pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 7, v, ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # Score bar
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(50, 7, "  Security Score Bar:", ln=False)
    bx = pdf.get_x()
    by = pdf.get_y()
    pdf.set_fill_color(220, 220, 220)
    pdf.rect(bx, by + 1, 100, 5, "F")
    if score >= 85:
        pdf.set_fill_color(30, 180, 60)
    elif score >= 70:
        pdf.set_fill_color(200, 160, 0)
    else:
        pdf.set_fill_color(196, 30, 58)
    pdf.rect(bx, by + 1, score, 5, "F")
    pdf.ln(10)

    # Detailed findings grouped by category
    categories = {}
    for r in auditor.results:
        categories.setdefault(r.category, []).append(r)

    section_num = 2
    for cat, checks in categories.items():
        pdf.section_title(f"{section_num}. {cat}")
        section_num += 1

        status_colors = {
            "VULNERABLE": (196, 30, 58),
            "WARNING":    (200, 140, 0),
            "SECURE":     (30, 150, 60),
            "INFO":       (80, 80, 200),
        }

        for r in checks:
            col = status_colors.get(r.status, (100, 100, 100))
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(*col)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(25, 6, f"  {r.status}", fill=True, ln=False)
            pdf.set_text_color(0, 0, 0)
            pdf.set_fill_color(245, 245, 245)
            pdf.set_font("Helvetica", "", 8)
            pts = (f"-{r.deduction}pts" if r.status == "VULNERABLE"
                   else f"-{r.deduction // 2}pts" if r.status == "WARNING"
                   else "")
            pdf.cell(0, 6,
                     f"  {r.name}  {pts}",
                     fill=True, ln=True)
            pdf.set_font("Helvetica", "I", 7)
            pdf.set_text_color(80, 80, 80)
            detail_clean = r.detail.replace("\n", " ")[:120]
            pdf.cell(0, 5, f"    {detail_clean}", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)
        pdf.ln(3)

    # Recommendations
    pdf.add_page()
    pdf.section_title(f"{section_num}. Remediation Recommendations")
    section_num += 1
    non_secure = [r for r in auditor.results if r.status in ("VULNERABLE", "WARNING")]
    if non_secure:
        pdf.set_font("Helvetica", "", 9)
        for i, r in enumerate(non_secure, 1):
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 6, f"  {i}. [{r.status}] {r.name}", ln=True)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 5, f"     {r.recommendation}")
            pdf.ln(2)
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  No remediation required — system is well hardened.", ln=True)

    # Legal
    pdf.ln(4)
    pdf.section_title(f"{section_num}. Legal & Scope Declaration")
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(
        0, 6,
        f"This report was generated by {TOOL} v{VERSION}, developed by "
        f"{AUTHOR} / {BRAND}. The audit was performed on the local system "
        "under the authorization of the system operator.\n\n"
        "This report is confidential and intended solely for the authorized "
        "recipient. Redistribution without consent of the system owner is "
        "prohibited.\n\n"
        f"{BRAND} accepts no liability for actions taken based on the findings "
        "in this report without appropriate change-control and professional review."
    )

    try:
        pdf.output(filename)
        return filename
    except Exception as e:
        console.print(f"[bold red][!] PDF save failed: {e}[/bold red]")
        return None


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        console.print(
            "[bold red][!] PriViHarden requires root privileges. "
            "Run with sudo.[/bold red]"
        )
        sys.exit(1)

    print_header()

    console.print(
        Panel(
            "[bold white]This tool audits the [cyan]local system's[/cyan] Linux security "
            "configuration across 23 checks.\nAll checks are read-only — "
            "no changes are made to the system.\n"
            "Run this tool on systems you own or have written authorization to audit.[/bold white]",
            border_style="yellow",
            title="[bold yellow]Audit Notice[/bold yellow]"
        )
    )
    console.print()

    hostname = run_cmd("hostname")
    kernel   = run_cmd("uname -r")
    distro   = run_cmd("lsb_release -d 2>/dev/null | cut -d: -f2").strip() or \
               run_cmd("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2").strip("\"")

    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column(style="bold white", width=18)
    info_table.add_column(style="cyan")
    info_table.add_row("Hostname",    hostname)
    info_table.add_row("Kernel",      kernel)
    info_table.add_row("Distribution", distro)
    info_table.add_row("Audit Date",  datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    console.print(Panel(info_table, title="[bold cyan]Target System[/bold cyan]",
                        border_style="blue"))
    console.print()

    # Run all checks
    auditor = PriViHarden()
    console.print("[bold cyan][*] Starting 23-check security audit...[/bold cyan]\n")
    auditor.run_all()

    # Display results
    display_results(auditor)

    # Generate PDF
    console.print("\n[bold cyan][*] Generating PDF audit report...[/bold cyan]")
    try:
        pdf_file = generate_pdf(auditor)
        if pdf_file:
            console.print(f"[bold green][+] Report saved: {pdf_file}[/bold green]")
    except Exception as e:
        console.print(f"[bold red][!] PDF generation failed: {e}[/bold red]")

    console.print(
        "\n[bold green][✔] Audit complete. PriViSecurity standing by.[/bold green]\n"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Audit aborted.[/bold yellow]")
        sys.exit(0)
