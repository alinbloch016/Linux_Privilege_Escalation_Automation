# Linux Privilege Escalation Automation Toolkit

CLI-only automated Linux security auditing toolkit matching the project specification.

## Objective
Develop a fully automated scanner for privilege escalation weaknesses.

## Modules
1. System Information Collection
2. SUID/SGID Binary Discovery
3. Weak File & Directory Permissions
4. Misconfigured Services
5. Sudo Configuration Review
6. Cron Vulnerability Review
7. Kernel/CVE Candidate Detection
8. Risk Analysis
9. Markdown + JSON Reporting

## Safety
Detection, analysis and reporting only. The toolkit does not exploit vulnerabilities, modify permissions, alter sudoers, replace cron jobs, execute payloads, or attempt privilege escalation.

## Run on Linux
```bash
chmod +x run_toolkit.sh
./run_toolkit.sh
```
Or:
```bash
python3 toolkit.py
```
Reports are written to `reports/`.

## Requirements
Linux and Python 3.9+. No third-party Python packages are required. Some modules depend on standard Linux utilities such as `find`, `systemctl`, `sudo`, and `crontab` and safely report when they are unavailable.

Use only on systems you own or are authorized to audit.
