# Linux Privilege Escalation Automation Toolkit

A CLI-based Linux security auditing tool that automatically scans for potential privilege-escalation weaknesses and generates a security report.

## Features

* System information collection
* SUID/SGID binary discovery
* Weak file and directory permission checks
* Misconfigured service detection
* Sudo configuration review
* Cron job analysis
* Kernel and CVE candidate review
* Risk classification
* Markdown and JSON report generation

## Technologies

* Python 3
* Bash
* Linux

## Requirements

* Linux system
* Python 3.9+
* Standard Linux utilities such as `find`, `systemctl`, `sudo`, and `crontab`

No external Python packages are required.

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/Linux-Privilege-Escalation-Automation-Toolkit.git
cd Linux-Privilege-Escalation-Automation-Toolkit
```

Make the script executable:

```bash
chmod +x run_toolkit.sh
```

## Usage

Run the toolkit:

```bash
./run_toolkit.sh
```

Or:

```bash
python3 toolkit.py
```

Reports are automatically saved in the `reports/` directory.

## Project Structure

```text
├── toolkit.py
├── run_toolkit.sh
├── requirements.txt
├── README.md
├── docs/
└── reports/
```

## Safety

This project is **detection and reporting only**. It does not perform privilege-escalation exploits or modify system configuration.

Use the toolkit only on systems you own or are authorized to audit.

## Purpose

This project was developed for cybersecurity education and Linux security auditing, demonstrating automated enumeration, risk analysis, and security reporting.
