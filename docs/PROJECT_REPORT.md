# Project Report — Linux Privilege Escalation Automation Toolkit

## Objective
Develop a fully automated scanner for privilege escalation weaknesses.

## Problem Statement
Manual Linux security auditing is slow and error-prone. This project automates common enumeration, analysis and reporting tasks for authorized security assessments.

## Scope
The toolkit reviews system information, SUID/SGID binaries, weak permissions, services, sudo configuration, cron jobs and kernel/CVE candidates. It reports potential risk and mitigation without exploiting findings.

## Workflow
START → System Information → SUID/SGID → Weak Permissions → Services → Sudo → Cron → Kernel/CVE → Risk Analysis → Reports → END

## Technologies
Python 3, Bash, Linux utilities, JSON, Markdown.

## Learning Outcomes
Linux permissions, SUID/SGID auditing, service and cron review, sudo policy analysis, kernel security awareness, Python automation and report generation.

## Ethical Scope
Run only on systems for which you have authorization. No exploitation or system modification is implemented.
