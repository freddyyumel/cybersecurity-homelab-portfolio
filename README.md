# Cybersecurity Home Lab Portfolio

Hands-on security investigations and detection engineering exercises conducted in an **isolated, personally operated lab**. This repository documents the methodology, observed evidence, decisions, limitations and defensive lessons from each exercise. It is **not** a record of a live production incident.

## Case studies

| Case | Focus | Tools | Status |
|---|---|---|---|
| [SOC Case 001 — Privileged AD Group Membership](cases/SOC-Case-001-Privileged-Group-Investigation/README.md) | Investigate an account temporarily added to Domain Admins, followed by Kerberos authentication failures | Active Directory, Windows Security Logs, Splunk Enterprise, Microsoft Sentinel | Completed lab investigation |

## Lab at a glance

- **DC01:** Windows Server 2025 domain controller for `homelab.test`; Windows Security audit events
- **WIN11-01:** Domain-joined Windows 11 workstation; source of observed Kerberos failures
- **UBUNTU01:** Splunk Enterprise server receiving Windows Security and Sysmon data
- **Microsoft Sentinel / Log Analytics:** DC01 telemetry onboarded using Azure Arc, Azure Monitor Agent and a Data Collection Rule

All hosts, accounts, addresses and events in this repository belong to an authorised test environment. The domain `homelab.test` and RFC 1918 addresses are lab identifiers.

## What these projects demonstrate

- Working from security alerts to supporting host and identity logs
- Building and refining SPL/KQL searches
- Separating observations from interpretations and identifying telemetry gaps
- Documenting findings, response considerations and investigative limitations
