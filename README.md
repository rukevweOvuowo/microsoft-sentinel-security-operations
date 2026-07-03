# Microsoft Sentinel Security Operations

## Overview

This repository documents the configuration, monitoring, investigation, and analysis activities performed within a Microsoft Sentinel environment integrated with Microsoft Defender XDR.

The documented activities focus on security event analysis, incident investigation, and threat hunting using Microsoft Sentinel.

---

## Environment

The Microsoft Sentinel environment was provisioned and validated prior to the activities documented in this repository.

Configuration includes:

- Microsoft Sentinel deployed
- Microsoft Defender XDR connected
- Microsoft Defender for Endpoint onboarded
- Azure Log Analytics Workspace configured
- Data ingestion validated
- Endpoint telemetry verified

---

## Platform Components

- Microsoft Azure
- Azure Log Analytics Workspace
- Microsoft Sentinel
- Microsoft Defender XDR
- Microsoft Defender for Endpoint

---

## Technologies

### Microsoft Security

- Microsoft Sentinel
- Microsoft Defender XDR
- Microsoft Defender for Endpoint

### Azure

- Microsoft Azure
- Azure Log Analytics Workspace

### Detection & Investigation

- Kusto Query Language (KQL)
- Data Connectors
- Analytics Rules
- Incident Management
- Incident Investigation
- Threat Hunting

---

## Security Investigation

The following investigations document security monitoring, threat detection, incident analysis, and response activities performed using Microsoft Sentinel and Microsoft Defender XDR.

### Initial Access

- [01 - Phishing Email Investigation](Investigations/01-Phishing-Email-Investigation.md)

### Identity Security

- [02 - Brute Force Attack Investigation](Investigations/02-Brute-Force-Attack-Investigation.md)
- [03 - ](Investigations/03-.md)

### Endpoint Security

- [04 - Malware Investigation](Investigations/04-Malware-Investigation.md)
- [05 - PowerShell Suspicious Activity](Investigations/05-PowerShell-Suspicious-Activity.md)

### Threat Hunting

- [06 - Threat Hunting with KQL](Investigations/06-Threat-Hunting-KQL.md)

### Microsoft Defender XDR

- [07 - Microsoft Defender XDR Investigation](Investigations/07-Defender-XDR-Investigation.md)

### Incident Response

- [08 - Ransomware Investigation](Investigations/08-.md)
- [09 - Insider Threat Investigation](Investigations/09-Insider-Threat-Investigation.md)
- [10 - Incident Response Case Study](Investigations/10-Incident-Response-Case-Study.md)

---

## Repository Structure

- [Investigations](Exercises/)
- [Images](Images/)
- [Queries](Queries/)

---

## Status

Documentation is updated as additional Microsoft Sentinel investigations and configurations are completed.

---

## Scope

The repository documents activities performed using Microsoft Sentinel for security monitoring, event analysis, threat hunting, and incident investigation.

The content reflects the operational state of the configured environment at the time each investigation was completed.