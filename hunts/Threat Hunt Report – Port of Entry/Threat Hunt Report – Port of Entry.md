# Threat Hunt Report – Port of Entry

---

## Executive Summary

Competitor undercut long-term shipping contract by exactly 3%. Threat intelligence gather that the supplier contracts and pricing data appeared on underground forums. It was identified that between November 19-20, 2025, a threat actor gained unauthorized access to an IT admin workstation (AZUKI-SL) from the company Azuki Import/Export Trading Co.

The attacker was able to leverage stolen credentials to authenticate via RDP gaining inital access. After gaining inital access, the attacker conducted network reconnaisance and established a malware staging directory for payload deployment and defense evasion. Persistence was achieved via scheduled tasks while outbound encrypted C2 traffic was observed. Credential theft was executed to harvest authentication artifacts, followed by data staging, exfilitration, and anti-forensic log tampering. Finally, lateral movement was attempted toward an additional internal host and a persistence account was provisioned. 

The following report outlines the cyber kill chain, mapping it to MITRE ATT&CK, timeline, indicators, recommendations, and lesson learned.

---

## Scope & Environment

- **Environment:** Windows Endpoint on Azuki Import/Export Trading Co. Network
- **Data Sources:** DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceEvents
- **Timeframe:** 11/19/2025 - 11/20/2025

---

## Table of Contents

- [MITRE ATT&CK Summary](#mitre-attck-summary)
- [Analysis](#analysis)
  - [Flag 1](#flag-1)
  - [Flag 2](#flag-2)
  - [Flag 3](#flag-3)
  - [Flag 4](#flag-4)
  - [Flag 5](#flag-5)
  - [Flag 6](#flag-6)
  - [Flag 7](#flag-7)
  - [Flag 8](#flag-8)
  - [Flag 9](#flag-9)
  - [Flag 10](#flag-10)
  - [Flag 11](#flag-11)
  - [Flag 12](#flag-12)
  - [Flag 13](#flag-13)
  - [Flag 14](#flag-14)
  - [Flag 15](#flag-15)
  - [Flag 16](#flag-16)
  - [Flag 17](#flag-17)
  - [Flag 18](#flag-18)
  - [Flag 19](#flag-19)
  - [Flag 20](#flag-20)
- [Detection Gaps & Recommendations](#detection-gaps--recommendations)
- [Final Assessment](#final-assessment)
- [Analyst Notes](#analyst-notes)

---


## MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Tactic |
|-----:|-------------------|----------|----------|
| 1 | Remote Services (Remote Desktop Protocol) | T1021.001 | Initial Access |
| 2 | Valid Accounts | T1078 | Initial Access |
| 3 | System Network Configuration Discovery | T1016 | Discovery |
| 4 | Data Staged: Local Data Staging | T1074.001 | Collection |
| 5 | Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| 6 | Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| 7 | Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| 8 | Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence |
| 9 | Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence |
| 10 | Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |
| 11 | Application Layer Protocol: Web Protocols | T1071.001 | Command and Control |
| 12 | OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access |
| 12 | OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access |
| 14 | Archive Collected Data: Archive via Utility | T1560.001 | Collection |
| 15 | Exfiltration Over Web Service | T1567 | Exfiltration |
| 16 | Indicator Removal: Clear Windows Event Logs | T1070.001 | Defense Evasion |
| 17 | Create Account: Local Account | T1136.001 | Persistence |
| 18 | Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| 19 | Use Alternate Authentication Material | T1550 | Lateral Movement |
| 20 | Remote Services: Remote Desktop Protocol | T1021.001 | Lateral Movement |

---

## Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="flag-1"><strong>Flag 1: <Technique Name></strong></summary>

### Objective
<What the attacker was trying to accomplish>

### Finding
<High-level description of the activity>

### Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### Why it matters
<Explain impact, risk, and relevance>

### KQL Query Used
<Add KQL here>

### Screenshot
<Insert screenshot>

### Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<!-- Duplicate Flag 1 section for Flags 2–20 -->

---

## Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
