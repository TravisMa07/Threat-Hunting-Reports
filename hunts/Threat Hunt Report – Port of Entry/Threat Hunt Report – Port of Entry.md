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

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | <Placeholder> | <Placeholder> | <Placeholder> |
| 2 | <Placeholder> | <Placeholder> | <Placeholder> |
| 3 | <Placeholder> | <Placeholder> | <Placeholder> |
| 4 | <Placeholder> | <Placeholder> | <Placeholder> |
| 5 | <Placeholder> | <Placeholder> | <Placeholder> |
| 6 | <Placeholder> | <Placeholder> | <Placeholder> |
| 7 | <Placeholder> | <Placeholder> | <Placeholder> |
| 8 | <Placeholder> | <Placeholder> | <Placeholder> |
| 9 | <Placeholder> | <Placeholder> | <Placeholder> |
| 10 | <Placeholder> | <Placeholder> | <Placeholder> |
| 11 | <Placeholder> | <Placeholder> | <Placeholder> |
| 12 | <Placeholder> | <Placeholder> | <Placeholder> |
| 13 | <Placeholder> | <Placeholder> | <Placeholder> |
| 14 | <Placeholder> | <Placeholder> | <Placeholder> |
| 15 | <Placeholder> | <Placeholder> | <Placeholder> |
| 16 | <Placeholder> | <Placeholder> | <Placeholder> |
| 17 | <Placeholder> | <Placeholder> | <Placeholder> |
| 18 | <Placeholder> | <Placeholder> | <Placeholder> |
| 19 | <Placeholder> | <Placeholder> | <Placeholder> |
| 20 | <Placeholder> | <Placeholder> | <Placeholder> |

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
