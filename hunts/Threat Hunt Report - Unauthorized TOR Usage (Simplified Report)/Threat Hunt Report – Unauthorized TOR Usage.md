

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/TravisMa07/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file that had the string `“tor”` in it and discovered what looks like the user `“travis”` downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called `“tor-shopping-list.txt”` on the desktop at `2026-01-09T05:43:56.603495Z`. These events began at: `2026-01-09T05:26:56.2301759Z`


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "tm-vm-ir"
| where InitiatingProcessAccountName == "travis"
| where FileName contains "tor"
| where  Timestamp >= datetime(2026-01-09T05:26:56.2301759Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1374" height="492" alt="image" src="https://github.com/user-attachments/assets/d62bcaee-49b6-496a-8a32-d7ba9cae8183" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any `ProcessCommandLine` that contained the string “tor-browser”. Based on the logs returned, at `2026-01-09T05:31:21.3277886Z`, an employee on the “tm-vm-ir” device ran the file `tor-browser-windows-x86_64-portable-15.0.3.exe` from their desktop, using a command that triggered a `silent installation`.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "tm-vm-ir"
| where ProcessCommandLine contains "tor-browser"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1380" height="127" alt="image" src="https://github.com/user-attachments/assets/1486732f-3cfb-455f-bcc7-fe993a674a08" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “travis” actually opened the Tor browser. There was evidence that they did open it at `2026-01-09T05:32:01.1545744Z/`
There were several other instances of `firefox.exe` (Tor) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1333" height="572" alt="image" src="https://github.com/user-attachments/assets/6d75d616-7679-4118-bd10-68051debd669" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the Tor browser was used to establish a connection using any of the known Tor ports. At `2026-01-09T05:32:33.4322996Z`, an employee on the “tm-vm-ir” device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\travis\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a few other connections to sites over `port 443`,

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "tm-vm-ir"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1357" height="283" alt="image" src="https://github.com/user-attachments/assets/5d843896-7d11-4b08-82f8-0fa7e32274ba" />

---

## Chronological Event Timeline 

### 1. Tor Browser Artifact Acquisition (Download Phase)

- 2026-01-09 05:26:56Z — User account travis downloads tor-browser-windows-x86_64-portable-15.0.3.exe to C:\Users\travis\Downloads\ (FileCreated/FileRenamed events).
- Interpretation: Intentional acquisition of the Tor installer; no indication of drive-by or malware-initiated download.

### 2. Execution & Installation Phase (Silent Portable Deploy)

- 2026-01-09 ~05:31:21Z — tor-browser-windows-x86_64-portable-15.0.3.exe is executed from the Desktop with a silent install command (ProcessCreated).
- Files begin populating inside C:\Users\travis\Desktop\Tor Browser\... indicating a successful portable extraction.
- Interpretation: Normal portable Tor Browser install behavior, consistent with user-driven installation.

### 3. Browser Launch & Initialization Activity

- 2026-01-09 05:32:01Z — Process creation events for:
  - firefox.exe (Tor Browser wrapper)
  - tor.exe (Tor daemon)
  - Additional firefox/tor child processes in short succession
- Interpretation: Tor Browser successfully launched and Tor daemon responsible for circuit creation initiated.


### 4. Network Establishment of Tor Circuits

- 2026-01-09 05:32:33Z — tor.exe initiates outbound connection to 176.198.159.33:9001
  - Port 9001 is a known Tor OR Port used for relay nodes
- Additional outbound connections observed on TCP 443
  - Also consistent with Tor circuit bootstrap and directory fetch behavior
- Interpretation: Confirmed Tor network usage; no evidence of proxy bypass attempts or lateral pivoting.

### 5. Resulting Local Artifacts & User Behavior Indicators

- Multiple Tor artifacts (sqlite state, profiles, cache) generated under:
  - C:\Users\travis\Desktop\Tor Browser\Browser\TorBrowser\Data\
- 2026-01-09 05:43:56Z — Creation of tor-shopping-list.txt on Desktop
  - Observed in both Desktop and Documents via copying
- Interpretation: Indicates not only use of the browser but possible intent to store content. File naming suggests user interest in darknet-related shopping behavior, though file content unknown (not provided).

---

## Summary

Between `2026-01-09 05:26Z and 05:44Z`, the user account `“travis”` on workstation `“tm-vm-ir”` intentionally downloaded, installed, and launched the Tor Browser. The activity consisted of a direct download of the Tor portable installer to the user’s Downloads directory, followed by the execution of a silent installation on the Desktop. Shortly after installation, Tor Browser processes (`firefox.exe` and `tor.exe`) ran and successfully established outbound encrypted connections to known Tor ports, including a confirmed Tor relay connection to remote IP `176.198.159.33:9001`. The session generated typical Tor Browser state files on disk and concluded with the creation of a file named `“tor-shopping-list.txt”` on the Desktop, indicating the user may have been planning or documenting content accessed via Tor.


No evidence was observed suggesting malware delivery, exploitation attempts, automated tooling, or external command-and-control. All activity appeared `user-driven`, consistent with anonymized browsing behavior linked to potential darknet marketplace research. Risk exposure is therefore categorized as `policy and insider risk`, not technical compromise.

---

## Response Taken

TOR usage was confirmed on the endpoint `tm-vm-ir` by the user `travis`. The device was isolated and the user's direct manager was notified.

---
