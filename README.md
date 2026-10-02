# SIEM Endpoint Monitoring Lab (Splunk + Sysmon)

A home lab that collects Windows endpoint telemetry with **Sysmon**, ships it with the **Splunk Universal Forwarder**, and analyzes it in **Splunk Enterprise** to detect suspicious process activity.

![Splunk](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-black)
![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-blue)
![Platform](https://img.shields.io/badge/Endpoint-Windows%2011-0078D4)
![Host](https://img.shields.io/badge/Server-Ubuntu%20Linux-E95420)

---

## Overview

This project builds a small but complete detection pipeline:

1. **Generate** – Sysmon records process creation and other endpoint events on a Windows 11 VM.
2. **Forward** – The Splunk Universal Forwarder sends those events over `TCP/9997`.
3. **Index** – Splunk Enterprise on Ubuntu stores the events in the `main` index.
4. **Detect** – SPL queries parse the raw XML into analyst-friendly fields and surface suspicious behavior.

**Goal:** show end-to-end understanding of how endpoint logs become searchable, actionable security data.

---

## Architecture

```
┌─────────────────────────────┐            ┌─────────────────────────────┐
│  Windows 11 VM (Endpoint)   │            │  Ubuntu Linux (SIEM)        │
│                             │            │                             │
│  Sysmon ──► Event Log       │  TCP/9997  │  Splunk Enterprise          │
│  Splunk Universal Forwarder │ ─────────► │  Receiver :9997             │
│                             │ (NAT net)  │  Web UI   :8000             │
└─────────────────────────────┘            └─────────────────────────────┘
```

| Component | Details |
|---|---|
| SIEM server | Splunk Enterprise on Ubuntu Linux (Web UI: `http://localhost:8000`) |
| Endpoint | Windows 11 VM with Sysmon and Splunk Universal Forwarder |
| Transport | Virtual NAT network, Splunk forwarding over `TCP/9997` |
| Target index | `main` |

---

## Prerequisites

- Splunk Enterprise installed on Ubuntu, with a receiving port enabled (**Settings → Forwarding and receiving → Configure receiving → 9997**)
- Windows 11 VM reachable from the Ubuntu host over the virtual network
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) installed on the endpoint with a configuration file (for example, a community config such as SwiftOnSecurity's `sysmon-config`)
- Splunk Universal Forwarder installed on the endpoint

---

## Implementation

### 1. Network and ingestion

- Opened the receiving port on the Ubuntu host:
  ```bash
  sudo ufw allow 9997/tcp
  ```
- Verified connectivity from the Windows endpoint in PowerShell:
  ```powershell
  Test-NetConnection -ComputerName <Ubuntu_IP> -Port 9997
  ```
  `TcpTestSucceeded : True` confirms the port is reachable.
- Pointed the forwarder at the indexer (`outputs.conf`):
  ```ini
  [tcpout]
  defaultGroup = default-autolb-group

  [tcpout:default-autolb-group]
  server = <Ubuntu_IP>:9997
  ```

### 2. Log channels and permissions

Configured `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` to collect Sysmon and Security logs:

```ini
[XmlWinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main

[WinEventLog://Security]
disabled = 0
renderXml = true
index = main
```

**Permissions fix:** The forwarder service could not read the custom Sysmon channel. Adding the service account to the **Event Log Readers** local group resolved it:

```powershell
net localgroup "Event Log Readers" "NT SERVICE\SplunkForwarder" /add
```

Restart the service afterward:

```powershell
Restart-Service SplunkForwarder
```

> **Note:** Use only one stanza per channel. Defining the same Sysmon channel as both `WinEventLog://` and `XmlWinEventLog://` ingests every event twice and inflates counts.

### 3. Parsing and field extraction

- Inspected the raw XML payload of Sysmon events in Splunk.
- Wrote SPL with `rex` to pull nested XML values into SOC-friendly fields: `User`, `Image`, `CommandLine`, `ParentImage`.
- Saved the result as a reusable report: **Sysmon - Process Creation (Event ID 1)**.

---

## Core Detection Query

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?<User>[^<]+)"
| table _time, host, User, Image, CommandLine, ParentImage
| sort - _time
```

Filtering on `<EventID>1</EventID>` in the base search lets Splunk discard non-matching events early, which is faster than filtering after parsing.

---

## Threat Simulation and Validation

| Item | Detail |
|---|---|
| Action | Ran `whoami /priv` in PowerShell to simulate privilege enumeration |
| MITRE ATT&CK | [T1033 – System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/) |
| Expected event | Sysmon Event ID 1 (Process Create) |

**Result:** the query extracted the activity correctly.

| Field | Value |
|---|---|
| `Image` | `C:\Windows\System32\whoami.exe` |
| `CommandLine` | `"C:\WINDOWS\system32\whoami.exe" /priv` |
| `ParentImage` | `powershell.exe` |
| `User` | `LLANES\KURT LUIS` |

---

## Example Detection Ideas (Next Steps)

Simple extensions using the same fields:

```spl
# Recon commands launched from a shell
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| search Image IN ("*\\whoami.exe","*\\net.exe","*\\ipconfig.exe","*\\systeminfo.exe")
| stats count values(CommandLine) AS commands BY host, ParentImage
```

- Alert on encoded PowerShell (`-enc`, `-EncodedCommand`)
- Detect Office applications spawning `cmd.exe` or `powershell.exe`
- Add Sysmon Event ID 3 (network connections) and Event ID 11 (file creation)

---

## Troubleshooting

| Symptom | Check |
|---|---|
| No data in Splunk | `Test-NetConnection` on port 9997, `ufw status`, receiving enabled in Splunk |
| Sysmon events missing | Event Log Readers group membership, `inputs.conf` stanza name, service restart |
| Duplicate events | Only one input stanza per channel |
| Fields not extracting | Confirm the sourcetype and that `rex` quoting matches the raw XML (`'` vs `"`) |

Useful forwarder log: `C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log`

---

## Skills Demonstrated

- **SIEM administration:** Splunk Enterprise indexing, receiving ports, Universal Forwarder deployment
- **Endpoint telemetry:** Sysmon Event ID 1, Windows Event Log channels, service account permissions
- **Detection engineering:** SPL, regex field extraction (`rex`), reusable saved reports
- **Threat mapping:** aligning simulated activity to MITRE ATT&CK
- **Network and host hardening:** firewall rules (`ufw`), connectivity validation

---

## Disclaimer

This lab runs in an isolated virtual environment for learning purposes. Do not run simulated attack commands on systems you do not own.

---

## Portfolio Screenshots

### Windows endpoint validation
Endpoint-side verification that Sysmon and the forwarder are running and generating events.

<img width="1009" height="718" alt="windows-endpoint-validation" src="https://github.com/user-attachments/assets/170caedf-f5f1-43f7-851e-cb30a00bfd22" />

### Saved Splunk report
The reusable report **Sysmon - Process Creation (Event ID 1)** in Splunk.

<img width="1861" height="964" alt="splunk-saved-report" src="https://github.com/user-attachments/assets/286bf2fe-6be2-498d-a4aa-368acafbf3d9" />

### `whoami /priv` detection
Splunk results showing the simulated privilege enumeration with extracted `Image`, `CommandLine`, `ParentImage` and `User` fields.

<img width="1861" height="964" alt="whoami-detection" src="https://github.com/user-attachments/assets/14927c15-02aa-40f9-88fc-544793f1ce39" />
