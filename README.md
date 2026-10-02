# 🛡️️ SIEM Endpoint Monitoring Lab (Splunk + Sysmon)

## 📌 Project Overview
Designed and deployed a local **Security Information and Event Management (SIEM)** endpoint monitoring pipeline to capture, parse, and analyze endpoint telemetry. The setup collects process creation events and system logs from a Windows 11 target host and forwards them over a virtual network to a Splunk Enterprise instance running on an Ubuntu Linux host.

---

## 🏗️ Lab Architecture & Environment
* **SIEM Server (Indexer):** Splunk Enterprise running on Ubuntu Linux (`http://localhost:8000`)
* **Endpoint (Target Machine):** Windows 11 Virtual Machine (`Host: LLANES`) with Microsoft Sysmon & Splunk Universal Forwarder
* **Network & Ingestion:** Virtual NAT network transporting log data via `TCP/9997`
* **Target Index:** `main`

---

## ⚙️ Key Implementation Steps

### 1. Ingestion Pipeline & Network Configuration
* Installed and configured the **Splunk Universal Forwarder** on the Windows 11 endpoint.
* Configured Ubuntu host firewall rules (`sudo ufw allow 9997/tcp`) to allow incoming forwarder traffic.
* Validated TCP socket connectivity over `TCP/9997` from PowerShell using `Test-NetConnection -ComputerName <Ubuntu_IP> -Port 9997`.

### 2. Log Channel Configuration & Service Permissions
* Configured `inputs.conf` (`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`) to monitor Windows Security logs and Sysmon operational logs:
  ```ini
  [WinEventLog://Microsoft-Windows-Sysmon/Operational]
  disabled = 0
  renderXml = 1
  index = main

  [XmlWinEventLog://Microsoft-Windows-Sysmon/Operational]
  disabled = 0
  index = main

  [WinEventLog://Security]
  disabled = 0
  renderXml = 1
  index = main

  Resolved service privilege restrictions on custom Windows Event Log channels by adding the NT SERVICE\SplunkForwarder service account to the Event Log Readers local group.

3. Log Parsing & Field Extraction

    Analyzed raw XML attribute payloads from Sysmon logs in Splunk.

    Authored custom Search Processing Language (SPL) queries using regular expressions (rex) to parse nested XML attributes into SOC-ready fields (User, Image, CommandLine, ParentImage).

    Created and saved a reusable report: Sysmon - Process Creation (Event ID 1).

📊 Core Technical Artifacts
Process Creation Detection Query (SPL)
Splunk SPL

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?<User>[^<]+)"
| xmlkv
| search EventID=1
| table _time, host, User, Image, CommandLine, ParentImage

🧪 Verification & Threat Simulation

    Test Action: Simulated privilege enumeration on the Windows host by executing whoami /priv inside PowerShell.

    Telemetry Verification: Verified live ingestion in Splunk. The SOC query accurately extracted:

        Executable Path (Image): C:\Windows\System32\whoami.exe

        Command Arguments (CommandLine): "C:\WINDOWS\system32\whoami.exe" /priv

        Parent Process (ParentImage): powershell.exe

        User Context (User): LLANES\KURT LUIS

💡 Key Skills Demonstrated

    SIEM Management: Splunk Enterprise indexing, inputs configuration, Universal Forwarder deployment, port binding (9997/tcp).

    Endpoint Telemetry: Sysmon Event ID 1 (Process Creation), Windows Event Logging, local access controls.

    Data Transformation: Search Processing Language (SPL), Regular Expressions (rex), XML field extraction (xmlkv).
