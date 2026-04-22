# Microsoft Sentinel & Defender Security Stack

## 🛠️ Security Architecture (SIEM + XDR)

| Component | Category | Primary Function | Technical Detail |
| :--- | :--- | :--- | :--- |
| **Microsoft Sentinel** | **SIEM / SOAR** | Global log correlation and incident automation. | **Consumes** telemetry via data connectors. Uses **KQL** for hunting. |
| **Defender for Endpoint** | **EDR** | Advanced protection for devices (laptops/servers). | Monitors processes, files, and network. Detects *Credential Dumping* and lateral movement. |
| **Defender for Identity** | **ITDR** | Identity protection (On-prem AD). | Analyzes domain controller traffic to detect *Pass-the-Hash* or *Golden Ticket* attacks. |
| **Defender for Cloud** | **CSPM** | Cloud Security Posture Management (Azure/AWS/GCP). | Identifies misconfigured resources and infrastructure vulnerabilities. |

---

## 🔍 Telemetry & Threat Hunting (KQL)

To demonstrate how Sentinel consumes telemetry from the Defender suite, here is a foundational **Kusto Query Language (KQL)** query used to identify suspicious PowerShell execution reported by the EDR:

```kql
// Hunting for suspicious PowerShell download cradles
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Net.WebClient", "DownloadString", "IEX")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
| take 10
