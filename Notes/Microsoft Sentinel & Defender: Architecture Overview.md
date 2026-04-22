# Microsoft Security Stack: SIEM, XDR & Data Governance

## 🛠️ Unified Security Architecture

| Component | Category | Primary Function | Technical Detail |
| :--- | :--- | :--- | :--- |
| **Microsoft Sentinel** | **SIEM / SOAR** | Global log correlation and incident automation. | **Consumes** telemetry via data connectors. Uses **KQL** for hunting. |
| **Defender for Endpoint** | **EDR** | Advanced protection for devices (laptops/servers). | Monitors processes and network. Detects *Credential Dumping* and lateral movement. |
| **Microsoft Purview** | **Data Security** | Data governance, compliance, and risk management. | Identifies and labels sensitive data (DLP). Detects **Insider Risks** (data exfiltration). |
| **Defender for Identity** | **ITDR** | Identity protection (On-prem AD). | Analyzes domain controller traffic to detect *Pass-the-Hash* or *Golden Ticket* attacks. |
| **Defender for Cloud** | **CSPM** | Cloud Security Posture Management (Azure/AWS/GCP). | Identifies misconfigured resources and infrastructure vulnerabilities. |

---

## 🔍 The Integration Story: XDR + Data Security

The power of this stack is the **integration**. For example, if a user's account is compromised:
1.  **Defender for Identity** flags the suspicious login.
2.  **Defender for Endpoint** detects an unauthorized file access on their laptop.
3.  **Microsoft Purview** triggers a Data Loss Prevention (DLP) alert because the user tried to upload a "Confidential" labeled document to a personal cloud.
4.  **Microsoft Sentinel** correlates all three events into a single **Incident**, allowing the SOC analyst to see the full attack timeline.

---

## 🛡️ Sample KQL Hunting Query
This query searches for instances where Purview has flagged a Data Loss Prevention (DLP) event alongside suspicious device activity:

```kql
// Correlating Purview DLP alerts with Endpoint events
OfficeActivity
| where RecordType == "DataLossPrevention"
| join kind=inner (DeviceEvents) on $left.UserId == $right.InitiatingProcessAccountName
| project TimeGenerated, UserId, DeviceName, Operation, ActionType
| order by TimeGenerated desc
