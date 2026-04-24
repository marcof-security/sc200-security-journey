# 🛡️ Deep Dive: Microsoft Purview Insider Risk Management

This section details the operational workflow for detecting and mitigating internal threats using **Microsoft Purview**. Unlike traditional security tools that focus on external actors, Purview analyzes user behavior to protect sensitive organizational data.

## 📊 Alert Generation Workflow

The following process illustrates how Purview moves from initial configuration to a high-confidence security alert.

![Purview Workflow](https://raw.githubusercontent.com/your-username/your-repo/main/image_6ac7b8.png)
*Note: This diagram represents the standard Microsoft Purview scoring engine.*

---

## 🔍 Technical Breakdown of the Workflow

### 1. Settings Configured (The Foundation)
Before detection begins, the environment must be tuned to the organization's specific risk appetite.
* **Privacy Management:** Implementing "Pseudonymization" to hide usernames during the initial investigation phase, ensuring compliance with privacy laws (like GDPR).
* **Indicators:** Selecting specific telemetry signals from **Microsoft Defender for Endpoint** and **Office 365** that the policy should monitor.
* **Domain Filtering:** Defining which web domains are considered "untrusted" for data upload alerts.

### 2. Policy Creation (The Logic)
Policies define the "who" and the "what."
* **Targeting:** Applying specific rules to high-risk groups (e.g., users in a notice period or users with access to highly sensitive intellectual property).
* **Detection Scenarios:** Choosing templates like *Data Theft by Departing Users* or *General Data Leaks*.

### 3. Triggering Event (The Catalyst)
The system does not actively score a user's risk until a **Triggering Event** occurs. This is a crucial distinction in Microsoft Purview.
* **HR Integration:** A user's resignation date is updated in the HR system (e.g., Workday/SAP).
* **DLP Match:** A user performs an activity that matches a high-severity Data Loss Prevention (DLP) policy.
* **Behavioral:** Accessing a restricted or risky website.

### 4. Evaluation & Risk Scoring (The Analysis)
Once triggered, the engine evaluates the user's activities over a look-back period.
* **Contextual Scoring:** A user downloading 50 files might be normal; a user downloading 50 files *after* submitting their resignation is assigned a much higher risk score.
* **Factors:** The volume of data, the sensitivity of the files (labels), and the user's historical baseline.

### 5. Alert Generation (The Escalation)
If the cumulative risk score exceeds the defined threshold:
* An **Alert** is generated in the Insider Risk Management dashboard.
* The alert can be automatically exported to **Microsoft Sentinel** for a unified SOC response.

---

## 🛠️ Security Analyst Hunting (KQL)

When an Insider Risk alert is triggered, an analyst can use **Kusto Query Language** in Sentinel to investigate the user's activity on the endpoint:

```kql
// Identify mass file movement to USB or Cloud by a specific user
DeviceEvents
| where ActionType in ("FileCopiedToUsb", "FileCopiedToCloudDrive")
| where InitiatingProcessAccountUpn == "user@company.com"
| summarize FileCount = count(), UniqueFiles = dcount(FileName) by DeviceName, bin(TimeGenerated, 1h)
| where FileCount > 50
| project TimeGenerated, DeviceName, FileCount, UniqueFiles
| order by TimeGenerated desc
