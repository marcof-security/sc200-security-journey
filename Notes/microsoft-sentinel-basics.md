# Microsoft Sentinel Basics

## Overview

Microsoft Sentinel is a cloud-native SIEM and SOAR solution built on Azure.
It provides centralized log collection, threat detection, investigation, 
and automated response capabilities.

Unlike traditional SIEMs, Sentinel is fully cloud-based and scalable.

---

## What is a SIEM?

A SIEM (Security Information and Event Management) system:

- Collects logs from multiple sources
- Normalizes and stores data
- Correlates events
- Generates alerts
- Creates incidents for investigation

Sentinel does not generate raw telemetry.
It analyzes and correlates logs collected from connected data sources.

---

## What is SOAR?

SOAR (Security Orchestration, Automation, and Response) allows:

- Automated investigation workflows
- Automated response actions
- Integration with external systems

In Sentinel, automation is handled using:
- Playbooks
- Logic Apps

---

## Core Components of Microsoft Sentinel

### 1. Data Connectors
Used to ingest logs from:
- Microsoft Defender products
- Azure resources
- On-premises servers
- Third-party security tools

### 2. Log Analytics Workspace
All logs are stored in a Log Analytics workspace.
Data is queried using KQL (Kusto Query Language).

### 3. Analytics Rules
Rules that detect suspicious activity.
They can:
- Generate alerts
- Create incidents
- Trigger automation

### 4. Incidents
Incidents group related alerts into one investigation case.

### 5. Workbooks
Dashboards for visualizing security data.

### 6. Playbooks
Automated response workflows triggered by alerts or incidents.

---

## High-Level Alert Flow

1. A device generates telemetry (e.g., suspicious PowerShell execution).
2. Defender for Endpoint creates an alert.
3. Alert is sent to Microsoft Sentinel.
4. Sentinel correlates it with identity and cloud logs.
5. An incident is created.
6. A playbook may isolate the device or disable the account.
7. SOC analyst investigates.

---

## Basic SOC Investigation Workflow in Sentinel

1. Review incident severity
2. Analyze related alerts
3. Check involved entities (user, device, IP)
4. Query logs using KQL
5. Determine if activity is malicious or false positive
6. Take response action

---

## Key Concepts to Remember

- Sentinel is only as good as the logs it receives.
- Proper data connector configuration is critical.
- Correlation reduces alert fatigue.
- Automation reduces response time.

---

## My Key Takeaways

- A SIEM provides visibility across the entire environment.
- Sentinel integrates tightly with Microsoft Defender products.
- Effective detection depends on analytics rule quality.
- Investigation requires understanding of networking, identity, and endpoint behavior.
