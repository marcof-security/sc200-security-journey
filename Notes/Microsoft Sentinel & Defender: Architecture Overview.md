# Microsoft Sentinel & Defender: Architecture Overview

# Microsoft Sentinel (SIEM & SOAR)

--

Role: The "Brain." It provides a bird's-eye view across the entire enterprise.

Function: Aggregates data from multiple sources (Azure, AWS, On-prem, 3rd party) for long-term retention and complex correlation.

Key Capability: Uses KQL (Kusto Query Language) for deep-dive threat hunting and Logic Apps-based Playbooks to automate incident response.

Clarification: Sentinel is a consumer of data; it relies on connectors to ingest telemetry from the Defender suite.
