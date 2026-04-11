# Detection Rule: Multiple Failed Logins (Brute Force Attempt)

## Objective
Detect potential brute-force attacks by identifying multiple failed login attempts from the same source within a short time window.

---

## Data Source
- Table: DeviceLogonEvents
- Source: Microsoft Defender for Endpoint

---

## KQL Query

DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count() by RemoteIP, AccountName, bin(TimeGenerated, 1h)
| where FailedAttempts >= 5
| sort by FailedAttempts desc

---

## Detection Logic
- Filters failed login attempts
- Groups activity by:
  - Source IP (RemoteIP)
  - Target account (AccountName)
  - Time window (1 hour)
- Flags any instance with 5 or more failed attempts

---

## Why This Matters
Repeated failed login attempts may indicate:
- Brute-force attacks
- Credential stuffing
- Unauthorized access attempts

Early detection helps prevent account compromise.

---

## Investigation Steps
1. Identify affected accounts
2. Review login timeline for patterns
3. Check if any successful login occurred after failures
4. Analyze source IP reputation
5. Correlate with other alerts or unusual activity

---

## Possible Response Actions
- Lock or disable affected accounts
- Enforce Multi-Factor Authentication (MFA)
- Block malicious IP address
- Notify security team

---

## Potential False Positives
- Users forgetting passwords
- Automated scripts or services using outdated credentials
- Misconfigured applications

---

## Improvements / Enhancements
- Correlate with successful login after failures
- Add geolocation analysis for unusual locations
- Reduce threshold based on environment baseline
- Integrate with alert rules in Microsoft Sentinel

---

## MITRE ATT&CK Mapping
- Technique: T1110 – Brute Force
- Tactic: Credential Access

---

## Key Takeaway
This detection helps identify early-stage attacks targeting user credentials, allowing security teams to respond before a full compromise occurs.
