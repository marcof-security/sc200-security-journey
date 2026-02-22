# Failed Login Detection

## Objective
Detect multiple failed login attempts from the same IP address.

## Query

DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count() by RemoteIP, bin(TimeGenerated, 1h)
| where FailedAttempts > 5

## Explanation
This query identifies potential brute-force attempts within a 1-hour window.

## Lessons Learned
- Importance of bin()
- Filtering noise
- Using summarize properly
