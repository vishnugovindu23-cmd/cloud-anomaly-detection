# Cloud Anomaly Detection Report

Analysed **8,159 CloudTrail events** and **53,270 VPC flow records**, scored as 890 identity-hours and 8,400 host-hours. Baseline (training) window: 2026-09-01 to 2026-09-11.

## Detection results against ground truth

- Attacks injected: **7**, detected: **7** (recall 100%)
- Incidents raised: **6**, false-positive incidents: **1** (ops.zoe)

## Incidents

| Severity | Source | Entity | Window | Alert hours | Why | Likely ATT&CK |
|---|---|---|---|---|---|---|
| HIGH | CloudTrail | `dev.sarah` | Sep 12 03:00 to Sep 12 04:00 | 2 | 31 API calls (4x typical); 12 distinct APIs; 39% error rate; 4 sensitive IAM/logging calls; 21 IAM/STS recon calls | T1580 Cloud Infrastructure Discovery (permission probing)<br>T1098 Account Manipulation / T1562.008 Disable Cloud Logs<br>T1087.004 Cloud Account Discovery<br>T1078.004 Valid Accounts: Cloud Accounts |
| HIGH | VPC Flow | `10.0.1.23` | Sep 12 04:00 to Sep 12 05:00 | 2 | 1,203 flows (241x typical); 13 distinct destination IPs (3x typical); 1,144 distinct destination ports (381x typical); 100% rejected-connection ratio; 4,502 MB sent (2188x typical) | T1046 Network Service Discovery<br>T1041 Exfiltration Over C2 Channel<br>T1071 Application Layer Protocol (new external destination) |
| HIGH | CloudTrail | `ops.mike` | Sep 14 02:00 | 1 | 45 API calls (6x typical); 40 EC2 instances launched; source IP never seen for this identity; AWS region never used by this identity; activity outside this entity's normal hours | T1496 Resource Hijacking<br>T1078.004 Valid Accounts: Cloud Accounts<br>T1535 Unused/Unsupported Cloud Regions |
| MEDIUM | CloudTrail | `analyst.raj` | Sep 13 20:00 | 1 | 650 API calls (81x typical); 650 S3 GetObject calls | T1530 Data from Cloud Storage |
| MEDIUM | VPC Flow | `10.0.2.14` | Sep 11 07:00 to Sep 14 22:00 | 39 | 19 flows (4x typical); 1 never-seen external destinations; 4 distinct destination ports; 7 distinct destination IPs; 6.05 MB sent | T1071 Application Layer Protocol (new external destination) |
| LOW | CloudTrail | `ops.zoe` | Sep 11 13:00 | 1 | 100% error rate | T1580 Cloud Infrastructure Discovery (permission probing) |

## C2 beaconing

| Host | Destination | Connections | Interval | Jitter | Avg bytes | First seen | Last seen |
|---|---|---|---|---|---|---|---|
| `10.0.2.14` | `91.219.236.18:8443` | 1080 | 300s | 0.009 | 620 | Sep 11 06:00 | Sep 14 23:55 |

Likely ATT&CK: T1071.001 Web Protocols (C2 beaconing)
