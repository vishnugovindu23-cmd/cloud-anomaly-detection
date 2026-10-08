"""Map alert reasons to likely MITRE ATT&CK techniques to guide triage."""
from __future__ import annotations

import re

# (text in the reason, technique, minimum "Nx typical" ratio needed; 0 = always)
RULES = [
    ("sensitive IAM/logging", "T1098 Account Manipulation / T1562.008 Disable Cloud Logs", 0),
    ("IAM/STS recon", "T1087.004 Cloud Account Discovery", 0),
    ("source IP never seen", "T1078.004 Valid Accounts: Cloud Accounts", 0),
    ("region never used", "T1535 Unused/Unsupported Cloud Regions", 0),
    ("EC2 instances launched", "T1496 Resource Hijacking", 0),
    ("S3 GetObject", "T1530 Data from Cloud Storage", 0),
    ("error rate", "T1580 Cloud Infrastructure Discovery (permission probing)", 0),
    ("distinct destination ports", "T1046 Network Service Discovery", 10),
    ("rejected-connection", "T1046 Network Service Discovery", 0),
    ("MB sent to the internet", "T1041 Exfiltration Over C2 Channel", 10),
    ("never-seen external", "T1071 Application Layer Protocol (new external destination)", 0),
    ("beacon", "T1071.001 Web Protocols (C2 beaconing)", 0),
]

_RATIO = re.compile(r"\((\d+)x typical\)")


def map_reasons(reasons: list[str]) -> list[str]:
    out = []
    for reason in reasons:
        m = _RATIO.search(reason)
        ratio = int(m.group(1)) if m else 0
        for needle, technique, min_ratio in RULES:
            if needle in reason and ratio >= min_ratio and technique not in out:
                out.append(technique)
    return out
