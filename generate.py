"""Synthetic but realistic CloudTrail and VPC Flow Log data with labelled attacks.

14 days of normal activity for a small AWS account. Attacks are injected in the
last 4 days so the model can be trained on a clean baseline (days 1-10) and
evaluated against known ground truth.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

START = datetime(2026, 9, 1, tzinfo=timezone.utc)
DAYS = 14
TRAIN_DAYS = 10
ACCOUNT = "123456789012"

DEV_EVENTS = [
    ("ec2.amazonaws.com", "DescribeInstances"), ("s3.amazonaws.com", "GetObject"),
    ("s3.amazonaws.com", "PutObject"), ("s3.amazonaws.com", "ListBuckets"),
    ("logs.amazonaws.com", "DescribeLogGroups"), ("logs.amazonaws.com", "GetLogEvents"),
    ("lambda.amazonaws.com", "Invoke"), ("lambda.amazonaws.com", "UpdateFunctionCode"),
    ("cloudwatch.amazonaws.com", "GetMetricData"), ("sts.amazonaws.com", "AssumeRole"),
]
ANALYST_EVENTS = [
    ("s3.amazonaws.com", "GetObject"), ("s3.amazonaws.com", "ListObjects"),
    ("athena.amazonaws.com", "StartQueryExecution"), ("athena.amazonaws.com", "GetQueryResults"),
    ("glue.amazonaws.com", "GetTable"),
]
OPS_EVENTS = [
    ("ec2.amazonaws.com", "DescribeInstances"), ("ec2.amazonaws.com", "StartInstances"),
    ("ec2.amazonaws.com", "StopInstances"), ("autoscaling.amazonaws.com", "DescribeAutoScalingGroups"),
    ("cloudwatch.amazonaws.com", "DescribeAlarms"), ("ssm.amazonaws.com", "SendCommand"),
    ("iam.amazonaws.com", "GetRole"),
]

USERS = (
    [(f"dev.{n}", DEV_EVENTS) for n in ("sarah", "arjun", "li", "maria", "tom", "priya", "ken")]
    + [(f"analyst.{n}", ANALYST_EVENTS) for n in ("raj", "emma", "noah")]
    + [(f"ops.{n}", OPS_EVENTS) for n in ("mike", "zoe", "sam")]
)

ATTACKER_IP = "45.155.205.233"
C2_IP = "91.219.236.18"
EXFIL_IP = "185.220.101.45"


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _event(user, source, name, when, ip, region="us-east-1", error=None, params=None):
    rec = {
        "eventVersion": "1.09",
        "eventTime": _ts(when),
        "eventSource": source,
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": "aws-cli/2.15.30 Python/3.11.8" if ip != ATTACKER_IP else "python-requests/2.31.0",
        "userIdentity": {
            "type": "IAMUser",
            "userName": user,
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
            "accountId": ACCOUNT,
        },
        "requestParameters": params or {},
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT,
    }
    if error:
        rec["errorCode"] = error
        rec["errorMessage"] = "User is not authorized to perform this operation"
    return rec


def generate_cloudtrail(rng: random.Random) -> tuple[list[dict], list[dict]]:
    records, labels = [], []
    profiles = {}
    for i, (user, _) in enumerate(USERS):
        profiles[user] = {
            "ips": [f"203.0.113.{10 + i}", f"198.51.100.{20 + i}"],
            "start": rng.choice([12, 13, 14]),
            "end": rng.choice([21, 22, 23]),
        }

    for day in range(DAYS):
        date = START + timedelta(days=day)
        if date.weekday() >= 5:
            continue
        for user, catalogue in USERS:
            p = profiles[user]
            for hour in range(p["start"], p["end"]):
                if rng.random() < 0.25:
                    continue
                for _ in range(max(1, int(rng.gauss(9, 3)))):
                    when = date + timedelta(hours=hour, seconds=rng.randint(0, 3599))
                    src, name = rng.choice(catalogue)
                    err = "AccessDenied" if rng.random() < 0.02 else None
                    records.append(_event(user, src, name, when, rng.choice(p["ips"]), error=err))

    def attack(user, when, events, ip, label, technique, region="us-east-1", gap=7):
        for i, (src, name, err) in enumerate(events):
            records.append(_event(user, src, name, when + timedelta(seconds=gap * i), ip, region, err))
        labels.append({"entity": user, "hour": _ts(when.replace(minute=0, second=0)), "attack": label, "technique": technique})

    t = START + timedelta(days=11, hours=3, minutes=12)
    recon = [("sts.amazonaws.com", "GetCallerIdentity", None)]
    for name in ["ListUsers", "ListRoles", "ListPolicies", "ListAttachedUserPolicies", "GetAccountAuthorizationDetails"]:
        recon += [("iam.amazonaws.com", name, rng.choice([None, "AccessDenied"])) for _ in range(4)]
    recon += [("s3.amazonaws.com", "ListBuckets", None), ("ec2.amazonaws.com", "DescribeInstances", None)] * 3
    escalate = [
        ("iam.amazonaws.com", "CreateAccessKey", None),
        ("iam.amazonaws.com", "CreateUser", None),
        ("iam.amazonaws.com", "AttachUserPolicy", None),
        ("iam.amazonaws.com", "CreateLoginProfile", None),
    ]
    attack("dev.sarah", t, recon + escalate, ATTACKER_IP, "Compromised credentials: recon + privilege escalation", "T1078.004, T1087.004, T1098")

    t = START + timedelta(days=11, hours=4, minutes=5)
    evade = [
        ("cloudtrail.amazonaws.com", "StopLogging", None),
        ("guardduty.amazonaws.com", "DeleteDetector", None),
        ("s3.amazonaws.com", "PutBucketPolicy", None),
        ("config.amazonaws.com", "StopConfigurationRecorder", None),
    ]
    attack("dev.sarah", t, evade, ATTACKER_IP, "Defense evasion: logging and detection disabled", "T1562.008")

    t = START + timedelta(days=12, hours=20, minutes=2)
    exfil = [("s3.amazonaws.com", "GetObject", None)] * 650
    attack("analyst.raj", t, [(s, n, e) for s, n, e in exfil], profiles["analyst.raj"]["ips"][0], "Bulk S3 download (data staging/exfiltration)", "T1530", gap=5)

    t = START + timedelta(days=13, hours=2, minutes=40)
    mining = [("ec2.amazonaws.com", "RunInstances", None)] * 40 + [("ec2.amazonaws.com", "DescribeInstances", None)] * 5
    attack("ops.mike", t, mining, "103.75.201.4", "Resource hijacking: 40 instances launched in unused region", "T1496", region="ap-southeast-1")

    records.sort(key=lambda r: r["eventTime"])
    return records, labels


def _flow(eni, src, dst, sport, dport, proto, packets, nbytes, start, action="ACCEPT"):
    end = start + rng_duration(nbytes)
    return f"2 {ACCOUNT} {eni} {src} {dst} {sport} {dport} {proto} {packets} {nbytes} {int(start.timestamp())} {int(end.timestamp())} {action} OK"


def rng_duration(nbytes: int) -> timedelta:
    return timedelta(seconds=max(1, min(600, nbytes // 500_000)))


def generate_flow_logs(rng: random.Random) -> tuple[list[str], list[dict]]:
    hosts = [f"10.0.1.{i}" for i in range(10, 25)] + [f"10.0.2.{i}" for i in range(10, 20)]
    internal_services = [("10.0.3.10", 443), ("10.0.3.20", 5432), ("10.0.3.30", 6379)]
    aws_endpoints = ["52.216.10.4", "54.231.8.99", "3.5.140.2", "52.94.133.131"]
    lines, labels = [], []

    for day in range(DAYS):
        for hour in range(24):
            base = START + timedelta(days=day, hours=hour)
            busy = 13 <= hour <= 23
            for idx, h in enumerate(hosts):
                eni = f"eni-0{idx:02d}a1b2c3d4e5f6"
                for _ in range(rng.randint(4, 9) if busy else rng.randint(1, 3)):
                    dst, port = rng.choice(internal_services)
                    lines.append(_flow(eni, h, dst, rng.randint(32768, 60999), port, 6,
                                       rng.randint(5, 60), rng.randint(2_000, 90_000),
                                       base + timedelta(seconds=rng.randint(0, 3500))))
                for _ in range(rng.randint(1, 3)):
                    lines.append(_flow(eni, h, rng.choice(aws_endpoints), rng.randint(32768, 60999), 443, 6,
                                       rng.randint(10, 200), rng.randint(10_000, 2_000_000),
                                       base + timedelta(seconds=rng.randint(0, 3500))))

    scanner, scan_eni = "10.0.1.23", "eni-013a1b2c3d4e5f6"
    t = START + timedelta(days=11, hours=4)
    for target in [f"10.0.2.{i}" for i in range(10, 20)]:
        for port in rng.sample(range(1, 10000), 120):
            action = "ACCEPT" if port in (22, 443, 5432) else "REJECT"
            lines.append(_flow(scan_eni, scanner, target, rng.randint(40000, 60000), port, 6, 1, 44,
                               t + timedelta(seconds=rng.randint(0, 3000)), action))
    labels.append({"entity": scanner, "hour": _ts(t), "attack": "Internal port scan", "technique": "T1046"})

    t = START + timedelta(days=11, hours=5)
    for i in range(30):
        lines.append(_flow(scan_eni, scanner, EXFIL_IP, rng.randint(40000, 60000), 443, 6, 110_000,
                           150_000_000, t + timedelta(seconds=90 * i)))
    labels.append({"entity": scanner, "hour": _ts(t), "attack": "Large outbound transfer to Tor exit", "technique": "T1041"})

    beacon_host, beacon_eni = "10.0.2.14", "eni-019a1b2c3d4e5f6"
    t = START + timedelta(days=10, hours=6)
    while t < START + timedelta(days=DAYS):
        lines.append(_flow(beacon_eni, beacon_host, C2_IP, rng.randint(40000, 60000), 8443, 6, 4, 620,
                           t + timedelta(seconds=rng.randint(-3, 3))))
        t += timedelta(seconds=300)
    labels.append({"entity": beacon_host, "hour": "beacon", "attack": f"C2 beaconing every 5 min to {C2_IP}:8443", "technique": "T1071.001"})

    header = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
    lines.sort(key=lambda l: int(l.split()[10]))
    return [header] + lines, labels


def generate(out_dir: str | Path = "data", seed: int = 7) -> dict[str, Path]:
    rng = random.Random(seed)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    records, ct_labels = generate_cloudtrail(rng)
    flows, flow_labels = generate_flow_logs(rng)
    paths = {
        "cloudtrail": out / "cloudtrail.json",
        "flowlogs": out / "vpc_flow_logs.log",
        "labels": out / "ground_truth.json",
    }
    paths["cloudtrail"].write_text(json.dumps({"Records": records}))
    paths["flowlogs"].write_text("\n".join(flows) + "\n")
    paths["labels"].write_text(json.dumps({"cloudtrail": ct_labels, "flowlogs": flow_labels, "train_days": TRAIN_DAYS}, indent=2))
    return paths
