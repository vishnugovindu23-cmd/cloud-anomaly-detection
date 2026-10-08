"""Hourly behaviour features per identity (CloudTrail) and per host (VPC Flow Logs).

"New" features (new IP, new region, new external destination) are measured
against each entity's own baseline from the training window, so the model
learns what is normal for that user or host, not for the account as a whole.
"""
from __future__ import annotations

import pandas as pd

SENSITIVE_APIS = {
    "CreateAccessKey", "CreateUser", "CreateLoginProfile", "UpdateLoginProfile", "AttachUserPolicy",
    "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreatePolicyVersion", "AddUserToGroup",
    "StopLogging", "DeleteTrail", "UpdateTrail", "DeleteDetector", "DisableSecurityHub",
    "StopConfigurationRecorder", "DeleteFlowLogs", "PutBucketPolicy", "PutBucketAcl",
    "DeleteBucketEncryption", "ModifySnapshotAttribute", "ModifyImageAttribute",
}
RECON_PREFIXES = ("List", "Describe", "GetAccount", "GetCallerIdentity")

CLOUDTRAIL_FEATURES = [
    "events", "distinct_apis", "error_rate", "sensitive_calls", "iam_recon_calls",
    "s3_reads", "ec2_launches", "new_ip", "new_region", "new_user_agent", "off_hours",
]
FLOW_FEATURES = [
    "flows", "bytes_out_mb", "external_mb", "distinct_dst_ips", "distinct_dst_ports",
    "reject_ratio", "new_external_dsts", "off_hours",
]


def _typical_hours(times: pd.Series) -> set[int]:
    hours = times.dt.hour.value_counts(normalize=True)
    return set(hours[hours >= 0.01].index)


def cloudtrail_features(df: pd.DataFrame, train_end: pd.Timestamp) -> pd.DataFrame:
    df = df.copy()
    df["hour"] = df["time"].dt.floor("h")
    train = df[df["time"] < train_end]
    base_ips = train.groupby("principal")["source_ip"].agg(set).to_dict()
    base_regions = train.groupby("principal")["region"].agg(set).to_dict()
    base_agents = train.groupby("principal")["user_agent"].agg(set).to_dict()
    base_hours = {p: _typical_hours(g["time"]) for p, g in train.groupby("principal")}

    df["is_error"] = df["error"].notna()
    df["is_sensitive"] = df["event_name"].isin(SENSITIVE_APIS)
    df["is_iam_recon"] = (df["event_source"].isin(["iam.amazonaws.com", "sts.amazonaws.com"])) & df["event_name"].str.startswith(RECON_PREFIXES)
    df["is_s3_read"] = (df["event_source"] == "s3.amazonaws.com") & (df["event_name"] == "GetObject")
    df["is_launch"] = df["event_name"] == "RunInstances"
    df["new_ip"] = [ip not in base_ips.get(p, set()) for p, ip in zip(df["principal"], df["source_ip"])]
    df["new_region"] = [r not in base_regions.get(p, set()) for p, r in zip(df["principal"], df["region"])]
    df["new_agent"] = [a not in base_agents.get(p, set()) for p, a in zip(df["principal"], df["user_agent"])]

    g = df.groupby(["principal", "hour"])
    feats = pd.DataFrame({
        "events": g.size(),
        "distinct_apis": g["event_name"].nunique(),
        "error_rate": g["is_error"].mean(),
        "sensitive_calls": g["is_sensitive"].sum(),
        "iam_recon_calls": g["is_iam_recon"].sum(),
        "s3_reads": g["is_s3_read"].sum(),
        "ec2_launches": g["is_launch"].sum(),
        "new_ip": g["new_ip"].max().astype(int),
        "new_region": g["new_region"].max().astype(int),
        "new_user_agent": g["new_agent"].max().astype(int),
    }).reset_index()
    feats["off_hours"] = [
        int(h.hour not in base_hours.get(p, set(range(24)))) for p, h in zip(feats["principal"], feats["hour"])
    ]
    feats = feats.rename(columns={"principal": "entity"})
    feats["sample_ips"] = g["source_ip"].agg(lambda s: ", ".join(sorted(set(s))[:3])).values
    feats["top_apis"] = g["event_name"].agg(lambda s: ", ".join(s.value_counts().index[:4])).values
    return feats


def flow_features(df: pd.DataFrame, train_end: pd.Timestamp) -> pd.DataFrame:
    df = df[df["srcaddr"].str.startswith(("10.", "172.", "192.168."))].copy()
    df["hour"] = df["time"].dt.floor("h")
    train = df[df["time"] < train_end]
    base_ext = train[train["dst_external"]].groupby("srcaddr")["dstaddr"].agg(set).to_dict()
    base_hours = {h: _typical_hours(g["time"]) for h, g in train.groupby("srcaddr")}

    df["is_reject"] = df["action"] == "REJECT"
    df["ext_bytes"] = df["bytes"].where(df["dst_external"], 0)
    df["new_ext"] = [
        ext and dst not in base_ext.get(src, set())
        for src, dst, ext in zip(df["srcaddr"], df["dstaddr"], df["dst_external"])
    ]
    g = df.groupby(["srcaddr", "hour"])
    feats = pd.DataFrame({
        "flows": g.size(),
        "bytes_out_mb": g["bytes"].sum() / 1e6,
        "external_mb": g["ext_bytes"].sum() / 1e6,
        "distinct_dst_ips": g["dstaddr"].nunique(),
        "distinct_dst_ports": g["dstport"].nunique(),
        "reject_ratio": g["is_reject"].mean(),
        "new_external_dsts": df[df["new_ext"]].groupby(["srcaddr", "hour"])["dstaddr"].nunique(),
    }).fillna({"new_external_dsts": 0}).reset_index()
    feats["off_hours"] = [
        int(h.hour not in base_hours.get(s, set(range(24)))) for s, h in zip(feats["srcaddr"], feats["hour"])
    ]
    top_dst = g["dstaddr"].agg(lambda s: ", ".join(s.value_counts().index[:3])).rename("top_destinations")
    feats = feats.merge(top_dst.reset_index(), on=["srcaddr", "hour"])
    return feats.rename(columns={"srcaddr": "entity"})
