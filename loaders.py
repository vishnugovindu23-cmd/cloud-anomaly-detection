"""Read real-format CloudTrail (JSON / .json.gz / folder of them) and VPC Flow Logs (v2 text)."""
from __future__ import annotations

import gzip
import ipaddress
import json
from pathlib import Path

import pandas as pd

FLOW_COLUMNS = [
    "version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport", "dstport",
    "protocol", "packets", "bytes", "start", "end", "action", "log_status",
]


def _read_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt") as fh:
            return fh.read()
    return path.read_text()


def load_cloudtrail(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    records = []
    for f in files:
        if not f.name.endswith((".json", ".json.gz")):
            continue
        records.extend(json.loads(_read_text(f)).get("Records", []))
    rows = []
    for r in records:
        ident = r.get("userIdentity", {})
        principal = ident.get("userName") or ident.get("arn", "").rsplit("/", 1)[-1] or ident.get("type", "unknown")
        rows.append({
            "time": r["eventTime"],
            "principal": principal,
            "event_source": r.get("eventSource", ""),
            "event_name": r.get("eventName", ""),
            "region": r.get("awsRegion", ""),
            "source_ip": r.get("sourceIPAddress", ""),
            "user_agent": r.get("userAgent", ""),
            "error": r.get("errorCode"),
        })
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["time"] = pd.to_datetime(df["time"], utc=True)
    return df.sort_values("time").reset_index(drop=True)


def load_flow_logs(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    lines = [l for l in _read_text(path).splitlines() if l and not l.startswith("version")]
    rows = [l.split() for l in lines]
    df = pd.DataFrame([r for r in rows if len(r) == len(FLOW_COLUMNS) and r[13] == "OK"], columns=FLOW_COLUMNS)
    if df.empty:
        return df
    for col in ("srcport", "dstport", "protocol", "packets", "bytes", "start", "end"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype("int64")
    df["time"] = pd.to_datetime(df["start"], unit="s", utc=True)
    df["dst_external"] = df["dstaddr"].map(_is_external)
    return df.sort_values("time").reset_index(drop=True)


def _is_external(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False
