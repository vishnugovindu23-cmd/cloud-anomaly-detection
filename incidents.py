"""Group hourly alerts into incidents so one compromised host isn't 40 separate tickets."""
from __future__ import annotations

import pandas as pd

SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}


def group_incidents(alerts: pd.DataFrame, source: str, max_gap_hours: int = 24) -> pd.DataFrame:
    """Merge alerts for the same entity that are within max_gap_hours of each other."""
    if alerts.empty:
        return pd.DataFrame(columns=["source", "entity", "first_seen", "last_seen", "alert_hours",
                                     "severity", "peak_score", "reasons", "mitre"])
    rows = []
    for entity, g in alerts.sort_values("hour").groupby("entity"):
        cluster: list[pd.Series] = []
        for _, alert in g.iterrows():
            if cluster and (alert["hour"] - cluster[-1]["hour"]) > pd.Timedelta(hours=max_gap_hours):
                rows.append(_summarise(source, entity, cluster))
                cluster = []
            cluster.append(alert)
        rows.append(_summarise(source, entity, cluster))
    out = pd.DataFrame(rows)
    out["_rank"] = out["severity"].map(SEVERITY_RANK)
    return out.sort_values(["_rank", "peak_score"], ascending=False).drop(columns="_rank").reset_index(drop=True)


def _summarise(source: str, entity: str, cluster: list[pd.Series]) -> dict:
    reasons: list[str] = []
    mitre: list[str] = []
    for a in cluster:
        for r in a["reasons"]:
            key = r.split(" (")[0].lstrip("0123456789.,")
            if not any(existing.split(" (")[0].lstrip("0123456789.,") == key for existing in reasons):
                reasons.append(r)
        for t in a["mitre"]:
            if t not in mitre:
                mitre.append(t)
    severity = max((a["severity"] for a in cluster), key=lambda s: SEVERITY_RANK[s])
    return {
        "source": source,
        "entity": entity,
        "first_seen": cluster[0]["hour"],
        "last_seen": cluster[-1]["hour"],
        "alert_hours": len(cluster),
        "severity": severity,
        "peak_score": max(a["anomaly_score"] for a in cluster),
        "reasons": reasons,
        "mitre": mitre,
    }


def evaluate(incidents: pd.DataFrame, beacons: pd.DataFrame, labels: dict) -> dict:
    """Compare detections with the generator's ground truth."""
    detected, missed = [], []
    for kind in ("cloudtrail", "flowlogs"):
        for label in labels.get(kind, []):
            if label["hour"] == "beacon":
                hit = not beacons.empty and label["entity"] in set(beacons["entity"])
            else:
                hour = pd.Timestamp(label["hour"])
                inc = incidents[incidents["entity"] == label["entity"]]
                hit = bool(((inc["first_seen"] <= hour) & (inc["last_seen"] >= hour)).any())
            (detected if hit else missed).append(label)
    attack_entities = {l["entity"] for k in ("cloudtrail", "flowlogs") for l in labels.get(k, [])}
    false_positives = incidents[~incidents["entity"].isin(attack_entities)]
    total = len(detected) + len(missed)
    return {
        "attacks": total,
        "detected": len(detected),
        "missed": missed,
        "recall": round(len(detected) / total, 3) if total else None,
        "incidents": len(incidents),
        "false_positive_incidents": len(false_positives),
        "false_positive_entities": sorted(false_positives["entity"]),
    }
