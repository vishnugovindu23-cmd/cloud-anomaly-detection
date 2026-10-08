"""Hybrid detector: Isolation Forest score + baseline-novelty signals.

Isolation Forest alone struggles here: identity-specific flags such as "new source IP"
are always 0 in the training window (the baseline defines what is known), so the
forest never learns to split on them. The detector therefore combines two views:

  * anomaly_score  - Isolation Forest, how unusual the hour looks overall
  * novelty        - count of hard signals the baseline never produced
                     (new IP/region/client, or a metric at 1.5x its training max)

Alert when novelty >= 2, or novelty >= 1 and the hour is either off-hours for
that entity or above the 99th percentile of training anomaly scores.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from .mitre import map_reasons

LABELS = {
    "events": "API calls", "distinct_apis": "distinct APIs", "error_rate": "error rate",
    "sensitive_calls": "sensitive IAM/logging calls", "iam_recon_calls": "IAM/STS recon calls",
    "s3_reads": "S3 GetObject calls", "ec2_launches": "EC2 instances launched",
    "flows": "flows", "bytes_out_mb": "MB sent", "external_mb": "MB sent to the internet",
    "distinct_dst_ips": "distinct destination IPs", "distinct_dst_ports": "distinct destination ports",
    "reject_ratio": "rejected-connection ratio", "new_external_dsts": "never-seen external destinations",
}
FLAGS = {
    "new_ip": "source IP never seen for this identity",
    "new_region": "AWS region never used by this identity",
    "new_user_agent": "new client / user agent",
}
OFF_HOURS = "off_hours"
PERCENT_FEATURES = {"error_rate", "reject_ratio"}
NOVELTY_FACTOR = 1.5


@dataclass
class DetectorResult:
    scored: pd.DataFrame
    score_threshold: float

    @property
    def alerts(self) -> pd.DataFrame:
        a = self.scored[self.scored["is_anomaly"]]
        return a.sort_values(["novelty", "anomaly_score"], ascending=False)


class BehaviourDetector:
    def __init__(self, features: list[str], seed: int = 42):
        self.features = features
        self.scaler = RobustScaler()
        self.model = IsolationForest(n_estimators=300, random_state=seed)

    def fit(self, train: pd.DataFrame) -> "BehaviourDetector":
        X = self.scaler.fit_transform(np.log1p(train[self.features].astype(float)))
        self.model.fit(X)
        self.train_scores = -self.model.score_samples(X)
        self.score_threshold = float(np.percentile(self.train_scores, 99))
        self.train_max = train[self.features].max()
        self.p99 = train[self.features].quantile(0.99)
        self.median = train[self.features].median()
        return self

    def score(self, df: pd.DataFrame) -> DetectorResult:
        X = self.scaler.transform(np.log1p(df[self.features].astype(float)))
        out = df.copy()
        out["anomaly_score"] = np.round(-self.model.score_samples(X), 4)
        out["novelty"] = [self._novelty(row) for _, row in out.iterrows()]
        off = out[OFF_HOURS] == 1 if OFF_HOURS in out else False
        out["is_anomaly"] = (out["novelty"] >= 2) | (
            (out["novelty"] >= 1) & (off | (out["anomaly_score"] > self.score_threshold))
        )
        out["severity"] = np.where(
            out["novelty"] >= 3, "HIGH", np.where((out["novelty"] >= 2) | off, "MEDIUM", "LOW")
        )
        out.loc[~out["is_anomaly"], "severity"] = ""
        out["reasons"] = [self.explain(r) if a else [] for (_, r), a in zip(out.iterrows(), out["is_anomaly"])]
        out["mitre"] = out["reasons"].map(map_reasons)
        return DetectorResult(out, self.score_threshold)

    def _novelty(self, row: pd.Series) -> int:
        n = 0
        for f in self.features:
            if f in FLAGS:
                n += int(row[f] > 0)
            elif f == OFF_HOURS:
                continue
            elif self.train_max[f] > 0:
                n += int(row[f] > NOVELTY_FACTOR * self.train_max[f])
            else:
                n += int(row[f] > 0)
        return n

    def explain(self, row: pd.Series) -> list[str]:
        reasons = []
        for f in self.features:
            if f in FLAGS:
                if row[f]:
                    reasons.append(FLAGS[f])
                continue
            if f == OFF_HOURS:
                if row[f]:
                    reasons.append("activity outside this entity's normal hours")
                continue
            value, p99, med = row[f], self.p99[f], self.median[f]
            if value > p99 and value > 0:
                ratio = f" ({value / med:.0f}x typical)" if med and value / med >= 3 else ""
                if f in PERCENT_FEATURES:
                    shown = f"{value:.0%}"
                elif float(value).is_integer() or value >= 10:
                    shown = f"{value:,.0f}"
                else:
                    shown = f"{value:.2f}"
                reasons.append(f"{shown} {LABELS.get(f, f)}{ratio}")
        return reasons or ["unusual combination of features"]
