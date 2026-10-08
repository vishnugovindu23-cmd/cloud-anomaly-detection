"""Command line: `python -m anomaly demo | generate | detect`."""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from . import report
from .beacon import find_beacons
from .features import CLOUDTRAIL_FEATURES, FLOW_FEATURES, cloudtrail_features, flow_features
from .generate import generate
from .incidents import evaluate, group_incidents
from .loaders import load_cloudtrail, load_flow_logs
from .model import BehaviourDetector


@dataclass
class RunResult:
    incidents: pd.DataFrame
    beacons: pd.DataFrame
    ct_scored: pd.DataFrame
    flow_scored: pd.DataFrame
    metrics: dict | None
    outputs: dict[str, Path]


def run(cloudtrail: str | Path, flowlogs: str | Path, out_dir: str | Path = "output",
        train_days: int = 10, train_end: str | None = None, labels: str | Path | None = None) -> RunResult:
    ct = load_cloudtrail(cloudtrail)
    flows = load_flow_logs(flowlogs)
    start = min(ct["time"].min(), flows["time"].min()).floor("D")
    cutoff = pd.Timestamp(train_end, tz="UTC") if train_end else start + pd.Timedelta(days=train_days)

    ct_feats = cloudtrail_features(ct, cutoff)
    flow_feats = flow_features(flows, cutoff)
    ct_det = BehaviourDetector(CLOUDTRAIL_FEATURES).fit(ct_feats[ct_feats["hour"] < cutoff])
    flow_det = BehaviourDetector(FLOW_FEATURES).fit(flow_feats[flow_feats["hour"] < cutoff])
    ct_res = ct_det.score(ct_feats)
    flow_res = flow_det.score(flow_feats)

    incidents = pd.concat(
        [group_incidents(ct_res.alerts, "CloudTrail"), group_incidents(flow_res.alerts, "VPC Flow")],
        ignore_index=True,
    )
    incidents["_r"] = incidents["severity"].map({"HIGH": 3, "MEDIUM": 2, "LOW": 1})
    incidents = incidents.sort_values(["_r", "peak_score"], ascending=False).drop(columns="_r").reset_index(drop=True)
    beacons = find_beacons(flows)

    metrics = evaluate(incidents, beacons, json.loads(Path(labels).read_text())) if labels else None

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stats = {
        "cloudtrail_events": len(ct), "flow_records": len(flows),
        "ct_windows": len(ct_feats), "flow_windows": len(flow_feats),
        "train_start": start.strftime("%Y-%m-%d"), "train_end": cutoff.strftime("%Y-%m-%d"),
    }
    outputs = {
        "report": out / "report.md",
        "incidents": out / "incidents.csv",
        "alerts": out / "hourly_alerts.csv",
        "chart": out / "anomaly_timeline.png",
    }
    outputs["report"].write_text(report.markdown(incidents, beacons, metrics, stats))
    inc_csv = incidents.copy()
    inc_csv["reasons"] = inc_csv["reasons"].map("; ".join)
    inc_csv["mitre"] = inc_csv["mitre"].map("; ".join)
    inc_csv.to_csv(outputs["incidents"], index=False)
    alerts = pd.concat([ct_res.alerts.assign(source="CloudTrail"), flow_res.alerts.assign(source="VPC Flow")])
    alerts[["source", "entity", "hour", "severity", "novelty", "anomaly_score", "reasons", "mitre"]].to_csv(outputs["alerts"], index=False)
    report.timeline_chart(ct_res.scored, flow_res.scored, start, cutoff,
                          (ct_res.score_threshold, flow_res.score_threshold), outputs["chart"])
    return RunResult(incidents, beacons, ct_res.scored, flow_res.scored, metrics, outputs)


def print_summary(result: RunResult) -> None:
    print(f"\n{len(result.incidents)} incidents, {len(result.beacons)} beaconing channel(s)\n")
    for _, i in result.incidents.iterrows():
        when = i["first_seen"].strftime("%b %d %H:%M")
        print(f"  [{i['severity']:<6}] {i['source']:<10} {i['entity']:<12} {when}  {'; '.join(i['reasons'][:3])}")
        if i["mitre"]:
            print(f"  {'':8} {'':10} {'':12} {'':12} ATT&CK: {', '.join(t.split(' ')[0] for t in i['mitre'])}")
    for _, b in result.beacons.iterrows():
        print(f"  [BEACON] {b['entity']} -> {b['destination']} every {b['interval_seconds']}s "
              f"({b['connections']} connections, jitter {b['jitter']})")
    if result.metrics:
        m = result.metrics
        print(f"\nGround truth: detected {m['detected']}/{m['attacks']} attacks, "
              f"{m['false_positive_incidents']} false-positive incident(s)")
    print("\nOutputs:")
    for name, path in result.outputs.items():
        print(f"  {name:<10} {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="anomaly", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Create synthetic CloudTrail + VPC Flow Logs with labelled attacks")
    g.add_argument("--out", default="data")
    g.add_argument("--seed", type=int, default=7)

    d = sub.add_parser("detect", help="Run detection on CloudTrail + VPC Flow Log files")
    d.add_argument("--cloudtrail", required=True, help="CloudTrail JSON / .json.gz file or folder")
    d.add_argument("--flowlogs", required=True, help="VPC Flow Logs (default v2 format)")
    d.add_argument("--train-days", type=int, default=10, help="Days from the start used as the clean baseline")
    d.add_argument("--train-end", help="Explicit baseline end (ISO date), overrides --train-days")
    d.add_argument("--labels", help="Ground-truth JSON to score detection (synthetic data only)")
    d.add_argument("--out", default="output")

    demo = sub.add_parser("demo", help="Generate data, then detect and score against ground truth")
    demo.add_argument("--out", default="output")

    args = parser.parse_args(argv)
    if args.cmd == "generate":
        paths = generate(args.out, args.seed)
        for k, v in paths.items():
            print(f"{k:<11} {v}")
        return 0
    if args.cmd == "detect":
        result = run(args.cloudtrail, args.flowlogs, args.out, args.train_days, args.train_end, args.labels)
    else:
        paths = generate("data")
        result = run(paths["cloudtrail"], paths["flowlogs"], args.out, labels=paths["labels"])
    print_summary(result)
    return 0
