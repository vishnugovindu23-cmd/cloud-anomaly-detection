"""Markdown report, CSV exports and a timeline chart."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3de"
NORMAL = "#9d9c96"
ALERT = "#e34948"
BASELINE = "#f0efea"


def _fmt(ts: pd.Timestamp) -> str:
    return ts.strftime("%b %d %H:%M")


def markdown(incidents: pd.DataFrame, beacons: pd.DataFrame, metrics: dict | None, stats: dict) -> str:
    lines = ["# Cloud Anomaly Detection Report", ""]
    lines += [
        f"Analysed **{stats['cloudtrail_events']:,} CloudTrail events** and "
        f"**{stats['flow_records']:,} VPC flow records**, scored as "
        f"{stats['ct_windows']:,} identity-hours and {stats['flow_windows']:,} host-hours. "
        f"Baseline (training) window: {stats['train_start']} to {stats['train_end']}.",
        "",
    ]
    if metrics:
        lines += [
            "## Detection results against ground truth",
            "",
            f"- Attacks injected: **{metrics['attacks']}**, detected: **{metrics['detected']}** "
            f"(recall {metrics['recall']:.0%})",
            f"- Incidents raised: **{metrics['incidents']}**, false-positive incidents: "
            f"**{metrics['false_positive_incidents']}**"
            + (f" ({', '.join(metrics['false_positive_entities'])})" if metrics["false_positive_entities"] else ""),
            "",
        ]
    lines += ["## Incidents", "", "| Severity | Source | Entity | Window | Alert hours | Why | Likely ATT&CK |", "|---|---|---|---|---|---|---|"]
    for _, i in incidents.iterrows():
        window = _fmt(i["first_seen"]) if i["first_seen"] == i["last_seen"] else f"{_fmt(i['first_seen'])} to {_fmt(i['last_seen'])}"
        lines.append(
            f"| {i['severity']} | {i['source']} | `{i['entity']}` | {window} | {i['alert_hours']} | "
            f"{'; '.join(i['reasons'][:5])} | {'<br>'.join(i['mitre'][:4])} |"
        )
    lines += ["", "## C2 beaconing", ""]
    if beacons.empty:
        lines.append("No periodic beaconing found.")
    else:
        lines += ["| Host | Destination | Connections | Interval | Jitter | Avg bytes | First seen | Last seen |", "|---|---|---|---|---|---|---|---|"]
        for _, b in beacons.iterrows():
            lines.append(
                f"| `{b['entity']}` | `{b['destination']}` | {b['connections']} | {b['interval_seconds']}s | "
                f"{b['jitter']} | {b['avg_bytes']} | {_fmt(b['first_seen'])} | {_fmt(b['last_seen'])} |"
            )
        lines += ["", "Likely ATT&CK: T1071.001 Web Protocols (C2 beaconing)"]
    return "\n".join(lines) + "\n"


def timeline_chart(ct_scored: pd.DataFrame, flow_scored: pd.DataFrame, train_start: pd.Timestamp,
                   train_end: pd.Timestamp, thresholds: tuple[float, float], path: str | Path) -> Path:
    fig, axes = plt.subplots(2, 1, figsize=(11, 6.4), sharex=True, facecolor=SURFACE)
    panels = [("CloudTrail: identity-hours", ct_scored, thresholds[0]),
              ("VPC Flow Logs: host-hours", flow_scored, thresholds[1])]
    for ax, (title, df, thr) in zip(axes, panels):
        ax.set_facecolor(SURFACE)
        start = train_start
        ax.axvspan(start, train_end, color=BASELINE, zorder=0)
        ax.text(start, 1.0, "  baseline (training)", transform=ax.get_xaxis_transform(),
                va="top", ha="left", fontsize=8, color=INK_2)
        normal = df[~df["is_anomaly"]]
        alerts = df[df["is_anomaly"]]
        ax.scatter(normal["hour"], normal["anomaly_score"], s=8, color=NORMAL, alpha=0.45, linewidths=0, label="Normal hour", zorder=2)
        ax.scatter(alerts["hour"], alerts["anomaly_score"], s=42, color=ALERT, marker="^",
                   edgecolors=SURFACE, linewidths=1.5, label="Alert", zorder=3)
        ax.axhline(thr, color=INK_2, lw=1, ls=(0, (4, 3)), zorder=1)
        ax.text(df["hour"].max(), thr, " p99 of baseline", va="bottom", ha="right", fontsize=8, color=INK_2)
        top = alerts.sort_values("anomaly_score", ascending=False).drop_duplicates("entity").head(3)
        for _, a in top.iterrows():
            ax.annotate(a["entity"], (a["hour"], a["anomaly_score"]), xytext=(6, 4),
                        textcoords="offset points", fontsize=8, color=INK)
        ax.set_title(title, loc="left", fontsize=10, color=INK, pad=6)
        ax.set_ylabel("Anomaly score", fontsize=9, color=INK_2)
        ax.grid(axis="y", color=GRID, lw=0.8)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(GRID)
        ax.tick_params(colors=INK_2, labelsize=8, length=0)
    axes[0].legend(loc="upper left", bbox_to_anchor=(0, 1.28), ncol=2, frameon=False, fontsize=8)
    fig.autofmt_xdate()
    fig.tight_layout()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)
    return path
