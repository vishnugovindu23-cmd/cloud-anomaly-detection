"""C2 beacon detection: many small connections to one external host at a steady interval.

Hourly aggregates hide beacons (a few KB an hour looks normal), so this looks at
the timing between connections for each (source, destination) pair instead.
"""
from __future__ import annotations

import pandas as pd


def find_beacons(
    flows: pd.DataFrame,
    min_connections: int = 30,
    max_jitter: float = 0.1,
    max_avg_bytes: int = 20_000,
) -> pd.DataFrame:
    ext = flows[flows["dst_external"]]
    rows = []
    for (src, dst, port), g in ext.groupby(["srcaddr", "dstaddr", "dstport"]):
        if len(g) < min_connections:
            continue
        gaps = g["start"].sort_values().diff().dropna()
        gaps = gaps[gaps > 0]
        if gaps.empty:
            continue
        mean = gaps.mean()
        jitter = gaps.std() / mean if mean else 1.0
        avg_bytes = g["bytes"].mean()
        if jitter <= max_jitter and avg_bytes <= max_avg_bytes:
            rows.append({
                "entity": src,
                "destination": f"{dst}:{port}",
                "connections": len(g),
                "interval_seconds": round(mean),
                "jitter": round(jitter, 3),
                "avg_bytes": round(avg_bytes),
                "first_seen": g["time"].min(),
                "last_seen": g["time"].max(),
            })
    return pd.DataFrame(rows)
