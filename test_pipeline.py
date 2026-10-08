import json
from pathlib import Path

import pandas as pd
import pytest

from anomaly.beacon import find_beacons
from anomaly.cli import run
from anomaly.generate import generate
from anomaly.incidents import group_incidents
from anomaly.loaders import load_cloudtrail, load_flow_logs
from anomaly.mitre import map_reasons
from anomaly.model import BehaviourDetector


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    base = tmp_path_factory.mktemp("demo")
    paths = generate(base / "data")
    return run(paths["cloudtrail"], paths["flowlogs"], base / "out", labels=paths["labels"])


def test_all_injected_attacks_detected(demo):
    assert demo.metrics["detected"] == demo.metrics["attacks"] == 7
    assert demo.metrics["missed"] == []


def test_false_positives_stay_low(demo):
    assert demo.metrics["false_positive_incidents"] <= 1


def test_no_alerts_inside_training_window(demo):
    cutoff = demo.ct_scored["hour"].min().floor("D") + pd.Timedelta(days=10)
    assert not demo.ct_scored[(demo.ct_scored["hour"] < cutoff) & demo.ct_scored["is_anomaly"]].shape[0]
    assert not demo.flow_scored[(demo.flow_scored["hour"] < cutoff) & demo.flow_scored["is_anomaly"]].shape[0]


def test_compromised_user_explained_and_mapped(demo):
    sarah = demo.incidents[demo.incidents["entity"] == "dev.sarah"].iloc[0]
    assert sarah["severity"] == "HIGH"
    assert "source IP never seen for this identity" in sarah["reasons"]
    assert any(t.startswith("T1078.004") for t in sarah["mitre"])
    assert any("T1562.008" in t for t in sarah["mitre"])


def test_outputs_written(demo):
    for path in demo.outputs.values():
        assert Path(path).exists() and Path(path).stat().st_size > 0
    assert "Detection results against ground truth" in demo.outputs["report"].read_text()


def test_flow_log_parser_handles_nodata_and_header(tmp_path):
    f = tmp_path / "flows.log"
    f.write_text(
        "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n"
        "2 123456789012 eni-1 10.0.1.5 8.8.8.8 50000 53 17 1 70 1757000000 1757000001 ACCEPT OK\n"
        "2 123456789012 eni-1 - - - - - - - 1757000000 1757000060 - NODATA\n"
    )
    df = load_flow_logs(f)
    assert len(df) == 1
    assert bool(df.iloc[0]["dst_external"]) is True


def test_cloudtrail_loader_reads_role_sessions(tmp_path):
    f = tmp_path / "ct.json"
    f.write_text(json.dumps({"Records": [{
        "eventTime": "2026-09-01T10:00:00Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
        "awsRegion": "us-east-1", "sourceIPAddress": "10.0.0.1",
        "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/ci-deploy/session-42"},
    }]}))
    df = load_cloudtrail(f)
    assert df.iloc[0]["principal"] == "session-42"


def test_beacon_detection_finds_regular_small_connections():
    start = pd.Timestamp("2026-09-01", tz="UTC").timestamp()
    rows = [{"srcaddr": "10.0.0.9", "dstaddr": "91.219.236.18", "dstport": 8443, "bytes": 600,
             "start": int(start + 300 * i), "time": pd.Timestamp(start + 300 * i, unit="s", tz="UTC"),
             "dst_external": True} for i in range(50)]
    rows += [{"srcaddr": "10.0.0.9", "dstaddr": "52.1.1.1", "dstport": 443, "bytes": 800,
              "start": int(start + i * i * 37), "time": pd.Timestamp(start + i * i * 37, unit="s", tz="UTC"),
              "dst_external": True} for i in range(50)]
    beacons = find_beacons(pd.DataFrame(rows))
    assert list(beacons["destination"]) == ["91.219.236.18:8443"]
    assert beacons.iloc[0]["interval_seconds"] == 300


def test_novelty_requires_new_behaviour():
    train = pd.DataFrame({"events": [5, 6, 7, 8, 9] * 20, "new_ip": [0] * 100, "off_hours": [0] * 100})
    det = BehaviourDetector(["events", "new_ip", "off_hours"]).fit(train)
    test = pd.DataFrame({"events": [7, 40, 7], "new_ip": [0, 0, 1], "off_hours": [0, 1, 1],
                         "entity": ["u"] * 3, "hour": pd.date_range("2026-09-01", periods=3, freq="h", tz="UTC")})
    scored = det.score(test).scored
    assert list(scored["is_anomaly"]) == [False, True, True]


def test_mitre_mapping_respects_ratio():
    assert map_reasons(["4 distinct destination ports"]) == []
    assert map_reasons(["1,144 distinct destination ports (381x typical)"]) == ["T1046 Network Service Discovery"]


def test_incident_grouping_merges_nearby_hours():
    hours = pd.to_datetime(["2026-09-12 04:00", "2026-09-12 05:00", "2026-09-20 05:00"], utc=True)
    alerts = pd.DataFrame({"entity": ["h"] * 3, "hour": hours, "severity": ["HIGH", "MEDIUM", "LOW"],
                           "anomaly_score": [0.6, 0.7, 0.5], "reasons": [["a"], ["b"], ["c"]], "mitre": [[], [], []]})
    inc = group_incidents(alerts, "VPC Flow")
    assert len(inc) == 2
    first = inc[inc["alert_hours"] == 2].iloc[0]
    assert first["severity"] == "HIGH" and first["reasons"] == ["a", "b"]
