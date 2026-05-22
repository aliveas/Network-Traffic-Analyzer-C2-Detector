

from datetime import datetime
import pandas as pd


SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _beacon_interval_str(mean_iat: float) -> str:
    """Human-readable beacon interval."""
    if mean_iat < 1:
        return f"{mean_iat*1000:.0f}ms"
    if mean_iat < 60:
        return f"{mean_iat:.1f}s"
    return f"{mean_iat/60:.1f}min"


def _summary(row) -> str:
    sev = row.get("severity", "Info")
    src = row.get("src_ip", "?")
    dst = row.get("dst_ip", "?")
    dpt = int(row.get("dst_port", 0))
    pkt = int(row.get("pkt_count", 0))
    cv  = row.get("coeff_var_iat", 1.0)

    if row.get("confirmed_c2"):
        return (f"C2 beaconing — {src} → {dst}:{dpt}"
                f"  ({pkt} pkts, regularity={cv:.2f})")
    return f"Anomalous flow — {src} → {dst}:{dpt}  ({pkt} pkts)"


def build_alerts(results_df: pd.DataFrame, flows: list) -> list:
    
    alerts = []

    for _, row in results_df.iterrows():
        sev = row.get("severity", "Info")
        if sev == "Info":
            continue   # skip clean flows

        rule_hits = row.get("rule_hits", [])
        if isinstance(rule_hits, list):
            rules_str = ", ".join(rule_hits) if rule_hits else "ML only"
        else:
            rules_str = str(rule_hits)

        alert = {
            "severity"    : sev,
            "confidence"  : row.get("confidence", "Low"),
            "confirmed_c2": bool(row.get("confirmed_c2", False)),
            "summary"     : _summary(row),
            "src_ip"      : row.get("src_ip", ""),
            "dst_ip"      : row.get("dst_ip", ""),
            "dst_port"    : int(row.get("dst_port", 0)),
            "protocol"    : row.get("protocol", ""),
            "start_time"  : row.get("start_time", ""),
            "pkt_count"   : int(row.get("pkt_count", 0)),
            "total_bytes" : int(row.get("total_bytes", 0)),
            "duration"    : round(float(row.get("duration", 0)), 1),
            "ml_score"    : round(float(row.get("ml_score", 0)), 4),
            "coeff_var_iat": round(float(row.get("coeff_var_iat", 0)), 4),
            "std_pkt_size": round(float(row.get("std_pkt_size", 0)), 2),
            "mean_iat"    : round(float(row.get("mean_iat", 0)), 4),
            "beacon_interval": _beacon_interval_str(
                float(row.get("mean_iat", 0))
            ),
            "night_ratio" : round(float(row.get("night_ratio", 0)), 3),
            "pkts_per_min": round(float(row.get("pkts_per_min", 0)), 2),
            "rule_hits"   : rules_str,
            "mitre"       : "T1071",
            "mitre_name"  : "Application Layer Protocol",
        }
        alerts.append(alert)

    alerts.sort(key=lambda a: SEV_ORDER.get(a["severity"], 99))
    return alerts
