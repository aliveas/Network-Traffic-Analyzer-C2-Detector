import math
import datetime
from collections import Counter

import pandas as pd
from colorama import Fore


# Ports commonly abused by C2 frameworks (score 0–3)
PORT_RISK = {
    # Low risk — expected services
    80:   0, 443:  0, 53:   0, 123:  0,
    # Medium — less common but legitimate
    8080: 1, 8443: 1, 3128: 1,
    # Higher risk — often C2
    4444: 3, 1234: 3, 8888: 2, 9999: 2,
    31337:3, 1337: 3, 6666: 2, 5555: 2,
    4433: 2, 8081: 1, 8082: 1,
}


def _inter_arrival_times(timestamps: list) -> list:
    """Compute list of time gaps between consecutive packets."""
    if len(timestamps) < 2:
        return [0.0]
    return [timestamps[i+1] - timestamps[i]
            for i in range(len(timestamps) - 1)]


def _night_ratio(timestamps: list) -> float:
    """Fraction of packets sent between 22:00 and 06:00 local time."""
    if not timestamps:
        return 0.0
    night = sum(
        1 for ts in timestamps
        if datetime.datetime.fromtimestamp(ts).hour in
           list(range(22, 24)) + list(range(0, 6))
    )
    return night / len(timestamps)


def _port_risk(port: int) -> int:
    """Return risk score (0–3) for a destination port."""
    if port in PORT_RISK:
        return PORT_RISK[port]
    # High numbered ports not in list — slightly suspicious
    if port > 49152:
        return 1
    return 0


def extract_features(flows: list, verbose: bool = False) -> pd.DataFrame:
    """
    Compute behavioral features for every flow.

    Parameters
    ----------
    flows   : list of flow dicts from flow_builder
    verbose : bool

    Returns
    -------
    pd.DataFrame with one row per flow + metadata columns
    """
    rows = []

    for flow in flows:
        pkts = flow["packets"]
        ts_list = [p["timestamp"] for p in pkts]
        sz_list = [p["length"]    for p in pkts]

        iats = _inter_arrival_times(ts_list)

        # Basic stats
        pkt_count   = len(pkts)
        total_bytes = flow["total_bytes"]
        duration    = max(flow["duration"], 0.001)   # avoid div-by-zero

        mean_sz = sum(sz_list) / len(sz_list)
        variance_sz = sum((s - mean_sz)**2 for s in sz_list) / len(sz_list)
        std_sz  = math.sqrt(variance_sz)

        mean_iat = sum(iats) / len(iats)
        variance_iat = sum((x - mean_iat)**2 for x in iats) / len(iats)
        std_iat = math.sqrt(variance_iat)

        # Coefficient of variation for IAT (normalised regularity)
        # Low CoV → very regular timing → beacon-like
        coeff_var = (std_iat / mean_iat) if mean_iat > 0 else 0

        bytes_per_sec = total_bytes / duration
        pkts_per_min  = (pkt_count / duration) * 60

        night_r  = _night_ratio(ts_list)
        port_r   = _port_risk(flow["dst_port"])

        row = {
            # Metadata (not used in ML, used in report)
            "src_ip"       : flow["src_ip"],
            "dst_ip"       : flow["dst_ip"],
            "dst_port"     : flow["dst_port"],
            "protocol"     : flow["protocol"],
            "start_time"   : datetime.datetime.fromtimestamp(
                                 flow["start_time"]
                             ).strftime("%Y-%m-%d %H:%M:%S"),
            # ML features
            "pkt_count"    : pkt_count,
            "total_bytes"  : total_bytes,
            "duration"     : round(duration, 3),
            "mean_pkt_size": round(mean_sz, 2),
            "std_pkt_size" : round(std_sz, 2),
            "mean_iat"     : round(mean_iat, 4),
            "std_iat"      : round(std_iat, 4),
            "coeff_var_iat": round(coeff_var, 4),
            "bytes_per_sec": round(bytes_per_sec, 2),
            "pkts_per_min" : round(pkts_per_min, 2),
            "night_ratio"  : round(night_r, 3),
            "dst_port_risk": port_r,
        }
        rows.append(row)

        if verbose:
            print(
                f"{Fore.CYAN}    [feat] {flow['src_ip']}→{flow['dst_ip']}:{flow['dst_port']}"
                f"  cv_iat={coeff_var:.3f}  std_sz={std_sz:.1f}"
                f"  night={night_r:.2f}  port_risk={port_r}"
            )

    df = pd.DataFrame(rows)
    return df


# The columns the ML model trains on (exclude metadata)
ML_FEATURE_COLS = [
    "pkt_count", "total_bytes", "duration",
    "mean_pkt_size", "std_pkt_size",
    "mean_iat", "std_iat", "coeff_var_iat",
    "bytes_per_sec", "pkts_per_min",
    "night_ratio", "dst_port_risk",
]
