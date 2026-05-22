

import pandas as pd
from colorama import Fore


# Known C2 framework default ports
KNOWN_C2_PORTS = {
    4444,   # Metasploit default
    5555,   # various RATs
    8888,   # Cobalt Strike alt
    1234,   # generic backdoor
    31337,  # "elite" / Back Orifice
    1337,   # various RATs
    4433,   # Cobalt Strike HTTPS alt
    8443,   # Cobalt Strike HTTPS alt
    6666,   # various malware
    9999,   # various malware
    2222,   # SSH backdoor alt
    3333,   # generic C2
}

# Thresholds (tunable)
IAT_COV_THRESHOLD     = 0.30   # coeff_var_iat < this → very regular
STD_SIZE_THRESHOLD    = 20.0   # std_pkt_size < this → consistent sizes
PKTS_PER_MIN_THRESH   = 2.0    # pkts_per_min > this → high frequency
NIGHT_RATIO_THRESH    = 0.40   # night_ratio > this → suspicious
LONG_LOW_DURATION     = 300.0  # seconds — long-running flow
LONG_LOW_BPS          = 500.0  # bytes/sec — low bandwidth threshold


def _check_timing_regularity(row) -> str | None:
    """R1: Very regular inter-packet timing = beacon interval."""
    if row["coeff_var_iat"] < IAT_COV_THRESHOLD and row["pkt_count"] >= 10:
        return (f"R1:RegularTiming(cv={row['coeff_var_iat']:.3f}"
                f"<{IAT_COV_THRESHOLD})")
    return None


def _check_size_consistency(row) -> str | None:
    """R2: Consistent packet sizes = same payload each beacon."""
    if row["std_pkt_size"] < STD_SIZE_THRESHOLD and row["pkt_count"] >= 8:
        return f"R2:ConsistentSize(std={row['std_pkt_size']:.1f}B)"
    return None


def _check_high_frequency(row) -> str | None:
    """R3: High connection frequency to same host:port."""
    if row["pkts_per_min"] > PKTS_PER_MIN_THRESH:
        return f"R3:HighFreq({row['pkts_per_min']:.1f}pkt/min)"
    return None


def _check_suspicious_port(row) -> str | None:
    """R4: Destination port in suspicious list."""
    if row["dst_port_risk"] >= 2:
        return f"R4:SuspiciousPort({int(row['dst_port'])}risk={row['dst_port_risk']})"
    return None


def _check_night_activity(row) -> str | None:
    """R5: High fraction of night-time traffic."""
    if row["night_ratio"] > NIGHT_RATIO_THRESH:
        return f"R5:NightActivity({row['night_ratio']*100:.0f}%)"
    return None


def _check_long_low_bandwidth(row) -> str | None:
    """R6: Long-running low-bandwidth = keep-alive beaconing."""
    if (row["duration"] > LONG_LOW_DURATION and
            row["bytes_per_sec"] < LONG_LOW_BPS):
        return (f"R6:LongLowBW(dur={row['duration']:.0f}s"
                f",bps={row['bytes_per_sec']:.0f})")
    return None


def _check_known_c2_port(row) -> str | None:
    """R7: Destination port matches known C2 framework defaults."""
    port = int(row["dst_port"])
    if port in KNOWN_C2_PORTS:
        return f"R7:KnownC2Port({port})"
    return None


RULES = [
    _check_timing_regularity,
    _check_size_consistency,
    _check_high_frequency,
    _check_suspicious_port,
    _check_night_activity,
    _check_long_low_bandwidth,
    _check_known_c2_port,
]


def apply_rules(df: pd.DataFrame, verbose: bool = False) -> pd.DataFrame:
    """
    Apply all heuristic rules to every flow.

    Parameters
    ----------
    df      : pd.DataFrame with ml_anomaly column
    verbose : bool

    Returns
    -------
    pd.DataFrame with added rule_hits and confirmed_c2 columns
    """
    result = df.copy()
    rule_hits_col   = []
    confirmed_col   = []
    severity_col    = []
    confidence_col  = []

    for _, row in result.iterrows():
        hits = []
        for rule_fn in RULES:
            hit = rule_fn(row)
            if hit:
                hits.append(hit)

        # confirmed_c2 = ML flagged it AND at least one rule fired
        confirmed = bool(row.get("ml_anomaly", False)) and len(hits) >= 1

        # Severity based on number of rules triggered + ML score
        n = len(hits)
        score = row.get("ml_score", 0)
        if confirmed and (n >= 3 or score < -0.2):
            sev = "Critical"
            conf = "High"
        elif confirmed and n >= 2:
            sev = "High"
            conf = "High"
        elif confirmed and n == 1:
            sev = "Medium"
            conf = "Medium"
        elif row.get("ml_anomaly", False):
            sev = "Low"
            conf = "Low"
        else:
            sev = "Info"
            conf = "Low"

        rule_hits_col.append(hits)
        confirmed_col.append(confirmed)
        severity_col.append(sev)
        confidence_col.append(conf)

        if verbose and confirmed:
            print(
                f"{Fore.RED}    [rule] CONFIRMED C2: "
                f"{row['src_ip']}→{row['dst_ip']}:{int(row['dst_port'])}"
                f"  {', '.join(hits)}"
            )

    result["rule_hits"]   = rule_hits_col
    result["confirmed_c2"] = confirmed_col
    result["severity"]    = severity_col
    result["confidence"]  = confidence_col

    return result
