"""
report/generator.py
====================
Renders the HTML C2 detection dashboard.
"""

import os
from collections import Counter
from jinja2 import Environment, FileSystemLoader
import pandas as pd


def generate_report(
    output_path  : str,
    scan_time    : str,
    elapsed      : float,
    source_label : str,
    total_pkts   : int,
    total_flows  : int,
    alerts       : list,
    results_df   : pd.DataFrame,
) -> None:

    critical  = sum(1 for a in alerts if a["severity"] == "Critical")
    high      = sum(1 for a in alerts if a["severity"] == "High")
    medium    = sum(1 for a in alerts if a["severity"] == "Medium")
    low       = sum(1 for a in alerts if a["severity"] == "Low")
    confirmed = sum(1 for a in alerts if a["confirmed_c2"])

    if critical > 0:
        risk_level, risk_color = "Critical", "#E24B4A"
    elif high > 0:
        risk_level, risk_color = "High",     "#D85A30"
    elif medium > 0:
        risk_level, risk_color = "Medium",   "#BA7517"
    else:
        risk_level, risk_color = "Low / Clean", "#3B6D11"

    top_src = Counter(a["src_ip"] for a in alerts).most_common(5)
    top_dst = Counter(
        f"{a['dst_ip']}:{a['dst_port']}" for a in alerts
    ).most_common(5)

    tdir = os.path.dirname(__file__)
    env  = Environment(loader=FileSystemLoader(tdir), autoescape=True)
    tmpl = env.get_template("template.html")

    html = tmpl.render(
        scan_time    = scan_time,
        elapsed      = elapsed,
        source_label = source_label,
        total_pkts   = total_pkts,
        total_flows  = total_flows,
        total_alerts = len(alerts),
        confirmed    = confirmed,
        critical     = critical,
        high         = high,
        medium       = medium,
        low          = low,
        risk_level   = risk_level,
        risk_color   = risk_color,
        alerts       = alerts,
        top_src      = top_src,
        top_dst      = top_dst,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
