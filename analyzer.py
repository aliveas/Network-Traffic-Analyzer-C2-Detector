"""
Network Traffic Analyzer & C2 Detector
=======================================
Main CLI entry point.

Usage:
    # Analyze a PCAP file
    python analyzer.py --pcap samples/capture.pcap

    # Live capture on an interface (requires admin/root)
    python analyzer.py --interface eth0 --duration 60

    # PCAP with custom output
    python analyzer.py --pcap samples/capture.pcap --output c2_report.html --verbose
"""

import argparse
import datetime
import os
import sys
import time

from colorama import Fore, Style, init

from capture.pcap_reader   import read_pcap
from capture.flow_builder  import build_flows
from features.extractor    import extract_features
from ml.trainer            import train_model
from ml.detector           import run_detection
from rules.beacon_rules    import apply_rules
from alerts.alert_engine   import build_alerts
from report.generator      import generate_report

init(autoreset=True)


def print_banner():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║     Network Traffic Analyzer & C2 Detector  v1.0    ║
║           SOC Analysis Toolkit  2026                 ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network C2 Beaconing Detector — SOC Educational Tool"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap",      metavar="FILE",
                        help="Path to .pcap or .pcapng file")
    source.add_argument("--interface", metavar="IFACE",
                        help="Network interface for live capture (requires root)")

    parser.add_argument("--duration",    type=int, default=60,
                        help="Live capture duration in seconds (default: 60)")
    parser.add_argument("--output",      default="report.html",
                        help="HTML report filename (default: report.html)")
    parser.add_argument("--min-packets", type=int, default=5,
                        help="Minimum packets per flow to analyse (default: 5)")
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="Expected fraction of anomalous flows 0-0.5 (default: 0.05)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print detailed output for every step")
    return parser.parse_args()


def section(title, color=Fore.CYAN):
    print(f"\n{color}{'─' * 54}\n  {title}\n{'─' * 54}{Style.RESET_ALL}")


def main():
    print_banner()
    args      = parse_args()
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    t0        = time.time()

    print(f"{Fore.CYAN}[*] Started : {scan_time}")

    # ── Step 1: Read packets ─────────────────────────────────────────
    section("STEP 1 — Reading packets")

    if args.pcap:
        if not os.path.isfile(args.pcap):
            print(f"{Fore.RED}[!] File not found: {args.pcap}")
            sys.exit(1)
        print(f"{Fore.CYAN}[*] Source : {args.pcap}")
        packets = read_pcap(args.pcap, verbose=args.verbose)
        source_label = os.path.basename(args.pcap)
    else:
        from capture.live_capture import capture_live
        print(f"{Fore.CYAN}[*] Interface : {args.interface}  Duration: {args.duration}s")
        packets = capture_live(args.interface, args.duration, verbose=args.verbose)
        source_label = f"{args.interface} (live)"

    print(f"{Fore.GREEN}[+] Packets read: {len(packets)}")

    if len(packets) < 10:
        print(f"{Fore.YELLOW}[!] Too few packets to analyse. Capture more traffic.")
        sys.exit(1)

    # ── Step 2: Build flows ──────────────────────────────────────────
    section("STEP 2 — Building network flows")
    flows = build_flows(packets, min_packets=args.min_packets, verbose=args.verbose)
    print(f"{Fore.GREEN}[+] Flows built: {len(flows)}")

    if not flows:
        print(f"{Fore.YELLOW}[!] No flows met the minimum packet threshold.")
        sys.exit(1)

    # ── Step 3: Extract features ─────────────────────────────────────
    section("STEP 3 — Extracting behavioral features")
    feature_df = extract_features(flows, verbose=args.verbose)
    print(f"{Fore.GREEN}[+] Features extracted for {len(feature_df)} flows")
    if args.verbose:
        print(f"    Columns: {list(feature_df.columns)}")

    # ── Step 4: Train ML model ───────────────────────────────────────
    section("STEP 4 — Training Isolation Forest model")
    model, scaler = train_model(feature_df, contamination=args.contamination,
                                verbose=args.verbose)
    print(f"{Fore.GREEN}[+] Model trained on {len(feature_df)} flows")

    # ── Step 5: Run ML detection ─────────────────────────────────────
    section("STEP 5 — Running ML anomaly detection")
    ml_results = run_detection(model, scaler, feature_df, verbose=args.verbose)
    anomalous  = ml_results[ml_results["ml_anomaly"] == True]
    print(f"{Fore.GREEN}[+] ML flagged {len(anomalous)} anomalous flow(s) out of {len(ml_results)}")

    # ── Step 6: Apply rule-based heuristics ──────────────────────────
    section("STEP 6 — Applying C2 beacon rules")
    rule_results = apply_rules(ml_results, verbose=args.verbose)
    confirmed    = rule_results[rule_results["confirmed_c2"] == True]
    print(f"{Fore.GREEN}[+] Rules confirmed {len(confirmed)} high-confidence C2 flow(s)")

    # ── Step 7: Build alerts ─────────────────────────────────────────
    section("STEP 7 — Building alert list")
    alerts = build_alerts(rule_results, flows)
    for a in alerts[:5]:
        color = Fore.RED if a["severity"] in ("Critical","High") else Fore.YELLOW
        print(f"{color}  [{a['severity']}] {a['summary']}")

    # ── Step 8: Generate report ──────────────────────────────────────
    section("STEP 8 — Generating HTML dashboard", Fore.GREEN)
    os.makedirs("output", exist_ok=True)
    output_path = os.path.join("output", args.output)
    elapsed     = round(time.time() - t0, 1)

    generate_report(
        output_path  = output_path,
        scan_time    = scan_time,
        elapsed      = elapsed,
        source_label = source_label,
        total_pkts   = len(packets),
        total_flows  = len(flows),
        alerts       = alerts,
        results_df   = rule_results,
    )

    crit  = sum(1 for a in alerts if a["severity"] in ("Critical","High"))
    med   = sum(1 for a in alerts if a["severity"] == "Medium")
    low   = sum(1 for a in alerts if a["severity"] == "Low")

    print(f"\n{Fore.CYAN}[*] Done in {elapsed}s")
    print(f"[*] Total alerts : {len(alerts)}")
    print(f"    {Fore.RED}High/Critical : {crit}")
    print(f"    {Fore.YELLOW}Medium        : {med}")
    print(f"    {Fore.BLUE}Low           : {low}")
    print(f"\n{Fore.GREEN}[*] Report → {output_path}\n")


if __name__ == "__main__":
    main()
