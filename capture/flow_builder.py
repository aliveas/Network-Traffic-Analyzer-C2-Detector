"""
capture/flow_builder.py
========================
Groups individual packets into network flows.

A flow is identified by the 5-tuple:
  (src_ip, dst_ip, dst_port, protocol)

We intentionally use a one-directional key — C2 beaconing is
always client→server, so we track that direction only.

Each flow dict:
  {
    "flow_key"    : tuple (src_ip, dst_ip, dst_port, protocol),
    "src_ip"      : str,
    "dst_ip"      : str,
    "dst_port"    : int,
    "protocol"    : str,
    "packets"     : list of packet dicts,
    "start_time"  : float,
    "end_time"    : float,
    "duration"    : float seconds,
    "total_bytes" : int,
    "pkt_count"   : int,
  }
"""

from collections import defaultdict
from colorama import Fore


def build_flows(packets: list, min_packets: int = 5,
                verbose: bool = False) -> list:
    """
    Group packets into flows.

    Parameters
    ----------
    packets     : list of packet dicts from pcap_reader
    min_packets : minimum packets a flow must have to be kept
    verbose     : bool

    Returns
    -------
    list of flow dicts
    """
    raw_flows = defaultdict(list)

    for pkt in packets:
        key = (
            pkt["src_ip"],
            pkt["dst_ip"],
            pkt["dst_port"],
            pkt["protocol"],
        )
        raw_flows[key].append(pkt)

    flows = []
    for key, pkts in raw_flows.items():
        if len(pkts) < min_packets:
            continue

        pkts.sort(key=lambda p: p["timestamp"])
        src_ip, dst_ip, dst_port, protocol = key
        start = pkts[0]["timestamp"]
        end   = pkts[-1]["timestamp"]

        flow = {
            "flow_key"   : key,
            "src_ip"     : src_ip,
            "dst_ip"     : dst_ip,
            "dst_port"   : dst_port,
            "protocol"   : protocol,
            "packets"    : pkts,
            "start_time" : start,
            "end_time"   : end,
            "duration"   : end - start,
            "total_bytes": sum(p["length"] for p in pkts),
            "pkt_count"  : len(pkts),
        }
        flows.append(flow)

        if verbose:
            print(
                f"{Fore.CYAN}    [flow] {src_ip} → {dst_ip}:{dst_port}"
                f"  {protocol}  {len(pkts)} pkts  "
                f"{flow['total_bytes']}B  {flow['duration']:.1f}s"
            )

    # Sort by packet count descending (busiest flows first)
    flows.sort(key=lambda f: f["pkt_count"], reverse=True)

    print(f"{Fore.CYAN}    Kept {len(flows)} flows (≥{min_packets} pkts), "
          f"dropped {len(raw_flows) - len(flows)} small flows")
    return flows
