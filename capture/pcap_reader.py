"""
capture/pcap_reader.py
=======================
Reads .pcap / .pcapng files and returns a list of normalised
packet dicts using Scapy.

Each packet dict:
  {
    "timestamp"  : float (Unix epoch),
    "src_ip"     : str,
    "dst_ip"     : str,
    "src_port"   : int or 0,
    "dst_port"   : int or 0,
    "protocol"   : "TCP" | "UDP" | "ICMP" | "OTHER",
    "length"     : int (bytes),
    "flags"      : str (TCP flags, e.g. "S", "SA", "PA"),
  }
"""

from colorama import Fore

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def _parse_packet(pkt) -> dict | None:
    """Convert a Scapy packet object into our normalised dict."""
    try:
        if not pkt.haslayer(IP):
            return None                     # skip non-IP (ARP, etc.)

        ip = pkt[IP]
        ts = float(pkt.time)

        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        length = len(pkt)

        if pkt.haslayer(TCP):
            tcp      = pkt[TCP]
            protocol = "TCP"
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            # Decode TCP flags to readable string
            flag_map = {0x01:"F",0x02:"S",0x04:"R",0x08:"P",0x10:"A",0x20:"U"}
            flags    = "".join(v for k,v in flag_map.items() if tcp.flags & k)
        elif pkt.haslayer(UDP):
            udp      = pkt[UDP]
            protocol = "UDP"
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            flags    = ""
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            src_port = 0
            dst_port = 0
            flags    = ""
        else:
            protocol = "OTHER"
            src_port = 0
            dst_port = 0
            flags    = ""

        return {
            "timestamp" : ts,
            "src_ip"    : src_ip,
            "dst_ip"    : dst_ip,
            "src_port"  : src_port,
            "dst_port"  : dst_port,
            "protocol"  : protocol,
            "length"    : length,
            "flags"     : flags,
        }
    except Exception:
        return None


def read_pcap(file_path: str, verbose: bool = False) -> list:
    """
    Read a PCAP file and return a list of packet dicts.

    Parameters
    ----------
    file_path : str  — path to .pcap or .pcapng
    verbose   : bool

    Returns
    -------
    list of packet dicts sorted by timestamp
    """
    if not HAS_SCAPY:
        print(f"{Fore.RED}[!] Scapy not installed. Run: pip install scapy")
        return []

    try:
        raw_packets = rdpcap(file_path)
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to read PCAP: {e}")
        return []

    packets = []
    for pkt in raw_packets:
        parsed = _parse_packet(pkt)
        if parsed:
            packets.append(parsed)
            if verbose and len(packets) <= 10:
                print(
                    f"{Fore.CYAN}    [pkt] {parsed['src_ip']}:{parsed['src_port']}"
                    f" → {parsed['dst_ip']}:{parsed['dst_port']}"
                    f"  {parsed['protocol']}  {parsed['length']}B"
                )

    packets.sort(key=lambda p: p["timestamp"])
    print(f"{Fore.CYAN}    Protocols: "
          + ", ".join(f"{p}:{sum(1 for pk in packets if pk['protocol']==p)}"
                      for p in ["TCP","UDP","ICMP","OTHER"]
                      if any(pk["protocol"]==p for pk in packets)))
    return packets
