"""
capture/live_capture.py
========================
Captures live packets from a network interface using Scapy.
Requires root / administrator privileges.

Returns the same normalised packet list format as pcap_reader.py.
"""

import time
from colorama import Fore

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def capture_live(interface: str, duration: int = 60,
                 verbose: bool = False) -> list:
    """
    Capture packets from a live interface for `duration` seconds.

    Parameters
    ----------
    interface : str  — e.g. "eth0", "wlan0", "en0"
    duration  : int  — seconds to capture
    verbose   : bool

    Returns
    -------
    list of normalised packet dicts
    """
    if not HAS_SCAPY:
        print(f"{Fore.RED}[!] Scapy not installed. Run: pip install scapy")
        return []

    print(f"{Fore.CYAN}[*] Capturing on {interface} for {duration}s ...")
    print(f"    (Press Ctrl+C to stop early)")

    captured = []

    def _handle(pkt):
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        length = len(pkt)
        ts = float(pkt.time)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            protocol = "TCP"
            src_port, dst_port = int(tcp.sport), int(tcp.dport)
            flag_map = {0x01:"F",0x02:"S",0x04:"R",0x08:"P",0x10:"A",0x20:"U"}
            flags = "".join(v for k,v in flag_map.items() if tcp.flags & k)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            protocol = "UDP"
            src_port, dst_port = int(udp.sport), int(udp.dport)
            flags = ""
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            src_port = dst_port = 0
            flags = ""
        else:
            protocol = "OTHER"
            src_port = dst_port = 0
            flags = ""

        p = {
            "timestamp" : ts,
            "src_ip"    : str(ip.src),
            "dst_ip"    : str(ip.dst),
            "src_port"  : src_port,
            "dst_port"  : dst_port,
            "protocol"  : protocol,
            "length"    : length,
            "flags"     : flags,
        }
        captured.append(p)
        if verbose and len(captured) % 100 == 0:
            print(f"{Fore.CYAN}    [live] {len(captured)} packets captured...")

    try:
        sniff(iface=interface, prn=_handle, timeout=duration, store=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Capture stopped early by user.")
    except Exception as e:
        print(f"{Fore.RED}[!] Capture error: {e}")
        print(f"    Tip: Run with sudo/admin privileges.")

    captured.sort(key=lambda p: p["timestamp"])
    print(f"{Fore.GREEN}[+] Captured {len(captured)} packets in {duration}s")
    return captured
