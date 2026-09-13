from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from datetime import datetime

def get_available_interfaces():
    """
    Returns a dictionary mapping human-friendly interface names to Scapy interface identifiers.
    """
    iface_map = {}
    try:
        for dev_id, iface in conf.ifaces.items():
            name = getattr(iface, "name", dev_id)
            description = getattr(iface, "description", "")
            label = f"{name} ({description})" if description and description != name else name
            iface_map[label] = dev_id
    except Exception:
        iface_map["Default System Interface"] = None
    if not iface_map:
        iface_map["Default System Interface"] = None
    return iface_map

def _convert(pkt):
    if not pkt.haslayer(IP):
        return None
    proto = "OTHER"
    src_port = None
    dst_port = None
    flags = ""
    summary = pkt.summary()

    if pkt.haslayer(TCP):
        proto = "TCP"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        flags = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        proto = "UDP"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "protocol": proto,
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
        "length": len(pkt),
        "summary": summary
    }

def capture_packets(seconds=10, iface=None, packet_limit=300):
    try:
        captured = sniff(timeout=seconds, iface=iface, count=packet_limit, store=True)
        return [x for x in (_convert(p) for p in captured) if x]
    except Exception as e:
        print(f"Error during packet capture: {e}")
        return []

