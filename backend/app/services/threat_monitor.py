import threading
import collections
import time
from datetime import datetime, timezone

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

MAX_EVENTS = 100
threat_events = collections.deque(maxlen=MAX_EVENTS)

# Thread-safe set of blocked IPs for Active Defense
blocked_ips = set()

def add_blocked_ip(ip: str):
    blocked_ips.add(ip)

def remove_blocked_ip(ip: str):
    blocked_ips.discard(ip)

# For port scan detection
# Track SYNs: IP -> set of ports
syn_tracking = collections.defaultdict(set)
last_syn_cleanup = time.time()

def add_threat(title: str, description: str, severity: str, tags: list[str]):
    event = {
        "id": f"evt-{int(datetime.now().timestamp()*1000)}",
        "title": title,
        "severity": severity,
        "description": description,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tags": tags
    }
    
    # Simple deduplication: don't add if the exact same event was added recently
    for e in list(threat_events)[:10]:
        if e["title"] == title and e["description"] == description:
            return
            
    threat_events.appendleft(event)

def process_packet(packet):
    global last_syn_cleanup
    try:
        if not packet.haslayer(IP):
            return
            
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Active Defense: TCP RST Injection
        if ip_src in blocked_ips and packet.haslayer(TCP):
            rst_pkt = IP(src=ip_dst, dst=ip_src) / \
                      TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, 
                          seq=packet[TCP].ack, ack=packet[TCP].seq + 1, flags="RA")
            send(rst_pkt, verbose=False)
            return

        # 1. Port Scan Detection (TCP SYN)
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            
            if flags == 'S':
                syn_tracking[ip_src].add(dport)
                
                if len(syn_tracking[ip_src]) > 15:
                    add_threat(
                        "Possible Port Scan Detected", 
                        f"Host {ip_src} is scanning multiple ports on {ip_dst}.", 
                        "HIGH", 
                        ["Reconnaissance", "Port Scan"]
                    )
                    # Reset tracking to avoid spamming
                    syn_tracking[ip_src].clear()

            # 2. Cleartext Credentials Detection
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode(errors='ignore').lower()
                    if 'pass=' in payload or 'password=' in payload or 'authorization: basic' in payload:
                        add_threat(
                            "Cleartext Credentials Exposed",
                            f"Potential credentials sent in cleartext from {ip_src} to {ip_dst}:{dport}.",
                            "CRITICAL",
                            ["Credentials", "Cleartext", "Insecure"]
                        )
                except Exception:
                    pass
                    
        # Clean up memory every 60 seconds
        if time.time() - last_syn_cleanup > 60:
            syn_tracking.clear()
            last_syn_cleanup = time.time()
            
    except Exception:
        pass

def start_sniffer():
    if not SCAPY_AVAILABLE:
        add_threat(
            "Sniffer Engine Offline",
            "Scapy module is not installed or requires root privileges.",
            "INFO",
            ["System", "Diagnostic"]
        )
        return
        
    def sniff_loop():
        try:
            # Filter out local DB/Redis traffic to reduce noise
            sniff(filter="not port 5432 and not port 6379", prn=process_packet, store=False)
        except Exception as e:
            add_threat(
                "Sniffer Engine Error",
                f"Packet capture failed to start: {str(e)}",
                "MEDIUM",
                ["System", "Error"]
            )
            
    t = threading.Thread(target=sniff_loop, daemon=True)
    t.start()

def get_recent_threats():
    return list(threat_events)
