from scapy.all import *
from collections import defaultdict
import time
import subprocess
import hashlib
import ipaddress
from sklearn.svm import OneClassSVM

# ---------------- CONFIG ----------------
blockList = set()  # store blocked IPs
connection_attempts = defaultdict(list)  # track SYN packets
packet_counts = defaultdict(int)  # for DDoS detection

# Security Policies
ALLOWED_DNS_SERVERS = {"8.8.8.8", "1.1.1.1"}  # trusted DNS servers
ALLOWED_PORTS = {22, 443, 80}  # Example allowed ports (SSH, HTTPS, HTTP)
ALLOWED_MACS = {
    "00:11:22:33:44:55",
    "aa:bb:cc:dd:ee:ff"
}

# Thresholds
TIME_WINDOW = 5        # seconds
SYN_THRESHOLD = 50     # number of SYNs in time window
PKT_THRESHOLD = 200    # packets per second per IP

# Malware payload indicators
MALWARE_SIGNATURES = [
    b"malicious_code",
    b"shellshock",
    b"mimikatz",
    b"powershell -enc"
]

MALWARE_HASHES = {
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # example
}
# ----------------------------------------


# ---------- FIREWALL CONTROL ----------
def blockIP(ip):
    """Block an IP using nftables firewall."""
    if ip not in blockList:
        print(f"[!] Blocking IP: {ip}")
        blockList.add(ip)
        try:
            subprocess.run(
                ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"],
                check=True
            )
        except Exception as e:
            print(f"[!] Failed to block {ip} via nftables: {e}")
# --------------------------------------


# ---------- SECURITY CHECKS ------------
def check_mac(pkt):
    """Allow only packets from trusted MAC addresses."""
    if pkt.haslayer(Ether):
        src_mac = pkt[Ether].src.lower()
        if src_mac not in ALLOWED_MACS:
            print(f"[!] Unauthorized MAC {src_mac} detected, blocking...")
            if pkt.haslayer(IP):
                blockIP(pkt[IP].src)
            return False
    return True


def check_payload(pkt):
    """Inspect packet payload for malware signatures or hashes."""
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load

        # Signature-based
        for sig in MALWARE_SIGNATURES:
            if sig in payload:
                print(f"[!] Malware signature detected in payload from {pkt[IP].src}")
                blockIP(pkt[IP].src)
                return False

        # Hash-based
        payload_hash = hashlib.sha256(payload).hexdigest()
        if payload_hash in MALWARE_HASHES:
            print(f"[!] Malicious payload hash detected from {pkt[IP].src}")
            blockIP(pkt[IP].src)
            return False

    return True


def detect_syn_flood(pkt):
    """Detect SYN flood by tracking SYN packets without ACKs."""
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        src = pkt[IP].src
        connection_attempts[src].append(time.time())

        # Clean old attempts
        connection_attempts[src] = [
            t for t in connection_attempts[src] if time.time() - t < TIME_WINDOW
        ]

        if len(connection_attempts[src]) > SYN_THRESHOLD:
            print(f"[!] SYN Flood detected from {src}")
            blockIP(src)


def detect_ddos(pkt):
    """Detect DDoS by packet rate per IP."""
    src = pkt[IP].src
    packet_counts[src] += 1

    # Reset counts periodically
    if time.time() % TIME_WINDOW < 1:
        for ip, count in list(packet_counts.items()):
            if count > PKT_THRESHOLD:
                print(f"[!] Possible DDoS from {ip} with {count} pps")
                blockIP(ip)
            packet_counts[ip] = 0


def detect_unauthorized_port(pkt):
    """Detect traffic to unauthorized ports."""
    if pkt.haslayer(TCP):
        dst_port = pkt[TCP].dport
        if dst_port not in ALLOWED_PORTS:
            print(f"[!] Unauthorized TCP port access from {pkt[IP].src} to port {dst_port}")
            blockIP(pkt[IP].src)

    elif pkt.haslayer(UDP):
        dst_port = pkt[UDP].dport
        if dst_port not in ALLOWED_PORTS:
            print(f"[!] Unauthorized UDP port access from {pkt[IP].src} to port {dst_port}")
            blockIP(pkt[IP].src)


def detect_dns_spoof(pkt):
    """Detect DNS spoofing by checking DNS response IPs."""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
        src = pkt[IP].src
        if src not in ALLOWED_DNS_SERVERS:
            print(f"[!] DNS spoofing attempt from {src}")
            blockIP(src)
# --------------------------------------

from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import ipaddress
from sklearn.svm import OneClassSVM

def run_packet_svm_anomaly_detector(baseline_count=100, nu=0.05, kernel='rbf', gamma='scale'):
    baseline_data = []

    # ----------------------
    # Feature extraction helper
    # ----------------------
    def extract_features(pkt):
        if IP not in pkt:
            return None
        features = {
            "src_ip": int(ipaddress.ip_address(pkt[IP].src)),
            "dst_ip": int(ipaddress.ip_address(pkt[IP].dst)),
            "ttl": pkt[IP].ttl,
            "proto": pkt[IP].proto
        }
        if TCP in pkt:
            features.update({
                "sport": pkt[TCP].sport,
                "dport": pkt[TCP].dport,
                "flags": int(pkt[TCP].flags),
                "length": len(pkt)
            })
        elif UDP in pkt:
            features.update({
                "sport": pkt[UDP].sport,
                "dport": pkt[UDP].dport,
                "flags": 0,
                "length": len(pkt)
            })
        else:
            return None
        return features

    # ----------------------
    # Collect baseline
    # ----------------------
    def baseline_handler(pkt):
        features = extract_features(pkt)
        if features:
            baseline_data.append(features)

    print(f"Sniffing {baseline_count} packets to build baseline...")
    sniff(prn=baseline_handler, store=False, count=baseline_count)

    df_baseline = pd.DataFrame(baseline_data).fillna(0)

    # ----------------------
    # Train One-Class SVM
    # ----------------------
    svm_model = OneClassSVM(nu=nu, kernel=kernel, gamma=gamma)
    svm_model.fit(df_baseline)
    print(f"One-Class SVM trained on {len(df_baseline)} packets.")

    # ----------------------
    # Live detection
    # ----------------------
    def live_detector(pkt):
        features = extract_features(pkt)
        if not features:
            return
        df_new = pd.DataFrame([features])
        prediction = svm_model.predict(df_new)[0]  # 1 = normal, -1 = anomaly
        if prediction == -1:
            print("⚠️ Anomaly detected:", pkt.summary())
        else:
            print("Packet normal:", pkt.summary())

    print("\nSniffing live traffic for anomalies (Ctrl+C to stop)...")
    sniff(prn=live_detector, store=False)


# ---------- IDS MAIN LOOP -------------
def IDS(pkt):
    """Main IDS function that checks all rules."""
    # Run the SVM detector
    # ----------------------
    run_packet_svm_anomaly_detector()
    if not check_mac(pkt):  # MAC whitelist
        return

    if IP in pkt:
        src = pkt[IP].src
        if src in blockList:
            print(f"[X] Dropped packet from {src}")
            return

        if not check_payload(pkt):  # Malware payload inspection
            return

        detect_syn_flood(pkt)
        detect_ddos(pkt)
        detect_unauthorized_port(pkt)
        detect_dns_spoof(pkt)


print("[*] Starting IDS/IPS with nftables...")
print("[*] Make sure nftables is set up: sudo nft add table inet filter; sudo nft add chain inet filter input { type filter hook input priority 0; }")

sniff(prn=IDS, store=False)