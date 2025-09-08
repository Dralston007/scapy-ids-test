from scapy.all import *;

from scapy.all import *
import random
import sys

def fuzz_packet(target_ip):
    pkt = IP(dst=target_ip)/TCP(dport=80)
    
    # Randomize IP fields
    pkt[IP].version = random.choice([4, 6])
    pkt[IP].ihl = random.randint(5, 15)
    pkt[IP].tos = random.randint(0, 255)
    pkt[IP].id = random.randint(0, 65535)
    pkt[IP].flags = random.randint(0, 7)
    pkt[IP].frag = random.randint(0, 8191)
    pkt[IP].ttl = random.randint(1, 255)

    # Randomize TCP fields
    pkt[TCP].sport = random.randint(1024, 65535)
    pkt[TCP].flags = random.choice(["S", "A", "F", "R", "P", "U", ""])
    pkt[TCP].seq = random.randint(0, 4294967295)
    pkt[TCP].ack = random.randint(0, 4294967295)
    pkt[TCP].window = random.randint(0, 65535)

    pkt[TCP].payload = Raw(load=bytes(random.getrandbits(8) for _ in range(random.randint(0, 20))))
    
    return pkt

def main():
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    print(f"Starting packet fuzzing on target {target_ip}...")

    for i in range(100):
        packet = fuzz_packet(target_ip)
        packet.show()
        
        try:
            response = sr1(packet, timeout=2, verbose=0)
            if response:
                logging.info(f"Sent packet {i+1}: Received response: {response.summary()}")
            else:
                logging.info(f"Sent packet {i+1}: No response")
        except Exception as e:
            logging.error(f"Error sending packet {i+1}: {e}")

if __name__ == "__main__":
    main()