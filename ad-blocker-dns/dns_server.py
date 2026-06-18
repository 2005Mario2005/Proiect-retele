from scapy.all import *
import time
import logging

logging.basicConfig(
    filename='blocked.log',
    level=logging.INFO,
    format='%(asctime)s %(message)s'
)

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
udp_sock.bind(('0.0.0.0', 53))

cache = {}
blacklist = ()

def get_from_cache(domain):
    if domain in cache:
        response, expiry = cache[domain]
        if time.time() < expiry:
            return response
        else:
            del cache[domain]
    return None

def add_to_cache(domain, response):
    if response.ancount > 0:
        ttl = response.an.ttl
        cache[domain] = (response, time.time() + ttl)

def load_blacklist(filepath):
    blacklist = set()
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()

            if line.startswith('#') or line == '':
                continue
            # 0.0.0.0 domain
            parts = line.split()
            if len(parts) == 2:
                blacklist.add(parts[1])
    return blacklist

def resolve_upstream(domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    query = DNS(rd=1, qd=DNSQR(qname=domain))
    sock.sendto(bytes(query), ("8.8.8.8", 53))
    try:
        response, _ = sock.recvfrom(65535)
        sock.close()
        return DNS(response)
    except socket.timeout:
        sock.close()
        return None

blacklist = load_blacklist('adservers.txt')

while True:
    request, adresa_sursa = udp_sock.recvfrom(65535)
    packet = DNS(request)
    dns = packet.getlayer(DNS)

    if dns is not None and dns.opcode == 0:
        try:
            domain = dns.qd.qname.decode('utf-8').rstrip('.').lower()  # ex: 'google.com'
        except (AttributeError, ValueError, UnicodeDecodeError):
            # ignoram pachetele cu malformatii :)
            continue

        if adresa_sursa[0] == '127.0.0.1' and not domain.endswith('tunel.sunt.software'):
            # sa nu fim open DNS resolver ca primim email de la Digital Ocean
            if domain in blacklist:
                logging.info(f"BLOCKED: {domain}")
                response = DNS(
                    id=dns.id,
                    qr=1,
                    aa=1,
                    qd=dns.qd,
                    an=DNSRR(rrname=dns.qd.qname, ttl=60, rdata='0.0.0.0')
                )
                udp_sock.sendto(bytes(response), adresa_sursa)
                continue

            cached = get_from_cache(domain)
            if cached is not None:
                cached_bytes = bytes(cached)
                # patch id ca sa se potriveasca cu query-ul curent
                cached_bytes = bytes([request[0], request[1]]) + cached_bytes[2:]
                udp_sock.sendto(cached_bytes, adresa_sursa)
                continue

            response = resolve_upstream(domain)
            if response is not None:
                response.id = dns.id
                add_to_cache(domain, response)
                udp_sock.sendto(bytes(response), adresa_sursa)
        elif domain.endswith('tunel.sunt.software'):
            import sys
            sys.path.insert(0, '/app/tunel-dns')
            from tunel_server import tunel_query
            response = tunel_query(dns, domain)
            udp_sock.sendto(bytes(response), adresa_sursa)
        else:
            continue

