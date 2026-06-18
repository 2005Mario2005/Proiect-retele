import socket
import base64
import hashlib
import json
import os
import sys
import time
from scapy.all import DNS, DNSQR, DNSRR

TUNNEL_DOMAIN = 'tunel.sunt.software'
SERVER_IP = '165.22.87.54'
SERVER_PORT = 53
TIMEOUT = 3
RETRIES = 5
STATE_FILE = 'transfer_state.json'

def dns_query_txt(qname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    query = DNS(rd=1, qd=DNSQR(qname=qname, qtype='TXT'))
    for attempt in range(RETRIES):
        try:
            sock.sendto(bytes(query), (SERVER_IP, SERVER_PORT))
            response, _ = sock.recvfrom(65535)
            sock.close()
            parsed = DNS(response)
            if parsed.ancount > 0:
                txt = parsed.an.rdata
                if isinstance(txt, list):
                    txt = txt[0]
                if isinstance(txt, bytes):
                    txt = txt.decode('ascii')
                return txt
            return None
        except socket.timeout:
            print(f"  timeout, retry {attempt + 1}/{RETRIES}...")
    sock.close()
    return None

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return None

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)

def delete_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

def download_file(filename):
    # verifica daca exista stare salvata
    state = load_state()
    if state and state['filename'] == filename:
        print(f"Reia transfer de la chunkul {state['next_chunk']}/{state['total_chunks']}")
        chunks = state['chunks']
        total_chunks = state['total_chunks']
        expected_md5 = state['md5']
        next_chunk = state['next_chunk']
    else:
        # cere info despre fisier
        print(f"Cerere info fisier: {filename}")
        qname = f'eof.{filename}.{TUNNEL_DOMAIN}'
        response = dns_query_txt(qname)
        if response is None:
            print("Eroare: nu am primit raspuns de la server")
            return
        if response.startswith('ERROR'):
            print(f"Eroare server: {response}")
            return
        parts = response.split(':')
        total_chunks = int(parts[1])
        expected_md5 = parts[2]
        print(f"Fisier are {total_chunks} chunk-uri, md5: {expected_md5}")
        chunks = {}
        next_chunk = 0
        save_state({
            'filename': filename,
            'total_chunks': total_chunks,
            'md5': expected_md5,
            'chunks': chunks,
            'next_chunk': next_chunk
        })

    # descarca chunk-urile
    for i in range(next_chunk, total_chunks):
        print(f"Chunk {i+1}/{total_chunks}...", end=' ')
        qname = f'{i}.{filename}.{TUNNEL_DOMAIN}'
        chunk_data = dns_query_txt(qname)
        if chunk_data is None:
            print("ESUAT dupa toate retry-urile")
            save_state({
                'filename': filename,
                'total_chunks': total_chunks,
                'md5': expected_md5,
                'chunks': chunks,
                'next_chunk': i
            })
            print("Stare salvata. Ruleaza din nou pentru a continua.")
            return
        chunks[str(i)] = chunk_data
        print("ok")
        save_state({
            'filename': filename,
            'total_chunks': total_chunks,
            'md5': expected_md5,
            'chunks': chunks,
            'next_chunk': i + 1
        })

    # asambleaza fisierul
    print("Asamblare fisier...")
    data = b''
    for i in range(total_chunks):
        data += base64.b64decode(chunks[str(i)])

    # verifica md5
    actual_md5 = hashlib.md5(data).hexdigest()
    if actual_md5 != expected_md5:
        print(f"EROARE md5! asteptat: {expected_md5}, primit: {actual_md5}")
        return

    # salveaza fisierul
    with open(filename, 'wb') as f:
        f.write(data)

    delete_state()
    print(f"Gata! Fisier salvat: {filename}")
    print(f"MD5: {actual_md5}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("USAGE: python3 client.py <nume_fisier>")
        sys.exit(1)
    download_file(sys.argv[1])
