import base64
import hashlib
import os
from scapy.all import DNS, DNSRR

DOMAIN_TUNEL = 'tunel.sunt.software'
FILES_DIR = '/app/tunel-dns/files'
CHUNK_SIZE = 67

def get_file_info(filename):
    file = os.path.join(FILES_DIR,filename)
    if not os.path.exists(file):
        return None, None
    with open(file, 'rb') as f:
        data = f.read()
    chunk_count = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
    md5 = hashlib.md5(data).hexdigest()
    return chunk_count, md5

def get_chunk(filename, index):
    file = os.path.join(FILES_DIR,filename)
    if not os.path.exists(file):
        return None
    with open(file, 'rb') as f:
        f.seek(index * CHUNK_SIZE)
        data = f.read(CHUNK_SIZE)
    return base64.b64encode(data).decode('ascii')

def tunel_query(dns_layer, domain):
    prefix = domain[:-(len(DOMAIN_TUNEL) + 1)]
    parts = prefix.split('.')
    index_str = parts[0]
    filename = '.'.join(parts[1:])

    if index_str == 'eof':
        chunk_count, md5 = get_file_info(filename)
        if chunk_count is None:
            txt_data = 'ERROR:file not found'
        else:
            txt_data = f'TOTAL:{chunk_count}:{md5}'
    else:
        try:
            index = int(index_str)
        except ValueError:
            txt_data = 'ERROR: bad index'
        else:
            chunk = get_chunk(filename, index)
            if chunk is None:
                txt_data = 'ERROR:file not found'
            else:
                txt_data = chunk

    return DNS(
        id = dns_layer.id,
        qr = 1,
        aa = 1,
        rcode = 0,
        qd = dns_layer.qd,
        an = DNSRR(
            rrname = dns_layer.qd.qname,
            type = 'TXT',
            ttl = 0,
            rdata = txt_data
        )
    )

