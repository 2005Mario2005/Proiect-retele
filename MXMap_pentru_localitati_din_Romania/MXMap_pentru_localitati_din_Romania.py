import json
from scapy.all import IP, UDP, DNS, DNSQR, sr1
import unicodedata

def curata_nume(text):
    #elimina diacriticele prin normalizare
    nfkd_form = unicodedata.normalize('NFKD', text)
    fara_diacritice = "".join([c for c in nfkd_form if not unicodedata.combining(c)])
    # Hărău -> Harau (si se asigura ca nu raman caractere ciudate)
    return fara_diacritice.encode('ascii', 'ignore').decode('utf-8').strip().title()

def categoriseste_provider(mx, txt):
    if 'google.com' in mx or '_spf.google.com' in txt:
        return 'SUA - Google'
    elif 'outlook.com' in mx or 'spf.protection.outlook.com' in txt:
        return 'SUA - Microsoft'
    elif mx != '' and (mx in txt or 'primar' in mx or 'sts' in mx):
        return 'local'
    else:
        return 'tert: ' + mx


with open('query.json', 'r') as f:
    date = json.load(f)
    date_procesate = []

    for primarie in date:
        domeniu_brut = primarie['email']
        domeniu = domeniu_brut.split('@')[1].lower().strip()

        server_mx = ''
        server_txt = ''

        strat_ip = IP(dst = '8.8.8.8')
        strat_udp = UDP(dport = 53)

        strat_dns = DNS(rd = 1, qd = DNSQR(qname = domeniu, qtype = 'MX'))
        pachet = strat_ip / strat_udp / strat_dns
        raspuns = sr1(pachet, timeout = 5, verbose = 0)

        if raspuns is not None and raspuns.haslayer(DNS) and raspuns[DNS].ancount > 0:
            server_mx = raspuns[DNS].an.exchange.decode('utf-8')

        strat_dns_2 = DNS(rd = 1, qd = DNSQR(qname = domeniu, qtype = 'TXT'))
        pachet_2 = strat_ip / strat_udp / strat_dns_2
        raspuns_2 = sr1(pachet_2, timeout = 5, verbose = 0)

        if raspuns_2 is not None and raspuns_2.haslayer(DNS) and raspuns_2[DNS].ancount > 0:
            rdata_val = raspuns_2[DNS].an.rdata[0]
            # rdata_val este deja text (bytes) sau altceva (int)
            if isinstance(rdata_val, bytes):
                server_txt = rdata_val.decode('utf-8')
            else:
                #daca e int sau altceva -> string forțat
                server_txt = str(rdata_val)

        cat = categoriseste_provider(server_mx, server_txt)

        date_procesate.append({
            'nume': curata_nume(primarie['localitateLabel']),
            'coordonate': primarie['coordonate'],
            'domeniu': domeniu,
            'mx': server_mx,
            'txt': server_txt,
            'cat': cat
        })
    with open('harta.json', 'w') as f:
        json.dump(date_procesate, f, indent = 4, ensure_ascii = False)