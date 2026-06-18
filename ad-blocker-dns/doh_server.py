from fastapi import FastAPI, Request, Response
from scapy.all import *
import socket
import base64

app = FastAPI()

def dns_query_raw(query_bytes):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.sendto(query_bytes, ("127.0.0.1", 53))
    try:
        response, _ = sock.recvfrom(65535)
        sock.close()
        return response
    except socket.timeout:
        sock.close()
        return None

def dns_query(domain, qtype="A"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    query = DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    sock.sendto(bytes(query), ("127.0.0.1", 53))
    response, _ = sock.recvfrom(65535)
    sock.close()
    return DNS(response)

@app.get("/dns-query")
async def doh_get(dns: str):
    query_bytes = base64.urlsafe_b64decode(dns + '==')
    response = dns_query_raw(query_bytes)
    if response is None:
        return Response(status_code=500)
    return Response(content=response, media_type="application/dns-message")

@app.post("/dns-query")
async def doh_post(request: Request):
    try:
        query_bytes = await request.body()
        response = dns_query_raw(query_bytes)
        if response is None:
            return Response(status_code=500)
        return Response(content=response, media_type="application/dns-message")
    except Exception as e:
        print(f"ERROR: {e}")
        traceback.print_exc()
        return Response(status_code=500)

@app.get("/resolve")
async def resolve(name: str, qtype: str = "A"):
    response = dns_query(name, qtype)
    answers = []
    if response.ancount > 0:
        for i in range(response.ancount):
            rr = response.an[i]
            answers.append({
                "name": rr.rrname.decode('utf-8'),
                "type": rr.type,
                "TTL": rr.ttl,
                "data": rr.rdata
            })
    return {
        "Status": response.rcode,
        "Answer": answers
    }
