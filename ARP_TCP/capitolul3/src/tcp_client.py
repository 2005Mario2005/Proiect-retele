# TCP client
import socket
import logging
import time
import sys
import random
import string
import threading

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.10.0.2'
server_address = (adresa, port)
#mesaj = sys.argv[1]
def send_messages(connection):
    while True:
        message = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        connection.send(message.encode())
        logging.info('CLIENT sent: "%s"', message)
        time.sleep(2)

def receive_messages(connection):
    while True:
        data = connection.recv(1024)
        if not data:
            break
        logging.info('CLIENT received: "%s"', data.decode())
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.connect(server_address)
try:
    logging.info('Waiting for connections...')
    logging.info("Connected to server")

    t_send = threading.Thread(target=send_messages, args=(sock,))
    t_recv = threading.Thread(target=receive_messages, args=(sock,))
    t_send.daemon = True
    t_recv.daemon = True
    t_send.start()
    t_recv.start()
    t_recv.join()

except KeyboardInterrupt:
    logging.info('closing socket')
    sock.close()
