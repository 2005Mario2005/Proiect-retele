#TCP SERVER
import socket
import logging
import time
import random
import string
import threading

logging.basicConfig(
    format='[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s',level=logging.NOTSET
)

def send_messages(connection):
    while True:
        message = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        connection.send(message.encode())
        logging.info('SERVER sent: "%s"', message)
        time.sleep(2)

def receive_messages(connection):
    while True:
        data = connection.recv(1024)
        if not data:
            break
        logging.info('SERVER received: "%s"', data.decode())

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

port = 10000
address = '0.0.0.0'
sock.bind((address, port))
logging.info("Server started on %s port %d", address, port)
sock.listen(5)

try:
    while True:
        logging.info('Waiting for connections...')
        connection, address = sock.accept()
        logging.info("Connection from %s", address)

        t_send = threading.Thread(target=send_messages, args=(connection,))
        t_recv = threading.Thread(target=receive_messages, args=(connection,))
        t_send.daemon = True
        t_recv.daemon = True
        t_send.start()
        t_recv.start()
        t_recv.join()

except KeyboardInterrupt:
    sock.close()
