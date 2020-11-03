import socket
import threading

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

K3 = b'aaaaaaaaaaaaaaaa'


def server_thread(conn, addr):
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(3)
            if not data:
                break
            data_str = data.decode("utf-8")
            print(data_str)
            if data_str == "CBC" or data_str == "OFB":
                generate(conn, addr)
            else:
                error(conn, addr, data)


def generate(conn, addr):
    K = get_random_bytes(16)
    cipher = AES.new(K3, AES.MODE_ECB)
    K_crpyt = cipher.encrypt(K)
    IV = get_random_bytes(16)
    IV_crypt = cipher.encrypt(IV)
    conn.sendall(K_crpyt + IV_crypt)



def error(conn, addr, data):
    conn.sendall(data)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=server_thread, args=(conn, addr))
        client_thread.start()
