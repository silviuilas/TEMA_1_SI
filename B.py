import socket
import threading

from Crypto.Cipher import AES

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65000  # Port to listen on (non-privileged ports are > 1023)

K3 = b'aaaaaaaaaaaaaaaa'
refresh = 5


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def server_thread(conn, addr):
    with conn:
        print('Connected by', addr)
        received_data = bytearray(b'')
        while True:
            data = conn.recv(3)
            if not data:
                break
            data_str = data.decode("utf-8")
            print(data_str)
            if data_str == "CBC":
                received_data.extend(CBC(conn, addr))
            elif data_str == "OFB":
                received_data.extend(OFB(conn, addr))
            else:
                error(conn, addr, data)
        print(received_data.decode('utf-8'))
        print("Disconnected from", addr)





def CBC(conn, addr):
    def CBC_decrypt(cripted, to_xor, cipher):
        chunk = cipher.decrypt(cripted)
        plain = byte_xor(chunk, to_xor)
        return plain
    data = conn.recv(32)
    decipher = AES.new(K3, AES.MODE_ECB)
    plaintext = decipher.decrypt(data)
    K = plaintext[:16]
    IV = plaintext[16:]
    print('Key recived', K)
    print('IV recived', IV)
    to_receive = bytearray(b'')
    decipher_data = AES.new(K, AES.MODE_ECB)
    to_xor = IV
    i = 1
    while i % refresh != 0:
        rec_data = conn.recv(16)
        if not rec_data:
            break
        data = CBC_decrypt(rec_data, to_xor, decipher_data)
        print(data.decode('utf-8'))
        to_xor = rec_data
        to_receive.extend(data)
        i += 1
    return to_receive


def OFB(conn, addr):
    data = conn.recv(32)
    decipher = AES.new(K3, AES.MODE_ECB)
    plaintext = decipher.decrypt(data)
    K = plaintext[:16]
    IV = plaintext[16:]
    print('Key recived', K)
    print('IV recived', IV)
    to_receive = bytearray(b'')
    decipher_data = AES.new(K, AES.MODE_ECB)
    to_cript = IV
    i = 1
    while i % refresh != 0:
        rec_data = conn.recv(16)
        if not rec_data:
            break
        to_xor = decipher_data.encrypt(to_cript)
        plaintext = byte_xor(rec_data, to_xor)
        print(plaintext)
        to_cript = to_xor
        to_receive.extend(plaintext)
        i += 1
    return to_receive


def error(conn, addr, data):
    conn.sendall(data)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=server_thread, args=(conn, addr))
        client_thread.start()
