import socket

from Crypto.Cipher import AES

K3 = b'aaaaaaaaaaaaaaaa'
refresh = 5

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432  # The port used by the server

to_send = str.encode("Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book.")


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def initialization(mode, server, receiver, key):
    server.sendall(str.encode(mode))
    requested_key = server.recv(32)
    decipher = AES.new(key, AES.MODE_ECB)
    receiver.sendall(str.encode(mode))
    receiver.sendall(requested_key)
    plain = decipher.decrypt(requested_key)
    K = plain[:16]
    IV = plain[16:]
    return K, IV


def CBC(receiver, K, IV, to_send):
    def CBC_encrypt(plain, to_xor, cipher):
        chunk = byte_xor(plain, to_xor)
        chunk_cript = cipher.encrypt(chunk)
        return chunk_cript

    cipher = AES.new(K, AES.MODE_ECB)
    to_xor = IV
    i = 1
    while len(to_send) > 0 and i % refresh != 0:
        to_send_chunk_cript = CBC_encrypt(to_send[0:16], to_xor, cipher)
        receiver.sendall(to_send_chunk_cript)
        to_xor = to_send_chunk_cript
        to_send = to_send[16:]
        i += 1
        print(len(to_send))
    return to_send


def OFB(receiver, K, IV, to_send):
    def OFB_encrypt(to_cript, plain, cipher):
        to_cript = cipher.encrypt(to_cript)
        cripted = byte_xor(plain, to_cript)
        return to_cript, cripted

    cipher = AES.new(K, AES.MODE_ECB)
    to_cript = IV
    i = 1
    while len(to_send) > 0 and i % refresh != 0:
        to_cript, to_send_chunk = OFB_encrypt(to_cript, to_send[0:16], cipher)
        receiver.sendall(to_send_chunk)
        to_send = to_send[16:]
        i += 1
    return to_send


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as KM:
    KM.connect((HOST, PORT))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as receiver:
        SEND_TO = '127.0.0.1'
        SEND_TO_PORT = 65000
        receiver.connect((SEND_TO, SEND_TO_PORT))
        while len(to_send) > 0:
            print(len(to_send), "bytes remaining to send")
            K, IV = initialization('OFB', KM, receiver, K3)
            print('Key recived', K)
            print('IV recived', IV)
            to_send = OFB(receiver, K, IV, to_send)
