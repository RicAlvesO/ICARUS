import threading
import struct
import socket
import json
import ssl

class ClientChannel:

    # ------------------------------------------------------------------
    # Configuration of Communication Channel
    # ------------------------------------------------------------------

    def __init__(self, host='127.0.0.1', port=65432, cafile='data/certs/server.pem'):
        self.host = host
        self.port = port
        self.cafile = cafile
        self.sock = None

    def connect(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.cafile)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = context.wrap_socket(raw_sock, server_hostname=self.host)
        self.sock.connect((self.host, self.port))
        print(f"Connected securely to server at {(self.host, self.port)}")
    
    def close(self):
        if self.sock:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            self.sock = None
            print("Connection closed.")

    # ------------------------------------------------------------------
    # Send and Receive Functions
    # ------------------------------------------------------------------

    def send(self, type="data", data={}):
        message = {
            "type": type,
            "data": data
        }
        encoded = json.dumps(message).encode()
        length = struct.pack('>I', len(encoded))
        self.sock.sendall(length + encoded)
    
    def recv_message(self):
        raw_msglen = self.recvall(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.recvall(msglen)

    def recvall(self, n):
        data = bytearray()
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data
    