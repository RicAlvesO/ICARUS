from logging.handlers import TimedRotatingFileHandler

import threading
import logging
import struct
import socket
import json
import ssl


class ServerChannel:

    # ------------------------------------------------------------------
    # Configuration of Communication Channel
    # ------------------------------------------------------------------

    def __init__(self, host='0.0.0.0', port=65432, certfile='data/certs/server.pem', keyfile='data/certs/server.key', logfile='/var/log/mon-server/server.log', queries=None, logger=None):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.clients = []
        self.server_socket = None
        self.is_running = False
        self.queries = queries
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger('MonServer Channel')
            self.logger.setLevel(logging.INFO)
            if not self.logger.hasHandlers():
                handler = TimedRotatingFileHandler(logfile, when='D', interval=1, backupCount=7)
                handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                self.logger.addHandler(handler)
            self.logger.info("SecureServerChannel initialized.")


    # ------------------------------------------------------------------
    # Server State
    # ------------------------------------------------------------------

    def start(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bindsocket.bind((self.host, self.port))
        bindsocket.listen(5)
        self.is_running = True
        self.server_socket = bindsocket
        self.logger.info(f"Server started on {self.host}:{self.port} with SSL.")
        try:
            while self.is_running:
                newsocket, fromaddr = bindsocket.accept()
                try:
                    connstream = context.wrap_socket(newsocket, server_side=True)
                    self.logger.info(f"SSL connection established from {fromaddr}")
                    client_thread = threading.Thread(target=self.handle_client, args=(connstream, fromaddr))
                    client_thread.daemon = True
                    client_thread.start()
                except ssl.SSLError as e:
                    self.logger.info(f"SSL error: {e}")
                    newsocket.close()
        finally:
            bindsocket.close()
    
    def stop(self):
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
        for client in self.clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
                client.close()
            except:
                pass
        self.clients.clear()
        self.logger.info("Server stopped.")

    # ------------------------------------------------------------------
    # Send and Receive Functions
    # ------------------------------------------------------------------

    def send(self, sock, type="ack", data={}):
        message = {
            "type": type,
            "data": data
        }
        encoded = json.dumps(message).encode()
        length = struct.pack('>I', len(encoded))  # 4-byte big-endian length prefix
        self.logger.debug(f"Sending message of type '{type}' with data: {data}")
        sock.sendall(length + encoded)
    
    def recv_message(self, sock):
        raw_msglen = self.recvall(sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.recvall(sock, msglen)

    def recvall(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    # ------------------------------------------------------------------
    # Client Handling 
    # ------------------------------------------------------------------

    def handle_client(self, connstream, addr):
        self.clients.append(connstream)
        try:
            current_queries = self.queries.export_all_queries() if self.queries else {}
            self.send(connstream, type="upd", data=current_queries)
            while True:
                at_queries = self.queries.export_all_queries() if self.queries else {}
                if at_queries != current_queries:
                    self.send(connstream, type="upd", data=at_queries)
                    current_queries = at_queries
                data = self.recv_message(connstream)
                if not data:
                    break
                self.logger.info(f"Received message from {addr}")
                try:
                    self.process_input(data,addr)
                    self.send(connstream, type="ack")
                except Exception as e:
                    self.logger.error(f"Error processing input from {addr}: {e}")
                    self.send(connstream, type="err", data=str(e))
        except Exception as e:
            self.logger.info(f"Error with client {addr}: {e}")
        finally:
            self.logger.info(f"Closing connection to {addr}")
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()
            self.clients.remove(connstream)

    def process_input(self, message, addr):
        data = json.loads(message.decode())
        if data["type"]=="data":
            for key, value in data["data"].items():
                self.logger.info(f"Processing input from {addr}: {key}")
                self.queries.apply_query(addr[0],key, value)
        else:
            raise ValueError(f"Unknown message type: {data['type']}")