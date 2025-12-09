from src.client_channel import ClientChannel
from src.query_manager import QueryManager

from configparser import ConfigParser
from logging.handlers import TimedRotatingFileHandler

import threading
import logging
import time
import json

class Agent:

    # ------------------------------------------------------------------
    # Agent Configuration
    # ------------------------------------------------------------------

    def __init__(self, config=None):
        self.id = "agent_"
        if config is None:
            raise ValueError("Configuration must be provided")
        self.load_config(config)
        self.channel = None
        self.query_manager = QueryManager()        

    def load_config(self, config):
        cfg_parser = ConfigParser()
        cfg_parser.read(config)
        agent_config = cfg_parser['agent'] if 'agent' in cfg_parser else None
        if agent_config is None:
            raise ValueError("Agent configuration not found in provided config file")
        self.heartbeat = agent_config.getint('heartbeat', 60)
        host, port = agent_config.get('server', None).split(":")
        self.set_server_args(
            host=host,
            port=int(port),
            cafile=agent_config.get('cafile', None)
        )
        self.set_logger(
            logfile=agent_config.get('logfile', '/var/log/mon-agent.log')
        )

    def set_server_args(self, host=None, port=None, cafile=None):
        if host is not None:
            self.server_ip = host
        if port is not None:
            self.server_port = port
        if cafile is not None:
            self.server_ca = cafile

    def set_logger(self,logfile="/var/log/mon-agent.log"):
        self.logger = logging.getLogger('MonAgent')
        self.logger.setLevel(logging.INFO)
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
        handler = TimedRotatingFileHandler(logfile, when='D', interval=1, backupCount=7)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        self.logger.info("MonAgent initialized.")

    # ------------------------------------------------------------------
    # Agent State 
    # ------------------------------------------------------------------

    def start(self):
        self.channel = ClientChannel(
            host=self.server_ip,
            port=self.server_port,
            cafile=self.server_ca
        )
        self.channel.connect()
        self.logger.info(f"Agent started and connected to server at {self.server_ip}:{self.server_port}")
        threading.Thread(target=self.listener_loop, daemon=True).start()
        self.sender_loop()
        self.channel.close()
    
    def stop(self):
        if self.channel is not None:
            self.channel.close()
            self.logger.info("Agent stopped and connection closed.")
        else:
            self.logger.warning("Agent stop called but channel was not initialized.")

    # ------------------------------------------------------------------
    #  Server <-> Agent Communication
    # ------------------------------------------------------------------

    def sender_loop(self):
        while True:
            try:
                data = self.query_manager.run_all_queries()
                self.channel.send(type="data", data=data)
                time.sleep(self.heartbeat)
            except Exception as e:
                self.logger.error(f"Error in sender loop: {e}")
                break
        
    def listener_loop(self):
        while True:
            try:
                message = self.channel.recv_message()
                if not message:
                    self.logger.info("No message received, closing connection.")
                    break
                self.logger.info(f"Received message: {message.decode()}")
                self.process_input(message)
            except Exception as e:
                self.logger.error(f"Error in listener loop: {e}")
                break

    def process_input(self, message):
        data = json.loads(message.decode())
        if data["type"]=="upd":
            print(f"Update from server: {data['data']}")
            self.query_manager.update_queries(data["data"])
        else:
            self.logger.warning(f"Unknown message type: {data['type']}")
            self.logger.warning(f"Message content: {data}")
