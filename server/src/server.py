from src.server_channel import ServerChannel
from src.agent_manager import AgentManager
from src.alert_manager import AlertManager
from src.query_manager import QueryManager
from src.feed_manager import FeedManager
from src.cti_db import CTIDatabase
from src.cti_utils import *

from logging.handlers import TimedRotatingFileHandler
from configparser import ConfigParser

import threading
import logging

class Server:

    # ------------------------------------------------------------------
    # Server Configuration
    # ------------------------------------------------------------------

    def __init__(self, config=None):
        self.id = "server_01"
        if config is None:
            raise ValueError("Configuration must be provided")
        self.channel = None
        self.query_manager = None
        self.log_file = None
        self.db = CTIDatabase()
        self.agents = AgentManager()
        self.alerts = None
        self.feeds = None
        self.load_config(config)

    def load_config(self, config):
        cfg_parser = ConfigParser()
        cfg_parser.read(config)
        server_config = cfg_parser['server'] if 'server' in cfg_parser else None
        if server_config is None:
            raise ValueError("Server configuration not found in provided config file")
        self.heartbeat = server_config.getint('heartbeat', 60)
        self.set_server_args(
            host=server_config.get('host', None),
            interface=server_config.get('interface', None),
            cert=server_config.get('certfile', None),
            key=server_config.get('keyfile', None)
        )
        self.log_file = server_config.get('logfile', '/var/log/mon-server.log')
        self.set_logger(
            logfile=self.log_file
        )


        if 'agents' in cfg_parser:
            for agent_name, agent_hosts in cfg_parser['agents'].items():
                agent_identity = create_identity(name=agent_name)
                new, agent_obj_id = self.db.create(agent_identity, origin="server", tlp="red")
                internal_ip, external_ip = agent_hosts.split("|") if "|" in agent_hosts else (agent_hosts, None)
                int_obj = create_ipv4_address(internal_ip)
                new, agent_int_obj_id = self.db.create(int_obj, origin="server", tlp="red")
                agent_int_rel = create_relationship(agent_obj_id, agent_int_obj_id, "resolved_by")
                self.db.create(agent_int_rel, origin="server", tlp="red")
                if external_ip:
                    ext_obj = create_ipv4_address(external_ip)
                    new, agent_ext_obj_id = self.db.create(ext_obj, origin="server", tlp="red")
                    agent_ext_rel = create_relationship(agent_obj_id, agent_ext_obj_id, "resolved_by")
                    self.db.create(agent_ext_rel, origin="server", tlp="red")
                self.agents.create(agent_name, agent_obj_id, internal_ip, external_ip)
                self.logger.info(f"Agent created: {agent_name} with ID: {agent_obj_id}")

        self.feeds = FeedManager(db=self.db, logger=self.logger)

        if 'feeds' in cfg_parser:
            for feed_name, feed_url in cfg_parser['feeds'].items():
                self.feeds.create(feed_name, feed_url)

        self.query_manager = QueryManager(server_config.get('queryfile', 'data/queries/osq.json'),db=self.db, am=self.agents, logger=self.logger)
        self.alerts = AlertManager(db=self.db, agents=self.agents, qm=self.query_manager, logger=self.logger)


    def set_server_args(self, host=None, interface=None, cert=None, key=None):
        if host is not None:
            ip, port = host.split(":")
            self.server_ip = ip
            self.server_port = int(port)
        if interface is not None:
            ip, port = interface.split(":")
            self.server_interface_ip = ip
            self.server_interface_port = int(port)
        if cert is not None:
            self.server_cert = cert
        if key is not None:
            self.server_key = key
    
    def set_logger(self, logfile="/var/log/mon-server.log"):
        self.logger = logging.getLogger('MonServer')
        self.logger.setLevel(logging.INFO)
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
        handler = TimedRotatingFileHandler(logfile, when='D', interval=1, backupCount=7)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        self.logger.info("MonServer initialized.")

    # ------------------------------------------------------------------
    # Server State 
    # ------------------------------------------------------------------

    def start(self):
        self.channel = ServerChannel(
            host=self.server_ip,
            port=self.server_port,
            certfile=self.server_cert,
            keyfile=self.server_key,
            queries=self.query_manager
        )
        self.feeds.start()
        self.alerts.start()
        self.channel.start()

    def stop(self):
        if self.channel:
            self.channel.stop()
            self.logger.info("MonServer stopped.")
        else:
            self.logger.warning("MonServer stop called but channel was not initialized.")
        if self.feeds:
            self.feeds.stop()
            self.logger.info("FeedManager stopped.")
        if self.alerts:
            self.alerts.stop()
            self.logger.info("AlertManager stopped.")

    # ------------------------------------------------------------------
    # Information Getters
    # ------------------------------------------------------------------

    def get_log_location(self):
        return self.log_file
    
    def get_interface(self):
        return self.server_interface_ip, self.server_interface_port

    def get_all_data(self):
        return self.db.export_bundle()

    def get_observables(self):
        return self.db.get_observable_list()

    def get_observable(self, observable_id):
        return self.db.read(observable_id),self.db.export_object_graph(observable_id,1)

    def get_traffic(self):
        return self.db.get_all_of_type("network-traffic")

    def get_relationships(self):
        return self.db.get_all_of_type("relationship")

    def get_rel_obj(self, obj_id):
        obj=self.db.read(obj_id)
        if not obj:
            return {"rel": None, "source": None, "target": None}
        if 'source_ref' in obj:
            src= self.db.read(obj['source_ref'])
            dst= self.db.read(obj['target_ref'])
            return {"rel":obj, "source": src, "target": dst}
        elif 'src_ref' in obj:
            src= self.db.read(obj['src_ref'])
            dst= self.db.read(obj['dst_ref'])
            return {"rel":obj, "source": src, "target": dst}
        return {"rel": obj, "source": None, "target": None}

    def get_agents(self):
        return self.agents.get_agent_list()

    def get_agent(self, agent_id):
        return self.agents.read(agent_id)

    def get_agent_graph(self, agent_id, search_depth=2):
        return self.db.export_object_graph(agent_id, search_depth=search_depth)

    def check_for_agent(self, agent_id):
        return self.agents.check_for_agent(agent_id)

    def get_queries(self):
        return self.query_manager.export_all_queries()  

    def get_alerts(self):
        return self.alerts.get_all_alerts()

    def get_alerts_by_type(self, alert_type):
        if alert_type == "active":
            return self.alerts.get_active_alerts()
        elif alert_type == "resolved":
            return self.alerts.get_resolved_alerts()
        elif alert_type == "dismissed":
            return self.alerts.get_dismissed_alerts()
        else:
            return []

    def get_alert_by_id(self, alert_id):
        return self.alerts.get_alert_by_id(alert_id)