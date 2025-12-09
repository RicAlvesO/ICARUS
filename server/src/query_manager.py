from src.agent_manager import AgentManager
from src.cti_db import CTIDatabase
from src.cti_utils import *

from datetime import datetime

import json

class QueryManager:
    
    # ------------------------------------------------------------------
    # Query Manager Configuration
    # ------------------------------------------------------------------
    
    def __init__(self, query_file, db, am, logger):
        self._queries = {}
        self.cti_db = db
        self.broker = self.cti_db.get_broker()
        self.agent_db = am
        self.logger = logger
        if query_file:
            with open(query_file, 'rb') as f:
                data = f.read()
            if data.startswith(b'\xef\xbb\xbf'):  # Check for BOM
                data = data[3:]  # Remove BOM
            self._queries = json.loads(data.decode('utf-8')) 

    # ------------------------------------------------------------------
    # CRUD Operations
    # ------------------------------------------------------------------
    
    def create(self, name, sql):
        if name in self._queries:
            return False
        self._queries[name] = sql
        return True

    def read(self, name):
        if name not in self._queries:
            return None
        return self._queries.get(name)

    def update(self, name, sql):
        if name not in self._queries:
            return False
        self._queries[name] = sql
        return True

    def delete(self, name):
        if name not in self._queries:
            return False
        del self._queries[name]
        return True
    
    # ------------------------------------------------------------------
    # Extra Functions
    # ------------------------------------------------------------------

    def export_all_queries(self):
        queries = {}
        for name, data in self._queries.items():
            if data['enabled']:
                queries[name] = data['query']
        return queries

    def update_rules(self, risks):
        for name, data in self._queries.items():
            current = data['enabled']
            if data['type'] not in risks:
                risks[data['type']] = 0
            if data['threshold'] <= risks[data['type']]:
                self._queries[name]['enabled'] = True
            else:
                self._queries[name]['enabled'] = False

            if current != self._queries[name]['enabled']:
                self.logger.info(f"Query '{name}' enabled state changed from {current} to {self._queries[name]['enabled']}")

    # ------------------------------------------------------------------
    # Query Handling
    # ------------------------------------------------------------------    

    def parse_query(self, stix_type, data, agent):
        try:
            if stix_type == "ipv4-addr":
                return create_ipv4_address(data['value'])
            elif stix_type == "process":
                return create_process(data['pid'], data['path'], data['cmdline'])
            elif stix_type == "vulnerability":
                return create_vulnerability(data['name'], data['description'], data.get('external_references'))
            elif stix_type == "file":
                hashes={
                    "MD5": data['md5'],
                    "SHA-1": data['sha1'],
                    "SHA-256": data['sha256']
                }
                ctime = datetime.fromtimestamp(int(data['ctime'])).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                mtime = datetime.fromtimestamp(int(data['mtime'])).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                atime = datetime.fromtimestamp(int(data['atime'])).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                return create_file(data['path'], int(data['size']), ctime, mtime, atime, hashes)
            elif stix_type == "network-traffic":
                src_ref = create_ipv4_address(data['local_address'])
                new,src_id = self.cti_db.create(src_ref, origin=agent, tlp="red")
                if new:
                    self.logger.info(f"Added new source {data['local_address']} with ID {src_id} to CTI database.")
                dst_ref = create_ipv4_address(data['remote_address'])
                new,dst_id = self.cti_db.create(dst_ref, origin=agent, tlp="red")
                if new:
                    self.logger.info(f"Added new destination {data['remote_address']} with ID {dst_id} to CTI database.")
                return create_network_traffic(src_id, dst_id, data['local_port'], data['remote_port'], data['protocol'])
            else:
                print(f"Unknown STIX type: {stix_type}")
                return None
        except Exception as e:
            print(f"Error parsing object: {e}")
            return None
                
    def apply_query(self, agent, name, data=None):
        query = self._queries.get(name)
        if not query:
            return None

        agent = self.agent_db.get_by_ip(agent)
        if not agent:
            return None
        else:
            self.agent_db.seen(agent['obj_id'])

        if not isinstance(data, list):
            data = [data] if data else []

        for item in data:
            obj = self.parse_query(query['type'], item, agent['name'])
            new,obj_id = self.cti_db.create(obj, origin = agent['name'], tlp="red")
            if new:
                self.logger.info(f"Added object {obj_id} of type {query['type']} to CTI database.")
            if query['type'] in ["process", "file"]:
                rel = create_relationship(agent['obj_id'], obj_id, query['relationship'])
                new, rel_id = self.cti_db.create(rel, origin=agent['name'], tlp="red")
                if new:
                    self.broker.set_history(agent['obj_id'], f"{datetime.now().isoformat()}: Detected {query['relationship']} relationship from {rel_id} to {obj_id}.")
                    self.broker.set_history(obj_id, f"{datetime.now().isoformat()}: Detected {query['relationship']} relationship from {rel_id} to {agent['obj_id']}.")
                    self.logger.info(f"Created relationship {rel_id} between agent {agent['obj_id']} and object {obj_id}.")
            elif query['type'] == "network-traffic" and new:
                self.broker.set_history(agent['obj_id'], f"{datetime.now().isoformat()}: Detected network traffic {obj_id} {obj['src_ref']} > {query['relationship']} > {obj['dst_ref']}")
                self.broker.set_history(obj['src_ref'], f"{datetime.now().isoformat()}: Detected network traffic {obj_id} {obj['src_ref']} > {query['relationship']} > {obj['dst_ref']}")
                self.broker.set_history(obj['dst_ref'], f"{datetime.now().isoformat()}: Detected network traffic {obj_id} {obj['dst_ref']} < {query['relationship']} < {obj['src_ref']}")
                self.logger.info(f"Created network traffic object {obj_id} between {obj['src_ref']} and {obj['dst_ref']}.")