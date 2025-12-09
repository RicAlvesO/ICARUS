from collections import defaultdict
from datetime import datetime
from uuid import uuid4

import threading
import time
import json

class AlertManager:

    # ------------------------------------------------------------------
    # Alert Management Configuration
    # ------------------------------------------------------------------

    def __init__(self, db, agents, qm, logger, threshold=40, depth_multiplier=3, depth_threshold=5, decay=1):
        self.alerts = {
            'active': [],
            'resolved': [],
            'dismissed': []
        }
        self.paths = {}
        self.threshold = threshold
        self.depth_multiplier = depth_multiplier
        self.depth_threshold = depth_threshold
        self.decay = decay
        self.db = db
        self.broker = db.get_broker()
        self.qm = qm
        self.logger = logger
        self.agents = agents

    # ------------------------------------------------------------------
    # Alert Management State
    # ------------------------------------------------------------------

    def start(self):
        self.logger.info("Initializing AlertManager...")
        self.alert_thread = threading.Thread(target=self.alert_loop)
        self.alert_thread.start()
        self.logger.info("AlertManager started.")

    def stop(self):
        self.logger.info("Stopping AlertManager...")
        self.alert_thread.join()
        self.logger.info("AlertManager stopped.")

    # ------------------------------------------------------------------
    # Main Loop
    # ------------------------------------------------------------------

    def build_adjacency(self, nodes, edges):
        adj = defaultdict(list)
        for edge in edges:
            src = edge["source"]
            dst = edge["target"]
            rel_id = edge["id"]
            adj[src].append((rel_id, dst))
        return adj


    def find_all_paths(self, adj, start_id, end_id):
        all_paths = []
        def dfs(current, path, visited):
            if current == end_id:
                all_paths.append(path[:])
                return

            for rel_id, neighbor in adj.get(current, []):
                if (rel_id, neighbor) not in visited:  
                    visited.add((rel_id, neighbor))
                    dfs(neighbor, path + [rel_id, neighbor], visited)
                    visited.remove((rel_id, neighbor))
        dfs(start_id, [start_id], set())
        return all_paths

    def make_path(self, start, end, data):
        if not data:
            return []
        adj = self.build_adjacency(data['nodes'], data['edges'])
        paths = self.find_all_paths(adj, start, end)
        return paths

    def check_alert_path(self, start, end, path_data):
        if not path_data:
            return False, True
        new = True
        same = False
        path = [p for i, p in enumerate(path_data) if i % 2 == 0]
        if start not in self.paths:
            self.paths[start] = {}
        if end not in self.paths[start]:
            self.paths[start][end] = []
        else:
            new = False
        if path in self.paths[start][end]:
            same = True
        else:
            self.paths[start][end].append(path)
        return new, same

    def filter_graph_path(self, path, graph):
        simplified_graph = {
            'nodes': [],
            'edges': []
        }
        for node in graph['nodes']:
            if node['id'] in path:
                simplified_graph['nodes'].append(node)
        for edge in graph['edges']:
            if edge['source'] in path and edge['target'] in path:
                simplified_graph['edges'].append(edge)
        return simplified_graph

    def check_for_alerts(self, obj, agent, agent_graph):
        paths = self.make_path(agent, obj['id'], agent_graph)
        for p in paths:
            new, same = self.check_alert_path(agent, obj['id'], p)
            new_risk = min((obj['risk']*self.depth_multiplier*2)/(len(p)-1),100)
            new_risk = int(new_risk)
            if (new or not same) and new_risk > self.threshold:
                self.logger.warning(f"{obj['id']} has score {obj['risk']} above threshold {self.threshold}")
                simple_graph = self.filter_graph_path(p, agent_graph)
                self.create(agent, obj['id'], new, new_risk, p, simple_graph)
        
    def process_alerts_for_agent(self, agent):
        agent_graph = self.db.export_object_graph(agent, search_depth=self.depth_threshold)
        self.logger.info(f"Processing alerts for agent {agent}")
        for node in agent_graph['nodes']:
            obj = node['object']
            if obj['risk'] > 0:
                self.check_for_alerts(obj, agent, agent_graph)

    def alert_loop(self):
        while True:
            for agent in self.agents.get_agents():
                self.process_alerts_for_agent(agent)
            self.broker.decay(self.decay)
            risks = self.broker.access_risks()
            self.logger.info(f"Current mean risks by type: {json.dumps(risks)}")
            self.qm.update_rules(risks)
            time.sleep(30)

    # ------------------------------------------------------------------
    # CRUD Operations
    # ------------------------------------------------------------------

    def create(self, agent, node_id, new, risk, data, graph):
        if new:
            self.logger.warning(f"Creating new alert from {node_id} targeting agent {agent}:\n{data}")
        else:
            self.logger.warning(f"Creating new attack path from {node_id} to agent {agent}:\n{data}")
        alert = {
            "id": f"alert--{uuid4()}",
            "type": "alert",
            "agent": agent,
            "object": node_id,
            "risk": risk,
            "path": data,
            "graph": graph,
            "timestamp": datetime.now().isoformat(),
            "resolved": False,
            "dismissed": False
        }
        self.alerts['active'].append(alert)

    def read(self, id, status='active'):
        for alert in self.alerts[status]:
            if alert['id'] == id:
                return alert
        return None
        

    def update(self, id, updates, status='active'):
        for alert in self.alerts[status]:
            if alert['id'] == id:
                alert.update(updates)
                return True
        return False

    def delete(self, id, status='active'):
        for i, alert in enumerate(self.alerts[status]):
            if alert['id'] == id:
                del self.alerts[status][i]
                return True
        return False

    # ------------------------------------------------------------------
    # Query Operations
    # ------------------------------------------------------------------

    def get_active_alerts(self):
        return self.alerts['active']

    def get_resolved_alerts(self):
        return self.alerts['resolved']

    def get_dismissed_alerts(self):
        return self.alerts['dismissed']

    def get_all_alerts(self):
        return self.alerts

    def get_alert_by_id(self, alert_id):
        for status, alerts in self.alerts.items():
            for alert in alerts:
                if alert['id'] == alert_id:
                    return alert
        return None