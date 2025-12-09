from datetime import datetime

class AgentManager:

    # ------------------------------------------------------------------
    # Agent Management Configuration
    # ------------------------------------------------------------------
    
    def __init__(self):
        self.agents = {}

    # ------------------------------------------------------------------
    # CRUD Operations
    # ------------------------------------------------------------------

    def create(self, agent, obj_id, internal_ip, external_ip=None):
        if agent in self.agents:
            return False, agent

        self.agents[obj_id] = {
            "name": agent,
            "type": "agent",
            "obj_id": obj_id,
            "risk": 0,
            "internal_ip": internal_ip,
            "external_ip": external_ip,
            "last_seen": None
        }
        return True

    def read(self, agent):
        if agent in self.agents:
            return self.agents[agent]
        return None

    def update(self, agent, updates):
        if agent not in self.agents:
            return None

        agent = self.agents[agent]
        for key, value in updates.items():
            if key in agent:
                agent[key] = value
        return agent

    def delete(self, agent):
        if agent in self.agents:
            del self.agents[agent]
            return True
        return False

    # ------------------------------------------------------------------
    # Query Operations
    # ------------------------------------------------------------------
    
    def check_for_agent(self, obj_id):
        return obj_id in self.agents

    def get_by_ip(self, ip):
        for agent in self.agents.values():
            if agent["internal_ip"] == ip or agent["external_ip"] == ip:
                return agent
        return None
    
    def get_agent_list(self):
        agent_list = [x for x in self.agents.values()]
        return agent_list

    def get_agents(self):
        return list(self.agents.keys())

    # ------------------------------------------------------------------
    # Utils
    # ------------------------------------------------------------------

    def seen(self, agent):
        self.agents[agent]["last_seen"] = datetime.now().isoformat()