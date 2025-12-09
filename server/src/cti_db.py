from src.cti_broker import CTIBroker

from stix2 import MemoryStore, CompositeDataSource, Filter
from typing import Dict, List, Optional, Union
from uuid import uuid4

try:
    from stix2.base import _STIXBase as STIXObject 
except ImportError:
    STIXObject = object 

import json

class CTIDatabase:

    # ------------------------------------------------------------------
    # CTI DB Configuration
    # ------------------------------------------------------------------
    
    def __init__(self):
        self.mem_store = MemoryStore()
        self._composite = CompositeDataSource()
        self._composite.add_data_source(self.mem_store.source)
        self.broker = CTIBroker(self)

    # ------------------------------------------------------------------
    # CRUD Operations
    # ------------------------------------------------------------------

    def create(self, obj, origin=None, tlp=None, risk=None):
        exists,obj_id = self.broker.check_if_exists(obj)
        if exists:
            obj = self.read(obj_id)
            self.broker.update(obj, origin=origin, tlp=tlp, risk=risk)
            return False, obj_id
        self.mem_store.add(obj)
        self.broker.create(obj, origin=origin, tlp=tlp, risk=risk)
        return True, obj['id']

    def read(self, obj_id):
        obj = self._composite.get(obj_id)
        if not isinstance(obj, dict):
            obj = json.loads(obj.serialize())
        extra = self.broker.read(id=obj_id)
        obj.update(extra)
        return obj

    def update(self, obj_id, updates):
        existing = self._composite.get(obj_id)
        if not existing:
            return None
        new_obj = existing.new_version(**updates)
        if not self.broker.update(new_obj):
            return None
        self.mem_store.add(new_obj)
        return new_obj

    def delete(self, obj_id):
        if not self.broker.delete(obj_id):
            return False
        self.mem_store.source.delete(obj_id)
        return True

    # ------------------------------------------------------------------
    # Complex Query Functions
    # ------------------------------------------------------------------

    def get_broker(self):
        return self.broker

    def query(self, filters: List[dict]):
        stix_filters = [Filter(**f) if isinstance(f, dict) else f for f in filters]
        data = self._composite.query(stix_filters)
        if not data:
            return []
        data = [self.read(obj['id']) for obj in data]
        return data

    def get_observable_list(self):
        return self.query([Filter("type", "!=", "relationship"),Filter("type", "!=", "network-traffic")])

    def get_all_of_type(self, stix_type: str):
        return self.query([Filter("type", "=", stix_type)])

    def get_object_graph(self, obj_id, search_depth=1, visited_ids=None):
        if visited_ids is None:
            visited_ids = set()

        # Skip already processed IDs
        if obj_id in visited_ids:
            return {"nodes": [], "edges": []}
        visited_ids.add(obj_id)

        main_obj = self.read(obj_id)
        if not main_obj:
            return {"nodes": [], "edges": []}

        # Add main object to nodes
        node = {
            "id": main_obj['id'],
            "object": main_obj
        }
        nodes = [node]
        edges = []

        if search_depth <= 0:
            return {"nodes": nodes, "edges": edges}

        # Gather relationships in both directions
        relationships_out = self.query([
            Filter("type", "=", "relationship"),
            Filter("source_ref", "=", obj_id)
        ])
        relationships_in = self.query([
            Filter("type", "=", "relationship"),
            Filter("target_ref", "=", obj_id)
        ])

        # Gather network-traffic in both directions
        net_out = self.query([
            Filter("type", "=", "network-traffic"),
            Filter("src_ref", "=", obj_id)
        ])
        net_in = self.query([
            Filter("type", "=", "network-traffic"),
            Filter("dst_ref", "=", obj_id)
        ])

        children = []

        # Process relationships (both directions)
        for rel in relationships_out:
            target = self.read(rel['target_ref'])
            if target:
                children.append((target['id'], rel, "relationship"))

        for rel in relationships_in:
            source = self.read(rel['source_ref'])
            if source:
                children.append((source['id'], rel, "relationship"))

        # Process network traffic (both directions)
        for net in net_out:
            target = self.read(net['dst_ref'])
            if target:
                children.append((target['id'], net, "network-traffic"))

        for net in net_in:
            source = self.read(net['src_ref'])
            if source:
                children.append((source['id'], net, "network-traffic"))

        # Traverse the children to fetch more objects
        for child_id, relation_obj, link_type in children:
            # Add edges (relations and network traffic) to the edge list
            edge = None
            if relation_obj['type'] == "relationship":
                edge = {
                    "id": relation_obj['id'],
                    "source": relation_obj['source_ref'],
                    "target": relation_obj['target_ref'],
                    "type": link_type,
                    "relation": relation_obj
                }
            else:
                edge = {
                    "id": relation_obj['id'],
                    "source": relation_obj['src_ref'],
                    "target": relation_obj['dst_ref'],
                    "type": link_type,
                    "relation": relation_obj 
                }
            edges.append(edge)

            # Recursively get child node details
            child_bundle = self.get_object_graph(
                child_id,
                search_depth=search_depth - 1,
                visited_ids=visited_ids
            )
            if child_bundle:
                nodes.extend(child_bundle["nodes"])
                edges.extend(child_bundle["edges"])

        # remove duplicates
        nodes = list({node["id"]: node for node in nodes}.values())
        edges = list({edge["id"]: edge for edge in edges}.values())

        return {"nodes": nodes, "edges": edges}


    # ------------------------------------------------------------------
    # Export Functions
    # ------------------------------------------------------------------

    def export_bundle(self) -> dict:
        stix_data = self.query([Filter("type", "!=", "relationship"),
                                Filter("type", "!=", "network-traffic")])
        stix_net_traffic = self.query([Filter("type", "=", "network-traffic")])
        stix_rels = self.query([Filter("type", "=", "relationship")])
        data = [json.loads(obj.serialize()) for obj in stix_data]
        rels = [json.loads(obj.serialize()) for obj in stix_rels]
        traffic = [json.loads(obj.serialize()) for obj in stix_net_traffic]
        return {
            "type": "bundle",
            "id": f"bundle--{uuid4()}",
            "objects": data,
            "relationships": rels,
            "network_traffic": traffic
        }

    def export_object_graph(self, root_id, search_depth=1):
        full_object = self.get_object_graph(root_id, search_depth=search_depth)
        
        return {
            "type": "graph",
            "id": f"graph--{uuid4()}",
            "nodes": full_object["nodes"],
            "edges": full_object["edges"]
        }
