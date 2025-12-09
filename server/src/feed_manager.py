from src.cti_utils import *

from copy import deepcopy

import threading
import requests
import logging
import time
import json

class FeedManager:

    # ------------------------------------------------------------------
    # Feed Manager Configuration
    # ------------------------------------------------------------------

    def __init__(self, db, logger):
        self.feeds = {}
        self.db = db
        self.broker = db.get_broker()
        self.logger = logger

    # ------------------------------------------------------------------
    # Feed Management State
    # ------------------------------------------------------------------

    def start(self):
        self.logger.info("Initializing FeedManager...")
        self.read_thread = threading.Thread(target=self.read_loop)
        self.read_thread.start()
        self.logger.info("FeedManager started.")

    def stop(self):
        self.logger.info("Stopping FeedManager...")
        self.read_thread.join()
        self.logger.info("FeedManager stopped.")

    # ------------------------------------------------------------------
    # Main Loop
    # ------------------------------------------------------------------

    def check_if_exists(self, obj, origin):
        dup = deepcopy(obj)
        risk = dup.pop('risk', None)
        tlp = dup.pop('tlp', None)
        exists, obj_id = self.broker.check_if_exists(dup)
        try:
            if exists:
                dup['id'] = obj_id
                self.broker.update(dup, origin=origin, tlp=tlp, risk=risk)
        except Exception as e:
            self.logger.error(f"Error updating object with ID {obj.get('id')}: {e}")
        return exists, obj_id

    def parse_object(self, obj, origin):
        dup = deepcopy(obj)
        risk = dup.pop('risk', None)
        tlp = dup.pop('tlp', None)
        if dup['type'] == 'relationship':
            dup = create_relationship(dup['source_ref'], dup['target_ref'], dup['relationship_type'])
        self.db.create(dup, origin=origin, tlp=tlp, risk=risk)

    def parse_feed_data(self, data, origin):
        objects = data.get('objects', [])
        traffic = data.get('network_traffic', [])
        relationships = data.get('relationships', [])
        id_map = {}
        for item in objects + traffic + relationships:
            self.logger.debug(f"Checking item: {item}")
            item_id = item['id']
            exists, obj_id = self.check_if_exists(item, origin)
            if not exists:
                for key, value in item.items():
                    if isinstance(value, str) and value in id_map:
                        item[key] = id_map[value]
                self.parse_object(item, origin)
                self.logger.info(f"Added new object with ID {item_id} from feed '{origin}'.")
            else:
                id_map[item_id] = obj_id

    def read_feed(self, name, url):
        try:
            self.logger.info(f"Reading feed '{name}' from {url}...")
            response = requests.get(url)
        except Exception as e:
            self.logger.error(f"Error reading feed '{name}': {e}")
        if response.status_code == 200:
            self.logger.info(f"Successfully read feed '{name}'.")
            data = response.json()
            for d in data:
                self.parse_feed_data(d, name)
        else:
            self.logger.error(f"Failed to read feed '{name}'.")

    def read_loop(self):
        while True:
            for name, url in self.feeds.items():
                self.read_feed(name, url)
            time.sleep(60)

    # ------------------------------------------------------------------
    # CRUD Operations
    # ------------------------------------------------------------------

    def create(self, name, url):
        self.logger.info(f"Creating feed '{name}' with URL: {url}")
        self.feeds[name] = url

    def read(self, name):
        return self.feeds.get(name)

    def update(self, name, url):
        if name in self.feeds:
            self.logger.info(f"Updating feed '{name}' to URL: {url}")
            self.feeds[name] = url

    def remove(self, name):
        if name in self.feeds:
            self.logger.info(f"Removing feed '{name}'")
            del self.feeds[name]

    # ------------------------------------------------------------------
    # Query Operations
    # ------------------------------------------------------------------

    def get_feeds(self):
        return self.feeds
