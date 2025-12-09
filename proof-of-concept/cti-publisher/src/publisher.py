from flask import Flask, jsonify

import threading
import json
import time


class Publisher:
    
    # ------------------------------------------------------------------
    # CTI Publisher Configuration
    # ------------------------------------------------------------------

    def __init__(self, host="0.0.0.0", port=5000):
        self.app = Flask(__name__)
        self.host = host
        self.port = port
        self.collections = {}
        self.available_data = {}
        self.start_time = time.time()
        self.setup_routes()
    
    # ------------------------------------------------------------------
    # Publisher State
    # ------------------------------------------------------------------

    def run(self):
        self.updater = threading.Thread(target=self.updater, daemon=True)
        self.updater.start()
        self.app.run(debug=True, host=self.host, port=self.port)

    def stop(self):
        self.updater.join()
        self.app.stop()

    # ------------------------------------------------------------------
    # Data Managementcvnb
    # ------------------------------------------------------------------

    def load_data(self, json_file, collection):
        with open(json_file, "r") as f:
            self.collections[collection] = json.load(f)

    def updater(self):
        while True:
            elapsed_minutes = int((time.time() - self.start_time) // 60)
            for collection_id in list(self.collections.keys()):
                count = min(elapsed_minutes, len(self.collections[collection_id]))
                if collection_id not in self.available_data:
                    self.available_data[collection_id] = []
                self.available_data[collection_id] = self.collections[collection_id][(count-1):count]
            time.sleep(60)

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def setup_routes(self):

        @self.app.route("/", methods=["GET"])
        def index():
            return self.app.redirect("/collections")

        @self.app.route("/collections", methods=["GET"])
        def get_collections():
            data = {"collections": list(self.available_data.keys())}
            return jsonify(data)

        @self.app.route("/collections/<collection_id>", methods=["GET"])
        def get_collection(collection_id):
            return jsonify(self.available_data.get(collection_id, []))
