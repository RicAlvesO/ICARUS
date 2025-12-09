from src.server import Server

from flask import *
import matplotlib.pyplot as plt
import networkx as nx
import json
import time
import io
import os

class Interface:
    
    # ------------------------------------------------------------------
    # Web Interface Configuration
    # ------------------------------------------------------------------

    def __init__(self, server, logfile='/var/log/mon-server.log'):
        template_folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        self.app = Flask(__name__, template_folder=template_folder)
        self.server = server
        self.logfile = logfile
        self.collectors = {}
        self.rules = {}
        self.alerts = []
        self.stix_data = []
        self.setup_routes()

    # ------------------------------------------------------------------
    # Web Interface State
    # ------------------------------------------------------------------

    def run(self, **kwargs):
        self.app.run(**kwargs)

    def stop(self):
        self.app.shutdown()

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def setup_routes(self):

        # ------------------------------------------------------------------
        # Home
        # ------------------------------------------------------------------

        @self.app.route('/')
        def index():
            return render_template('home.html')

        # ------------------------------------------------------------------
        # Data Home 
        # ------------------------------------------------------------------

        @self.app.route('/data', methods=['GET'])
        def data_index():
            return render_template('data.html')

        # ------------------------------------------------------------------
        # Alerts
        # ------------------------------------------------------------------

        @self.app.route('/alerts', methods=['GET'])
        def get_alerts():
            return redirect('/alerts/type/active')

        @self.app.route('/alerts/type/<type>', methods=['GET'])
        def get_alerts_by_type(type):
            alerts = self.server.get_alerts_by_type(type)
            return render_template('tables/alerts.html', type=type, alerts=alerts)

        @self.app.route('/alerts/id/<alert_id>', methods=['GET'])
        def get_alert(alert_id):
            alert = self.server.get_alert_by_id(alert_id)
            if not alert:
                return render_template('error.html', code=404, title='Alert Not Found', description='The alert you are looking for does not exist.')
            alert_details = {
                "Agent Affected": alert['agent'],
                "Estimated Risk Level": alert['risk'],
                "Timestamp": alert['timestamp'],
                "Malicious Object": alert['object']
            }
            object_list = []
            for id in alert['path']:
                for obj in alert['graph']['nodes']:
                    if obj['id'] == id:
                        object_list.append(obj['object'])
                        break
                for obj in alert['graph']['edges']:
                    if obj['id'] == id:
                        object_list.append(obj['relation'])
                        break
            return render_template('details/alert.html', alert=alert_details, objs=object_list, bundle=alert['graph'])

        # ------------------------------------------------------------------
        # Observables
        # ------------------------------------------------------------------

        @self.app.route('/data/observables', methods=['GET'])
        def get_observables():
            data = self.server.get_observables()
            if data:
                return render_template('tables/observables.html', data=data)
            return render_template('tables/observables.html', data=[])

        @self.app.route('/data/observables/<object_id>', methods=['GET'])
        def get_observable_detail(object_id):
            data,bundle = self.server.get_observable(object_id)
            if data:
                return render_template('details/observable.html', item=data, bundle=bundle)
            return render_template('error.html', code=404, title='Page Not Found', description='The page you are looking for does not exist.')

        # ------------------------------------------------------------------
        # Relationships
        # ------------------------------------------------------------------

        @self.app.route('/data/relationships', methods=['GET'])
        def get_relationships():
            data = self.server.get_relationships()
            if data:
                return render_template('tables/relationships.html', data=data)
            return render_template('tables/relationships.html', data=[])

        @self.app.route('/data/relationships/<relationship_id>', methods=['GET'])
        def get_relationship_detail(relationship_id):
            data = self.server.get_rel_obj(relationship_id)
            if data:
                return render_template('details/relationship.html', relationship=data['rel'], source=data['source'], target=data['target'])
            return render_template('error.html', code=404, title='Page Not Found', description='The page you are looking for does not exist.')

        # ------------------------------------------------------------------
        # Network Traffic
        # ------------------------------------------------------------------

        @self.app.route('/data/traffic', methods=['GET'])
        def get_traffic():
            data = self.server.get_traffic()
            if data:
                return render_template('tables/traffic.html', data=data)
            return render_template('tables/traffic.html', data=[])

        @self.app.route('/data/traffic/<traffic_id>', methods=['GET'])
        def get_traffic_detail(traffic_id):
            data = self.server.get_rel_obj(traffic_id)
            if data:
                return render_template('details/traffic.html', traffic=data['rel'], source=data['source'], target=data['target'])
            return render_template('error.html', code=404, title='Page Not Found', description='The page you are looking for does not exist.')

        # ------------------------------------------------------------------
        # Agents
        # ------------------------------------------------------------------

        @self.app.route('/agents', methods=['GET'])
        def get_agents():
            data = self.server.get_agents()
            depth = request.args.get('depth', default=2, type=int)
            return render_template('tables/agents.html', data=data, depth=depth)

        @self.app.route('/agents/<agent_id>/data', methods=['GET'])
        def get_agent_graph(agent_id):
            if not self.server.check_for_agent(agent_id):
                return render_template('error.html', code=404, title='Agent Not Found', description='The agent you are looking for does not exist.')
            depth = request.args.get('depth', default=2, type=int)
            bundle = self.server.get_agent_graph(agent_id, search_depth=depth)
            return jsonify(bundle)

        @self.app.route('/agents/<agent_id>', methods=['GET'])
        def get_agent(agent_id):
            agent = self.server.get_agent(agent_id)
            if not agent:
                return render_template('error.html', code=404, title='Agent Not Found', description='The agent you are looking for does not exist.')
            depth = request.args.get('depth', default=2, type=int)
            bundle = self.server.get_agent_graph(agent_id, search_depth=depth)
            return render_template('details/agent.html', agent=agent, bundle=bundle)

        # ------------------------------------------------------------------
        # Collectors 
        # ------------------------------------------------------------------

        @self.app.route('/collectors', methods=['GET'])
        def manage_collectors():
            return jsonify(self.server.get_queries())

        @self.app.route('/collectors/<collector_id>', methods=['PUT', 'DELETE', 'PATCH'])
        def update_collector(collector_id):
            if collector_id not in self.collectors:
                return render_template('error.html', code=404, title='Page Not Found', description='The page you are looking for does not exist.')
            return render_template('error.html', code=503, title='Service Unavailable', description='This page is still under development.')

        # ------------------------------------------------------------------
        # System Logs
        # ------------------------------------------------------------------

        @self.app.route('/system/logs')
        def system_logs():
            return render_template("logs.html")

        @self.app.route('/system/logs/stream')
        def stream_logs():
            def generate():
                with open(self.logfile, 'r') as f:
                    lines = f.readlines()
                    lines = lines[-100:]  
                    for line in lines:
                        yield f"data: {line.strip()}\n\n"
                    f.seek(0, os.SEEK_END) 
                    while True:
                        line = f.readline()
                        if line:
                            yield f"data: {line.strip()}\n\n"
                        else:
                            time.sleep(0.5)
            return Response(stream_with_context(generate()), mimetype='text/event-stream')

        # ------------------------------------------------------------------
        # Unknown Routes
        # ------------------------------------------------------------------

        @self.app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        def catch_all(path):
            return render_template('error.html', code=404, title='Page Not Found', description='The page you are looking for does not exist.')