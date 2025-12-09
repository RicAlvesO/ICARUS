import subprocess
import json

class QueryManager:

    # ------------------------------------------------------------------
    # Query Manager Configuration
    # ------------------------------------------------------------------

    def __init__(self, osquery_path="osqueryi", queries={}):
        self.queries = queries 
        self.osquery_path = osquery_path

    # ------------------------------------------------------------------
    # Query Management
    # ------------------------------------------------------------------

    def update_queries(self, new_queries):
        if not isinstance(new_queries, dict):
            raise ValueError("new_queries must be a dictionary")
        self.queries.update(new_queries)

    # ------------------------------------------------------------------
    # Query Execution
    # ------------------------------------------------------------------

    def run_query(self, query):
        try:
            completed_process = subprocess.run(
                [self.osquery_path, "--json", query],
                check=True,
                capture_output=True,
                text=True,
            )
            output = completed_process.stdout
            result = json.loads(output)
            return result
        except subprocess.CalledProcessError as e:
            print("Error executing query:", e)
            if e.stderr:
                print("stderr:", e.stderr)
            return None
        except json.JSONDecodeError as e:
            print("Error decoding JSON output:", e)
            return None

    def run_named_query(self, query_name):
        query = self.queries.get(query_name)
        if not query:
            print("Query '{}' not found in predefined queries.".format(query_name))
            return None
        return self.run_query(query)

    def run_all_queries(self):
        results = {}
        for name, query in self.queries.items():
            results[name] = self.run_query(query)
        return results

