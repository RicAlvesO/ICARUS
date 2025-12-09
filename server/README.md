# ICARUS Server

This folder contains the source code for ICARUS' Server component. The main server is responsible for receiving data from both agents and external sources, process it, correlate the information, assess potential threats, and alert analysts accordingly.

## Folder Structure

- `src/`: Contains the source code for the ICARUS Server, including data ingestion, processing, correlation, alerting, and interface modules.
- `data/`: Contains configuration files and other data required by the Server.
- `templates/`: Contains Jinja2 templates used for rendering the web interface.
- `mon-server`: The main executable for the ICARUS Server.
- `requirements.txt`: A list of Python dependencies required to run the ICARUS Server.