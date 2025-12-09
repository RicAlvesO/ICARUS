# Intelligence-driven Contextual Assessment of Risks in Unseen Scenarios (ICARUS)

This repository contains the ICARUS project, which focuses on developing a comprehensive system for threat detection based on Cyber Threat Intelligence (CTI) and contextual analysis.

## Repository Structure

- `agent/`: Contains the source code and related files for the ICARUS Agent component. This Agent is responsible for collecting and sending data from the monitored systems to the ICARUS Server for analysis, correlation, and threat detection.

- `server/`: Contains the source code for ICARUS' Server component. The main server is responsible for receiving data from both agents and external sources, process it, correlate the information, assess potential threats, and alert analysts accordingly.

- `proof-of-concept/`: Contains the components necessary to demonstrate the core functionalities of the ICARUS system through a proof-of-concept setup. It also includes the developed "CTI Publisher", which is responsible for acting as a external CTI provider.

- `docs/`: Contains relevant documents related to the ICARUS project, including a draft research article and the main dissertation document.