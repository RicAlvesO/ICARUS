# Proof of Concept

This folder contains the components necessary to demonstrate the core functionalities of the ICARUS system. It includes the developed "CTI Publisher", which is responsible for acting as a external CTI provider.

Adittionally, this folder contains configuration files and playbooks to deploy the ICARUS system in a controlled environment for testing and validation purposes.

It is important to note that, while a Makefile is provided for convenience, different OS environments may require manual adjustments to the deployment process. Users should be prepared to adapt the provided scripts and configurations to suit their specific setup and requirements as needed.

## Folder Structure

- `cti-publisher/`: Contains the source code for the implemented CTI Publisher. This module is responsible for publishing threat intelligence data to the ICARUS system in the proof-of-concept setup.
- `data/`: Contains sample data and configuration files used by the various components of the ICARUS system during testing.
- `dockerfiles/`: Contains the Dockerfiles for building the various container images used for testing purposes.
- `playbooks/`: Contains the Ansible playbooks and roles for deploying the ICARUS system in the test environment.
- `Makefile`: A convenience file to automate the deployment and testing process. Users may need to modify this file based on their specific OS environment.
- `docker-compose.yml`: A Docker Compose file to orchestrate the deployment of the hosts required for the proof-of-concept demonstration.
- `README.md`: This documentation file providing an overview of the proof-of-concept folder and its contents.
- `sample.env`: A sample environment configuration file to set up necessary environment variables for the proof-of-concept deployment. It should be copied to `.env` and modified as needed.