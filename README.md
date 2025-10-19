Python IPTables Firewall with Flask GUI

This project provides a simple web-based graphical user interface (GUI) for managing iptables firewall rules on a Linux host. The application is containerized using Docker for easy deployment.

Architecture

This application works by providing a user-friendly web interface that edits a central configuration file (firewall_rules.json). This file acts as the single "source of truth". The Python backend reads this file and uses the python-iptables library to translate the JSON definitions into actual iptables rules in the Linux kernel.

Flow:

User interacts with the Flask Web GUI in their browser.

Flask backend modifies the firewall_rules.json file.

The backend then calls the apply_rules_to_iptables() function.

This function flushes all old rules and rebuilds the entire firewall ruleset from the firewall_rules.json file, ensuring the kernel is always in sync with the configuration.

How to Build and Run

Prerequisites

Docker installed and running on your system.

1. Build the Docker Image

Navigate to the directory containing the Dockerfile and other project files, then run the build command:

docker build -t firewall-app .


2. Run the Docker Container

To run the container, you must provide it with the NET_ADMIN capability. This allows the container to modify the host's network stack and firewall rules.

docker run --rm -it --cap-add=NET_ADMIN -p 5000:5000 firewall-app


Security Note: Using --cap-add=NET_ADMIN is the correct, security-conscious way to grant the necessary permissions. Do not use --privileged, as it would grant the container excessive permissions and create a significant security risk.

3. Access the GUI

Once the container is running, open a web browser and navigate to:

http://localhost:5000

You should now see the firewall control panel and can begin adding or removing rules.