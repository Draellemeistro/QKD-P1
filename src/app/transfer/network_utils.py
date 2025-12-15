import os
import sys
import requests

# Defaults to localhost, but can be overridden by Docker env vars
DIRECTORY_URL = os.getenv("DIRECTORY_SERVICE_URL", "http://172.18.0.10:5000")

def resolve_host(hostname):
    """
    Asks the Directory Service for the target's IP, Port, and Site ID.
    Returns: (ip, port, site_id) or exits the program on error.
    """
    try:
        print(f"Looking up '{hostname}' via {DIRECTORY_URL}...")
        response = requests.get(f"{DIRECTORY_URL}/lookup/{hostname}")

        if response.status_code == 200:
            data = response.json()
            return data["ip"], int(data["port"]), data["site_id"]
        else:
            print(f"Error: Host '{hostname}' not found in Directory.")
            sys.exit(1)

    except requests.exceptions.ConnectionError:
        print(f"Error: Could not reach Directory Service at {DIRECTORY_URL}")
        sys.exit(1)