import requests
import os

NODE_API_URL = f"http://{os.getenv('NODE_HOST', 'localhost')}:{os.getenv('NODE_PORT', '8000')}"  # Base URL for node middleman API


def request_get_key(block_id, index, sender_id=None):
    """Request an existing key from the node server.
    Matches server `/get_key` which expects JSON body with
    `sender_id`, `key_block_id`, and `key_index`.
    """
    payload = {
        "sender_id": sender_id,
        "key_block_id": block_id,
        "key_index": index,
    }
    r = requests.post(f"{NODE_API_URL}/get_key", json=payload)
    r.raise_for_status()
    return r.json()


def request_new_key(receiver_id=None):
    """Request a new key from the node server.
    Server currently exposes GET `/new_key` and ignores receiver_id.
    """
    if receiver_id:
        r = requests.get(f"{NODE_API_URL}/new_key", params={"receiver_id": receiver_id})
    else:
        r = requests.get(f"{NODE_API_URL}/new_key")
    r.raise_for_status()
    return r.json()


def authenticate():
    authenticated = request_authentication()
    if authenticated.get("status") == "success":
        print("Authenticated with node")
        return True
    elif authenticated.get("message") == "Authenticated":
        print("Authenticated with node")
        return True
    else:
        print(f"Authentication response: {authenticated}")
        return False


def request_authentication():
    """Authenticate against the node server.
    Matches server `/auth` (POST) expecting JSON body.
    """
    params = dummy_authenticate()
    r = requests.post(f"{NODE_API_URL}/auth", json=params)
    r.raise_for_status()
    return r.json()


def dummy_authenticate():
    return {"username": "user", "password": "pass"}


def connect_to_node(purpose):
    """Connect to node server for role assignment.
    Matches server `/connect` (POST) expecting JSON body with `purpose`.
    """
    if purpose not in ["sender", "receiver"]:
        raise ValueError("Purpose must be either 'sender' or 'receiver'")

    r = requests.post(f"{NODE_API_URL}/connect", json={"purpose": purpose})
    r.raise_for_status()
    node_id = r.json().get("node_id")
    return node_id
