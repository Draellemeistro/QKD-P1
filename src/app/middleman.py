from flask import Flask, request, jsonify
from typing import Optional
from src.app.kms_api import get_key, new_key
from src.crypto.authentication import load_public_key, load_private_key, sign, verify
import os

# Constants
SERVER_PORT = 8000
DEFAULT_RECEIVER_ID = "A"
DEFAULT_SENDER_ID = "B"
DEFAULT_NODE_LISTEN_IP = "172.18.0.4"
DEFAULT_NODE_LISTEN_PORT = 12345
USERS = {"user": "pass"}

# Environment variables
# TODO: use dotenv, and check if vars exist
RECEIVER_NODE_ID = os.getenv("NODE_RECEIVER_ID", DEFAULT_RECEIVER_ID)
SENDER_NODE_ID = os.getenv("NODE_SENDER_ID", DEFAULT_SENDER_ID)
NODE_ID = os.getenv("NODE_ID", RECEIVER_NODE_ID)
NODE_LISTEN_IP = os.getenv("NODE_LISTEN_IP", DEFAULT_NODE_LISTEN_IP)
NODE_LISTEN_PORT = int(os.getenv("NODE_LISTEN_PORT", str(DEFAULT_NODE_LISTEN_PORT)))

app = Flask(__name__)


def check_auth(username: Optional[str], password: Optional[str]) -> bool:
    if username is None or password is None:
        return False
    return USERS.get(username) == password


# ----- GET KEY -----
@app.route(
    "/connect", methods=["POST"]
)  # Should be GET, probably, but need node id in env somewhere?
def serve_connect():
    data = request.json or {}
    purpose = data.get("purpose")
    if purpose == "sender":
        node_id = SENDER_NODE_ID
    elif purpose == "receiver":
        node_id = RECEIVER_NODE_ID
    else:
        node_id = NODE_ID
    return jsonify({"node_id": node_id})


# ----- GET KEY -----
@app.route("/get_key", methods=["POST"])
def serve_get_key():
    # Stand-in: returns a dummy key
    """
    expected JSON body:
    {
        "sender_id": "A"
        "key_block_id": "block-id"
        "key_index": "0"
    }
    """
    data = request.json or {}
    id = data.get("sender_id", SENDER_NODE_ID)
    block_id = data.get("key_block_id", "stand")
    index = data.get("key_index", 0)
    return get_key(id, block_id, index)


# ----- NEW KEY -----
@app.route("/new_key", methods=["GET"])
def serve_new_key():
    return new_key(RECEIVER_NODE_ID)


#  ----- AUTH -----
@app.route("/auth", methods=["POST"])
def serve_auth():
    data = request.json or {}
    message = data.get("message")
    signature = data.get("signature")
    identifier = data.get("identifier")
    if isinstance(message, str):
        message = message.encode()
    if isinstance(signature, str):
        signature = signature.encode()
    if message is None or signature is None or identifier is None:
        return jsonify({"error": "Missing required fields"}), 400
    consumer_public_key = load_public_key(identifier)
    if verify(
        message,
        signature,
        consumer_public_key,
    ):
        return jsonify({"status": "success"})
    if not check_auth(data.get("username"), data.get("password")):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"message": "Authenticated"})


# ----- REQUEST FILE ----- #NOT_IMPLEMENTED
@app.route("/request_file", methods=["POST"])
def serve_request_file():
    data = request.json or {}
    file_path = data.get("file_path")

    # Stand-in: returns a dummy file content
    print(f"File requested: {file_path}")
    return jsonify({"file": "This is your requested file content."})


if __name__ == "__main__":
    app.run(port=SERVER_PORT)
