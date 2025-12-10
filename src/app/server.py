from flask import Flask, request, jsonify
from kms_api import get_key, new_key
import receiver
import sender

app = Flask(__name__)

SERVER_PORT = 8000
SERVER_IP = ""  # Unused in this context

RECEIVER_NODE_ID = "A"
SENDER_NODE_ID = "B"
NODE_ID = RECEIVER_NODE_ID  # IDK, midlertidig værdi

NODE_LISTEN_IP = "172.18.0.4"
NODE_LISTEN_PORT = 12345

# Simple auth (replace with real logic)
USERS = {"user": "pass"}


def check_auth(username, password):
    return USERS.get(username) == password


# ----- GET KEY -----
@app.route("/get_key", methods=["GET"])
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
    data = request.json
    if data.get("sender_id"):
        id = data["sender_id"]
    else:
        id = SENDER_NODE_ID

    if data.get("key_block_id"):
        block_id = data["key_block_id"]
    else:
        block_id = "stand"

    if data.get("key_index"):
        index = data["key_index"]
    else:
        index = 0

    return receiver.get_decryption_key(id, block_id, index)


# ----- NEW KEY -----
@app.route("/new_key", methods=["GET"])
def serve_new_key():
    return new_key(RECEIVER_NODE_ID)


#  ----- AUTH -----
@app.route("/auth", methods=["POST"])
def serve_auth():
    data = request.json
    if not data or not check_auth(data.get("username"), data.get("password")):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"message": "Authenticated"})


# ----- REQUEST FILE -----
@app.route("/request_file", methods=["POST"])
def serve_request_file():
    data = request.json
    file_path = data.get("file_path")

    # Stand-in: returns a dummy file content
    print(f"File requested: {file_path}")
    return jsonify({"file": "This is your requested file content."})


if __name__ == "__main__":
    app.run(port=SERVER_PORT)
