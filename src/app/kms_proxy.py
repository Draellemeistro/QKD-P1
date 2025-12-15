from flask import Flask, request, jsonify
from typing import Optional
from src.app.kms_api import get_key, new_key
import os

# --- Constants & Config ---
SERVER_PORT = 5000  # Standard Flask port, match this in docker-compose
USERS = {"user": "pass"}

# We rely on the environment variables already set in your Node docker
# Ensure KMS_URL=http://localhost:8095 is set in the environment where this script runs!
DEFAULT_RECEIVER_ID = os.getenv("PEER_SITE_ID", "A")  # Fallback to env var if client doesn't send it

app = Flask(__name__)


# --- Helper Functions ---
def check_auth(username: Optional[str], password: Optional[str]) -> bool:
    if username is None or password is None:
        return False
    return USERS.get(username) == password


# --- ROUTES ---

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "online"})


# 1. NEW KEY (Matches calls from sender.py)
# Client sends: POST /api/newkey?siteid=B
@app.route("/api/newkey", methods=["POST"])
def serve_new_key():
    # 1. Extract 'siteid' from Query Parameters (kms_api sends it here)
    target_site = request.args.get("siteid")

    # Fallback to defaults if not provided (optional)
    if not target_site:
        target_site = DEFAULT_RECEIVER_ID

    try:
        # 2. Call the imported function (which talks to Local KMS)
        # Note: We return the dictionary directly as JSON
        return jsonify(new_key(target_site))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 2. GET KEY (Matches calls from receiver.py)
# Client sends: POST /api/getkey?siteid=A&blockid=...&index=0
@app.route("/api/getkey", methods=["POST"])
def serve_get_key():
    # 1. Extract params from Query Parameters
    site_id = request.args.get("siteid")
    block_id = request.args.get("blockid")
    index = request.args.get("index")

    # Validate
    if not all([site_id, block_id, index is not None]):
        return jsonify({"error": "Missing required parameters (siteid, blockid, index)"}), 400

    try:
        # 2. Call imported function
        return jsonify(get_key(site_id, block_id, index))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---  AUTH ---



@app.route("/auth", methods=["POST"])
def serve_auth():
    data = request.json or {}
    if not check_auth(data.get("username"), data.get("password")):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"message": "Authenticated"})


if __name__ == "__main__":
    # Listen on 0.0.0.0 so Docker containers can reach it
    app.run(host="0.0.0.0", port=SERVER_PORT)