from flask import Flask, request, jsonify
from typing import Optional
from src.app.kms_api import get_key, new_key
import os
import time

# --- Constants & Config ---
SERVER_PORT = 5000
USERS = {"user": "pass"}
DEFAULT_RECEIVER_ID = os.getenv("PEER_SITE_ID", "A")

app = Flask(__name__)

# KEY AVAILABILITY SIMULATION

PHYSICS_CONFIG = {
    "KEY_REFILL_RATE": 10.0,  # Keys per second (Adjust this to simulate distance!)
    "MAX_BUCKET_SIZE": 10.0  # Burst capacity (How many keys can sit in buffer)
}

# Simulation State (Global)
sim_state = {
    "bucket": PHYSICS_CONFIG["MAX_BUCKET_SIZE"],
    "last_check": time.time()
}


def consume_key_token():
    """
    Implements the Token Bucket Algorithm.
    Returns True if a key is physically available, False if exhausted.
    """
    now = time.time()
    elapsed = now - sim_state["last_check"]

    # 1. Refill the bucket based on Rate (R)
    added_tokens = elapsed * PHYSICS_CONFIG["KEY_REFILL_RATE"]
    sim_state["bucket"] = min(PHYSICS_CONFIG["MAX_BUCKET_SIZE"], sim_state["bucket"] + added_tokens)
    sim_state["last_check"] = now

    # 2. Try to consume 1 token
    if sim_state["bucket"] >= 1:
        sim_state["bucket"] -= 1
        return True
    return False


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def check_auth(username: Optional[str], password: Optional[str]) -> bool:
    if username is None or password is None:
        return False
    return USERS.get(username) == password


# ==========================================
# ROUTES
# ==========================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "online"})


# 1. NEW KEY (Sender Requests) -> APPLY LIMIT HERE
# Client sends: POST /api/newkey?siteid=B
@app.route("/api/newkey", methods=["POST"])
def serve_new_key():
    # --- PHYSICS CHECK START ---
    if not consume_key_token():
        # Return 503 Service Unavailable so Sender knows to wait/adapt
        return jsonify({
            "error": "Key Exhaustion",
            "detail": "Simulated QKD link rate limit reached."
        }), 503
    # --- PHYSICS CHECK END ---

    # 1. Extract 'siteid'
    target_site = request.args.get("siteid")
    if not target_site:
        target_site = DEFAULT_RECEIVER_ID

    try:
        # 2. Call Real KMS
        return jsonify(new_key(target_site))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 2. GET KEY (Receiver Requests) -> USUALLY NO LIMIT
# Client sends: POST /api/getkey?siteid=A&blockid=...&index=0
@app.route("/api/getkey", methods=["POST"])
def serve_get_key():
    site_id = request.args.get("siteid")
    block_id = request.args.get("blockid")
    index = request.args.get("index")

    if not all([site_id, block_id, index is not None]):
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        return jsonify(get_key(site_id, block_id, index))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/auth", methods=["POST"])
def serve_auth():
    data = request.json or {}
    if not check_auth(data.get("username"), data.get("password")):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"message": "Authenticated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=SERVER_PORT)