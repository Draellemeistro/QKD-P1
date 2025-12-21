from flask import Flask, request, jsonify
from typing import Optional
from src.app.kms_api import get_key, new_key
import os
import time

SERVER_PORT = 5000
USERS = {"user": "pass"}
DEFAULT_RECEIVER_ID = os.getenv("PEER_SITE_ID", "A")

app = Flask(__name__)


# For 300 kbps with 256-bit keys: 300_000 / 256 = 1171.875 keys/s
KEYS_PER_SEC = 20
MIN_INTERVAL_S = 1.0 / KEYS_PER_SEC

# Global limiter state
sim_state = {
    "next_allowed_ts": time.time()
}


def allow_key_now() -> bool:
    """
    Smooth rate limiter: permits one key issuance every MIN_INTERVAL_S seconds.
    No burst accumulation/buffer.
    """
    now = time.time()
    if now >= sim_state["next_allowed_ts"]:
        # Schedule next slot; using now prevents drift if requests arrive late.
        sim_state["next_allowed_ts"] = now + MIN_INTERVAL_S
        return True
    return False




def check_auth(username: Optional[str], password: Optional[str]) -> bool:
    if username is None or password is None:
        return False
    return USERS.get(username) == password



@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "online", "keys_per_sec": KEYS_PER_SEC})



# Client sends: POST /api/newkey?siteid=B
@app.route("/api/newkey", methods=["POST"])
def serve_new_key():
    if not allow_key_now():
        return jsonify({
            "error": "Key Exhaustion",
            "detail": "Simulated QKD key-rate limit reached (smooth limiter)."
        }), 503

    target_site = request.args.get("siteid") or DEFAULT_RECEIVER_ID

    try:
        return jsonify(new_key(target_site))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
    app.run(host="0.0.0.0", port=SERVER_PORT, debug=False)
