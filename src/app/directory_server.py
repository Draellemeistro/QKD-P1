from flask import Flask, jsonify, request

app = Flask(__name__)

# Fake database
DIRECTORY = {
    "alice": {
        "ip": "172.18.0.3",
        "port": 12345,
        "site_id": "A"
    },
    "bob": {
        "ip": "172.18.0.21",
        "port": 12345,
        "site_id": "B"
    },
    "charlie": {
        "ip": "172.18.0.5",
        "port": 12345,
        "site_id": "C"
    }
}

@app.route('/lookup/<hostname>', methods=['GET'])
def lookup(hostname):
    """
        Input: "bob"
        Output: {"ip": "172.18.0.4", "port": 12345, "site_id": "B"}
    """

    hostname = hostname.lower()
    if hostname in DIRECTORY:
        return jsonify(DIRECTORY[hostname])
    else:
        return jsonify({"error": "Host not found"}), 404

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "running"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)