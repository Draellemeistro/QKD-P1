import requests
import os
import time

"""
load_dotenv()  # NOTE: ikke sikker på hvor .env burde ligge i forhold til app og nodes


# Access variables
kms_ip_env_var = os.getenv("KMS_URL")

if kms_ip_env_var:
    kms_server_ip = kms_ip_env_var
else:
    print("KMS_URL not found in environment variables.")
    kms_server_ip = "http://localhost:8095"  # Default value if not set
"""

kms_server_ip = os.getenv("KMS_URL", "http://localhost:8095")

endpoints = {
    "get_key": kms_server_ip + "/api/getkey",
    "new_key": kms_server_ip + "/api/newkey",
}

# --- OPTIMIZATION: Persistent Session ---
# Initializes a single TCP connection pool to reuse sockets (HTTP Keep-Alive)
session = requests.Session()
# ----------------------------------------

def new_key(receiver_id):
    """
    REQUEST:
        Method : POST URL path : /api/newkey URL params: siteid=[alhpanumeric]
            e.g. siteid=A

    RESPONSE:
    {
        index: index of the key
        hexKey: Key in hexidecimal format
        blockId: Id of the block containing the key
    }
    """
    # PROFILING START
    start_time = time.time()
    try:
        # Use session.post instead of requests.post
        r = session.post(endpoints["new_key"], params={"siteid": str(receiver_id)})
        r.raise_for_status()  # Raise an error for bad responses (4xx and 5xx)

        duration = time.time() - start_time
        # Log purely the network/KMS wait time
        #print(f" [Profile] KMS HTTP Request took: {duration:.4f}s")

        return r.json()

    except Exception as e:
        print(f" [Profile] KMS Request FAILED after {time.time() - start_time:.4f}s")
        raise e
    # PROFILING END


def get_key(receiver_id, block_id, index):
    """
    REQUEST:
        Method:
            POST
        URL path:
            /api/getkey
        URL params:
            siteid=[alhpanumeric] e.g. siteid=B
            blockid=
            index=[Integer]

    RESPONSE:
    {
        index: index of the key
        hexKey: Key in hexidecimal format
        blockId: Id of the block containing the key
    }
    """
    kms_url = endpoints["get_key"]
    params = {"siteid": str(receiver_id), "index": str(index), "blockid": str(block_id)}

    # PROFILING START
    start_time = time.time()
    try:
        # Use session.post instead of requests.post
        r = session.post(kms_url, params=params)
        r.raise_for_status()  # Raise an error for bad responses (4xx and 5xx)
        duration = time.time() - start_time
        # Only log if it's slow (> 100ms) to avoid spamming console on Receiver
        if duration > 0.1:
            print(f" [Profile] KMS GET Request took: {duration:.4f}s")

        return r.json()

    except Exception as e:
        print(f" [Profile] KMS GET Request FAILED after {time.time() - start_time:.4f}s")
        raise e
    # PROFILING END