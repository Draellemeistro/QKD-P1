import requests
from dotenv import load_dotenv
import os

load_dotenv()  # NOTE: ikke sikker på hvor .env burde ligge i forhold til app og nodes

# Access variables
kms_ip_env_var = os.getenv("KMS_URL")

if kms_ip_env_var:
    kms_server_ip = kms_ip_env_var
else:
    print("KMS_URL not found in environment variables.")
    kms_server_ip = "http://localhost:8095"  # Default value if not set


endpoints = {
    "get_key": kms_server_ip + "/api/getkey",
    "new_key": kms_server_ip + "/api/newkey",
}


def new_key(sender):
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

    r = requests.post(endpoints["new_key"], data={"siteid": str(sender)})
    r.raise_for_status()  # Raise an error for bad responses (4xx and 5xx)

    return r.json()


def get_key(receiver, block_id, index):
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
    params = {"siteid": str(receiver), "index": str(index), "blockid": str(block_id)}

    r = requests.post(kms_url, data=params)
    r.raise_for_status()  # Raise an error for bad responses (4xx and 5xx)

    return r.json()
