import requests

kms_server_ip = "serverip"

endpoints = {
    "get_key": kms_server_ip + "/api/getkey",
    "new_key": kms_server_ip + "/api/newkey"
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

    r = requests.post()
    ret = r
    return ret


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

    kms_url = kms_server_ip + endpoints["get_key"]

    params = {"siteid": str(receiver), "index": str(
        index), "blockid": str(block_id)}

    r = requests.post(kms_url, data=params)
    r.json()
    return r.response
