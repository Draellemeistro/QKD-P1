import pytest
from src.app.crypto.kms_requests import get_key


def test_get_key_request():
    kms_server_ip = "1.2.1.2.1"
    receiver = "B"
    block_id = ""
    index = 1
    key_material = get_key(kms_server_ip, receiver, block_id, index)
    return key_material
