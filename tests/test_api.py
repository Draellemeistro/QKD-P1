import pytest
from unittest.mock import patch, MagicMock
from dotenv import load_dotenv
import os

load_dotenv()

# Access variables
kms_ip_env_var = os.getenv("KMS_URL")

if kms_ip_env_var:
    kms_server_ip = kms_ip_env_var
else:
    print("KMS_URL not found in environment variables.")
    kms_server_ip = "http://localhost:8095"  # Default value if not set


@pytest.fixture
def get_key_response():
    return {"index": 42, "hexKey": "abcdef1234567890", "blockId": "1234"}


@pytest.fixture
def new_key_response():
    return {"index": 1, "hexKey": "abcdef1234567890", "blockId": "5678"}


@pytest.fixture
def api_response_pattern():
    return {"index": int, "hexKey": str, "blockId": str}


@patch("src.app.kms_api.requests.post")
def test_get_key(mock_post, get_key_response):
    from src.app.kms_api import get_key

    receiver = "B"
    block_id = "1234"
    index = 42
    url_path = kms_server_ip + "/api/getkey"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = get_key_response
    mock_post.return_value = mock_response

    result = get_key(receiver, block_id, index)

    assert result == get_key_response
    mock_post.assert_called_once_with(
        url_path,
        params={"siteid": receiver, "blockid": block_id, "index": index},
    )


@patch("src.app.kms_api.requests.post")
def test_new_key(mock_post, new_key_response):
    from src.app.kms_api import new_key

    sender = "A"
    url_path = kms_server_ip + "/api/newkey"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = new_key_response
    mock_post.return_value = mock_response

    result = new_key(sender)

    assert result == new_key_response
    mock_post.assert_called_once_with(url_path, data={"siteid": sender})
