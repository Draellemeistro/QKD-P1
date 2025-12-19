import pytest
from unittest.mock import MagicMock, patch
import os

# Set dummy env var before importing to avoid warnings
os.environ["KMS_URL"] = "http://localhost:8095"

@pytest.fixture
def get_key_response():
    return {"index": 42, "hexKey": "deadbeefcafebabe", "blockId": "1234"}

@pytest.fixture
def new_key_response():
    return {"index": 1, "hexKey": "abcdef1234567890", "blockId": "5678"}

# Patch the SESSION object inside kms_api, not requests.post
@patch("src.app.kms_api.session.post")
def test_get_key(mock_post, get_key_response):
    from src.app.kms_api import get_key, kms_server_ip

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
    # Verify we called the session, not requests directly
    mock_post.assert_called_once_with(
        url_path,
        params={"siteid": receiver, "blockid": block_id, "index": str(index)},
    )

@patch("src.app.kms_api.session.post")
def test_new_key(mock_post, new_key_response):
    from src.app.kms_api import new_key, kms_server_ip

    sender = "A"
    url_path = kms_server_ip + "/api/newkey"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = new_key_response
    mock_post.return_value = mock_response

    result = new_key(sender)

    assert result == new_key_response
    mock_post.assert_called_once_with(url_path, params={"siteid": sender})