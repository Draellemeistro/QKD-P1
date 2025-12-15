import pytest
from unittest.mock import patch
from src.app.middleman import app

# NOTE: These tests need to be expanded and set up with proper mocking where necessary.


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_connect_sender(client):
    response = client.post("/connect", json={"purpose": "sender"})
    assert response.status_code == 200
    assert "node_id" in response.get_json()


def test_auth_success(client):
    response = client.post("/auth", json={"username": "user", "password": "pass"})
    assert response.status_code == 200
    assert response.json["messa"]


def test_auth_fail(client):
    response = client.post("/auth", json={"username": "user", "password": "wrong"})
    assert response.status_code == 401


def test_request_file(client):
    response = client.post("/request_file", json={"file_path": "dummy.txt"})
    assert response.status_code == 200
    assert "file" in response.get_json()


@patch("src.app.middleman.get_key")
def test_get_key(mock_get_key, client):
    mock_get_key.return_value = {
        "index": 0,
        "hexKey": "abcdef1234567890",
        "blockId": "b1",
    }
    resp = client.post(
        "/get_key", json={"sender_id": "A", "key_block_id": "b1", "key_index": 0}
    )
    assert resp.status_code == 200
    assert resp.json["hexKey"] == "abcdef1234567890"
    mock_get_key.assert_called_once_with("A", "b1", 0)

    response = client.post(
        "/get_key", json={"sender_id": "A", "key_block_id": "block", "key_index": 0}
    )
    assert response.status_code == 200


def test_new_key(client):
    response = client.get("/new_key")
    assert response.status_code == 200
