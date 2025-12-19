import pytest
from src.app.directory_server import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_lookup_existing_user(client):
    """Test Requirement F14: Resolving a known Site ID."""
    # The code has 'alice' hardcoded
    response = client.get('/lookup/alice')
    data = response.get_json()

    assert response.status_code == 200
    assert data['ip'] == '172.18.0.3'
    assert data['site_id'] == 'A'


def test_lookup_unknown_user(client):
    """Test resolving a non-existent site."""
    response = client.get('/lookup/unknown_host')
    assert response.status_code == 404
    assert response.get_json() == {"error": "Host not found"}


def test_health_check(client):
    """Test the health endpoint."""
    response = client.get('/health')
    assert response.status_code == 200
    assert response.get_json()['status'] == 'running'