import pytest
from src.app.directory_server import app  # Assuming app instance is here


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_resolve_site_id(client):
    """Test Requirement F14: Resolving a Site ID to an IP."""
    # Register a dummy site
    client.post('/register', json={'site_id': 'A', 'ip': '1.2.3.4', 'port': 9999})

    # Query it
    response = client.get('/resolve?site_id=A')
    data = response.get_json()

    assert response.status_code == 200
    assert data['ip'] == '1.2.3.4'
    assert data['port'] == 9999


def test_resolve_unknown_site(client):
    """Test Error Handling for F14."""
    response = client.get('/resolve?site_id=UNKNOWN')
    assert response.status_code == 404