import pytest
from flask import session
from app import app, db  # Asegúrate de que 'app' y 'db' están disponibles en 'app.py'


@pytest.fixture
def client():
    """Cliente de pruebas para la aplicación."""
    app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,  # Desactiva CSRF si aplica
    })
    with app.test_client() as client:
        yield client



# Test de autenticación

def test_login_required_for_protected_page(client):
    """Verifica que se redirige al login si el usuario no está autenticado."""
    response = client.get('/protected-page', follow_redirects=False)
    assert response.status_code == 302
    assert '/login' in response.headers['Location']

def test_successful_login(client):
    """Prueba el inicio de sesión exitoso."""
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    # Usa encode('utf-8') para manejar el texto con caracteres especiales
    assert "Inicio de sesión exitoso".encode('utf-8') in response.data


def test_failed_login(client):
    """Prueba un intento de inicio de sesión fallido."""
    response = client.post('/login', data={
        'username': 'invaliduser',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert "Nombre de usuario o contraseña incorrectos".encode('utf-8') in response.data


# Test de inyección SQL

def test_sql_injection_protection(client):
    """Prueba que la aplicación no sea vulnerable a inyecciones SQL."""
    malicious_input = "' OR 1=1 --"
    response = client.post('/login', data={
        'username': malicious_input,
        'password': 'test'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert "Credenciales inválidas" in response.get_data(as_text=True)

# Test de protección CSRF

def test_csrf_protection(client):
    """Verifica que las solicitudes POST requieran un token CSRF."""
    response = client.post('/protected-action', data={
        'key': 'value'
    }, follow_redirects=True)
    assert response.status_code == 400
    assert "CSRF token missing" in response.get_data(as_text=True)

# Test de sesiones seguras

def test_secure_cookies(client):
    """Prueba que las cookies de sesión sean seguras."""
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    cookie = response.headers.get('Set-Cookie')
    assert 'Secure' in cookie  # Las cookies deben ser seguras
    assert 'HttpOnly' in cookie

# Test de logout
def test_logout(client):
    """Verifica que el usuario pueda cerrar sesión correctamente."""
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    })
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert "Has cerrado sesión" in response.get_data(as_text=True)
