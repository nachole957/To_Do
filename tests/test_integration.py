import pytest
from app import app, db
from app import Usuario  # Importa el modelo Usuario
from unittest.mock import patch



@pytest.fixture
def app_instance():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app_instance):
    return app_instance.test_client()


def test_database_operations(client, app_instance):
    with app_instance.app_context():
        # Eliminar usuario si ya existe
        existing_user = Usuario.query.filter_by(username="testuser").first()
        if existing_user:
            db.session.delete(existing_user)
            db.session.commit()

        # Crear un usuario
        user = Usuario(username="testuser", password="testpassword")
        db.session.add(user)
        db.session.commit()

        # Verificar que el usuario fue agregado
        added_user = Usuario.query.filter_by(username="testuser").first()
        assert added_user is not None, "El usuario no fue agregado correctamente"





@pytest.mark.skip(reason="Saltando prueba de integración de OAuth por configuración pendiente.")
@patch('auth_google.flow.fetch_token')
@patch('auth_google.flow.credentials', create=True)  # Simular las credenciales
def test_oauth_integration(mock_credentials, mock_fetch_token, client):
    # Simular la respuesta de fetch_token
    mock_fetch_token.return_value = {"access_token": "fake_token"}
    mock_credentials.token = "fake_token"

    # Establecer el estado y el token en la sesión
    with client.session_transaction() as sess:
        sess["state"] = "fake_state"
        sess["token"] = {"access_token": "fake_token"}

    # Hacer la solicitud al callback
    response = client.get('/callback', query_string={"state": "fake_state"})

    # Verificar que la respuesta sea correcta
    assert response.status_code == 302  # Redirección esperada
    assert "Inicio de sesión exitoso" in response.location  # Redirige al lugar correcto


