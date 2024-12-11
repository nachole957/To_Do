import pytest
from app import app, db
import sys
import os

# Agrega el directorio raíz al sistema de rutas
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db  # Importa app y db

@pytest.fixture(scope="module")
def test_client():
    # Configuración de prueba
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",  # Base de datos en memoria para pruebas
        "WTF_CSRF_ENABLED": False,  # Desactiva CSRF si aplica
    })

    # Crear las tablas en la base de datos
    with app.app_context():
        db.create_all()
        # Agregar un usuario de prueba para las pruebas de login
        from app import Usuario  # Importa el modelo
        test_user = Usuario(username="testuser", password="testpassword")
        db.session.add(test_user)
        db.session.commit()

    with app.test_client() as client:
        yield client

    # Limpia la base de datos después de las pruebas
    with app.app_context():
        db.drop_all()