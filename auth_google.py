from flask import session, redirect, request, abort
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from googleapiclient.discovery import build
import requests
import os
import pathlib

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = ""
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
        "https://www.googleapis.com/auth/tasks"
    ],
    redirect_uri="http://127.0.0.1:5000/callback"
)

def login_is_required(function):
    """Middleware para verificar si el usuario está autenticado mediante Google OAuth."""
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()
    return wrapper

def google_login():
    """Inicia el flujo de autenticación con Google."""
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

def google_callback():
    """Maneja el callback después de la autenticación de Google."""
    flow.fetch_token(authorization_response=request.url)

    if session["state"] != request.args["state"]:
        abort(500)  # State mismatch

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")

    return session["email"], session["name"]

def get_google_tasks_service():
    """Crea y retorna el servicio de Google Tasks."""
    if "credentials" not in session:
        abort(401)  # Usuario no autenticado

    credentials = google.oauth2.credentials.Credentials(**session['credentials'])
    return build('tasks', 'v1', credentials=credentials)

def list_tasks():
    """Lista las tareas del usuario desde Google Tasks."""
    service = get_google_tasks_service()
    try:
        tasks = service.tasks().list(tasklist='@default').execute()
        return tasks.get('items', [])  # Retorna las tareas o una lista vacía
    except googleapiclient.errors.HttpError as e:
        print(f"Error HTTP al listar tareas: {e}")
        return []
    except Exception as e:
        print(f"Error general al listar tareas: {e}")
        return []

def add_task(task_title):
    """Agrega una nueva tarea al usuario autenticado en Google Tasks."""
    service = get_google_tasks_service()
    task = {'title': task_title}
    try:
        return service.tasks().insert(tasklist='@default', body=task).execute()
    except Exception as e:
        print(f"Error al agregar tarea a Google Tasks: {e}")
        return None

def credentials_to_dict(credentials):
    """Convierte las credenciales a un diccionario serializable."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
