from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from auth_google import google_login, google_callback, login_is_required, list_tasks, add_task
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from config import SECRET_KEY
import secrets

app = Flask(__name__)

# Configuración de la base de datos y la clave secreta
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False, default="oauth_user")

# Modelo de Tarea
class Tarea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.String(255), nullable=False)
    estado = db.Column(db.String(50), nullable=False, default='Sin iniciar')
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Ruta principal: Lista de tareas
@app.route('/')
@login_required
def index():
    tareas = Tarea.query.filter_by(usuario_id=current_user.id).all()
    return render_template('index.html', tareas=tareas)

# Ruta para agregar una tarea
@app.route('/add', methods=['POST'])
@login_required
def add():
    descripcion = request.form['descripcion']
    nueva_tarea = Tarea(descripcion=descripcion, estado='Sin iniciar', usuario_id=current_user.id)
    db.session.add(nueva_tarea)
    db.session.commit()

    # Si el usuario está autenticado con Google OAuth, sincroniza con Google Tasks
    if "google_id" in session:
        try:
            add_task(descripcion)
            flash("Tarea agregada también en Google Tasks.", "success")
        except Exception as e:
            flash(f"Error al sincronizar con Google Tasks: {e}", "error")

    return redirect(url_for('index'))

# Ruta para editar una tarea
@app.route('/edit/<int:id>', methods=['POST'])
@login_required
def edit(id):
    tarea = Tarea.query.get_or_404(id)
    nueva_descripcion = request.form['descripcion']
    nuevo_estado = request.form['estado']

    # Actualiza localmente
    tarea.descripcion = nueva_descripcion
    tarea.estado = nuevo_estado
    db.session.commit()
    flash("Tarea actualizada localmente.", "success")

    # Si el usuario está autenticado con Google OAuth, sincroniza con Google Tasks
    if "google_id" in session:
        try:
            credentials = Credentials(**session['credentials'])
            service = build('tasks', 'v1', credentials=credentials)

            # Buscar la tarea en Google Tasks por título
            tasks = service.tasks().list(tasklist='@default').execute().get('items', [])
            for task in tasks:
                if task['title'] == tarea.descripcion:
                    # Actualizar descripción y estado en Google Tasks
                    service.tasks().patch(
                        tasklist='@default',
                        task=task['id'],
                        body={'title': nueva_descripcion, 'status': 'completed' if nuevo_estado == 'Terminado' else 'needsAction'}
                    ).execute()
                    flash("Tarea actualizada también en Google Tasks.", "success")
                    break
            else:
                flash("No se encontró la tarea en Google Tasks para actualizarla.", "warning")
        except Exception as e:
            flash(f"Error al sincronizar con Google Tasks: {e}", "error")

    return redirect(url_for('index'))

# Ruta para eliminar una tarea
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    tarea = Tarea.query.get_or_404(id)
    
    # Si el usuario está autenticado con Google OAuth
    if "google_id" in session:
        try:
            # Crear credenciales desde la sesión
            credentials = Credentials(**session['credentials'])
            service = build('tasks', 'v1', credentials=credentials)
            
            # Buscar la tarea en Google Tasks por título
            tasks = service.tasks().list(tasklist='@default').execute().get('items', [])
            for task in tasks:
                if task['title'] == tarea.descripcion:
                    # Eliminar la tarea en Google Tasks
                    service.tasks().delete(tasklist='@default', task=task['id']).execute()
                    flash("Tarea eliminada también en Google Tasks.", "success")
                    break
            else:
                flash("No se encontró la tarea en Google Tasks para eliminarla.", "warning")
        except Exception as e:
            flash(f"Error al eliminar la tarea en Google Tasks: {e}", "error")
    else:
        flash("Eliminación en Google Tasks no implementada.", "info")

    # Eliminar la tarea localmente
    db.session.delete(tarea)
    db.session.commit()
    flash("Tarea eliminada localmente.", "success")

    return redirect(url_for('index'))


# Ruta para actualizar el estado de una tarea con drag-and-drop
@app.route('/update_status', methods=['POST'])
@login_required
def update_status():
    task_id = request.form.get('id')
    new_status = request.form.get('status')

    if not task_id or not new_status:
        return jsonify(success=False, error="Invalid data"), 400

    tarea = Tarea.query.get(task_id)
    if tarea and tarea.usuario_id == current_user.id:
        # Actualiza localmente
        tarea.estado = new_status
        db.session.commit()
        flash("Estado de la tarea actualizado localmente.", "success")

        # Sincroniza con Google Tasks
        if "google_id" in session:
            try:
                credentials = Credentials(**session['credentials'])
                service = build('tasks', 'v1', credentials=credentials)

                # Buscar la tarea en Google Tasks por título
                tasks = service.tasks().list(tasklist='@default').execute().get('items', [])
                for task in tasks:
                    if task['title'] == tarea.descripcion:
                        # Actualizar estado en Google Tasks
                        service.tasks().patch(
                            tasklist='@default',
                            task=task['id'],
                            body={'status': 'completed' if new_status == 'Terminado' else 'needsAction'}
                        ).execute()
                        flash("Estado de la tarea sincronizado con Google Tasks.", "success")
                        break
                else:
                    flash("No se encontró la tarea en Google Tasks para actualizar su estado.", "warning")
            except Exception as e:
                flash(f"Error al sincronizar estado con Google Tasks: {e}", "error")

        return jsonify(success=True)

    return jsonify(success=False, error="Unauthorized or task not found"), 403

# Ruta para registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = Usuario.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya existe. Por favor, elija otro.', 'error')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = Usuario(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Usuario registrado exitosamente. Por favor, inicie sesión.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Ruta para login de usuarios
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Usuario.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('index'))
        flash('Nombre de usuario o contraseña incorrectos.', 'error')
        return redirect(url_for('login'))
    return render_template('login.html')

# Ruta protegida para probar el login con Google
@app.route('/protected_area')
@login_is_required
def protected_area():
    return f"Bienvenido, {session['name']}! <br/> <a href='/logout'>Cerrar sesión</a>"

# Ruta para cerrar sesión
@app.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('login'))

# Ruta para login con Google
@app.route('/google-login')
def google_login_route():
    return google_login()

@app.route('/callback')
def google_callback_route():
    # Manejo de estado inválido
    if "state" not in session or session["state"] != request.args.get("state"):
        flash("Error: Estado inválido o faltante.", "danger")
        return redirect(url_for('index'))
    # Obtiene los datos del usuario desde el callback de Google
    email, name = google_callback()

    # Manejo de la base de datos en `main.py`
    existing_user = Usuario.query.filter_by(username=email).first()
    if not existing_user:
        print("Creando un nuevo usuario en la base de datos...")
        new_user = Usuario(username=email, password="oauth_user")
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
    else:
        print("Usuario existente encontrado. Autenticando...")
        login_user(existing_user)

    # Sincroniza las tareas de Google Tasks con la base de datos local
    if "google_id" in session:
        try:
            tasks = list_tasks()
            for task in tasks:
                if not Tarea.query.filter_by(descripcion=task['title'], usuario_id=current_user.id).first():
                    nueva_tarea = Tarea(descripcion=task['title'], estado='Sin iniciar', usuario_id=current_user.id)
                    db.session.add(nueva_tarea)
            db.session.commit()
            flash("Tareas de Google sincronizadas con la base de datos.", "success")
        except Exception as e:
            flash(f"Error al sincronizar tareas de Google: {e}", "error")

    return redirect(url_for('index'))

@app.route('/delete_user', methods=['POST'])
def delete_user():
    try:
        # Obtener el nombre de usuario desde el cuerpo de la solicitud
        data = request.json
        username = data.get('username')

        # Buscar el usuario en la base de datos
        user = Usuario.query.filter_by(username=username).first()

        if not user:
            return jsonify({'message': 'Usuario no encontrado'}), 404

        # Eliminar el usuario
        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': f'Usuario {username} eliminado con éxito'}), 200
    except Exception as e:
        return jsonify({'message': 'Ocurrió un error', 'error': str(e)}), 500
    

# Rutas básicas para prueba
@app.route('/')
def home():
    return "¡Hola, mundo!"



# Inicialización de la base de datos
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
