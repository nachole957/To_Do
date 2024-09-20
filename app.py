from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)

# Configuración de la base de datos y la clave secreta
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Clave secreta segura generada

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

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
    return redirect(url_for('index'))

# Ruta para editar una tarea
@app.route('/edit/<int:id>', methods=['POST'])
@login_required
def edit(id):
    tarea = Tarea.query.get_or_404(id)
    tarea.descripcion = request.form['descripcion']
    tarea.estado = request.form['estado']
    db.session.commit()
    return redirect(url_for('index'))

# Ruta para eliminar una tarea
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    tarea = Tarea.query.get_or_404(id)
    db.session.delete(tarea)
    db.session.commit()
    return redirect(url_for('index'))

# Ruta para actualizar el estado de una tarea con drag-and-drop
@app.route('/update_status', methods=['POST'])
@login_required
def update_status():
    task_id = request.form.get('id')
    new_status = request.form.get('status')
    
    tarea = Tarea.query.get(task_id)
    if tarea and tarea.usuario_id == current_user.id:
        tarea.estado = new_status
        db.session.commit()
    
    return jsonify(success=True)

# Ruta para registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = Usuario.query.filter_by(username=username).first()
        if existing_user:
            flash('Este nombre de usuario ya existe.')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = Usuario(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
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
            return redirect(url_for('index'))
        flash('Nombre de usuario o contraseña incorrectos')
        return redirect(url_for('login'))
    return render_template('login.html')

# Ruta para cerrar sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Inicialización de la base de datos
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
