from flask import Flask, render_template, request, redirect, url_for, flash, session  # Agrega 'session' aquí  # Importa las funciones necesarias de Flask (Todas las rutas y render_template dependen de esto)
from flask_migrate import Migrate  # Importa Migrate para manejar migraciones de la base de datos (Depende de db y app)
from werkzeug.security import generate_password_hash, check_password_hash # Importa funciones para manejar contraseñas seguras (Depende de la clase User)
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user # Importa funciones para manejar la autenticación de usuarios (Depende de la clase User y app)
from flask_sqlalchemy import SQLAlchemy # Importa SQLAlchemy para interactuar con la base de datos (Depende de app)
from werkzeug.utils import secure_filename # Importa secure_filename para manejar archivos cargados de forma segura (Depende de las rutas que manejan uploads)
import os # Importa el módulo os para interactuar con el sistema operativo (Depende de app.secret_key y rutas de uploads)
from datetime import datetime
import sqlite3
from flask_mail import Mail, Message
from sqlalchemy import or_
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateField, TimeField, FloatField, IntegerField, BooleanField, FileField, SubmitField
from wtforms.validators import DataRequired
import requests
import secrets #videos
import math
import secrets
from authlib.integrations.flask_client import OAuth
from flask import send_from_directory #Permite ver la imagen en el users
# from recuperacion_contraseña import crear_modulo_recuperacion_contraseña # Importacion del modulo.
from urllib.parse import urlparse
import csv
from flask import send_file
from io import BytesIO, StringIO # Add this line to import BytesIO and StringIO.
import io


app = Flask(__name__) # Crea una instancia de la aplicación Flask (Todas las rutas y configuraciones dependen de esto)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db' # Configura la URI de la base de datos (Depende de db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Desactiva el seguimiento de modificaciones de SQLAlchemy (Depende de db)
app.secret_key = os.urandom(24) # Genera una clave secreta para la sesión (Depende de flask_login)
UPLOAD_FOLDER = 'static/uploads/' # Define la carpeta para almacenar archivos cargados (Depende de las rutas de uploads)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} # Define las extensiones de archivo permitidas (Depende de las rutas de uploads)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # Configura la carpeta de carga en la aplicación (Depende de rutas que manejan uploads)
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS # Configura las extensiones permitidas en la aplicación (Depende de rutas que manejan uploads)
db = SQLAlchemy(app) # Crea una instancia de SQLAlchemy asociada a la aplicación (Depende de app y configura la base de datos)
login_manager = LoginManager() # Crea una instancia de LoginManager para manejar la autenticación (Depende de app)
login_manager.init_app(app) # Inicializa LoginManager con la aplicación (Depende de app)
login_manager.login_view = 'login' # Define la vista de inicio de sesión (Depende de flask_login)
migrate = Migrate(app, db) # Inicializa Migrate para manejar migraciones de la base de datos (Depende de db y app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS # No corchetes extras



class User(UserMixin, db.Model): # Define el modelo de usuario (Depende de db)
    id = db.Column(db.Integer, primary_key=True) # Define el ID del usuario (Depende de db)
    name = db.Column(db.String(100), nullable=False) # Define el nombre del usuario (Depende de db)
    first_last_name = db.Column(db.String(100), nullable=False) # Define el primer apellido del usuario (Depende de db)
    second_last_name = db.Column(db.String(100), nullable=False) # Define el segundo apellido del usuario (Depende de db)
    phone_number = db.Column(db.String(20), nullable=False) # Define el número de teléfono del usuario (Depende de db)
    email = db.Column(db.String(100), unique=True, nullable=False) # Define el correo electrónico del usuario (Depende de db)
    password_hash = db.Column(db.String(128), nullable=False) # Define el hash de la contraseña del usuario (Depende de db)
    avatar = db.Column(db.String(200)) # Define la ruta del avatar del usuario (Depende de db)
    registration_count = db.Column(db.Integer, default=0) # Define el contador de registros del usuario (Depende de db)
    posts = db.relationship('Post', backref='author', lazy=True) # Add this line
    def set_password(self, password): # Define un método para establecer la contraseña del usuario (Depende de generate_password_hash)
        self.password_hash = generate_password_hash(password) # Genera el hash de la contraseña

    def check_password(self, password): # Define un método para verificar la contraseña del usuario (Depende de check_password_hash)
        return check_password_hash(self.password_hash, password) # Verifica el hash de la contraseña

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_post_user'))

class Tarea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(200), nullable=False)
    completada = db.Column(db.Boolean, default=False)

@login_manager.user_loader # Define una función para cargar el usuario desde la base de datos (Depende de User y db)
def load_user(user_id):
    return User.query.get(int(user_id)) # Obtiene el usuario de la base de datos

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    detail = db.Column(db.Text)
    video_url = db.Column(db.String(200))
    image_url = db.Column(db.String(200))  # Nuevo campo para la URL de la imagen

class Contacto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido1 = db.Column(db.String(100), nullable=False)
    apellido2 = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100))
    telefono = db.Column(db.String(20))
    celular = db.Column(db.String(20))
    empresa = db.Column(db.String(100))
    categoria = db.Column(db.String(50))


@app.route("/")
@app.route("/home")
@app.route("/index")
def index():
    title = "Este es el Index"
    page = request.args.get('page', 1, type=int)
    per_page = 5
    posts_pagination = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=per_page)

    for post in posts_pagination.items:
        # Imprime los IDs y tipos de datos para depuración
        if current_user.is_authenticated:
            print(f"current_user.id: {current_user.id}, type: {type(current_user.id)}")
        else:
            print("Usuario no autenticado")
        print(f"post.user_id: {post.user_id}, type: {type(post.user_id)}")

        # Asegura que user_id sea un entero
        post.user_id = int(post.user_id) if post.user_id else None

    return render_template('index.html', posts_pagination=posts_pagination, title=title)

# version
@app.route('/version', methods=['GET', 'POST'])
def version():
    if request.method == 'POST':
        if 'titulo' in request.form:
            titulo = request.form['titulo']
            nueva_tarea = Tarea(titulo=titulo)
            db.session.add(nueva_tarea)
            db.session.commit()
            return redirect(url_for('version'))  # Redirigir después de agregar

    tareas = Tarea.query.all()
    return render_template('version.html', tareas=tareas)

@app.route('/version/completar/<int:tarea_id>', methods=['POST'])
def completar_tarea(tarea_id):
    tarea = Tarea.query.get_or_404(tarea_id)
    tarea.completada = not tarea.completada
    db.session.commit()
    return redirect(url_for('version'))

@app.route('/version/borrar/<int:tarea_id>', methods=['POST'])
def borrar_tarea(tarea_id):
    tarea = Tarea.query.get_or_404(tarea_id)
    db.session.delete(tarea)
    db.session.commit()
    return redirect(url_for('version'))
# versionn








# VER IMAGENES Y POSTS
@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post_detail.html', post=post)


@app.route('/new', methods=['GET', 'POST'])
@login_required # add this to ensure user is logged in
def new_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        image = request.files.get('image') # .get to prevent keyerror

        app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

        if image and image.filename != '':
            if len(image.read(512)) > app.config['MAX_CONTENT_LENGTH']: #read only the start of the file
                flash("El archivo es demasiado grande.", 'danger')
                return render_template('new_post.html')

            image.seek(0)  # reset the file pointer

            if allowed_file(image.filename):
                filename = secure_filename(image.filename)
                try:
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    post = Post(title=title, content=content, image=filename, date_posted=datetime.utcnow(), user_id=current_user.id) # assign user_id
                    db.session.add(post)
                    db.session.commit()
                    flash('Publicación creada con éxito', 'success')
                    return redirect(url_for('index'))
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error al crear la publicación: {e}', 'danger')
                    return render_template('new_post.html', error=str(e))
            else:
                flash("Archivo no permitido", "danger")
                return render_template('new_post.html')

        else: # no image uploaded.
            post = Post(title=title, content=content, image=None, date_posted=datetime.utcnow(), user_id=current_user.id) # assign user_id
            try:
                db.session.add(post)
                db.session.commit()
                flash('Publicación creada con éxito', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error al crear la publicación: {e}', 'danger')
                return render_template('new_post.html', error=str(e))

    return render_template('new_post.html')



@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required  # Requiere que el usuario esté logueado
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id: # check if the user is the post's author
        flash("No tienes permiso para editar este post.", "danger")
        return redirect(url_for('post', post_id=post.id))

    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        image = request.files.get('image') # get to prevent key error

        if image and image.filename != '':
            if allowed_file(image.filename):
                if post.image:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], post.image))
                    except Exception as e:
                        print(f"Error al borrar la imagen antigua: {e}")
                filename = secure_filename(image.filename)
                try:
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    post.image = filename
                except Exception as e:
                    print(f"Error al guardar el archivo: {e}")
                    flash(f"Error al guardar el archivo: {e}", 'danger')
                    return render_template('edit_post.html', post=post, error=str(e))

        db.session.commit()
        return redirect(url_for('post', post_id=post.id))
    return render_template('edit_post.html', post=post)


@app.route('/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.user_id != current_user.id:
        flash("No tienes permiso para borrar este post.", "danger")
        return redirect(url_for('post', post_id=post.id))

    if post.image:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], post.image)
        if os.path.exists(image_path):
            try:
                os.remove(image_path)
            except FileNotFoundError:
                flash("Error: La imagen no fue encontrada.", "danger")
                return redirect(url_for('post', post_id=post.id))
            except OSError as e:
                flash(f"Error al borrar la imagen: {e}", "danger")
                return redirect(url_for('post', post_id=post.id))

    try:
        db.session.delete(post)
        db.session.commit()
        flash("Publicación borrada con éxito.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al borrar la publicación: {e}", "danger")
    return redirect(url_for('index'))
# fin ver post






@app.route('/create_vids', methods=['GET', 'POST'])
def create_vids():
    if request.method == 'POST':
        title = request.form.get('title')
        detail = request.form['detail'] # Cambiado 'content' a 'detail'
        video_url = request.form.get('video_url')
        image = request.files.get('image')

        if not title or not video_url:
            flash("Título y URL del video son obligatorios.", 'danger')
            return redirect(request.referrer)

        if not is_valid_url(video_url):
            flash("URL del video no válida.", 'danger')
            return redirect(request.referrer)

        filename = None

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            try:
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            except Exception as e:
                print(f"Error al guardar el archivo: {e}")
                flash(f"Error al guardar el archivo: {e}", 'danger')
                return redirect(request.referrer)

        video = Video(title=title, detail=detail, video_url=video_url, image=filename, date_posted=datetime.utcnow())

        try:
            db.session.add(video)
            db.session.commit()
            flash('Video guardado con éxito', 'success')
            return redirect(url_for('index'))  # Reemplaza 'index' con tu ruta de éxito
        except Exception as e:
            db.session.rollback()
            flash(f'Error al guardar el video: {e}', 'danger')
            return redirect(request.referrer)

    return render_template('create_vids.html', titulo="Agregar Video")  # Reemplaza 'create_vids.html'

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

    

@app.route('/videos', methods=['GET', 'POST'])
@app.route('/videos/page/<int:page>', methods=['GET', 'POST'])
def videos(page=1):
    if request.method == 'POST':
        title = request.form['title']
        detail = request.form['detail']
        video_url = request.form['video_url']

        new_video = Video(title=title, detail=detail, video_url=video_url)
        db.session.add(new_video)
        db.session.commit()
        flash('Video guardado correctamente', 'success')
        return redirect(url_for('videos'))

    per_page = 6
    query = request.args.get('q', '')

    if query:
        videos_list = Video.query.filter(or_(
            Video.title.ilike(f"%{query}%"),
            Video.detail.ilike(f"%{query}%")
        )).paginate(page=page, per_page=per_page, error_out=False)
    else:
        videos_list = Video.query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template('videos.html', videos=videos_list)

@app.route('/videos/edit/<int:video_id>', methods=['GET', 'POST'])
def edit_video(video_id):
    video = Video.query.get_or_404(video_id)
    if request.method == 'POST':
        video.title = request.form['title']
        video.detail = request.form['detail'] # Corrección: usa 'detail' en lugar de 'content'
        video.video_url = request.form['video_url']
        image = request.files.get('image')

        if image:
            filename = secrets.token_hex(16) + os.path.splitext(image.filename)[1]
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            video.image_url = filepath
        db.session.commit()
        flash('Video actualizado correctamente', 'success')
        return redirect(url_for('videos'))
    return render_template('edit_video.html', video=video)



@app.route('/videos/delete_confirm/<int:video_id>')
def delete_video_confirm(video_id):
    video = Video.query.get_or_404(video_id)
    db.session.delete(video)
    db.session.commit()
    flash('Video eliminado correctamente', 'success')
    return redirect(url_for('videos'))


 # from flask import send_from_directory 
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
@app.route('/users', methods=['GET'])
def users():
    titulo = "Lista de Usuarios"
    search_term = request.args.get('search', '').lower()  # Convertir a minúsculas

    if search_term:
        # Búsqueda por nombre, apellido, teléfono, email o cualquier coincidencia parcial
        users = User.query.filter(
            db.or_(
                User.name.ilike('%' + search_term + '%'),
                User.first_last_name.ilike('%' + search_term + '%'),
                User.second_last_name.ilike('%' + search_term + '%'),
                User.phone_number.ilike('%' + search_term + '%'),
                User.email.ilike('%' + search_term + '%')
            )
        ).all()

        user_count = len(users)
        users_by_letter = {}
        for user in users:
            first_letter = user.name[0].upper()
            if first_letter not in users_by_letter:
                users_by_letter[first_letter] = []
            users_by_letter[first_letter].append(user)
    else:
        # Si no hay término de búsqueda, muestra todos los usuarios
        users = User.query.all()
        user_count = len(users)
        users_by_letter = {}
        for user in users:
            first_letter = user.name[0].upper()
            if first_letter not in users_by_letter:
                users_by_letter[first_letter] = []
            users_by_letter[first_letter].append(user)

    return render_template('users.html', titulo=titulo, users_by_letter=users_by_letter, user_count=user_count, search_term=search_term)



# REGISTRO DE USUARIO
@app.route('/registro', methods=['GET', 'POST']) # Define la ruta para el registro de usuarios (Depende de render_template, request, flash, User, generate_password_hash, login_user y url_for)
def registro(): # Define la función para el registro de usuarios
    if request.method == 'POST': # Verifica si la solicitud es POST
        nombre = request.form['nombre'].title().replace(" ", "") # Obtiene el nombre del formulario
        apellido1 = request.form['apellido1'].title().replace(" ", "") # Obtiene el primer apellido del formulario
        apellido2 = request.form['apellido2'].title().replace(" ", "") # Obtiene el segundo apellido del formulario
        email = request.form['email'].lower().replace(" ", "") # Obtiene el correo electrónico del formulario
        telefono = request.form['telefono'] # Obtiene el teléfono del formulario
        password = request.form['password'] # Obtiene la contraseña del formulario
        confirmar_password = request.form['confirmar_password'] # Obtiene la confirmación de la contraseña del formulario

        if password != confirmar_password: # Verifica si las contraseñas coinciden
            flash("Las contraseñas no coinciden", "danger") # Muestra un mensaje flash de error
            return render_template('registro.html') # Renderiza la plantilla registro.html

        existing_user = User.query.filter_by(email=email).first() # Verifica si el correo electrónico ya existe
        if existing_user: # Si el correo electrónico ya existe
            flash("El correo electrónico ya está registrado", "danger") # Muestra un mensaje flash de error
            return render_template('registro.html') # Renderiza la plantilla registro.html

        hashed_password = generate_password_hash(password) # Genera el hash de la contraseña

        if 'avatar' in request.files: # Verifica si se cargó un avatar
            file = request.files['avatar'] # Obtiene el archivo del avatar
            if file and allowed_file(file.filename): # Verifica si el archivo es válido
                filename = secure_filename(file.filename) # Obtiene el nombre seguro del archivo
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename)) # Guarda el archivo
                avatar_path = 'uploads/' + filename # Define la ruta del avatar
            else: # Si el archivo no es válido
                avatar_path = None # Define la ruta del avatar como None
        else: # Si no se cargó un avatar
            avatar_path = None # Define la ruta del avatar como None

        new_user = User(name=nombre, first_last_name=apellido1, second_last_name=apellido2, email=email, phone_number=telefono, password_hash=hashed_password, avatar=avatar_path) # Crea un nuevo usuario
        new_user.registration_count = 0 # Inicializa el contador de registros
        new_user.registration_count += 1 # Incrementa el contador de registros
        db.session.add(new_user) # Agrega el usuario a la sesión de la base de datos
        db.session.commit() # Guarda los cambios en la base de datos

        login_user(new_user) # Inicia sesión con el nuevo usuario
        return redirect(url_for('login')) # Redirige a la página de inicio de sesión
    return render_template('registro.html') # Renderiza la plantilla registro.html

@app.route('/actualizar_usuario/<int:user_id>', methods=['GET', 'POST']) # Define la ruta para actualizar un usuario (Depende de render_template, request, flash, User, db, login_required y url_for)
@login_required # Requiere que el usuario esté autenticado
def actualizar_usuario(user_id): # Define la función para actualizar un usuario
    usuario = User.query.get_or_404(user_id) # Obtiene el usuario de la base de datos o muestra un error 404 si no existe

    if request.method == 'POST': # Verifica si la solicitud es POST
        usuario.name = request.form['nombre'] # Actualiza el nombre del usuario
        usuario.first_last_name = request.form['apellido1'] # Actualiza el primer apellido del usuario
        usuario.second_last_name = request.form['apellido2'] # Actualiza el segundo apellido del usuario
        usuario.phone_number = request.form['telefono'] # Actualiza el número de teléfono del usuario
        usuario.email = request.form['email'] # Actualiza el correo electrónico del usuario

        if request.form.get('eliminar_usuario'): # Verifica si se solicitó eliminar el usuario
            db.session.delete(usuario) # Elimina el usuario de la base de datos
            db.session.commit() # Guarda los cambios en la base de datos
            flash("Usuario eliminado correctamente.", "success") # Muestra un mensaje flash de éxito
            return redirect(url_for('users')) # Redirige a la página de usuarios

        db.session.commit() # Guarda los cambios en la base de datos
        flash("Usuario actualizado correctamente.", "success") # Muestra un mensaje flash de éxito
        return redirect(url_for('perfil')) # Redirige a la página de perfil

    return render_template('actualizar_usuario.html', usuario=usuario) # Renderiza la plantilla actualizar_usuario.html

@app.route('/login', methods=['GET', 'POST']) # Define la ruta para el inicio de sesión (Depende de render_template, request, User, check_password_hash, login_user y url_for)
def login(): # Define la función para el inicio de sesión
    if request.method == 'POST': # Verifica si la solicitud es POST
        email = request.form['email'] # Obtiene el correo electrónico del formulario
        password = request.form['password'] # Obtiene la contraseña del formulario
        usuario = User.query.filter_by(email=email).first() # Obtiene el usuario de la base de datos

        if usuario and usuario.check_password(password): # Verifica si el usuario existe y la contraseña es correcta
            login_user(usuario) # Inicia sesión con el usuario
            return redirect(url_for('index')) # Redirige a la página de perfil
        else: # Si el usuario no existe o la contraseña es incorrecta
            return "Email o contraseña incorrectos" # Muestra un mensaje de error
    return render_template('login.html') # Renderiza la plantilla login.html

@app.route('/perfil') # Define la ruta para el perfil del usuario (Depende de render_template, current_user y login_required)
@login_required # Requiere que el usuario esté autenticado
def perfil(): # Define la función para el perfil del usuario
    return render_template('perfil.html', usuario=current_user) # Renderiza la plantilla perfil.html

@app.route('/actualizar_avatar', methods=['GET', 'POST'])
@login_required
def actualizar_avatar():
    usuario = current_user
    if request.method == 'POST':
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                avatar_path = 'uploads/' + filename
                usuario.avatar = avatar_path
                db.session.commit()
                return redirect(url_for('perfil'))
            else:
                return "Archivo no permitido"
        else:
            return "No se seleccionó ningún archivo"

    # Obtener la ruta del avatar actual
    current_avatar = usuario.avatar if usuario.avatar else None

    return render_template('actualizar_avatar.html', current_avatar=current_avatar)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sesión finalizada", "notification is-warning")
    return redirect(url_for("index"))  # Cambiado de "home" a "index"


# MODO NOCTURNO
@app.route('/toggle_dark_mode')
def toggle_dark_mode():
    session['dark_mode'] = not session.get('dark_mode', False)
    return redirect(request.referrer)  # Redirige a la página anterior

@app.context_processor
def inject_dark_mode():
    return dict(dark_mode=session.get('dark_mode', False))
# FINAL MODO NOCURNO

@app.errorhandler(404) # Define un manejador de errores para errores 404 (Depende de render_template)
def page_not_found(e): # Define la función para manejar errores 404
    return render_template('404.html'), 404 # Renderiza la plantilla 404.html

@app.errorhandler(500) # Define un manejador de errores para errores 500 (Depende de render_template)
def server_not_found(e): # Define la función para manejar errores 500
    return render_template('500.html'), 500 # Renderiza la plantilla 500.html




# AGENDA

@app.route('/agenda', methods=['GET', 'POST'])
@login_required
def agenda():
    if request.method == 'POST':
        if 'nombre' in request.form:
            nombre = request.form['nombre']
            apellido1 = request.form['apellido1']
            apellido2 = request.form['apellido2']
            email = request.form['email']
            telefono = request.form['telefono']
            celular = request.form['celular']
            empresa = request.form['empresa']
            categoria = request.form['categoria']

            nuevo_contacto = Contacto(nombre=nombre, apellido1=apellido1, apellido2=apellido2, email=email, telefono=telefono, celular=celular, empresa=empresa, categoria=categoria)
            db.session.add(nuevo_contacto)
            db.session.commit()
            return redirect(url_for('agenda'))

    contactos = Contacto.query.all()
    return render_template('agenda.html', contactos=contactos)

@app.route('/agenda/editar/<int:contacto_id>', methods=['GET', 'POST'])
@login_required
def editar_contacto(contacto_id):
    contacto = Contacto.query.get_or_404(contacto_id)
    if request.method == 'POST':
        contacto.nombre = request.form['nombre']
        contacto.apellido1 = request.form['apellido1']
        contacto.apellido2 = request.form['apellido2']
        contacto.email = request.form['email']
        contacto.telefono = request.form['telefono']
        contacto.celular = request.form['celular']
        contacto.empresa = request.form['empresa']
        contacto.categoria = request.form['categoria']
        db.session.commit()
        return redirect(url_for('agenda'))
    return render_template('editar_contacto.html', contacto=contacto)

@app.route('/agenda/borrar/<int:contacto_id>', methods=['POST'])
@login_required
def borrar_contacto(contacto_id):
    contacto = Contacto.query.get_or_404(contacto_id)
    db.session.delete(contacto)
    db.session.commit()
    return redirect(url_for('agenda'))

@app.route('/agenda/vcard/<int:contacto_id>')
@login_required
def contacto_vcard(contacto_id):
    contacto = Contacto.query.get_or_404(contacto_id)

    # Generar el contenido del archivo vCard
    vcard = f"""BEGIN:VCARD
VERSION:3.0
FN:{contacto.nombre} {contacto.apellido1} {contacto.apellido2}
N:{contacto.apellido1};{contacto.nombre};;;
TEL;TYPE=WORK,VOICE:{contacto.telefono}
TEL;TYPE=CELL,VOICE:{contacto.celular}
EMAIL:{contacto.email}
ORG:{contacto.empresa}
CATEGORIES:{contacto.categoria}
END:VCARD
"""

    # Crear un objeto BytesIO con el contenido del archivo vCard
    output = BytesIO(vcard.encode('utf-8'))

    # Devolver el archivo vCard como una descarga
    return send_file(output, download_name=f'{contacto.nombre}_{contacto_id}.vcf', mimetype='text/vcard', as_attachment=True)



login_manager = LoginManager() # Crea una instancia de LoginManager para manejar la autenticación (Depende de app)
login_manager.init_app(app) # Inicializa LoginManager con la aplicación (Depende de app)
login_manager.login_view = "login" # Define la vista de inicio de sesión (Depende de flask_login)
login_manager.login_message = u"Primero necesitas iniciar sesión" # Define el mensaje para cuando se requiere inicio de sesión (Depende de flask_login)
@login_manager.user_loader # Define una función para cargar el usuario desde la base de datos (Depende de User y db)
def load_user(user_id): # Define la función para cargar el usuario
    return User.query.get(int(user_id)) # Obtiene el usuario de la base de datos











# -------------------------------------------------------------------
# -------------------------------------------------------------------
# -------------------------------------------------------------------
# ALERTA DE ERRORES
# Error URL Invalida
@app.errorhandler(404)
# Error página no encontrada
def page_not_found(e):
   
    return render_template('404.html'), 404

# Error Servidor Interno
@app.errorhandler(500)
# Servidor no encontrada
def server_not_found(e):
   
    return render_template('500.html'), 500
# -----------------------




if __name__ == '__main__': # Verifica si el script se ejecuta directamente
    app.run(debug=True, port=3000) # Ejecuta la aplicación Flask


   # Migraciones Cmder
        # set FLASK_APP=main.py     <--Crea un directorio de migraciones
        # flask db init             <--
        # $ flask db stamp head
        # $ flask db migrate
        # $ flask db migrate -m "mensaje x"
        # $ flask db upgrade

        # ERROR [flask_migrate] Error: Target database is not up to date.
        # $ flask db stamp head
        # $ flask db migrate
        # $ flask db upgrade
# -----------------------