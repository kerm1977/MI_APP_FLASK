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
from bs4 import BeautifulSoup
import secrets #videos
import math
import secrets
from authlib.integrations.flask_client import OAuth





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




# AREA DE RECUPERACIÓN DE CONTRASEÑA
app.secret_key = secrets.token_hex(16) # Genera una clave secreta segura
# Configuración de Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'tu_correo@gmail.com'
app.config['MAIL_PASSWORD'] = 'tu_contraseña_de_aplicación'
# AREA DE RECUPERACIÓN DE CONTRASEÑA


# Configuración de OAuth
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id='TU_CLIENT_ID_GOOGLE',
    client_secret='TU_CLIENT_SECRET_GOOGLE',
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'email profile'},
)

facebook = oauth.register(
    name='facebook',
    client_id='TU_APP_ID_FACEBOOK',
    client_secret='TU_APP_SECRET_FACEBOOK',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/v12.0/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/v12.0/',
    client_kwargs={'scope': 'email public_profile'},
)




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
    def set_password(self, password): # Define un método para establecer la contraseña del usuario (Depende de generate_password_hash)
        self.password_hash = generate_password_hash(password) # Genera el hash de la contraseña

    def check_password(self, password): # Define un método para verificar la contraseña del usuario (Depende de check_password_hash)
        return check_password_hash(self.password_hash, password) # Verifica el hash de la contraseña

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(100))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)





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

def obtener_tipo_cambio_bcr():
    try:
        url = "https://gee.bccr.fi.cr/indicadoreseconomicos/Cuadros/frmVerCatCuadro.aspx?CodCuadro=401"
        response = requests.get(url)
        response.raise_for_status()  # Lanza una excepción para errores HTTP

        soup = BeautifulSoup(response.content, "html.parser")
        tabla = soup.find("table", {"id": "tblCuadro"})
        filas = tabla.find_all("tr")

        tipo_compra = None
        tipo_venta = None

        for fila in filas:
            celdas = fila.find_all("td")
            if len(celdas) >= 3:
                descripcion = celdas[0].text.strip()
                valor = celdas[2].text.strip()
                if "Compra" in descripcion:
                    tipo_compra = valor
                elif "Venta" in descripcion:
                    tipo_venta = valor
        return tipo_compra, tipo_venta

    except requests.exceptions.RequestException as e:
        print(f"Error al obtener los datos: {e}")
        return None, None
    except AttributeError:
        print("Error al parsear los datos.")
        return None, None


@app.route("/")
@app.route("/home")
@app.route("/index")
def index():
    tipo_compra, tipo_venta = obtener_tipo_cambio_bcr()
    print("Función index() ejecutada")
    title = "Este es el Index"
    page = request.args.get('page', 1, type=int)
    per_page = 5
    posts_pagination = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=per_page)
    return render_template('index.html', posts_pagination=posts_pagination, title=title, tipo_compra=tipo_compra, tipo_venta=tipo_venta)
    
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
# version


# GOOGLE Y FACEBOOK
@app.route('/google/login')
def google_login():
    redirect_uri = url_for('google_auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google/auth')
def google_auth():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    email = user_info['email']
    name = user_info['name']

    user = User.query.filter_by(email=email).first()
    if not user:
        # Crea un nuevo usuario
        user = User(name=name, email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(url_for('index'))

@app.route('/facebook/login')
def facebook_login():
    redirect_uri = url_for('facebook_auth', _external=True)
    return facebook.authorize_redirect(redirect_uri)

@app.route('/facebook/auth')
def facebook_auth():
    token = facebook.authorize_access_token()
    resp = facebook.get('me?fields=id,name,email')
    user_info = resp.json()
    email = user_info['email']
    name = user_info['name']

    user = User.query.filter_by(email=email).first()
    if not user:
        # Crea un nuevo usuario
        user = User(name=name, email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(url_for('index'))
# GOOGLE Y FACEBOOK



# RECUPERACION DE CONTRASEÑA
@app.route('/recuperar_contraseña', methods=['GET', 'POST'])
def recuperar_contraseña():
    if request.method == 'POST':
        email = request.form.get('email')
        # Lógica para generar un token de recuperación y enviar un correo
        token = secrets.token_urlsafe(16)
        # Aquí debes guardar el token y el email en la base de datos
        # Ejemplo: guardar_token_en_bd(email, token)
        # Luego enviar el correo
        msg = Message('Recuperación de Contraseña', sender='your_email@example.com', recipients=[email])
        msg.body = f'Para restablecer tu contraseña, haz clic en el siguiente enlace: {url_for("restablecer_contraseña", token=token, _external=True)}'
        mail.send(msg)
        flash('Se ha enviado un correo electrónico con instrucciones para restablecer tu contraseña.', 'success')
        return redirect(url_for('login'))
    return render_template('recuperar_contraseña.html')

@app.route('/restablecer_contraseña/<token>', methods=['GET', 'POST'])
def restablecer_contraseña(token):
    # Lógica para verificar el token y mostrar el formulario de restablecimiento
    # Ejemplo: email = obtener_email_de_token(token)
    # Si el token es válido, mostrar el formulario
    if request.method == 'POST':
        password = request.form.get('password')
        # Lógica para actualizar la contraseña en la base de datos
        # Ejemplo: actualizar_contraseña(email, password)
        flash('Tu contraseña ha sido restablecida con éxito.', 'success')
        return redirect(url_for('login'))
    return render_template('restablecer_contraseña.html', token=token)
# RECUPERACION DE CONTRASEÑA






# ver imagenes
@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post_detail.html', post=post)


@app.route('/new', methods=['GET', 'POST'])
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
                    post = Post(title=title, content=content, image=filename, date_posted=datetime.utcnow())
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
            post = Post(title=title, content=content, image=None, date_posted=datetime.utcnow())
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
        detail = request.form.get('detail')
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
        video.detail = request.form['detail']
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

@app.route('/videos/delete/<int:video_id>')
def delete_video(video_id):
    video = Video.query.get_or_404(video_id)
    db.session.delete(video)
    db.session.commit()
    flash('Video eliminado correctamente', 'success')
    return redirect(url_for('videos'))

@app.route('/videos/delete_confirm/<int:video_id>')
def delete_video_confirm(video_id):
    video = Video.query.get_or_404(video_id)
    db.session.delete(video)
    db.session.commit()
    flash('Video eliminado correctamente', 'success')
    return redirect(url_for('videos'))







@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    search_letter = request.args.get('letter')  # Obtiene la letra de búsqueda de la URL

    if search_letter:
        all_users = User.query.filter(User.name.startswith(search_letter)).order_by(User.name).all()
        user_count = len(all_users)
        users_by_letter = {search_letter: all_users}  # Crea un diccionario con solo la letra buscada
    else:
        all_users = User.query.order_by(User.name).all()
        user_count = len(all_users)
        users_by_letter = {}
        for user in all_users:
            first_letter = user.name[0].upper()
            if first_letter not in users_by_letter:
                users_by_letter[first_letter] = []
            users_by_letter[first_letter].append(user)

    return render_template('users.html', users_by_letter=users_by_letter, user_count=user_count, search_letter=search_letter)


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