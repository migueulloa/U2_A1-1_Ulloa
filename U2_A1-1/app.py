from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm
from flask_wtf.csrf import CSRFError

app = Flask(__name__)

app.config['SECRET_KEY'] = 'clave_super_secreta'  
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False

# --- Login Manager ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message = "Por favor inicia sesión para acceder a esta página."
login_manager.login_message_category = "warning"


USERS = {}
NEXT_ID = 1


class User(UserMixin):
    def __init__(self, id_, username, password_hash):
        self.id = str(id_)              
        self.username = username
        self.password_hash = password_hash


def find_user_by_username(username):
    for u in USERS.values():
        if u['username'] == username:
            return u
    return None

@login_manager.user_loader
def load_user(user_id):
    user_data = USERS.get(int(user_id))
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password_hash'])
    return None

# --- Rutas ---
@app.route('/')
def index():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    global NEXT_ID
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if find_user_by_username(username):
            flash('El nombre de usuario ya existe.', 'danger')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        user_id = NEXT_ID
        USERS[user_id] = {
            'id': user_id,
            'username': username,
            'password_hash': password_hash
        }
        NEXT_ID += 1

        flash('Registro exitoso. Ahora inicia sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user_data = find_user_by_username(username)
        if not user_data:
            flash('Credenciales inválidas.', 'danger')
            return redirect(url_for('login'))

        if check_password_hash(user_data['password_hash'], password):
            user_obj = User(user_data['id'], user_data['username'], user_data['password_hash'])

            login_user(user_obj)
            flash('Inicio de sesión correcto.', 'success')

            next_page = request.args.get('next')
            return redirect(next_page or url_for('profile'))
        else:
            flash('Credenciales inválidas.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username)

@app.errorhandler(401)
def unauthorized_error(error):
    return render_template('401.html'), 401

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Error de CSRF: formulario inválido o token faltante.", "danger")
    return render_template('csrf_error.html', reason=e.description), 400

if __name__ == '__main__':
    app.run(debug=True)