from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_wtf.csrf import CSRFProtect
import sqlite3
import secrets
import re
from flask_bcrypt import bcrypt
import logging

# Password policy requirements
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGITS = True
REQUIRE_SPECIAL_CHARS = True
SPECIAL_CHARS_REGEX = r'[!@#$%^&*()-=_+`~[\]{}|;:,.<>?]'

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.secret_key = 'your_secret_key_here'
app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(16)  # Set your CSRF secret key here
app.config['SESSION_TYPE'] = 'filesystem'
csrf = CSRFProtect(app)
app.config['DATABASE'] = 'database.db'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                item_name TEXT NOT NULL,
                item_quantity INTEGER NOT NULL,
                total_amount REAL NOT NULL,
                UNIQUE(name, email, item_name)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')

        db.commit()


@app.route('/')
def login_form():
    return render_template('login.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_user = request.form['username']
        admin_pass = request.form['password']
        
        admin_credentials = {'Admin': 'Password##'}
        
        if admin_user in admin_credentials and admin_pass == admin_credentials[admin_user]:
            return redirect(url_for('admin_page'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login_form'))
    else:
        return render_template('admin_login.html')


@app.route('/login', methods=['POST'])
def login():
    uname = request.form['username']
    pwd = request.form['password']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (uname,))
    user = cursor.fetchone()
    conn.close()
    if user and bcrypt.checkpw(pwd.encode('utf-8'), user['password']):
        return redirect(url_for('main_page'))
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('login_form'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email address.', 'error')
            return redirect(url_for('register'))
        
        if not (username and email and password and confirm_password):
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('register'))
          
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login_form'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
            return redirect(url_for('register'))
        finally:
            conn.close()
    
    return render_template('register.html')

def validate_password(password):
    # Check minimum length
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f'Password must be at least {MIN_PASSWORD_LENGTH} characters long.'

    # Check uppercase requirement
    if REQUIRE_UPPERCASE and not any(char.isupper() for char in password):
        return False, 'Password must contain at least one uppercase letter.'

    # Check lowercase requirement
    if REQUIRE_LOWERCASE and not any(char.islower() for char in password):
        return False, 'Password must contain at least one lowercase letter.'

    # Check digits requirement
    if REQUIRE_DIGITS and not any(char.isdigit() for char in password):
        return False, 'Password must contain at least one digit.'

    # Check special characters requirement
    if REQUIRE_SPECIAL_CHARS and not re.search(SPECIAL_CHARS_REGEX, password):
        return False, 'Password must contain at least one special character.'

    # Password meets all requirements
    return True, 'Password is valid.'


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        uname = request.form.get('name')
        password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')

        if not uname or not password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('forgot_password'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('forgot_password'))
        
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('forgot_password'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        logging.info(f"Username: {uname}, Hashed Password: {hashed_password}")
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (uname,))
        user_name = cursor.fetchone()
        if user_name is None:
          conn.close()
          flash('User not found.', 'error')
          logging.info(f"User not found: {uname}")
          return render_template('forgot_password.html')
        else:
          cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, uname))
          conn.commit()
          flash('Password reset successfully!', 'success')
          logging.info(f"Password updated for user: {uname}")
          conn.close()
          return redirect(url_for('login_go'))
    return render_template('forgot_password.html')  

     
@app.route('/login_go')
def login_go():
    return render_template('login.html')


@app.route('/main')
def main():
    return render_template('main.html')


@app.route('/main_page')
def main_page():
    return render_template('main.html')


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'cart' not in session:
        session['cart'] = []

    item_name = request.form.get('item_name')
    price = float(request.form.get('price'))

    item = {'name': item_name, 'price': price}
    session['cart'].append(item)

    flash('Item added to cart successfully!', 'success')
    return render_template('cart.html')


@app.route('/get_cart', methods=['GET'])
def get_cart():
    cart = session.get('cart', [])
    return jsonify({'cart': cart})


@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    if 'cart' not in session:
        session['cart'] = []

    item_name = request.form.get('item_name')
    session['cart'] = [item for item in session['cart'] if item['name'] != item_name]

    return render_template('cart.html')


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(port=9025)
