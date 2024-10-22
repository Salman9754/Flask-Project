from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '1318'

# SQLite Database Connection
DATABASE = 'database.db'

ADMIN_CREDENTIALS = {
    'email': 'admin@example.com',
    'password': 'admin123'  # You can set a hashed password for better security
}

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Routes

@app.route('/')
def home():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = get_db().cursor()
        cursor.execute("SELECT username, email FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        return render_template('landing.html', user=user)
    return redirect(url_for('login'))




@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        cursor = get_db().cursor()
        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            get_db().commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Email already exists."

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if logging in as admin
        if email == ADMIN_CREDENTIALS['email'] and password == ADMIN_CREDENTIALS['password']:
            session['admin'] = True
            return redirect(url_for('admin'))

        cursor = get_db().cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect(url_for('home'))
        return "Invalid email or password."

    return render_template('login.html')

@app.route('/admin')
def admin():
    if 'admin' in session:
        cursor = get_db().cursor()
        cursor.execute("SELECT id, username, email FROM users")
        users = cursor.fetchall()
        return render_template('admin.html', users=users)
    return redirect(url_for('login'))


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'admin' in session:
        cursor = get_db().cursor()
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']

            cursor.execute("UPDATE users SET username = ?, email = ? WHERE id = ?", 
                           (username, email, user_id))
            get_db().commit()
            return redirect(url_for('admin'))
        else:
            cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            return render_template('edit_user.html', user=user)
    return redirect(url_for('login'))

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'admin' in session:
        cursor = get_db().cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        get_db().commit()
        return redirect(url_for('admin'))
    return redirect(url_for('login'))



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
