from flask import Flask, render_template, redirect, request, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://vault:jeya%405264@localhost:5432/vault'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "home"
login_manager.init_app(app)

key_file = "secret.key"
if os.path.exists(key_file):
    with open(key_file, "rb") as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)

fernet = Fernet(key)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    name = db.Column(db.String)

class UserData(db.Model):
    __tablename__ = 'user_data'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    field_name = db.Column(db.String)
    field_value = db.Column(db.LargeBinary)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        name = request.form['name']
        if User.query.filter_by(username=uname).first():
            return "Username already exists"
        hashed_pwd = generate_password_hash(pwd)  # fixed hashing
        user = User(username=uname, password=hashed_pwd, name=name)
        db.session.add(user)
        db.session.commit()
        return redirect('/')
    return render_template('signup.html')

@app.route('/login', methods=['POST'])
def login():
    uname = request.form['username']
    pwd = request.form['password']
    user = User.query.filter_by(username=uname).first()
    if user and check_password_hash(user.password, pwd):
        login_user(user)
        return redirect('/dashboard')
    flash('Invalid username or password')
    return redirect('/')

@app.route('/dashboard')
@login_required
def dashboard():
    entries = UserData.query.filter_by(user_id=current_user.id).all()
    data = [(e.id, e.field_name, fernet.decrypt(e.field_value).decode()) for e in entries]
    return render_template('dashboard.html', name=current_user.name, data=data)

@app.route('/add', methods=['POST'])
@login_required
def add():
    field = request.form['field']
    value = fernet.encrypt(request.form['value'].encode())
    db.session.add(UserData(user_id=current_user.id, field_name=field, field_value=value))
    db.session.commit()
    return redirect('/dashboard')

@app.route('/edit/<int:data_id>', methods=['GET', 'POST'])
@login_required
def edit(data_id):
    entry = UserData.query.filter_by(id=data_id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        entry.field_name = request.form['field']
        entry.field_value = fernet.encrypt(request.form['value'].encode())
        db.session.commit()
        return redirect('/dashboard')
    decrypted_value = fernet.decrypt(entry.field_value).decode()
    return render_template('edit.html', entry=entry, value=decrypted_value)

@app.route('/delete/<int:data_id>', methods=['POST'])
@login_required
def delete(data_id):
    entry = UserData.query.filter_by(id=data_id, user_id=current_user.id).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    return redirect('/dashboard')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
