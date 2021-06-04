from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
import os
from .forms import *
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
import secrets
import hashlib
from PIL import Image
from flask_socketio import SocketIO, emit, send, join_room
from flask_sslify import SSLify
import json


# Initializing packages
app = Flask(__name__)
mail = Mail(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins='*')


# Mandatory configurations
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get("EMAIL_BLOGGY")
app.config['MAIL_PASSWORD'] = os.environ.get("PASSWORD_BLOGGY")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


users = db.Table("users",
                 db.Column('user_id', db.Integer, db.ForeignKey("user.id")),
                 db.Column('team_id', db.Integer, db.ForeignKey("team.id"))
                 )


# User schema
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    messages = db.relationship(
        "Message", backref='sender', foreign_keys="Message.user_id", lazy='dynamic')
    teams = db.relationship('Team', secondary=users,
                            backref='member', lazy='dynamic')


# Team schema
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    messages = db.relationship(
        "Message", backref="team", foreign_keys="Message.team_id", lazy='dynamic')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    team_id = db.Column(db.Integer, db.ForeignKey("team.id"))


# User loader callback


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
@app.route("/home")
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template("home.html", title="Home")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template("login.html", title="Login", form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data,
                        username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html", title="Register", form=form)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', title="Dashboard")
