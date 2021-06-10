from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message as MailMessage
import os
from forms import *
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
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature


# Initializing packages
app = Flask(__name__)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins='*')


# Mandatory configurations
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL')
app.config['MAIL_PASSWORD'] = os.environ.get('PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


# Reset password 
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


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
    profile_picture = db.Column(db.String(20), default="default.jpeg")
    messages = db.relationship(
        "Message", backref='sender', foreign_keys="Message.user_id", lazy='dynamic')
    teams = db.relationship('Team', secondary=users,
                            backref='members', lazy='dynamic')
    role = db.relationship('Team', backref='leader', lazy='dynamic')

# Team schema
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    team_key = db.Column(db.String(40), nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
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


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', title='404'), 404


@app.errorhandler(403)
def page_not_found(e):
    return render_template('403.html'), 403


@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500


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
        if not user:
            flash("This account does not exist.")
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


@app.route('/my-teams', methods=['GET', 'POST'])
@login_required
def my_teams():
    teams = Team.query.join(users).filter(users.c.user_id==current_user.id).all()
    return render_template('my_teams.html', title='Teams', teams=teams, length_of_teams=len(teams))


@app.route('/create-team', methods=['GET','POST'])
@login_required
def create_team():
    form = CreateTeamForm()
    if form.validate_on_submit():
        new_team = Team(name=form.name.data, team_key=secrets.token_hex(10), leader=current_user)
        db.session.add(new_team)
        new_team.members.append(current_user)
        db.session.commit()
        return redirect(url_for('my_teams'))
    return render_template('create_team.html', title="Create Team", form=form)


@app.route('/edit-team/<team_key>', methods=['GET','POST'])
@login_required
def edit_team(team_key):
    team = Team.query.filter_by(team_key=team_key).first_or_404()
    form = EditTeamForm()
    if form.validate_on_submit():
        team.name = form.name.data
        db.session.commit()
        flash("Your team has been updated!")
        return redirect(url_for('my_teams'))
    elif request.method == 'GET':
        form.name.data = team.name
    if team.leader != current_user:
        return render_template('403.html')
    return render_template('edit_team.html', title="Edit Team", form=form, team=team)


@app.route("/join-team/<team_key>", methods=['GET','POST'])
@login_required
def join_team(team_key):
    team = Team.query.filter_by(team_key=team_key).first_or_404()
    members = User.query.join(users).filter(users.c.team_id==team.id).all()
    if current_user in members:
        flash("You are already in this team.")
        return redirect(url_for('my_teams'))
    else:
        team.members.append(current_user)
        db.session.commit()
        flash("You have successfully joined this team!")
        return redirect(url_for('my_teams'))


@app.route('/leave-team/<team_key>', methods=['GET','POST'])
@login_required
def leave_team(team_key):
    team = Team.query.filter_by(team_key=team_key).first_or_404()
    members_in_team = User.query.join(users).filter(users.c.team_id==team.id).all()
    if team.leader == current_user:
        flash("You are team leader. You cannot leave this team.")
        return redirect(url_for('my_teams'))
    elif current_user not in members_in_team:
        return redirect(url_for('dashboard'))
    else:
        if current_user in members_in_team:
            team.members.clear(current_user)
            db.session.commit()
            flash("You have left the team.")
            return redirect(url_for('my_teams'))


@app.route('/team/<team_key>', methods=['GET','POST'])
@login_required
def team(team_key):
    team = Team.query.filter_by(team_key=team_key).first_or_404()
    messages = Message.query.filter_by(team=team).all()
    members = User.query.join(users).filter(users.c.team_id==team.id).all()
    return render_template('team.html', title=team.name, name=team.name, members=members)


@socketio.on('connectUser')
def connect_user():
    print("Connected.")


# Save profile pictures into profile_pics folder.
def save_picture(profile_pic):
    rand_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(profile_pic.filename)
    picture_name = rand_hex + f_ext
    path = os.path.join(app.root_path, 'static/profile_pics', picture_name)
    profile_pic.save(path)

    output_size = (125,125)
    i = Image.open(profile_pic)
    i.thumbnail(output_size)
    i.save(path)
    return picture_name


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.profile_picture.data:
            pic_file = save_picture(form.profile_picture.data)
            current_user.profile_picture = pic_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title="Account Settings", form=form)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = PasswordResetRequestForm()
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if form.validate_on_submit():
        # Check if user exists in order to send email
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(form.email.data, salt='forgot-password')
            msg = MailMessage('Password Reset Request',sender='noreply@demo.com', recipients=[form.email.data])
            msg.body = f''' 
            Hello {user.username}, we noticed that you wanted to reset your password. 
            To reset your password, use the link at the bottom of this email (this link will expire in 2 minutes). If this request was accidental, you may ignore this email.
            {url_for('reset_password', token=token, _external=True)}
            '''
            mail.send(msg)
            flash("A reset link has been sent to the email address.")
        if not user:
            flash("That account does not exist.")
    return render_template('forgot_password.html', title='Forgot Password', form=form)


@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    try:
        email = s.loads(token, salt='forgot-password', max_age=120)
    except SignatureExpired:
        return "<h1>This link has expired. Please try again.</h1>"
    except BadTimeSignature:
        return "<h1>This link is invalid.</h1>"   
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            user.password = hashed_password
            db.session.commit()
            flash("Your password has successfully been reset! You are able to log in now.")
        if not user:
            flash("This account does not exist.")
    return render_template('reset_password.html', form=form, title='Reset Password')


if __name__ == '__main__':
    socketio.run(app, debug=True)