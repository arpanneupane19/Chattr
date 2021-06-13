
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from main import *


class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email Address"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "Password (4 minimum)"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                "That email address belongs to different user. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "Password (4 minimum)"})
    submit = SubmitField("Login")


class PasswordResetRequestForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email Address"})
    submit = SubmitField("Request Password Reset")


class ResetPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email Address"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "Password (4 minimum)"})
    submit = SubmitField("Reset Password")

class UpdateAccountForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email Address"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    submit = SubmitField("Update Account")
    profile_picture = FileField(validators=[FileAllowed(['jpg', 'png', 'jpeg'])], render_kw={"placeholder":"Select Profile Picture"})

    def validate_username(self, username):
        if current_user.username != username.data:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(
                    "That username already exists. Please choose a different one.")

    def validate_email(self, email):
        if current_user.email != email.data:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError(
                    "That email address belongs to different user. Please choose a different one.")


class CreateTeamForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder":"Team Name"})
    submit = SubmitField("Create Team")


class EditTeamForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder":"Team Name"})
    leader = SelectField('Leader')
    submit = SubmitField("Save Changes")


class AdvancedTeamSettingsForm(FlaskForm):
    kick = SelectField("Kick Members?")
    submit = SubmitField("Save Changes")

class SearchTeamForm(FlaskForm):
    search = StringField(validators=[InputRequired(),Length(min=4, max=20)], render_kw={"placeholder":"Enter Team ID to join a team."})
    submit = SubmitField("Join")
