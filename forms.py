from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Email, Length
from wtforms import StringField, IntegerField, SelectField, BooleanField, PasswordField, TextAreaField


class RegisterUser(FlaskForm):
    """Registers new users for flask_feedback"""

    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])
    email = StringField("Email Address", validators=[InputRequired(), Email()])
    first_name = StringField("First Name", validators=[InputRequired()])
    last_name = StringField("Last Name", validators=[InputRequired()])


class LoginUser(FlaskForm):
    """Logs in an existing user for flask_feedback"""

    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])


class FeedbackForm(FlaskForm):
    """Adds user feedback"""

    title = StringField(
        "Title",
        validators=[
            InputRequired(),
            Length(min=0, max=100, message="Too long, tighten up your title")
        ])
    content = TextAreaField("Content", validators=[InputRequired()])
