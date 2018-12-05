from flask import Flask, render_template, redirect, flash
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError

from models import db, connect_db, User
from secrets import DB_URI, APP_SECRET
from forms import RegisterUser, LoginUser

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

connect_db(app)
db.create_all()

app.config['SECRET_KEY'] = APP_SECRET
DebugToolbarExtension(app)
app.config["DEBUG_TB_INTERCEPT_REDIRECTS"] = False


@app.route("/")
def handle_homepage():
    """Just redirects to register"""

    return redirect('/register')


@app.route("/register", methods=["POST", "GET"])
def display_register_form_and_handle_register_form():
    """Displays the register form and handles submitted forms"""

    form = RegisterUser()

    if form.validate_on_submit():
        db.session.add(
            User.register(
                **{
                    key: value
                    for (key, value) in form.data.items()
                    if key != 'csrf_token'
                }))
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append("Username already exists")
            return render_template("register.html", form=form)
        return redirect('/secret')
    else:
        return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def display_login_form_and_handle_login_form():
    """Displays the login form and handles submitted forms"""

    form = LoginUser()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.validate(form.password.data):
            return redirect("/secret")
        else:
            form.username.errors.append("Invalid Username/Password")
            return render_template("login.html", form=form)

    else:
        return render_template("login.html", form=form)


@app.route("/secret")
def display_secret_page():
    """Displays secrets to the worthy"""

    return "You made it!"
