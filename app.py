from flask import Flask, render_template, redirect, flash, session
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Unauthorized

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
        user = User.register(
            **{
                key: value
                for (key, value) in form.data.items() if key != 'csrf_token'
            })
        db.session.add(user)
        try:
            db.session.commit()
            session['user_id'] = user.id
            return redirect(f'/users/{form.username.data}')
        except IntegrityError:
            form.username.errors.append("Username already exists")
            return render_template("register.html", form=form)

    else:
        return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def display_login_form_and_handle_login_form():
    """Displays the login form and handles submitted forms"""

    form = LoginUser()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.validate(form.password.data):
            session['user_id'] = user.id
            return redirect(f'/users/{form.username.data}')
        else:
            form.username.errors.append("Invalid Username/Password")
            return render_template("login.html", form=form)

    else:
        return render_template("login.html", form=form)


@app.route("/users/<username>")
def display_secret_page(username):
    """Displays secrets to the worthy"""

    if "user_id" not in session:
        raise Unauthorized()
    user = User.query.get_or_404(session['user_id'])
    if user.username != username:
        raise Unauthorized()
    else:
        return render_template('user_template.html', user=user)


@app.route("/logout")
def logout_user():
    """Logs out user"""

    session.clear()
    return redirect("/")


@app.route("users/<username>/delete", methods=['POST'])
def delete_user(username):
    """Deletes user"""

    user = User.query.get_or_404(session['user_id'])
    if user.username == username:
        db.session.delete(user)
        db.session.commit()
        return redirect('/')
    else:
        raise Unauthorized()


@app.route('users/<username>feedback/add')
def add_feedback(username):
    user = User.query.get_or_404(session['user_id'])
