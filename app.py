from flask import Flask, render_template, redirect, flash, session, abort
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Unauthorized

from models import db, connect_db, User, Feedback
from secrets import DB_URI, APP_SECRET
from forms import RegisterUser, LoginUser, FeedbackForm

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

connect_db(app)
db.create_all()

app.config['SECRET_KEY'] = APP_SECRET
DebugToolbarExtension(app)
app.config["DEBUG_TB_INTERCEPT_REDIRECTS"] = False


@app.errorhandler(401)
def unauthorized(e):
    """ Unauthorized page"""
    flash("Unauthorized to view the page. Try logging in!")
    return redirect("/register")


@app.errorhandler(404)
def not_found(e):
    """ Not found the thing page"""
    return render_template("404.html")


@app.route("/")
def handle_homepage():
    """Will throw Unauthorized with redirects to login if not logged in
    else redirects to user page"""
    if 'user_id' in session:
        user = User.query.get_or_404(session['user_id'])
        return redirect(f'/users/{user.username}')
    return redirect("/register")


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
        except IntegrityError as error:
            flash(error.args[0][error.args[0].find("DETAIL"):])
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

    authorize(username)
    page_user = User.query.filter_by(username=username).first()
    if not page_user:
        abort(404)
    return render_template('user_template.html', user=page_user)


@app.route("/logout")
def logout_user():
    """Logs out user"""

    session.clear()
    return redirect("/")


@app.route("/users/<username>/delete", methods=['POST'])
def delete_user(username):
    """Deletes user"""

    user = User.query.get_or_404(session['user_id'])
    if user.username == username:
        db.session.delete(user)
        db.session.commit()
        return redirect('/')
    else:
        raise Unauthorized()


@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    user = authorize(username)
    form = FeedbackForm()

    if form.validate_on_submit():
        feedback = Feedback(
            title=form.title.data,
            content=form.content.data,
            username=user.username)
        db.session.add(feedback)
        db.session.commit()
        return redirect(f'/users/{user.username}')
    else:
        return render_template("feedback_form.html", form=form)


@app.route('/feedback/<feedback_id>/update', methods=['GET', 'POST'])
def display_edit_feedback_and_handle_edit_feedback(feedback_id):

    feedback = Feedback.query.get_or_404(feedback_id)
    form = FeedbackForm(obj=feedback)
    user = authorize(feedback.user.username)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        feedback.username = user.username
        db.session.commit()
        flash("Feedback updated!")
        return redirect(f'/users/{user.username}')
    else:
        return render_template("feedback_form.html", form=form)


@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_existing_feedback(feedback_id: int):
    feedback = Feedback.query.get_or_404(feedback_id)
    authorize(feedback.username)
    db.session.delete(feedback)
    db.session.commit()
    flash("Deleted that feedback, bruh")
    return redirect(f"/users/{feedback.username}")


def authorize(username):
    if "user_id" not in session:
        raise Unauthorized()
    user = User.query.get_or_404(session['user_id'])
    if (user.username.casefold() != username.casefold()) and not user.is_admin:
        raise Unauthorized()
    return user
