from flask import session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.sql import expression

db = SQLAlchemy()
bcrypt = Bcrypt()


def connect_db(app):
    """Connect to DB using flask app!"""

    db.app = app
    db.init_app(app)


class User(db.Model):
    """User class for flask_feedback"""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    is_admin = db.Column(db.Boolean, server_default=expression.false())

    def validate(self, input_password: str) -> bool:
        """Accepts input_password and returns boolean indicating match to password hash"""
        return bcrypt.check_password_hash(self.password, input_password)

    @classmethod
    def register(cls, username, password, email, first_name, last_name):
        """Hashes password and returns an instance of the User
        DB commit must happen outside of the function call"""
        hashed = bcrypt.generate_password_hash(password)
        return cls(
            username=username,
            password=hashed.decode("UTF-8"),
            email=email,
            first_name=first_name,
            last_name=last_name)


class Feedback(db.Model):
    """Feedback class for feedback"""

    __tablename__ = 'feedbacks'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    username = db.Column(
        db.String(20),
        db.ForeignKey('users.username', ondelete='CASCADE'),
        nullable=False)

    user = db.relationship('User', backref='feedbacks')