from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


from __init__ import db
class User(db.Model):
    """Data model for user accounts."""

    __tablename__ = 'usuario'
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    email = db.Column(
        db.String(80),
        index=True,
        unique=True,
        nullable=False
    )
    
    isadmin = db.Column(
        db.Boolean,
        index=False,
        unique=False,
        nullable=False
    )
    password_hash = db.Column(
        db.String(128),
        index=False,
        unique=False,
        nullable=False)

    def get_reset_token(self, expires=500):
        return jwt.encode({'reset_password': self.email, 'exp': time() + expires},
                           key=os.getenv('SECRET_KEY_FLASK'))

    @staticmethod
    def verify_reset_token(token):
        try:
            username = jwt.decode(token, key=os.getenv('SECRET_KEY_FLASK'))['reset_password']
            print(username)
        except Exception as e:
            print(e)
            return
        return User.query.filter_by(username=username).first()

    @staticmethod
    def verify_email(email):

        user = User.query.filter_by(email=email).first()

        return user

    @property
    def password(self):
        """
        Prevent pasword from being accessed
        """
        raise AttributeError('password is not a readable attribute.')

    @password.setter
    def password(self, password):
        """
        Set password to a hashed password
        """
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        """
        Check if hashed password matches actual password
        """
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

