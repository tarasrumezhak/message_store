from datetime import datetime

from app import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column( db.Integer, primary_key=True)

    first_name = db.Column(db.String(32))
    last_name = db.Column(db.String(32))
    username = db.Column(db.String(32), unique=True, index=True)
    email = db.Column(db.String(50), unique=True, index=True)
    password = db.Column('password', db.String(10))
    registered_on = db.Column('registered_on', db.DateTime)

    def __init__(self, first_name, last_name, username, password, email):
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.password = password
        self.email = email
        self.registered_on = datetime.utcnow()