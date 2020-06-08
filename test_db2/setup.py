from app import app
from models.user import db

with app.app_context():
    db.create_all()