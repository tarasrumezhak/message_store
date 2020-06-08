from flask import Flask, request, jsonify, abort, url_for, g
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
import datetime
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from sqlalchemy import Column, Integer, DateTime
from flask_cors import CORS
# from models.user import User
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

from flask_login import LoginManager

login_manager = LoginManager()

login_manager.init_app(app)

app = Flask(__name__)
CORS(app)

app.config.from_pyfile('config.py')

db = SQLAlchemy(app)

ma = Marshmallow(app)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(DateTime, default=datetime.datetime.utcnow)
    account = db.Column(db.String(60), unique=True)
    service = db.Column(db.String)
    message = db.Column(db.String)

    def __init__(self, account, service, message):
        self.account = account
        self.service = service
        self.message = message

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'date': self.date,
            'account': self.account,
            'service': self.service,
            'message': self.message
        }


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(32))
    last_name = db.Column(db.String(32))
    username = db.Column(db.String(32), index=True)
    email = db.Column(db.String(50))
    password_hash = db.Column(db.String(128))
    # birthday = db.Column(DateTime)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        return user


# Product Schema
class ProductSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'description', 'price', 'qty')


# Init Schema
product_schema = ProductSchema()
products_schema = ProductSchema(many=True)


class OrderSchema(ma.Schema):
    class Meta:
        field = ('id', 'date', 'account', 'service', 'message')


order_schema = OrderSchema()
orders_schema = OrderSchema(many=True)


# Create product
@app.route('/product', methods=['POST'])
def add_product():
    name = request.json['name']
    description = request.json['description']
    price = request.json['price']
    qty = request.json['qty']

    new_product = Product(name, description, price, qty)
    db.session.add(new_product)
    db.session.commit()

    return product_schema.jsonify(new_product)


@app.route('/order', methods=['POST'])
@auth.login_required
def add_order():
    account = request.json['account']
    service = request.json['service']
    message = request.json['message']

    new_order = Order(account, service, message)
    db.session.add(new_order)
    db.session.commit()

    return jsonify(new_order.serialize)


@app.route('/order', methods=['GET'])
@auth.login_required
def get_orders():
    all_orders = Order.query.all()
    # orders = orders_schema.dump(all_orders)
    # return jsonify(orders)
    # print(all_orders)
    return jsonify([order.serialize for order in all_orders])




@app.route('/order/<id>', methods=['GET'])
def get_order(id):
    order = Order.query.get(id)
    # return order_schema.jsonify(order)
    return jsonify(order.serialize)



@app.route('/users', methods=['POST'])
def new_user():
    first_name = request.json.get('first_name')
    last_name = request.json.get('last_name')
    email = request.json.get('email')
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)  # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)  # existing user
    user = User(username=username, first_name=first_name, last_name=last_name, email=email)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'username': user.username}), 201, {'Location': url_for('get_user', id=user.id, _external=True)}


@app.route('/users/<int:id>')
@auth.login_required
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


# @app.route('/users/auth', methods=['POST'])
@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/')
@auth.login_required
def index():
    return "Hello, {}!".format(auth.current_user())


if __name__ == '__main__':
    app.run(debug=True)
