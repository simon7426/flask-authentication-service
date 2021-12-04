from datetime import datetime, timedelta

import jwt
from flask import current_app
from random import randint

from project import db,bcrypt

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer,primary_key=True, autoincrement=True)
    username = db.Column(db.String(128), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), default=False, nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow(), nullable=False)
    activate_date = db.Column(db.DateTime)

    def __init__(self, username="", password=""):
        self.username = username
        self.password = bcrypt.generate_password_hash(
            password,
            current_app.config.get("BCRYPT_LOG_ROUNDS")
        ).decode()
    
    def encode_token(self, username, token_type):
        if token_type == 'access':
            seconds = current_app.config.get("ACCESS_TOKEN_EXPIRATION")
        else:
            seconds = current_app.config.get("REFRESH_TOKEN_EXPIRATION")

        payload = {
            "exp": datetime.utcnow() + timedelta(seconds=seconds),
            "iat": datetime.utcnow(),
            "type": token_type,
            "sub": username
        }
        return jwt.encode(
            payload,
            current_app.config.get("SECRET_KEY"),
            algorithm="HS256",
        )
    @staticmethod
    def decode_token(token):
        payload = jwt.decode(
            token, 
            current_app.config.get("SECRET_KEY"), 
            algorithms="HS256",
        )
        return payload["sub"], payload["type"]

class Account(db.Model):
    __tablename__ = "account"

    id = db.Column(db.Integer,primary_key=True, autoincrement=True)
    account_name = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(128), nullable=False)
    is_verified = db.Column(db.Boolean(), default=False, nullable=False)
    added_on = db.Column(db.DateTime, default=datetime.utcnow(), nullable=False)

    def __init__(self, account_name="", username=""):
        self.account_name = account_name
        self.username = username


class Activation(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    account_name = db.Column(db.String(128), nullable=False)
    activation_code = db.Column(db.String(20), nullable=False)
    status = db.Column(db.Boolean(), default=False, nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow(), nullable=False)
    expiration_time = db.Column(db.DateTime, nullable=False)

    def __init__(self, account_name=""):
        self.account_name = account_name
        self.activation_code = ''.join(["{}".format(randint(0, 9)) for i in range(0, 9)])
        self.expiration_time = datetime.utcnow() + timedelta(seconds=current_app.config.get('ACTIVATION_CODE_EXPIRATION'))