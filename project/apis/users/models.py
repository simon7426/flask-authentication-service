from datetime import datetime, timedelta

import jwt
from flask import current_app
from flask.globals import session
from sqlalchemy.sql import func

from project import db,bcrypt

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer,primary_key=True, autoincrement=True)
    username = db.Column(db.String(128), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), default=True, nullable=False)
    created_date = db.Column(db.DateTime, default=func.now(), nullable=False)

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

    def __init__(self, account_name="", username=""):
        self.account_name = account_name
        self.username = username
