from datetime import datetime, timedelta
from random import randint

from flask import current_app

from project import bcrypt, db
from project.apis.users.models import Account, Activation, User


def get_all_users():
    return User.query.all()


def get_user_by_id(user_id):
    return User.query.filter_by(id=user_id).first()


def get_user_by_username(username):
    return User.query.filter_by(username=username).first()


def get_user_by_account(account_name):
    account = Account.query.filter_by(account_name=account_name).first()
    if account:
        return get_user_by_username(account.username)
    return None


def get_account(account_name):
    return Account.query.filter_by(account_name=account_name).first()


def get_activation(account_name, activation_code=""):
    if activation_code:
        return Activation.query.filter_by(
            account_name=account_name, activation_code=activation_code
        ).first()
    return Activation.query.filter_by(account_name=account_name).first()


def add_user(username, password):
    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()
    return user


def add_account(account_name, username):
    account = Account(account_name=account_name, username=username)
    db.session.add(account)
    db.session.commit()
    return account


def add_activation(account_name):
    activation = Activation(account_name)
    db.session.add(activation)
    db.session.commit()
    return activation


def update_account(account, account_name, username):
    account.account_name = account_name
    account.username = username
    db.session.commit()
    return account


def delete_account(account):
    db.session.delete(account)
    db.session.commit()
    return account


def verify_user(user):
    user.active = True
    db.session.commit()
    return user


def verify_account(account):
    account.is_verified = True
    db.session.commit()
    return account


def verify_activation(activation):
    activation.status = True
    db.session.commit()
    return activation


def generate_new_activation_code(activation):
    activation.activation_code = "".join(
        ["{}".format(randint(0, 9)) for i in range(0, 9)]
    )
    activation.expiration_time = datetime.utcnow() + timedelta(
        seconds=current_app.config.get("ACTIVATION_CODE_EXPIRATION")
    )
    db.session.commit()
    return activation


def update_password(user, new_password):
    user.password = bcrypt.generate_password_hash(
        new_password, current_app.config.get("BCRYPT_LOG_ROUNDS")
    ).decode("utf-8")
    db.session.commit()
    return user
