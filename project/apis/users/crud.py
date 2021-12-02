from sqlalchemy.orm import session
from project import db
from project.apis.users.models import User, Account

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

def add_user(username, account_name, password):
    user = User(username=username, password=password)
    account = Account(account_name=account_name, username=username)
    db.session.add(user)
    db.session.add(account)
    db.session.commit()
    return user

def add_account(account_name, username):
    account = Account(account_name=account_name,username=username)
    db.session.add(account)
    db,session.commit()

def update_account(account, account_name, username):
    account.account_name = account_name
    account.username = username
    db.session.commit()
    return account

def delete_account(account):
    db.session.delete(account)
    db.session.commit()
    return account