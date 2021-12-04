from project import redis_client
from flask import current_app

def add_token_to_blacklist(token):
    return redis_client.set(token,"1",ex=current_app.config.get("REFRESH_TOKEN_EXPIRATION"))

def check_token_in_blacklist(token):
    if redis_client.get(token):
        return True
    else:
        return False