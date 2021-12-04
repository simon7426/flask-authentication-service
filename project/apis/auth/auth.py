import jwt 
from flask import request
from flask_restx import Namespace, Resource, fields

from project import bcrypt
from project.apis.auth.utils import add_token_to_blacklist, check_token_in_blacklist
from project.apis.users.crud import add_account, add_activation, add_user, get_user_by_account, get_user_by_username
from project.apis.users.models import User

auth_namespace = Namespace("auth")

user = auth_namespace.model(
    "User",
    {
        "username": fields.String(required=True),
    },
)

full_user = auth_namespace.clone(
    "Full User",user,{"account_name": fields.String(required=True),"password": fields.String(required=True)}
)

login = auth_namespace.model(
    "Login User",
    {
        "username": fields.String(required=True),
        "password": fields.String(required=True),
    },
)

refresh = auth_namespace.model(
    "Refresh", {"refresh_token": fields.String(required=True)}
)

tokens = auth_namespace.clone(
    "Access and refresh_tokens", refresh, {"access_token": fields.String(required=True)}
)

parser = auth_namespace.parser()
parser.add_argument("Authorization", location="headers")

class Register(Resource):
    @auth_namespace.marshal_with(user)
    @auth_namespace.expect(full_user, validate=True)
    @auth_namespace.response(201, "Success")
    @auth_namespace.response(400, "Sorry. That email already exists.")
    @auth_namespace.response(400, "Sorry. That username already exists.")
    def post(self):
        post_data = request.get_json()
        username = post_data.get("username")
        account_name = post_data.get("account_name")
        password = post_data.get("password")

        user_email = get_user_by_account(account_name)
        if user_email:
            auth_namespace.abort(400, "Sorry. That email already exists.")
        user_username = get_user_by_username(username)
        if user_username:
            auth_namespace.abort(400, "Sorry. That username already exists.")
        user = add_user(username=username, password=password)
        account = add_account(account_name = account_name, username = user.username)
        activation = add_activation(account_name = account.account_name)
        print(activation)
        return user, 201

class Login(Resource):
    @auth_namespace.marshal_with(tokens)
    @auth_namespace.expect(login, validate=True)
    @auth_namespace.response(200, "Success")
    @auth_namespace.response(404, "User does not exitst")
    def post(self):
        post_data = request.get_json()
        username = post_data.get("username")
        password = post_data.get("password")
        response_object = {}
        
        if get_user_by_account(username):
            username = get_user_by_account(username).username
        user = get_user_by_username(username)
        if not user:
            auth_namespace.abort(404, "Invalid username or password.")
        if not bcrypt.check_password_hash(user.password, password):
            auth_namespace.abort(404, "Invalid username or password.")
        if not user.active:
            auth_namespace.abort(401, "User is not verified.")
        access_token = user.encode_token(user.username, "access")
        refresh_token = user.encode_token(user.username, "refresh")

        response_object = {"access_token": access_token, "refresh_token": refresh_token}
        return response_object, 200

class Status(Resource):
    @auth_namespace.marshal_with(user)
    @auth_namespace.response(200, "Success")
    @auth_namespace.response(401, "Invalid token")
    @auth_namespace.expect(parser)
    def get(self):
        auth_header = request.headers.get("Authorization")
        if auth_header:
            try:
                access_token = auth_header.split(" ")[1]
                resp, token_type = User.decode_token(access_token)
                user = get_user_by_username(resp)
                if not user or token_type != "access":
                    auth_namespace.abort(401, "Invalid token")
                return user, 200
            except jwt.ExpiredSignatureError:
                auth_namespace.abort(401, "Signature expired. Please log in again.")
            except jwt.InvalidTokenError:
                auth_namespace.abort(401, "Invalid token. Please log in again.")
        else:
            auth_namespace.abort(403, "Token required")

class Refresh(Resource):
    @auth_namespace.expect(refresh, validate=True)
    @auth_namespace.response(200, "Success")
    @auth_namespace.response(401, "Invalid token")
    def post(self):
        post_data = request.get_json()
        refresh_token = post_data.get("refresh_token")
        response_object = {}

        try:
            resp, token_type = User.decode_token(refresh_token)
            user = get_user_by_username(resp)

            if not user or token_type != "refresh" or check_token_in_blacklist(refresh_token):
                auth_namespace.abort(401, "Invalid token")
            add_token_to_blacklist(refresh_token)
            access_token = user.encode_token(user.username, "access")
            refresh_token = user.encode_token(user.username, "refresh")
            response_object = {
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
            return response_object, 200
        except jwt.ExpiredSignatureError:
            auth_namespace.abort(401, "Signature expired. Please log in again.")
        except jwt.InvalidTokenError:
            auth_namespace.abort(401, "Invalid token. Please log in again.")

class Logout(Resource):
    @auth_namespace.expect(refresh, validate=True)
    @auth_namespace.response(200,"success")
    @auth_namespace.response(401,"Invalid token")
    def post(self):
        post_data = request.get_json()
        refresh_token = post_data.get("refresh_token")
        response_object = {}

        try:
            resp, token_type = User.decode_token(refresh_token)
            user = get_user_by_username(resp)

            if not user or token_type != "refresh":
                auth_namespace.abort(401, "Invalid token")
            
            data = add_token_to_blacklist(refresh_token)
            print(data)
            response_object = {
                "message": "Successfully logged out.",
            }
            return response_object, 200
        except jwt.ExpiredSignatureError:
            auth_namespace.abort(401, "Signature expired. Please log in again.")
        except jwt.InvalidTokenError:
            auth_namespace.abort(401, "Invalid token. Please log in again.")

auth_namespace.add_resource(Register,"/register",endpoint="register")
auth_namespace.add_resource(Login,"/login",endpoint="login")
auth_namespace.add_resource(Status,"/status",endpoint="status")
auth_namespace.add_resource(Refresh,"/refresh",endpoint="refresh")
auth_namespace.add_resource(Logout,"/logout",endpoint="logout")