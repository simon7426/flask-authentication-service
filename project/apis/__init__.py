from flask_restx import Api
from project.apis.ping.api import ping_namespace
from project.apis.auth.auth import auth_namespace

api = Api(version="1.0", title="Users API")

api.add_namespace(ping_namespace,path="/ping")
api.add_namespace(auth_namespace,path="/auth")