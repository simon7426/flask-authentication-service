import os

from flask_restx import Api, Namespace, Resource

ping_namespace = Namespace("ping")


class Ping(Resource):
    def get(self):
        return {
            "status": "success",
            "message": "pong!",
            "server": os.environ.get("SERVER_NO", "default"),
        }, 200


class Healthy(Resource):
    def get(self):
        return {"status": "success", "message": "healthy"}, 200


ping_namespace.add_resource(Ping, "/ping")
ping_namespace.add_resource(Healthy, "/healthy")
