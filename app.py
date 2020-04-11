from flask import Flask,jsonify,request
from flask_restful import Api,Resource
from pymongo import MongoClient
import bcrypt
import requests
import subprocess
import json

app= Flask(__name__)
api=Api(app)

client= MongoClient("mongodb://db:27017")
db= client.ImageRecognition
users= db["Users"]


class Register(Resource):
    def post(self):
        postedData=request.get_json()
        username= postedData["username"]
        password= postedData["password"]

        if UserNotExist(username):
        	retJson={
                "status":301,
                "msg": "user do not exist"

        	}

            return jsonify(retJson)

        hashed_pw=bcrypt.hashpw(password.encode("utf8"),bcrypt.gensalt())

        users.insert({
            "Username": username
            "Password": hashed_pw
            "Tokens": 4
        	})
