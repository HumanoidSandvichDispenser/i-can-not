#! /usr/bin/env python3
# vim:fenc=utf-8
#
# Copyright © 2023 sandvich <sandvich@artix>
#
# Distributed under terms of the MIT license.


from flask import make_response, request
from flask.app import Flask
import jwt
import os
import time
import requests
import re
import sys

JWT_SECRET = os.environ.get("JWT_SECRET")
JWT_REGEX = r"ICN_JWT=((?:[A-Za-z0-9-_=]+)+\.(?:[A-Za-z0-9-_=]+)+\.(?:[A-Za-z0-9-_=]+)+)"

if not JWT_SECRET:
    print("No JWT_SECRET env var provided", file=sys.stderr)
    exit(1)

app = Flask(__name__)

def consume_token(jwt_token: str, aud: str, token_type = "", salt = ""):
    try:
        body = jwt.decode(jwt_token, JWT_SECRET + salt, ["HS256"], audience=aud)
        if token_type != "":
            # should consume token if body is specified and matches
            if "type" in body and body["type"] == token_type:
                return body
            return None
        return body
    except jwt.exceptions.InvalidTokenError:
        return None

def remake_token(body, age, **kwargs):
    new_body = body | kwargs
    current_timestamp = int(time.time())
    new_body["iat"] = current_timestamp
    new_body["exp"] = current_timestamp + age
    token = jwt.encode(new_body, JWT_SECRET, algorithm="HS256")
    return token


def create_token(aud: str, age: int, salt = "", **kwargs):
    current_timestamp = int(time.time())
    jwt_body = {
        "sub": "ICN_JWT",
        #"type": "",
        "iss": "i-can-not",
        "aud": aud,
        #"username": name,
        #"user_key"
        "iat": current_timestamp,
        "exp": current_timestamp + age,
    } | kwargs
    token = jwt.encode(jwt_body, JWT_SECRET + salt, algorithm="HS256")
    return token

@app.post("/authenticate-identity/<string:user_key>")
def authenticate_identity(user_key):
    request_json = request.json
    if request_json and "token":
        token = consume_token(request_json["token"], user_key, "TOKEN_IDENTITY")
        if token:
            return make_response(
                {
                    "message": "MSG_TOKEN_VERIFIED"
                },
                200,
            )
        else:
            return make_response(
                {
                    "message": "MSG_ERR_TOKEN_INVALID"
                },
                401,
                { "WWW-Authenticate": "Bearer" },
            )
    return make_response(
        {
            "message": "MSG_ERR_TOKEN_NOT_FOUND"
        },
        401,
        { "WWW-Authenticate": "Bearer" },
    )

@app.post("/generate-identity/<string:user_key>")
def generate_identity(user_key):
    request_json = request.json
    if request_json and "token" in request_json and "audience" in request_json:
        token = consume_token(request_json["token"], user_key, "TOKEN_SESSION")
        audience = request_json["audience"]
        if token:
            identity_token = remake_token(
                    token, 30, type="TOKEN_IDENTITY", aud=audience)
            return make_response({ "token": identity_token }, 200)
        else:
            return make_response(
                {
                    "message": "MSG_ERR_TOKEN_INVALID"
                },
                401,
                { "WWW-Authenticate": "Bearer" },
            )
    return make_response(
        {
            "message": "MSG_ERR_TOKEN_NOT_FOUND"
        },
        401,
        { "WWW-Authenticate": "Bearer" },
    )

@app.post("/verify-user/<string:user_key>")
def verify_user(user_key):
    request_json = request.json
    if request_json and "salt" in request_json:
        print("Fetching user", user_key)
        response = requests.get(
                "https://twocansandstring.com/users/" + user_key)
        text = response.text
        match = re.search(JWT_REGEX, text)
        salt = request_json["salt"]
        if match:
            enc_t = match.group(1)
            print("Token:", enc_t)
            print("Salt:", salt)
            token = consume_token(enc_t, user_key, "TOKEN_VERIFICATION", salt)
            if token:
                print("Successfully verified user", user_key)
                token = create_token(
                    user_key,
                    604800,
                    type="TOKEN_SESSION",
                    username=token["username"],
                    user_key=token["user_key"],
                )
                return make_response(
                    {
                        "token": token,
                    },
                    200,
                )
            else:
                return make_response(
                    {
                        "msg": "ERR_MSG_TOKEN_INVALID",
                    },
                    401,
                )
        return make_response(
            {
                "msg": "ERR_MSG_TOKEN_NOT_FOUND",
            },
            401,
        )
    return make_response("ERR_MSG_SALT_NOT_FOUND", 400)

@app.post("/generate-verification/<string:user_key>")
def generate_verification(user_key):
    request_json = request.json
    if not request_json or "salt" not in request_json:
        return make_response(400)
    #user_key = request_json["user_url"]
    username = request_json["username"]
    salt = request_json["salt"]
    print("Generating token for", username, "with salt", salt)
    token = create_token(
        user_key,
        300,
        salt,
        type="TOKEN_VERIFICATION",
        username=username,
        user_key=user_key,
    )
    return make_response({
        "token": token,
    })

if __name__ == "__main__":
    app.run()

# curl localhost:5000/generate-verification/user64837 -H "Content-Type: application/json" -d '{"username":"user64837", "salt": "Level"}'
# curl localhost:5000/verify-user/user64837 -H "Content-Type: application/json" -d '{"username":"user64837", "salt": "Level"}'
