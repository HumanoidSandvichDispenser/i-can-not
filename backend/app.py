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

def consume_token(jwt_token, audience):
    try:
        body = jwt.decode(jwt_token, JWT_SECRET, ["HS256"], audience=audience)
        return body
    except jwt.exceptions.InvalidTokenError:
        return None

@app.post("/verify-token/<string:user_key>")
def verify_token(user_key):
    request_json = request.json
    if request_json and "token" in request_json:
        if consume_token(request_json["token"], user_key):
            return make_response()
        else:
            return make_response(
                {
                    "message": "Invalid token"
                },
                401,
                { "WWW-Authenticate": "Bearer" }
            )
    return make_response(
        {
            "message": "Token not provided"
        },
        401,
        { "WWW-Authenticate": "Bearer" }
    )

@app.route("/verify-user/<string:user_key>")
def verify_user(user_key):
    print("Fetching user", user_key)
    response = requests.get("https://twocansandstring.com/users/" + user_key)
    text = response.text
    match = re.search(JWT_REGEX, text)
    if match:
        enc_token = match.group(1)
        print("Token:", enc_token)
        if consume_token(enc_token, user_key):
            print("Successfully verified user", user_key)
            return make_response("", 200)
    return make_response("", 401)

@app.post("/generate-verification/<string:user_key>")
def generate_verification(user_key):
    request_json = request.json
    if not request_json:
        return make_response(400)
    #user_key = request_json["user_url"]
    username = request_json["username"]
    current_timestamp = int(time.time())
    print("Generating token for", username)
    jwt_body = {
        "sub": "ICN_JWT",
        "iss": "i-can-not",
        "aud": user_key,
        "username": username,
        "iat": current_timestamp,
        "exp": current_timestamp + 300,  # expires in 5 mins
    }
    token = jwt.encode(jwt_body, JWT_SECRET, algorithm="HS256")
    return make_response({
        "token": token,
    })

if __name__ == "__main__":
    app.run()

# curl localhost:5000/generate-verification/user64837 -H "Content-Type: application/json" -d '{"username":"user64837"}'
# curl localhost:5000/verify-user/user64837 -H "Content-Type: application/json"
