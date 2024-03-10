#!/usr/bin/env python3
"""
Basic App
"""
from flask import abort
from flask import Flask
from flask import jsonify
from flask import request

from auth import Auth


AUTH = Auth()


app = Flask(__name__)


@app.route("/", methods=["GET"], strict_slashes=False)
def home():
    """
    Landing page.
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users():
    """
    End point for registring a user.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        AUTH.register_user(email=email, password=password)

        return jsonify({"email": email, "message": "user created"})

    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """
    Login end point.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not AUTH.valid_login(email=email, password=password):
        abort(401)

    session_id = AUTH.create_session(email=email)

    reponse = jsonify({"email": email, "message": "logged in"})

    reponse.set_cookie("session_id", session_id)

    return reponse


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
