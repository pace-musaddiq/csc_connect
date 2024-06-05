# user.py

import base64
import random

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, session, redirect, request

app = Flask(__name__)
app.secret_key = "your_secret_key"

from connect_config import (
    CLIENT_ID,
    REDIRECT_URI,
    AUTHORIZATION_ENDPOINT,
    TOKEN_ENDPOINT,
    RESOURCE_URL,
    CLIENT_SECRET,
)


def login():
    state = random.randint(10000, 99999)
    session["connect_state"] = state
    auth_parameters = f"response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={state}"
    url = f"{AUTHORIZATION_ENDPOINT}?{auth_parameters}"
    return redirect(url)


@app.route("/login")
def login_route():
    return login()


# connect_success.py


def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if not state or state != session.get("connect_state"):
        return "STATE mismatch"

    session.pop("connect_state", None)

    if not code:
        return "No code!!"

    post_data = {
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": encrypt(CLIENT_SECRET),
    }

    token_resp = fetch_data(TOKEN_ENDPOINT, post_data, False)
    token_resp_data = token_resp.json()

    access_token = token_resp_data.get("access_token") if token_resp_data else False

    if not access_token:
        return "No token"

    header_data = {"Authorization": f"Bearer {access_token}"}
    response = fetch_data(
        f"{RESOURCE_URL}?access_token={access_token}", False, header_data
    )
    resp_json = response.json()

    session["User"] = resp_json.get("User") if resp_json else False
    return redirect("/login")


@app.route("/callback")
def callback_route():
    return callback()


def fetch_data(url, post, heads):
    headers = heads if heads else {}

    if post:
        response = requests.post(url, data=post, headers=headers)
    else:
        response = requests.get(url, headers=headers)

    if not response.ok:
        print({"Error code": response.status_code, "URL": url, "post": post, "LOG": ""})
        return "Error: 378972"

    print(response.text + "\n\n")
    return response


def encrypt(in_t, client_token):
    key = client_token.encode("utf-8")
    pre = ":"
    post = "@"
    plaintext = f"{random.randint(10, 99)}{pre}{in_t}{post}{random.randint(10, 99)}"

    # Pad the plaintext to a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    # Create a cipher object with AES-128 in CBC mode
    iv = b"0000000000000000"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Encode the ciphertext as hexadecimal
    encrypted_text = base64.b16encode(ciphertext).decode("utf-8")

    return encrypted_text


# login.py


@app.route("/")
def login_page():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Login :: Merchant .py</title>
        <!-- CSS and other head elements -->
    </head>
    <body>
        <div id="wrapper">
            <!-- Header -->
            <section id="inner-headline">
                <!-- Breadcrumb and other content -->
            </section>
            <section id="content">
                <div class="container">
                    <div class="row">
                        <div class="col-lg-6">
                            <!-- Call response -->
                            <h4>Digital Seva Connect Response</h4>
                            <pre class="prettyprint linenums">{{ session }}</pre>
                        </div>
                        <div class="col-lg-6">
                            <div class="col-xs-12 col-sm-8 col-md-6 col-sm-offset-2 col-md-offset-3">
                                {% if not session %}
                                    <a href="/login" class="btn btn-info">Login with Digital Seva Connect</a>
                                {% else %}
                                    <h4>Welcome {{ session['username'] }}</h4>
                                {% endif %}
                                <br><br>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
            <!-- Footer -->
        </div>
        <!-- JavaScript files -->
    </body>
    </html>
    """


# logout.py


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# session_valid.py


@app.before_request
def check_session():
    if not session and request.endpoint not in ["login_route", "callback_route"]:
        return redirect("/")


if __name__ == "__main__":
    app.run()
