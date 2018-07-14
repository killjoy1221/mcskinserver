#!/usr/env python3

import base64
import functools
import hashlib
import os
import random
import string
import time
import uuid as guid
from io import BytesIO

import requests
import rsa
from expiringdict import ExpiringDict
from flask import Flask, abort, jsonify, request,  send_from_directory
from PIL import Image

from . import database, mojang
from .validate import regex

app = Flask(__name__)

db_file = os.getenv('DB_FILE', 'hdskins.db')
root_dir = os.getenv('ROOT_DIR', os.getcwd())
root_url = os.getenv('ROOT_URL', '127.0.0.1')
offline_mode = bool(os.getenv('OFFLINE', False))

supported_types = ["skin", "cape", "elytra"]


def open_database():
    return database.Database(db_file)


def authorize(func):
    @functools.wraps(func)
    def decorator(*args, **kwargs):

        if not offline_mode:
            if 'Authorization' not in request.headers:
                return jsonify(message="Authorization token not provided"), 403
            auth = str(request.headers['Authorization'])

            with open_database() as db:
                access = db.find_access_token(auth)
                if access is None or access.address != request.remote_addr:
                    return jsonify(message="Authorization failed"), 403
                if int(access.issued) < time.time() - 24 * 60 * 60 * 100:
                    return jsonify(message="Access token expired"), 401
                if access.user.uniqueId != kwargs['user']:
                    return jsonify(message="User is forbidden"), 401

        return func(*args, **kwargs)
    return decorator


def require_formdata(*formdata):
    def callable(func):
        @functools.wraps(func)
        def decorator(*args, **kwargs):
            for data in formdata:
                if data not in request.form:
                    raise KeyError("Missing required form: '%s'" % data)
            return func(*args, **kwargs)
        return decorator
    return callable


@app.route('/')
def root():
    def status():
        try:
            open_database()
            return True
        except:
            return False

    return jsonify(
        implementation='valhalla',
        name='HD Skins',
        offlineMode=offline_mode,
        status=status(),
        version=1
    )


def metadata_json(data):
    for meta in data:
        yield meta.key, meta.val


def textures_json(textures):
    for texType, tex in textures:
        texType = str(texType).upper()
        dic = {'url': root_url + '/textures/' + tex.url}
        metadata = dict(metadata_json(tex.metadata))
        if metadata:  # Only include metadata if there is any
            dic['metadata'] = metadata
        yield texType, dic


@app.route('/user/<user>')
@regex(user=regex.UUID)
def get_textures(user):

    with open_database() as db:
        user = db.find_user(user, False)
        if user is None:
            return jsonify(message="User not found"), 403
        textures = textures_json(user.textures)
        if textures is None:
            return jsonify(message="Skins not found"), 403
        return jsonify(
            timestamp=int(time.time() * 1000),
            profileId=user.uniqueId,
            profileName=user.name,
            textures=dict(textures)
        )


if bool(app.config['DEBUG']):
    @app.route('/textures/<image>')
    def get_image(image):
        """This function is used during development to test the texture fetching.
        In production, a static web-server should be used.
        """
        return send_from_directory(root_dir + '/textures', image, mimetype='image/png')


@app.route('/user/<user>/<skinType>', methods=['POST'])
@regex(user=regex.UUID, skin_type=regex.choice(*supported_types))
@require_formdata('file')
@authorize
def change_skin(user, skin_type):

    model = request.form["model"] or 'default'
    url = request.form["file"]

    resp = requests.get(url)

    if resp.ok:
        skin = gen_skin_hash(resp.content)

        put_texture(user, skin, skin_type, request.remote_addr, model=model)

    return jsonify(message='OK')


@app.route('/user/<user>/<skin_type>', methods=['PUT'])
@regex(user=regex.UUID, skin_type=regex.choice(*supported_types))
@authorize
def upload_skin(user, skin_type):
    if 'file' not in request.files:
        raise ValueError('Missing required file: file')
    file = request.files['file']
    if 'model' in request.form:
        model = request.form["model"]
    else:
        model = 'default'

    if not file:
        raise ValueError("Empty file?")

    (image, skin) = gen_skin_hash(file.read())

    image.save(os.path.join(root_dir, "textures", skin), format="PNG")

    # TODO: support for arbitrary metadata

    put_texture(user, skin, skin_type, request.remote_addr, model=model)

    return jsonify(message="OK")


def gen_skin_hash(image_data):

    image = Image.open(BytesIO(image_data))

    if image.format != "PNG":
        raise ValueError("Format not allowed: " + image.format)

    # Check size of image.
    # width should be same as or double the height
    # Width is then checked for predefined values
    # 64, 128, 256, 512, 1024

    # set of supported width sizes. Height is either same or half
    sizes = set([64, 128, 256, 512, 1024])
    (width, height) = image.size
    valid = width / 2 == height or width == height

    if not valid or width not in sizes:
        raise ValueError("Unsupported image size: " + image.size)

    # Create a hash of the image and use it as the filename.
    return image, hashlib.sha1(image.tobytes()).hexdigest()


def put_texture(user, url, skin_type, uploader, **metadata):

    with open_database() as db:
        user = db.find_user(user)
        texture = user.put_texture(url, skin_type, uploader)
        texture.put_metadata(**metadata)


@app.route('/user/<user>/<skin_type>', methods=['DELETE'])
@regex(user=regex.UUID, skin_type=regex.choice(*supported_types))
@authorize
def reset_skin(user, skin_type):
    with open_database() as db:
        user = db.find_user(user)
        if user:
            tex = user.textures[skin_type]
            if tex and tex.clear():
                return ""
            return jsonify(message="Unknown texture"), 404
        return jsonify(message="Unknown user"), 404


# Validate tokens are kept 100 at a time for 30 seconds each
validate_tokens = ExpiringDict(100, 30)


@app.route('/auth/handshake', methods=["POST"])
@require_formdata('name')
def auth_handshake():
    """Use this endpoint to receive an authentication request.

    The public key is used by the client to join a server for verification.
    """

    name = request.form['name']

    # Generate a random 32 bit integer. It will be checked later.
    verify_token = random.getrandbits(32)
    validate_tokens[name] = verify_token, request.remote_addr

    return jsonify(
        offline=offline_mode,
        serverId=server_id,
        verifyToken=verify_token
    )


@app.route('/auth/response', methods=['POST'])
@require_formdata('name', 'verifyToken')
def auth_response():

    if offline_mode:
        abort(501)  # Not Implemented

    name = str(request.form['name'])
    verify_token = int(request.form['verifyToken'])

    def forbidden(msg):
        abort(403, jsonify(error="Forbidden", message=msg))

    if name not in validate_tokens:
        forbidden('The user has not requested a token or it has expired')

    try:
        token, addr = validate_tokens[name]

        if token != verify_token:
            forbidden('The verify token is not valid')
        if addr != request.remote_addr:
            forbidden('IP does not match')
    finally:
        del(validate_tokens[name])

    response = mojang.has_joined(name, server_id, request.remote_addr)

    if not response.ok:
        abort(403)

    json = response.json()

    uuid = json['id']
    name = json['name']

    with open_database() as db:
        user = db.find_user(uuid, name)

        # Invalidate the previous access token
        user.clear_access_token()

        # Generate unique access token. uuid1 guarentees it
        token = str(base64.b64encode(
            guid.uuid1().bytes, altchars=b"-_"), 'utf-8')

        user.put_access_token(token, request.remote_addr)

        return jsonify(
            accessToken=token,
            userId=user.uniqueId,
        )


@app.before_first_request
def init_auth():

    global server_id
    server_id = random_string(20)

    with open_database() as db:
        db.setup()


def random_string(size=20, chars=string.ascii_letters + string.digits):
    return ''.join([random.choice(chars) for n in range(size)])


@app.errorhandler(404)
def notFound(status):
    # Redirect 404 to 403 for security
    return jsonify(message="Forbidden"), 403


@app.errorhandler(405)
def methodNotAllowed(status):
    return jsonify(error="Method Not Allowed"), 405


@app.errorhandler(ValueError)
@app.errorhandler(KeyError)
def valueError(error):
    if app.config['DEBUG']:
        raise error
    return jsonify(message=type(error).__name__ + ": " + str(error)), 400

if __name__ == '__main__':
    app.run()
