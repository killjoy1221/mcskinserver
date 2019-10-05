import calendar
import functools
import hashlib
import random
from datetime import datetime
from io import BytesIO
from typing import List

from PIL import Image
from expiringdict import ExpiringDict
from flask import Blueprint, current_app, jsonify, request, g
from flask_httpauth import HTTPTokenAuth
from flask_restplus import Api, Resource, abort
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

from .. import *
from ..models import *
from ..mojang import *

apiv1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")

auth = HTTPTokenAuth()
api = Api(apiv1)


def gen_auth_token(user: User, expiration):
    s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
    return s.dumps({'id': user.id})


@auth.error_handler
def auth_failed():
    abort(401)


@auth.verify_token
def verify_auth_token(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        abort(401, "Token expired")
    except BadSignature:
        abort(401, "Bad token")
    else:
        g.user = User.get(data['id'])
        return g.user


def require_formdata(*formdata):
    def call(func):
        @functools.wraps(func)
        def decorator(*args, **kwargs):
            for data in formdata:
                if data not in request.form:
                    abort(404, f"Missing required form: '{data}'")
            return func(*args, **kwargs)

        return decorator

    return call


@api.route('/user/<user:user>')
class UserResource(Resource):
    def get(self, user: User):
        if user is None:
            return abort(404, "User not found")

        def metadata_json(data):
            for meta in data:
                yield meta.key, meta.value

        def textures_json(texture_list: List[Texture]):
            if not texture_list:
                return None
            for tex in texture_list:
                typ = tex.tex_type.upper()
                upload = tex.upload
                if upload is None:
                    continue
                dic = {'url': root_url() + '/textures/' + upload.hash}
                metadata = dict(metadata_json(tex.meta))
                if metadata:  # Only include metadata if there is any
                    dic['metadata'] = metadata
                yield typ, dic

        active = Texture.query(Texture). \
            filter_by(user=user). \
            order_by(Texture.id).reverse(). \
            distinct(Texture.tex_type). \
            all()

        textures = dict(textures_json(active))
        tex: Texture
        for tex in active:
            if tex.upload is None:
                continue
            dic = {'url': f"{root_url()}/textures/{tex.upload.hash}"}
            metadata = dict(metadata_json(tex.meta))
            if metadata:
                dic['metadata'] = metadata

        if not textures:
            return abort(404, "Skins not found")
        return jsonify(
            timestamp=calendar.timegm(datetime.utcnow().utctimetuple()),
            profileId=user.uuid,
            profileName=user.name,
            textures=dict(textures)
        )


def get_metadata_map(form):
    for k, v in form.items():
        yield k, v


@api.route('/user/<user:user>/<skin_type>')
class TextureResource(Resource):

    @auth.login_required
    def dispatch_request(self, user, skin_type):
        if skin_type in blacklist():
            abort(400, f"Type '{skin_type}' is not allowed. ")
        if user != g.user:
            abort(403, "Cannot change another user's textures")
        super().dispatch_request(user, skin_type)

    @require_formdata('file')
    def post(self, user: User, skin_type):
        url = request.form.pop("file")
        resp = requests.get(url)
        if not resp.ok:
            abort(400, "File download failed", error=resp.text)

        metadata = get_metadata_map(request.form)
        put_texture(user, resp.content, skin_type, **dict(metadata))

        return "", 202

    def put(self, user: User, skin_type):
        if 'file' not in request.files:
            raise abort(400, 'Missing required file: file')
        file = request.files['file']

        if not file:
            raise abort(400, "Empty file?")

        metadata = get_metadata_map(request.form)
        put_texture(user, file.read(), skin_type, **dict(metadata))

        return "", 202

    def delete(self, user: User, skin_type):
        db.session.add(Texture(
            user=user,
            tex_type=skin_type,
            upload=None,
            metadata=None)
        )
        db.session.commit()
        return "{}", 202


def gen_skin_hash(image_data):
    with Image.open(BytesIO(image_data)) as image:
        if image.format != "PNG":
            raise abort(400, f"Format not allowed: {image.format}")

        # Check size of image.
        # width should be same as or double the height
        # Width is then checked for predefined values
        # 64, 128, 256, 512, 1024

        # set of supported width sizes. Height is either same or half
        sizes = {64, 128, 256, 512, 1024}
        (width, height) = image.size
        valid = width / 2 == height or width == height

        if not valid or width not in sizes:
            raise abort(404, f"Unsupported image size: {image.size}")

        # Create a hash of the image and use it as the filename.
        return hashlib.sha1(image.tobytes()).hexdigest()


def put_texture(user: User, file, skin_type, **metadata):
    skin_hash = gen_skin_hash(file)

    upload = Upload.query.filter_by(hash=skin_hash).first()

    if upload is None:
        with open_fs() as fs:
            with fs.open(skin_hash, "wb") as f:
                f.write(file)

        upload = db.session.add(Upload(hash=skin_hash, user=user))

    db.session.add(Texture(user=user,
                           tex_type=skin_type,
                           upload=upload,
                           metadata=[Metadata(key=k, value=v) for k, v in metadata.items()]))
    db.session.commit()


# Validate tokens are kept 100 at a time for 30 seconds each
validate_tokens = ExpiringDict(100, 30)


@api.route('/auth/handshake')
class AuthHandshakeResource(Resource):

    @api.doc(params={
        'name': 'The username'
    }, verify=True)
    def post(self):
        """Use this endpoint to receive an authentication request.

        The public key is used by the client to join a server for verification.
        """
        name = request.form['name']

        # Generate a random 32 bit integer. It will be checked later.
        verify_token = random.getrandbits(32)
        validate_tokens[name] = verify_token, request.remote_addr

        return jsonify(
            offline=offline_mode(),
            serverId=current_app.config['server_id'],
            verifyToken=verify_token
        )


@api.route('/auth/response')
class AuthResponseResource(Resource):
    @api.doc(params={
        'name': "The player username",
        "verifyToken": "The token gotten from /auth/handshake"
    }, verify=True)
    def post(self):
        """Call after a handshake and Mojang's joinServer.

        This calls hasJoined to verify it.
        """
        if offline_mode():
            abort(501)  # Not Implemented

        name = str(request.form['name'])
        verify_token = int(request.form['verifyToken'])

        if name not in validate_tokens:
            abort(403, 'The user has not requested a token or it has expired')

        try:
            token, addr = validate_tokens[name]

            if token != verify_token:
                abort(403, 'The verify token is not valid')
            if addr != request.remote_addr:
                abort(403, 'IP does not match')
        finally:
            del validate_tokens[name]

        with has_joined(name, current_app.config['server_id'], request.remote_addr) as response:
            if not response.ok:
                abort(403)

            json = response.json()

        uuid = json['id']
        name = json['name']

        user = get_or_create_user(uuid, name)
        # Expire token after 1 hour
        token = f"Bearer {gen_auth_token(user, expiration=3600)}"

        return jsonify(
            accessToken=token,
            userId=user.uuid,
        ), 200, {
                   'Authorization': token
               }


def get_or_create_user(uuid, name) -> User:
    user = User.query.filter_by(uuid=uuid).one_or_none()
    if user is None:
        user = User(uuid=uuid, name=name)
        db.session.add(user)
    else:
        user.name = name
        db.session.commit()
    return user