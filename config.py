import os


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', "sqlite:///valhalla.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    textures_fs = os.getenv('TEXTURES_FS', 'file://.')
    ROOT_URL = os.getenv('ROOT_URL', 'http://127.0.0.1')
    OFFLINE = bool(os.getenv('OFFLINE', False))
    SKIN_BLACKLIST = ["cape"]


class DebugConfig(Config):
    DEBUG = True
    ENV = "testing"