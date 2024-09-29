from flask import Flask

fromt .e
from .routes import main

def create_app():
    app = Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = 'secret'

    app.register_blueprint(main)
    return app

