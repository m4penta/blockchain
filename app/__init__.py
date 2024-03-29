
# File: blockchain_project/app/__init__.py
from flask import Flask

def create_app():
    app = Flask(__name__)

    @app.route('/')
    def home():
        return 'Hello, this is your blockchain app!'

    # Add more routes and configurations as needed

    return app
