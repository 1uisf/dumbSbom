from flask import Flask
import os

def create_app():
    """Application factory pattern for Flask app creation"""
    app = Flask(__name__)
    
    # Set secret key for sessions
    app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)
    
    return app 