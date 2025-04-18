from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
import base64

db = SQLAlchemy()
DB_NAME = "database.db"


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'ajshsahshjas'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)
    

    from .views import views
    from .routes import api

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(api, url_prefix='/')

    from .models import User
    
    with app.app_context():
        db.create_all()
    app.jinja_env.filters['b64encode'] = lambda b: base64.b64encode(b).decode('utf-8')


    login_manager = LoginManager()
    login_manager.login_view = 'api.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists('web/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')
