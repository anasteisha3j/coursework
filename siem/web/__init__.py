



from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
import base64
import uuid
from werkzeug.security import generate_password_hash
import humanize 
from datetime import datetime  

from flask_migrate import Migrate
from dotenv import load_dotenv

#load_dotenv()

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'ajshsahshjas'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://postgres:postgres@localhost/siem'  # Виправлено помилку в DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
    db.init_app(app)
    migrate.init_app(app, db)

    from .models import User, Organization, Device, Log

    login_manager = LoginManager()
    login_manager.login_view = 'views.login'  
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(str(user_id))

    from .views import views
    app.register_blueprint(views, url_prefix='/')

    app.jinja_env.filters['humanize'] = humanize.naturaltime
    app.jinja_env.filters['b64encode'] = lambda b: base64.b64encode(b).decode('utf-8')

    # with app.app_context():
    #     db.create_all()

    #     if not User.query.first():
    #         new_org = Organization(name="Test Org")
    #         db.session.add(new_org)
    #         db.session.commit()

    #         password_hash = generate_password_hash("admin123")
    #         new_user = User(
    #             email="admin@example.com",
    #             password_hash=password_hash,
    #             role="admin",
    #             organization_id=new_org.id
    #         )
    #         db.session.add(new_user)
    #         db.session.commit()
    #         print(" Test user created successfully!")

    return app

from .simulator import DeviceSimulator
sim = DeviceSimulator



