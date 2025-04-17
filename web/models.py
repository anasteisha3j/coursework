import datetime
import uuid
from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

class Organization(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String, unique=True, nullable=False)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String)
    role = db.Column(db.String, nullable=False)
    organization_id = db.Column(db.String, db.ForeignKey('organizations.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = db.Column(db.String, db.ForeignKey('organizations.id'), nullable=False)
    name = db.Column(db.String, nullable=False)
    ip_address = db.Column(db.String)
    last_seen = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String, db.ForeignKey('devices.id'))
    organization_id = db.Column(db.String, db.ForeignKey('organizations.id'))
    event_type = db.Column(db.String, nullable=False)
    severity = db.Column(db.String)
    details = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
