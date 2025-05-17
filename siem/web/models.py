
import uuid
from datetime import datetime
from flask_login import UserMixin
from . import db
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate


class Organization(db.Model):
    __tablename__ = 'organizations'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    users = db.relationship('User', back_populates='organization', cascade='all, delete-orphan')
    devices = db.relationship('Device', back_populates='organization', cascade='all, delete-orphan')
    logs = db.relationship('Log', back_populates='organization')

    def __repr__(self):
        return f'<Organization {self.name}>'

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'admin', 'user', 'auditor'
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # Relationships
    organization = db.relationship('Organization', back_populates='users')

    def is_admin(self):
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.email} ({self.role})>'

class Device(db.Model):
    __tablename__ = 'devices'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    mac_address = db.Column(db.String(17))
    type = db.Column(db.String(50))  
    last_seen = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    organization = db.relationship('Organization', back_populates='devices')
    logs = db.relationship('Log', back_populates='device', cascade='all, delete-orphan')

    def status(self):
        return 'online' if self.is_active else 'offline'

    def __repr__(self):
        return f'<Device {self.name} ({self.ip_address})>'

class Log(db.Model):
    __tablename__ = 'logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'))
    organization_id = db.Column(db.String(36), db.ForeignKey('organizations.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # 'auth', 'network', 'system'
    severity = db.Column(db.String(10))  # 'info', 'warning', 'error', 'critical'
    def get_alert_class(self):
        return {
            'critical': 'alert-critical',
            'high': 'alert-high',
            'medium': 'alert-medium',
            'low': 'alert-low'
        }.get(self.severity, '')
    #message = db.Column(db.Text)
    details = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationships
    device = db.relationship('Device', back_populates='logs')
    organization = db.relationship('Organization', back_populates='logs')

    __table_args__ = (
        db.Index('idx_log_device_created', 'device_id', 'created_at'),
        db.Index('idx_log_org_created', 'organization_id', 'created_at'),
        db.Index('idx_log_severity', 'severity'),
    )

    def __repr__(self):
        return f'<Log {self.event_type}@{self.created_at}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'event_type': self.event_type,
            'severity': self.severity,
            'details': self.details if isinstance(self.details, dict) else {},
            'created_at': self.created_at.isoformat(),
            'ip_address': (
                self.details.get('ip') if isinstance(self.details, dict) and 'ip' in self.details
                else self.device.ip_address if self.device else None
            ),
            'device_name': self.device.name if self.device else 'Невідомий пристрій'
        }
    
    

class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address = db.Column(db.String(15), unique=True, nullable=False)
    reason = db.Column(db.String(200))
    blocked_by = db.Column(db.String(36), db.ForeignKey('users.id'))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

    # Relationship
    blocker = db.relationship('User')

    def is_active(self):
        return self.expires_at is None or self.expires_at > datetime.utcnow()

    def __repr__(self):
        return f'<BlockedIP {self.ip_address}>'
