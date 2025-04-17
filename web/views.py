from flask import Blueprint, render_template, jsonify
from .models import Log
from . import db

views = Blueprint('views', __name__)

@views.route('/view-logs')
def view_logs():
    return render_template('logs.html')

@views.route('/logs')
def get_logs():
    logs = Log.query.order_by(Log.created_at.desc()).all()
    return jsonify([{
        'id': log.id,
        'device_id': log.device_id,
        'organization_id': log.organization_id,
        'event_type': log.event_type,
        'severity': log.severity,
        'details': log.details,
        'created_at': log.created_at
    } for log in logs])
