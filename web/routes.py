from flask import Blueprint, request, jsonify
from .models import db, Log, Device, Organization

api = Blueprint('api', __name__)

@api.route('/logs', methods=['GET'])
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

@api.route('/logs', methods=['POST'])
def create_log():
    data = request.json
    log = Log(
        device_id=data['device_id'],
        organization_id=data['organization_id'],
        event_type=data['event_type'],
        severity=data['severity'],
        details=data.get('details', {})
    )
    db.session.add(log)
    db.session.commit()
    return jsonify({'message': 'Log added', 'id': log.id}), 201

@api.route('/devices', methods=['GET'])
def get_devices():
    devices = Device.query.all()
    return jsonify([{
        'id': d.id,
        'name': d.name,
        'ip_address': d.ip_address,
        'last_seen': d.last_seen,
        'is_active': d.is_active,
        'organization_id': d.organization_id
    } for d in devices])

@api.route('/organizations', methods=['GET'])
def get_organizations():
    orgs = Organization.query.all()
    return jsonify([{'id': o.id, 'name': o.name} for o in orgs])
