from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from .models import db, Log, Device, Organization, User
from flask import Blueprint, request, jsonify, redirect, url_for, render_template
from werkzeug.security import generate_password_hash


api = Blueprint('api', __name__)

@api.route('/logs', methods=['GET'])
@login_required
def get_logs():
    if not current_user.is_admin():  
        return jsonify({'error': 'Access denied'}), 403

    logs = Log.query.join(Device).filter_by(organization_id=current_user.organization_id)\
                     .add_columns(Device.name.label('device_name'))\
                     .order_by(Log.created_at.desc()).all()

    return jsonify([{
        'id': log.id,
        'device_id': log.device_id,
        'device_name': log.device_name,  
        'organization_id': log.organization_id,
        'event_type': log.event_type,
        'severity': log.severity,
        'details': log.details,
        'created_at': log.created_at.isoformat()  
    } for log in logs])



@api.route('/logs', methods=['POST'])
@login_required
def create_log():
    data = request.json
    if not data or not all(key in data for key in ['device_name', 'organization_id', 'event_type', 'severity']):
        return jsonify({'error': 'Missing required fields'}), 400

    if data['organization_id'] != current_user.organization_id:
        return jsonify({'error': 'Access denied to other organization logs'}), 403

    log = Log(
        device_name=data['device_name'],
        organization_id=data['organization_id'],
        event_type=data['event_type'],
        severity=data['severity'],
        details=data.get('details', {})
    )
    db.session.add(log)
    db.session.commit()
    return jsonify({'message': 'Log added', 'id': log.id}), 201



@api.route('/devices', methods=['GET'])
@login_required
def get_devices():
    page = request.args.get('page', 1, type=int)
    per_page = 10  

    devices = Device.query.filter_by(organization_id=current_user.organization_id)\
                          .paginate(page, per_page, False)

    return jsonify([{
        'id': d.id,
        'name': d.name,
        'ip_address': d.ip_address,
        'last_seen': d.last_seen,
        'is_active': d.is_active,
        'organization_id': d.organization_id
    } for d in devices.items])


@api.route('/organizations', methods=['GET'])
@login_required
def get_organizations():
    if not current_user.is_admin():
        return jsonify({'error': 'Access denied'}), 403

    orgs = Organization.query.all()
    return jsonify([{'id': o.id, 'name': o.name} for o in orgs])


from flask import render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from .models import db, Organization, User

@api.route('/register_organization', methods=['GET', 'POST'])
def register_organization():
    if request.method == 'POST':
        org_name = request.form.get('organization_name')
        email = request.form.get('admin_email')
        password = request.form.get('password')

        existing_org = Organization.query.filter_by(name=org_name).first()
        if existing_org:
            flash("Організація з такою назвою вже існує", "error")
            return redirect(url_for('api.register_organization'))

        new_org = Organization(name=org_name)
        db.session.add(new_org)
        db.session.commit()

        new_admin = User(
            email=email,
            password_hash=generate_password_hash(password),
            role='admin',
            organization_id=new_org.id
        )
        db.session.add(new_admin)
        db.session.commit()

        flash("Організацію успішно зареєстровано. Тепер увійдіть.", "success")
        return redirect(url_for('views.login'))

    return render_template('register_organization.html')




