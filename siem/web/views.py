from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash
from flask_login import login_required, current_user, login_user
from werkzeug.security import check_password_hash,generate_password_hash
from .models import db, Log, Device, User, Organization


views = Blueprint('views', __name__)

@views.route('/register_organization', methods=['GET', 'POST'])
def register_organization():
    if request.method == 'POST':
        org_name = request.form.get('organization_name')
        admin_email = request.form.get('admin_email')
        password = request.form.get('password')

        if not org_name or not admin_email or not password:
            flash("Усі поля обов'язкові", category='error')
            return redirect(url_for('views.register_organization'))

        existing_org = Organization.query.filter_by(name=org_name).first()
        existing_user = User.query.filter_by(email=admin_email).first()
        if existing_org or existing_user:
            flash("Організація або користувач вже існує", category='error')
            return redirect(url_for('views.register_organization'))

        new_org = Organization(name=org_name)
        db.session.add(new_org)
        db.session.flush()

        new_admin = User(
            email=admin_email,
            password_hash=generate_password_hash(password),
            role='admin',
            organization_id=new_org.id
        )
        db.session.add(new_admin)
        db.session.commit()

        flash('Організація зареєстрована, адмін створений!', category='success')
        return redirect(url_for('views.login'))

    return render_template('register_organization.html')



@views.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Тільки адміністратор може додавати користувачів', category='error')
        return redirect(url_for('views.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = 'user'

        if not email or not password:
            flash("Усі поля обов'язкові", category='error')
            return redirect(url_for('views.add_user'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Користувач з таким email вже існує", category='error')
            return redirect(url_for('views.add_user'))

        new_user = User(
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            organization_id=current_user.organization_id
        )
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('views.dashboard'))

    return render_template('add_user.html')





from datetime import datetime

@views.route('/devices')
@login_required
def devices():
    devices = Device.query.all()
    return render_template('devices.html', devices=devices, now=datetime.now())

@views.route('/add_device', methods=['GET', 'POST'])
@login_required
def add_device():
    if request.method == 'POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')

        if not name or not ip_address:
            flash("Будь ласка, заповніть всі поля", category="error")
            return redirect(url_for('views.add_device'))

        new_device = Device(
            name=name,
            ip_address=ip_address,
            organization_id=current_user.organization_id
        )
        db.session.add(new_device)
        db.session.commit()

        return redirect(url_for('views.devices'))

    return render_template('add_device.html')

# API для отримання логів у JSON
@views.route('/logs')
@login_required
def get_logs():
    logs = Log.query.filter_by(organization_id=current_user.organization_id)\
                    .order_by(Log.created_at.desc()).all()

    device_map = {d.id: d.name for d in Device.query.filter_by(organization_id=current_user.organization_id).all()}

    return jsonify([{
        'id': log.id,
        'device_id': log.device_id,
        'device_name': device_map.get(log.device_id, 'Невідомий пристрій'),
        #'organization_name': log.organization_name,
        #'organization_id': log.organization_id,
        'event_type': log.event_type,
        'severity': log.severity,
        'details': log.details,
        'created_at': log.created_at.isoformat()
    } for log in logs])




@views.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('views.dashboard')) 
        else:
            flash('Невірний email або пароль.', category='error')
            ###
        ip = request.remote_addr
        if BlockedIP.query.filter_by(ip_address=ip).first():
            flash("Вашу IP-адресу тимчасово заблоковано", category="error")
            return render_template('login.html')


    return render_template('login.html')




from flask_login import logout_user

@views.route('/logout')
@login_required
def logout():
    logout_user()
    flash(" Ви вийшли з системи", category="info")
    return redirect(url_for('views.login'))

@views.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash("Доступ лише для адміністратора", category='error')
        return redirect(url_for('views.dashboard'))

    users = User.query.filter_by(organization_id=current_user.organization_id).all()
    return render_template('users.html', users=users)



@views.route('/')
def index():
    if current_user.is_authenticated:
        logs = Log.query.filter_by(organization_id=current_user.organization_id)\
                        .order_by(Log.created_at.desc()).all()
        return render_template('index.html', logs=logs)
    return render_template('welcome.html')


@views.route('/dashboard')
@login_required
def dashboard():
    logs = Log.query.join(Device).filter_by(organization_id=current_user.organization_id)\
                .add_columns(Device.name.label('device_name'))\
                .order_by(Log.created_at.desc()).all()

    return render_template('index.html', logs=logs)




#

from flask import request
from .models import BlockedIP, Log


@views.route('/send_log', methods=['POST'])
def send_log():
    ip = request.remote_addr

    if BlockedIP.query.filter_by(ip_address=ip).first():
        return jsonify({'error': 'Your IP is temporarily blocked'}), 403

    data = request.get_json()
    device_id = data.get('device_id')
    event_type = data.get('event_type')
    severity = data.get('severity', 'info')
    details = data.get('details', '')
    organization_id = data.get('organization_id')  
    
    if not device_id or not event_type or not organization_id:
        return jsonify({'error': 'Missing required fields'}), 400
        
    device = Device.query.get(device_id)
    if not device or str(device.organization_id) != str(organization_id):
        return jsonify({'error': 'Invalid device or organization'}), 404

    if event_type.lower() == 'ddos':
        db.session.add(BlockedIP(ip_address=ip))
        db.session.commit()
        return jsonify({'status': 'DDoS detected — IP blocked'}), 200

    log = Log(
        device_id=device_id,
        event_type=event_type,
        severity=severity,
        details=details,
        organization_id=organization_id 
    )
    db.session.add(log)
    db.session.commit()
    return jsonify({'status': 'Log saved'}), 201



@views.route('/blocked_ips')
@login_required
def blocked_ips():
    if current_user.role != 'admin':
        flash('Доступ лише адміну', 'error')
        return redirect(url_for('views.dashboard'))
    blocked = BlockedIP.query.all()
    return render_template('blocked_ips.html', ips=blocked)

@views.route('/unblock_ip/<ip>')
@login_required
def unblock_ip(ip):
    if current_user.role != 'admin':
        flash('Недостатньо прав', 'error')
        return redirect(url_for('views.dashboard'))
    blocked = BlockedIP.query.filter_by(ip_address=ip).first()
    if blocked:
        db.session.delete(blocked)
        db.session.commit()
        flash(f'✅ IP {ip} розблоковано', 'success')
    return redirect(url_for('views.blocked_ips'))


@views.route('/block_ip/<ip>', methods=['GET', 'POST'])  
@login_required
def block_ip(ip):
    if current_user.role != 'admin':
        flash('Недостатньо прав', 'error')
        return redirect(url_for('views.dashboard'))

    if not BlockedIP.query.filter_by(ip_address=ip).first():
        blocked_ip = BlockedIP(
            ip_address=ip,
            reason="Manual block from dashboard",
            blocked_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(blocked_ip)
        db.session.commit()

        return jsonify({'status': 'success', 'message': f'IP {ip} blocked'}), 200
    else:
        flash(f'⚠️ IP {ip} вже заблокований', 'warning')
        return jsonify({'status': 'exists', 'message': f'IP {ip} already blocked'}), 200



from uuid import UUID

@views.route('/delete_user/<string:user_id>')
@login_required
def delete_user(user_id):
    try:
        UUID(user_id, version=4)  
    except ValueError:
        flash('❌ Недійсний UUID', 'error')
        return redirect(url_for('views.users'))

    user = User.query.get(user_id)
    if not user:
        flash('❌ Користувача не знайдено', 'error')
    elif user.id == current_user.id:
        flash('Неможливо видалити себе', 'error')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('✅ Користувача видалено', 'success')

    return redirect(url_for('views.users'))




@views.route('/delete_device/<string:device_id>')
@login_required
def delete_device(device_id):
    if current_user.role != 'admin':
        flash('⛔ Недостатньо прав', 'error')
        return redirect(url_for('views.devices'))

    device = Device.query.get(device_id)
    if not device:
        flash('❌ Пристрій не знайдено', 'error')
    else:
        db.session.delete(device)
        db.session.commit()
        flash(f'🗑 Пристрій {device.name} видалено', 'success')

    return redirect(url_for('views.devices'))











from datetime import datetime, timedelta

@views.route('/simulate_login_failure', methods=['POST'])
def simulate_login_failure():
    data = request.json
    ip_address = data.get('ip_address')
    user_email = data.get('email')
    org_id = data.get('organization_id')

    organization = Organization.query.get(org_id)
    if not organization:
        return jsonify({'error': 'Organization not found'}), 404

    device = Device.query.filter_by(ip_address=ip_address).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    if BlockedIP.query.filter_by(ip_address=ip_address).first():
        return jsonify({'error': 'This IP is blocked'}), 403

    new_log = Log(
        device_id=device.id,
        organization_id=org_id,
        event_type='login_failure',
        severity='high',
        details={
            'email': user_email,
            'ip': ip_address,
            'reason': 'Invalid password attempt'
        }
    )
    db.session.add(new_log)
    db.session.commit()

    time_threshold = datetime.utcnow() - timedelta(minutes=10)
    recent_failures = Log.query.filter(
        Log.event_type == 'login_failure',
        Log.details['ip'].astext == ip_address,
        Log.created_at >= time_threshold
    ).count()

    if recent_failures >= 5:
        db.session.add(BlockedIP(ip_address=ip_address))
        db.session.commit()
        return jsonify({'message': f'IP {ip_address} blocked due to brute-force'}), 403

    return jsonify({'message': 'Login failure logged'}), 200








from flask_login import login_required, current_user
from sqlalchemy.orm import Session
from .utils.reports import send_report
from . import db  

from flask import Blueprint, render_template, jsonify, request, flash
from .utils.bot import send_report, generate_report_text  


from flask import send_file
import os

@views.route('/generate_report', methods=["POST"])
@login_required
def generate_report():
    try:
        logs = Log.query.filter_by(organization_id=current_user.organization_id).all()
        
        report_message = generate_report_text(logs)  
        
        report_file_path = os.path.join('tmp', 'report.txt')

        os.makedirs('tmp', exist_ok=True)
        
        with open(report_file_path, 'w') as f:
            f.write(report_message)
        
        send_report(report_file_path)
        
        
        os.remove(report_file_path)

        return jsonify({"success": True})
    
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

























