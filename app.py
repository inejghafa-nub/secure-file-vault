import os
import re
import uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import text
from models import db, User, VaultFile, ShareLink, ActivityLog
from encryption import encrypt_file, decrypt_file
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-before-deployment')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.template_filter('filesize')
def filesize(value):
    size = int(value or 0)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f'{size:.0f} {unit}' if unit == 'B' else f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} TB'

def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append('at least 8 characters')
    if not re.search(r'[A-Z]', password):
        errors.append('one uppercase letter')
    if not re.search(r'[a-z]', password):
        errors.append('one lowercase letter')
    if not re.search(r'\d', password):
        errors.append('one number')
    if not re.search(r'[^A-Za-z0-9]', password):
        errors.append('one special character')
    return errors

def host_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('host_login'))
        if current_user.role != 'host':
            flash('Host access required.', 'error')
            return redirect(url_for('dashboard'))
        return view(*args, **kwargs)
    return wrapped

def user_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.role != 'user':
            return redirect(url_for('host_dashboard'))
        return view(*args, **kwargs)
    return wrapped

def ensure_database_ready():
    db.create_all()
    columns = db.session.execute(text("PRAGMA table_info(user)")).fetchall()
    column_names = {column[1] for column in columns}
    if 'role' not in column_names:
        db.session.execute(text("ALTER TABLE user ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'"))
        db.session.commit()

    file_columns = db.session.execute(text("PRAGMA table_info(vault_file)")).fetchall()
    file_column_names = {column[1] for column in file_columns}
    if 'file_size' not in file_column_names:
        db.session.execute(text("ALTER TABLE vault_file ADD COLUMN file_size INTEGER NOT NULL DEFAULT 0"))
    if 'content_type' not in file_column_names:
        db.session.execute(text("ALTER TABLE vault_file ADD COLUMN content_type VARCHAR(120) NOT NULL DEFAULT 'Unknown'"))
    if 'download_count' not in file_column_names:
        db.session.execute(text("ALTER TABLE vault_file ADD COLUMN download_count INTEGER NOT NULL DEFAULT 0"))
    db.session.commit()

    host = User.query.filter_by(username='host').first()
    if not host:
        host = User(
            username='host',
            password=generate_password_hash('Host@12345'),
            role='host'
        )
        db.session.add(host)
        db.session.commit()

    ActivityLog.query.filter(ActivityLog.action.like('Demo audit:%')).delete(synchronize_session=False)
    db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

# ---------- REGISTER ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('register'))
        password_errors = validate_password(password)
        if password_errors:
            flash('Password must contain ' + ', '.join(password_errors) + '.', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        user = User(username=username, password=hashed, role='user')
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.role == 'user' and check_password_hash(user.password, password):
            login_user(user)
            log = ActivityLog(user_id=user.id, action='User logged in')
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('dashboard'))
        db.session.add(ActivityLog(action=f'Failed user login attempt: {username or "blank"}'))
        db.session.commit()
        flash('Invalid credentials!', 'error')
    return render_template('login.html')

# ---------- HOST LOGIN ----------
@app.route('/host-login', methods=['GET', 'POST'])
def host_login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username, role='host').first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            log = ActivityLog(user_id=user.id, action='Host logged in')
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('host_dashboard'))
        db.session.add(ActivityLog(action=f'Failed host login attempt: {username or "blank"}'))
        db.session.commit()
        flash('Invalid host credentials!', 'error')
    return render_template('host_login.html')

# ---------- LOGOUT ----------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------- DASHBOARD ----------
@app.route('/dashboard')
@user_required
def dashboard():
    search = request.args.get('q', '').strip()
    file_query = VaultFile.query.filter_by(user_id=current_user.id)
    if search:
        file_query = file_query.filter(VaultFile.filename.ilike(f'%{search}%'))
    files = file_query.order_by(VaultFile.upload_time.desc()).all()
    all_files = VaultFile.query.filter_by(user_id=current_user.id).all()
    active_links = (
        ShareLink.query
        .join(VaultFile)
        .filter(
            VaultFile.user_id == current_user.id,
            ShareLink.expiry >= datetime.utcnow(),
            ShareLink.download_count < ShareLink.download_limit
        )
        .count()
    )
    stats = {
        'total_files': len(all_files),
        'total_size': sum(file.file_size or 0 for file in all_files),
        'downloads': sum(file.download_count or 0 for file in all_files),
        'active_links': active_links,
    }
    return render_template('dashboard.html', files=files, stats=stats, search=search)

# ---------- HOST DASHBOARD ----------
@app.route('/host-dashboard')
@host_required
def host_dashboard():
    stats = {
        'users': User.query.filter_by(role='user').count(),
        'files': VaultFile.query.count(),
        'links': ShareLink.query.count(),
        'logs': ActivityLog.query.count(),
        'failed_logins': ActivityLog.query.filter(ActivityLog.action.like('Failed%')).count(),
    }
    users = User.query.filter_by(role='user').order_by(User.id.desc()).all()
    files = VaultFile.query.order_by(VaultFile.upload_time.desc()).limit(20).all()
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(20).all()
    failed_logs = ActivityLog.query.filter(ActivityLog.action.like('Failed%')).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    return render_template('host_dashboard.html', stats=stats, users=users, files=files, logs=logs, failed_logs=failed_logs)

# ---------- UPLOAD ----------
@app.route('/upload', methods=['POST'])
@user_required
def upload():
    file = request.files.get('file')
    if not file or not file.filename:
        flash('Please choose a file to upload.', 'error')
        return redirect(url_for('dashboard'))
    if file:
        filename = secure_filename(file.filename)
        if not filename:
            flash('Invalid file name.', 'error')
            return redirect(url_for('dashboard'))
        data = file.read()
        encrypted_data = encrypt_file(data)
        stored_name = str(uuid.uuid4()) + '.enc'
        with open(os.path.join(app.config['UPLOAD_FOLDER'], stored_name), 'wb') as f:
            f.write(encrypted_data)
        vault_file = VaultFile(
            filename=filename,
            stored_name=stored_name,
            user_id=current_user.id,
            file_size=len(data),
            content_type=file.mimetype or 'Unknown'
        )
        db.session.add(vault_file)
        log = ActivityLog(user_id=current_user.id, action=f'Uploaded file: {filename}')
        db.session.add(log)
        db.session.commit()
        flash('File uploaded and encrypted successfully!', 'success')
    return redirect(url_for('dashboard'))

# ---------- DOWNLOAD ----------
@app.route('/download/<int:file_id>')
@user_required
def download(file_id):
    vault_file = VaultFile.query.get_or_404(file_id)
    if vault_file.user_id != current_user.id:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard'))
    with open(os.path.join(app.config['UPLOAD_FOLDER'], vault_file.stored_name), 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_file(encrypted_data)
    vault_file.download_count += 1
    log = ActivityLog(user_id=current_user.id, action=f'Downloaded file: {vault_file.filename}')
    db.session.add(log)
    db.session.commit()
    return send_file(io.BytesIO(decrypted_data), download_name=vault_file.filename, as_attachment=True)

# ---------- DELETE FILE ----------
@app.route('/delete-file/<int:file_id>', methods=['POST'])
@user_required
def delete_file(file_id):
    vault_file = VaultFile.query.get_or_404(file_id)
    if vault_file.user_id != current_user.id:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], vault_file.stored_name)
    ShareLink.query.filter_by(file_id=vault_file.id).delete()
    db.session.delete(vault_file)
    db.session.add(ActivityLog(user_id=current_user.id, action=f'Deleted file: {vault_file.filename}'))
    db.session.commit()

    if os.path.exists(file_path):
        os.remove(file_path)

    flash('File and related share links deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

# ---------- SHARE ----------
@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
@user_required
def share(file_id):
    vault_file = VaultFile.query.get_or_404(file_id)
    if vault_file.user_id != current_user.id:
        flash('Access denied!', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        hours = max(1, min(int(request.form.get('hours', 24)), 168))
        limit = max(1, min(int(request.form.get('limit', 5)), 100))
        token = str(uuid.uuid4())
        expiry = datetime.utcnow() + timedelta(hours=hours)
        link = ShareLink(token=token, file_id=file_id, expiry=expiry, download_limit=limit)
        db.session.add(link)
        log = ActivityLog(user_id=current_user.id, action=f'Created share link for: {vault_file.filename}')
        db.session.add(log)
        db.session.commit()
        share_url = url_for('shared_download', token=token, _external=True)
        flash(f'Share link created: {share_url}', 'success')
        return redirect(url_for('dashboard'))
    return render_template('share.html', file=vault_file)

# ---------- MANAGE SHARE LINKS ----------
@app.route('/share-links')
@user_required
def share_links():
    links = (
        ShareLink.query
        .join(VaultFile)
        .filter(VaultFile.user_id == current_user.id)
        .order_by(ShareLink.expiry.desc())
        .all()
    )
    return render_template('share_links.html', links=links, now=datetime.utcnow())

# ---------- REVOKE SHARE LINK ----------
@app.route('/revoke-link/<int:link_id>', methods=['POST'])
@user_required
def revoke_link(link_id):
    link = ShareLink.query.get_or_404(link_id)
    if link.file.user_id != current_user.id:
        flash('Access denied!', 'error')
        return redirect(url_for('share_links'))

    filename = link.file.filename
    db.session.delete(link)
    db.session.add(ActivityLog(user_id=current_user.id, action=f'Revoked share link for: {filename}'))
    db.session.commit()
    flash('Share link revoked successfully.', 'success')
    return redirect(url_for('share_links'))

# ---------- SHARED DOWNLOAD ----------
@app.route('/shared/<token>')
def shared_download(token):
    link = ShareLink.query.filter_by(token=token).first_or_404()
    if link.expiry and datetime.utcnow() > link.expiry:
        return 'This link has expired!', 403
    if link.download_count >= link.download_limit:
        return 'Download limit reached!', 403
    link.download_count += 1
    link.file.download_count += 1
    log = ActivityLog(action=f'Shared download: {link.file.filename} (token: {token})')
    db.session.add(log)
    db.session.commit()
    with open(os.path.join(app.config['UPLOAD_FOLDER'], link.file.stored_name), 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_file(encrypted_data)
    return send_file(io.BytesIO(decrypted_data), download_name=link.file.filename, as_attachment=True)

# ---------- LOGS ----------
@app.route('/logs')
@user_required
def logs():
    activity = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).all()
    return render_template('logs.html', logs=activity)

# ---------- CHANGE PASSWORD ----------
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))
        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'error')
            return redirect(url_for('change_password'))

        password_errors = validate_password(new_password)
        if password_errors:
            flash('Password must contain ' + ', '.join(password_errors) + '.', 'error')
            return redirect(url_for('change_password'))

        current_user.password = generate_password_hash(new_password)
        db.session.add(ActivityLog(user_id=current_user.id, action='Changed account password'))
        db.session.commit()
        flash('Password changed successfully.', 'success')
        if current_user.role == 'host':
            return redirect(url_for('host_dashboard'))
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

if __name__ == '__main__':
    with app.app_context():
        ensure_database_ready()
    app.run(debug=False)
