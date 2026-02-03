import os
import shutil
import xml.etree.ElementTree as ET
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- SETTINGS ---
BASE_DIR = "/home/kali/DRAXTER/scans"
os.makedirs(BASE_DIR, exist_ok=True)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config.update(
    SECRET_KEY='0i-G]3FTC*f2&V£o-0$y}-L0£,omm>Rm_ZRBG1;;K#]<rMWM>S',
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'draxter.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project = db.Column(db.String(100))
    subproject = db.Column(db.String(100))
    ip = db.Column(db.String(50))
    port = db.Column(db.String(10))
    protocol = db.Column(db.String(10))
    service = db.Column(db.String(100))
    os = db.Column(db.String(100))
    note = db.Column(db.Text, default="")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- AUTH ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter_by(username=request.form['username']).first()
        if u and check_password_hash(u.password, request.form['password']):
            login_user(u)
            return redirect(url_for('index'))
        
        # Instead of a simple string, return the error template for "Invalid Credentials"
        return render_template('error.html', 
            code=401, 
            title="Login Failed", 
            message="Invalid operator credentials. Access attempt logged."), 401
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- CORE ROUTES ---
@app.route('/')
@login_required
def index():
    return render_template('index.html', scan_data=ScanResult.query.all())

import subprocess

@app.route('/execute_command', methods=['POST'])
@login_required
def execute_command():
    data = request.json
    cmd = data.get('command')
    
    if not cmd:
        return jsonify({'status': 'error', 'message': 'No command provided'}), 400

    try:
        # Popen allows the command to run in the background 
        # so the web UI doesn't freeze while waiting for the scan
        subprocess.Popen(cmd, shell=True, stdout=None, stderr=None, start_new_session=True)
        
        return jsonify({'status': 'success', 'message': 'Execution started in background.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    p, s = request.form.get('project'), request.form.get('subproject')
    if not p or not s: return redirect(url_for('index'))

    # --- UPDATED LOGIC HERE ---
    # 1. Define the subproject path
    subproject_path = os.path.join(BASE_DIR, p, s)
    
    # 2. Create the subproject folder and the tool-specific folders
    os.makedirs(subproject_path, exist_ok=True)
    os.makedirs(os.path.join(subproject_path, 'gowitness'), exist_ok=True)
    os.makedirs(os.path.join(subproject_path, 'nxc'), exist_ok=True)
    # --------------------------

    files = request.files.getlist('files[]')
    
    for f in files:
        if f.filename.endswith('.xml'):
            try:
                tree = ET.parse(f)
                root = tree.getroot()
                for host in root.findall('host'):
                    # IP and OS detection
                    addr = host.find('address')
                    ip = addr.get('addr') if addr is not None else "Unknown"
                    
                    os_match = host.find('.//osmatch')
                    os_name = os_match.get('name') if os_match is not None else "Unknown"

                    for po in host.findall('.//port'):
                        state = po.find('state')
                        if state is not None and state.get('state') == 'open':
                            srv = po.find('service')
                            db.session.add(ScanResult(
                                project=p, subproject=s, ip=ip,
                                port=po.get('portid'), protocol=po.get('protocol'),
                                service=srv.get('name') if srv is not None else "unknown",
                                os=os_name, note=""
                            ))
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"[!] Error: {e}")
    return redirect(url_for('index'))

@app.route('/update_note', methods=['POST'])
@login_required
def update_note():
    data = request.json
    res = ScanResult.query.get(data.get('id'))
    if res:
        res.note = data.get('note', '')
        db.session.commit()
        return jsonify(status='success')
    return jsonify(status='error'), 400

@app.route('/delete_row/<int:id>', methods=['POST'])
@login_required
def delete_row(id):
    res = ScanResult.query.get(id)
    if res:
        db.session.delete(res)
        db.session.commit()
    return jsonify(status='success')

@app.route('/delete_project', methods=['POST'])
@login_required
def delete_project():
    data = request.json
    project = data.get('project')
    subproject = data.get('subproject')
    filename = data.get('filename') # New parameter from our JS

    # Base path to the project
    target_path = os.path.join(BASE_DIR, project)
    
    # If subproject is provided, move deeper into the path
    if subproject:
        target_path = os.path.join(target_path, subproject)
    
    # If a specific filename is provided, target ONLY that file
    if filename:
        target_path = os.path.join(target_path, filename)
        if os.path.exists(target_path) and os.path.isfile(target_path):
            os.remove(target_path)
            return jsonify({'status': 'success', 'message': 'File deleted'})
    
    # Corrected: os.path.isdir (no underscore)
    if os.path.exists(target_path) and os.path.isdir(target_path):
        shutil.rmtree(target_path)
        
        # Also cleanup the database if a whole project/subproject is deleted
        if not subproject:
            ScanResult.query.filter_by(project=project).delete()
        else:
            ScanResult.query.filter_by(project=project, subproject=subproject).delete()
        
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Directory deleted'})

    return jsonify({'status': 'error', 'message': 'Target not found'}), 404

# --- EXPORT ROUTES ---
@app.route('/save_to_disk', methods=['POST'])
@login_required
def save_to_disk():
    d = request.json
    target_dir = os.path.join(BASE_DIR, d['project'], d['subproject'])
    os.makedirs(target_dir, exist_ok=True)
    full_path = os.path.join(target_dir, d['filename'])
    with open(full_path, 'w') as f:
        f.write('\n'.join(d['ips']))
    return jsonify(status='success', full_path=full_path)

@app.route('/save_xlsx', methods=['POST'])
@login_required
def save_xlsx():
    d = request.json
    df = pd.DataFrame(d['rows'])
    if d.get('group_by_ip'):
        df['combined'] = df['protocol'] + "/" + df['port'].astype(str) + "/" + df['service']
        final = df.groupby('ip').agg({
            'combined': lambda x: '\n'.join(x), 
            'note': lambda x: ' | '.join(filter(None, set(x)))
        }).reset_index()
    else:
        final = df[d['columns']]
    
    out_path = os.path.join(BASE_DIR, d['project'], d['subproject'], "Draxter_Export.xlsx")
    final.to_excel(out_path, index=False)
    return jsonify({
    'status': 'success', 
    'full_path': os.path.abspath(full_path)})

# --- FILE BROWSER ---


@app.route('/browse/')
@app.route('/browse/<path:p>')
@login_required
def browse(p=''):
    target_path = os.path.join(BASE_DIR, p)
    if not os.path.exists(target_path):
        abort(404)

    # Generate breadcrumbs
    parts = p.split('/') if p else []
    breadcrumbs = []
    curr_path = ""
    for part in parts:
        curr_path = os.path.join(curr_path, part)
        breadcrumbs.append({'name': part, 'path': curr_path.replace("\\", "/")})

    entries = os.scandir(target_path)
    items = []
    for e in entries:
        items.append({
            "name": e.name, 
            "is_dir": e.is_dir(), 
            "rel": os.path.relpath(e.path, BASE_DIR).replace("\\", "/")
        })
    
    return render_template('browse.html', items=items, breadcrumbs=breadcrumbs, current_path=p)

@app.route('/get_file/<path:filename>')
@login_required
def get_file(filename):
    # This serves the file directly from your portable BASE_DIR (~/draxter_scans)
    return send_from_directory(BASE_DIR, filename)

# --- ERROR HANDLERS ---
@app.errorhandler(401)
def unauthorized(e):
    return render_template('error.html', 
        code=401, 
        title="Unauthorized", 
        message="Valid credentials required to access this node."), 401

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', 
        code=403, 
        title="Access Forbidden", 
        message="Your current clearance level does not allow access to this resource."), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', 
        code=404, 
        title="Target Not Found", 
        message="The requested path does not exist in the project filesystem."), 404



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='127.0.0.1', port=5000, ssl_context=('cert.pem', 'key.pem'))
