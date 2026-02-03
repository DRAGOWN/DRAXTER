import os
import subprocess
import re
import imgkit
import shutil
import xml.etree.ElementTree as ET
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

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
        return render_template('error.html', code=401, title="Login Failed", message="Invalid operator credentials. Access attempt logged."), 401
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

@app.route('/execute_command', methods=['POST'])
@login_required
def execute_command():
    data = request.json
    cmd = data.get('command')
    if not cmd:
        return jsonify({'status': 'error', 'message': 'No command provided'}), 400
    try:
        subprocess.Popen(cmd, shell=True, stdout=None, stderr=None, start_new_session=True)
        return jsonify({'status': 'success', 'message': 'Execution started in background.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/execute_capture', methods=['POST'])
@login_required
def execute_capture():
    data = request.json
    command = data.get('command', '').strip()
    base_project_path = data.get('path', '')
    tool_type = data.get('tool_type', 'general')
    raw_password = data.get('password', '')

    # 1. Directory Setup (handles nxc_webdav specifically)
    if tool_type.startswith('nxc_'):
        tool_folder = os.path.join(base_project_path, 'nxc', tool_type)
    else:
        tool_folder = os.path.join(base_project_path, tool_type)
    
    os.makedirs(tool_folder, exist_ok=True)

    try:
        # 2. Command Execution
        process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        output = (process.stdout + "\n" + process.stderr).strip()
        
        # --- SANITIZATION ---
        display_command = command
        clean_output = output.replace('<', '&lt;').replace('>', '&gt;')

        if raw_password and len(raw_password) > 1:
            display_command = display_command.replace(raw_password, '********')
            clean_output = clean_output.replace(raw_password, '********')
        
        mask_pattern = r'(-p|--password)\s+("[^"]*"|\'[^\']*\'|\S+)'
        display_command = re.sub(mask_pattern, r'\1 ********', display_command)

        # 3. Filename logic
        timestamp = datetime.now().strftime("%H%M%S")
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', command)
        target_ip = ip_match.group(0) if ip_match else "output"
        filename = f"{target_ip}_{timestamp}.png"
        full_output_path = os.path.join(tool_folder, filename)

        # 4. Terminal UI
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ background-color: #111111; margin: 0; padding: 30px; display: inline-block; }}
                .terminal-window {{ 
                    background-color: #1e1e1e; border-radius: 12px; border: 1px solid #333; 
                    font-family: 'monospace'; min-width: 800px; max-width: 1200px; overflow: hidden;
                    box-shadow: 0 20px 50px rgba(0,0,0,0.5);
                }}
                .terminal-header {{ 
                    background-color: #2d2d2d; padding: 12px 18px; display: flex; align-items: center;
                    border-bottom: 1px solid #3d3d3d;
                }}
                .dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
                .terminal-body {{ padding: 25px; color: #d1d1d1; font-size: 14px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }}
                .prompt {{ color: #38bdf8; font-weight: bold; }}
                .output {{ color: #4ade80; display: block; margin-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="terminal-window">
                <div class="terminal-header">
                    <div class="dot" style="background:#ff5f56;"></div>
                    <div class="dot" style="background:#ffbd2e;"></div>
                    <div class="dot" style="background:#27c93f;"></div>
                    <span style="color:#999; font-size:13px; margin-left:10px;">draxter@kali: ~/{tool_type}</span>
                </div>
                <div class="terminal-body">
                    <span class="prompt">$ </span><span>{display_command}</span>
                    <span class="output">{clean_output}</span>
                </div>
            </div>
        </body>
        </html>
        """

        # 5. Image Generation
        options = {'quiet': '', 'width': 1200, 'disable-smart-width': '', 'format': 'png'}
        imgkit.from_string(html_content, full_output_path, options=options)

        return jsonify({'status': 'success', 'filename': filename, 'folder': tool_type})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    p, s = request.form.get('project'), request.form.get('subproject')
    if not p or not s: return redirect(url_for('index'))
    subproject_path = os.path.join(BASE_DIR, p, s)
    os.makedirs(subproject_path, exist_ok=True)
    os.makedirs(os.path.join(subproject_path, 'gowitness'), exist_ok=True)
    os.makedirs(os.path.join(subproject_path, 'nxc'), exist_ok=True)

    files = request.files.getlist('files[]')
    for f in files:
        if f.filename.endswith('.xml'):
            try:
                tree = ET.parse(f)
                root = tree.getroot()
                for host in root.findall('host'):
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
    project, subproject, filename = data.get('project'), data.get('subproject'), data.get('filename')
    target_path = os.path.join(BASE_DIR, project)
    if subproject: target_path = os.path.join(target_path, subproject)
    if filename:
        target_path = os.path.join(target_path, filename)
        if os.path.exists(target_path) and os.path.isfile(target_path):
            os.remove(target_path)
            return jsonify({'status': 'success', 'message': 'File deleted'})
    if os.path.exists(target_path) and os.path.isdir(target_path):
        shutil.rmtree(target_path)
        if not subproject: ScanResult.query.filter_by(project=project).delete()
        else: ScanResult.query.filter_by(project=project, subproject=subproject).delete()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Directory deleted'})
    return jsonify({'status': 'error', 'message': 'Target not found'}), 404

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
        final = df.groupby('ip').agg({'combined': lambda x: '\n'.join(x), 'note': lambda x: ' | '.join(filter(None, set(x)))}).reset_index()
    else:
        final = df[d['columns']]
    out_path = os.path.join(BASE_DIR, d['project'], d['subproject'], "Draxter_Export.xlsx")
    final.to_excel(out_path, index=False)
    return jsonify({'status': 'success', 'full_path': os.path.abspath(out_path)})

@app.route('/browse/')
@app.route('/browse/<path:p>')
@login_required
def browse(p=''):
    target_path = os.path.join(BASE_DIR, p)
    if not os.path.exists(target_path): abort(404)
    parts = p.split('/') if p else []
    breadcrumbs = []
    curr_path = ""
    for part in parts:
        curr_path = os.path.join(curr_path, part)
        breadcrumbs.append({'name': part, 'path': curr_path.replace("\\", "/")})
    items = []
    for e in os.scandir(target_path):
        items.append({"name": e.name, "is_dir": e.is_dir(), "rel": os.path.relpath(e.path, BASE_DIR).replace("\\", "/")})
    return render_template('browse.html', items=items, breadcrumbs=breadcrumbs, current_path=p)

@app.route('/get_file/<path:filename>')
@login_required
def get_file(filename):
    return send_from_directory(BASE_DIR, filename)

@app.errorhandler(401)
def unauthorized(e): return render_template('error.html', code=401, title="Unauthorized", message="Credentials required."), 401

@app.errorhandler(404)
def page_not_found(e): return render_template('error.html', code=404, title="Not Found", message="Path does not exist."), 404

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=False, host='127.0.0.1', port=5000, ssl_context=('cert.pem', 'key.pem'))
