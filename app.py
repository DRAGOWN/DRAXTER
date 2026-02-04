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
from ansi2html import Ansi2HTMLConverter

app = Flask(__name__)
conv = Ansi2HTMLConverter(dark_bg=True, line_wrap=False, inline=True)

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
    command_template = data.get('command', '').strip()
    
    # 1. SANITIZE: Get the target and clean it
    raw_target = data.get('single_target', '')
    target = raw_target.strip().replace('\r', '').replace('\n', '')
    
    # FALLBACK: If target is empty, we check if it's a manual/single run
    if not target:
        target = "SINGLE_RUN"

    # 2. Path Handling: Ensure we use the absolute path from BASE_DIR
    relative_path = data.get('path', '')
    abs_project_path = os.path.join(BASE_DIR, relative_path)
    
    tool_type = data.get('tool_type', 'general')
    raw_password = data.get('password', '')

    if not command_template:
        return jsonify({'status': 'error', 'message': 'Empty command string'})

    # 3. Directory Setup
    tool_folder = os.path.join(abs_project_path, tool_type)
    os.makedirs(tool_folder, exist_ok=True)

    try:
        # 4. Flexible Command Construction
        if target != "SINGLE_RUN":
            if "sslscan" in command_template or tool_type == "sslscan":
                exec_cmd = f"sslscan {target}"
            elif "testssl" in command_template or tool_type == "testssl":
                exec_cmd = f"testssl.sh --color 1 --quiet --warnings off {target}"
            elif "gowitness" in command_template:
                exec_cmd = f"gowitness scan single -u https://{target}"
            else:
                # Replace the .txt filename in the command with the actual IP
                exec_cmd = re.sub(r'[\w\d_-]+\.txt', target, command_template)
        else:
            # If it's a single run, use the command as provided by the user
            exec_cmd = command_template

        # 5. Execution Environment
        env = os.environ.copy()
        env.update({"TERM": "xterm-256color", "CLICOLOR_FORCE": "1", "COLORTERM": "truecolor"})

        # Timeout: 300s (5 mins) for thorough scans
        process = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=300, cwd=abs_project_path, env=env)
        raw_output = (process.stdout + "\n" + process.stderr).strip()
        
        # 6. ANSI to HTML & Masking
        clean_html_fragment = conv.convert(raw_output, full=False)
        display_command = exec_cmd
        if raw_password and len(raw_password) > 1:
            display_command = display_command.replace(raw_password, '********')
            clean_html_fragment = clean_html_fragment.replace(raw_password, '********')

        # 7. Filename & Rendering
        timestamp = datetime.now().strftime("%H%M%S")
        safe_target = target.replace(':', '_').replace('.', '_').replace('/', '_')
        filename = f"{safe_target}_{timestamp}.png"
        full_output_path = os.path.join(tool_folder, filename)

        # Updated HTML Template (Wider for testssl results)
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ background-color: #1a1c1e; margin: 0; padding: 30px; display: inline-block; }}
                .terminal-window {{ 
                    background-color: #0d0f11; border-radius: 10px; border: 1px solid #45494e; 
                    font-family: 'DejaVu Sans Mono', monospace; min-width: 1200px;
                    box-shadow: 0 30px 60px rgba(0,0,0,0.5); overflow: hidden;
                }}
                .header {{ background-color: #26292c; padding: 10px 15px; border-bottom: 1px solid #3e4246; color: #aaa; font-size: 11px; }}
                .body {{ padding: 25px; color: #f1f1f1; font-size: 12px; line-height: 1.4; }}
                .output {{ white-space: pre !important; display: block; margin-top: 15px; font-size: 11px; color: #d1d1d1; }}
                .prompt {{ color: #2ecc71; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="terminal-window">
                <div class="header">kali@draxter: ~/{tool_type}</div>
                <div class="body">
                    <div class="prompt">└─$ <span style="color:#fff;">{display_command}</span></div>
                    <div class="output">{clean_html_fragment}</div>
                </div>
            </div>
        </body>
        </html>
        """

        imgkit.from_string(html_content, full_output_path, options={'quiet': '', 'width': 1300, 'zoom': '0.9'})
        
        return jsonify({'status': 'success', 'filename': filename, 'target': target})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    p, s = request.form.get('project'), request.form.get('subproject')
    if not p or not s: return redirect(url_for('index'))
    
    subproject_path = os.path.join(BASE_DIR, p, s)
    os.makedirs(subproject_path, exist_ok=True)
    # Ensure tool folders exist
    for tool in ['gowitness', 'nxc', 'sslscan', 'testssl']:
        os.makedirs(os.path.join(subproject_path, tool), exist_ok=True)

    files = request.files.getlist('files[]')
    for f in files:
        if f.filename.endswith('.xml') or f.filename.endswith('.nessus'):
            try:
                tree = ET.parse(f)
                root = tree.getroot()

                # --- CASE 1: NMAP XML ---
                if root.tag == 'nmaprun':
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
                                    os=os_name, note="Imported from Nmap"
                                ))

                # --- CASE 2: NESSUS XML (.nessus) ---
                elif 'NessusClientData' in root.tag:
                    for report_host in root.findall('.//ReportHost'):
                        ip = report_host.get('name') # Often the IP or Hostname
                        
                        # Extract OS from HostProperties
                        os_name = "Unknown"
                        properties = report_host.find('HostProperties')
                        if properties is not None:
                            for tag in properties.findall('tag'):
                                if tag.get('name') == 'operating-system':
                                    os_name = tag.text
                                if tag.get('name') == 'host-ip': # More accurate IP if name is a hostname
                                    ip = tag.text

                        # Process open ports/services from ReportItems
                        # We use a set to avoid duplicate port entries from different plugins
                        seen_ports = set()
                        for item in report_host.findall('ReportItem'):
                            port = item.get('port')
                            protocol = item.get('protocol')
                            svc_name = item.get('svc_name')
                            
                            # Nessus lists "port 0" for general host info; we only want real ports
                            if port != "0" and (port, protocol) not in seen_ports:
                                db.session.add(ScanResult(
                                    project=p, subproject=s, ip=ip,
                                    port=port, protocol=protocol,
                                    service=svc_name,
                                    os=os_name, note="Imported from Nessus"
                                ))
                                seen_ports.add((port, protocol))

                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"[!] Parsing Error: {e}")
                
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

@app.route('/get_targets', methods=['POST'])
@login_required
def get_targets():
    data = request.json
    filename = data.get('filename')
    project_path = data.get('path')
    
    # Construct absolute path using BASE_DIR if project_path is relative
    if not project_path.startswith('/'):
        file_path = os.path.join(BASE_DIR, project_path, filename)
    else:
        file_path = os.path.join(project_path, filename)
    
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            # Strip \r here too just in case
            targets = [line.strip().replace('\r', '') for line in f if line.strip()]
        return jsonify({'status': 'success', 'targets': targets})
    
    return jsonify({'status': 'error', 'message': f'File not found at {file_path}'})

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
