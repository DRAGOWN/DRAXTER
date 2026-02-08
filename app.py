import os
import subprocess
import re
import imgkit
import shutil
import shlex
import xml.etree.ElementTree as ET
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from ansi2html import Ansi2HTMLConverter

app = Flask(__name__)
conv = Ansi2HTMLConverter(dark_bg=True, line_wrap=False, inline=True)

# --- DYNAMIC SETTINGS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# All results, exports, and screenshots live here
SCANS_DIR = os.path.join(BASE_DIR, 'scans')
os.makedirs(SCANS_DIR, exist_ok=True)

app.config.update(
    SECRET_KEY='0i-G]3FTC*f2&V£o-0$y}-L0£,omm>Rm_ZRBG1;;K#]<rMWM>S',
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(BASE_DIR, 'draxter.db'),
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
        return render_template('error.html', code=401, title="Login Failed", message="Invalid operator credentials."), 401
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

@app.route('/execute_capture', methods=['POST'])
@login_required
def execute_capture():
    data = request.json
    
    # 1. Command Preparation
    raw_template = data.get('command', '').strip()
    cmd_template = raw_template.replace('\xa0', ' ').replace('&nbsp;', ' ')
    
    # Get Project/Target info
    project = data.get('project', 'General').strip()
    subproject = data.get('subproject', 'Default').strip()
    target = data.get('single_target', '').strip()
    password = data.get('password', '').strip()

    # Safe mapping logic
    port_val = str(data.get('port', ''))
    mapping = {
        "[TARGET]": target,
        "[PORT]": port_val,
        "[:PORT]": f":{port_val}" if port_val and port_val != '0' else "",
        "[PROTO]": data.get('protocol', 'http'),
        "[URL]": f"{data.get('protocol')}://{target}{':' + port_val if port_val and port_val != '0' else ''}",
        "[USER]": data.get('user', ''),
        "[PASS]": password,
        "[DOMAIN]": data.get('domain', ''),
        "[-D]": f"-d {data.get('domain')}" if data.get('domain') else ""
    }

    exec_cmd = cmd_template
    for key, val in mapping.items():
        exec_cmd = exec_cmd.replace(key, val)

    # 2. STRICT TOOL DIRECTORY LOGIC
    try:
        cmd_parts = shlex.split(exec_cmd)
        if '&&' in cmd_parts:
            # Handle chained commands
            last_and_idx = len(cmd_parts) - 1 - cmd_parts[::-1].index('&&')
            base_tool = cmd_parts[last_and_idx + 1] if (last_and_idx + 1) < len(cmd_parts) else cmd_parts[0]
        else:
            base_tool = cmd_parts[0]

        base_tool = os.path.basename(base_tool).lower()

        # SMART NXC SPLIT
        if base_tool == "nxc" and len(cmd_parts) > 1:
            proto = cmd_parts[1].lower()   
            tool_name = f"nxc_{proto}"
        else:
            tool_name = base_tool

    except Exception:
        tool_name = "manual_exec"

    # FORCE PATH: DRAXTER/scans/ToolName
    tool_dir = os.path.join(SCANS_DIR, tool_name)
    os.makedirs(tool_dir, exist_ok=True)
    
    # 3. Execution
    try:
        env = os.environ.copy()
        env.update({"TERM": "xterm-256color", "CLICOLOR_FORCE": "1"})
        
        # Run inside the SCANS_DIR
        process = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=300, cwd=SCANS_DIR, env=env)
        
        # Get RAW output (Stdout + Stderr)
        raw_output = (process.stdout + "\n" + process.stderr).strip()

        # UI Masking (Only affects HTML/Screenshot, NOT the text file usually)
        # If you want passwords masked in the text file too, move this block up.
        clean_html_fragment = conv.convert(raw_output, full=False)
        display_command = exec_cmd
        
        if password and len(password) > 1:
            display_command = display_command.replace(password, '********')
            clean_html_fragment = clean_html_fragment.replace(password, '********')
            # Optional: Mask password in txt file too for safety
            # raw_output = raw_output.replace(password, '********') 

        # File Naming
        timestamp = datetime.now().strftime("%H%M%S")
        safe_target = target.replace(':', '_').replace('.', '_').replace('/', '_')
        
        # Define Filenames
        base_filename = f"{tool_name}_{safe_target}_{timestamp}"
        png_filename = f"{base_filename}.png"
        txt_filename = f"{base_filename}.txt"
        
        full_screenshot_path = os.path.join(tool_dir, png_filename)
        full_txt_path = os.path.join(tool_dir, txt_filename)

        # --- SAVE TEXT OUTPUT ---
        with open(full_txt_path, 'w', encoding='utf-8') as f:
            f.write(f"COMMAND: {exec_cmd}\n")
            f.write("-" * 40 + "\n")
            f.write(raw_output)

        # --- SAVE SCREENSHOT ---
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ background-color: #1a1c1e; margin: 0; padding: 30px; display: inline-block; }}
                .terminal-window {{ background-color: #0d0f11; border-radius: 10px; border: 1px solid #45494e; font-family: 'DejaVu Sans Mono', monospace; min-width: 1200px; box-shadow: 0 30px 60px rgba(0,0,0,0.5); overflow: hidden; }}
                .header {{ background-color: #26292c; padding: 10px 15px; border-bottom: 1px solid #3e4246; color: #aaa; font-size: 11px; }}
                .body {{ padding: 25px; color: #f1f1f1; font-size: 12px; line-height: 1.4; }}
                .output {{ white-space: pre !important; display: block; margin-top: 15px; font-size: 11px; color: #d1d1d1; }}
                .prompt {{ color: #2ecc71; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="terminal-window">
                <div class="header">kali@draxter: ~/scans/{tool_name}/</div>
                <div class="body">
                    <div class="prompt">└─$ <span style="color:#fff;">{display_command}</span></div>
                    <div class="output">{clean_html_fragment}</div>
                </div>
            </div>
        </body>
        </html>
        """
        imgkit.from_string(html_content, full_screenshot_path, options={'quiet': '', 'width': 1300, 'zoom': '0.9'})
        
        return jsonify({
            'status': 'success', 
            'filename': png_filename, 
            'txt_filename': txt_filename, # Return this so UI knows about it
            'path': tool_name,
            'target': target
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    p, s = request.form.get('project'), request.form.get('subproject')
    if not p or not s: return redirect(url_for('index'))
    
    # --- DYNAMIC DIR CREATION ---
    # Create DRAXTER/scans/Project/Subproject
    subproject_path = SCANS_DIR
    os.makedirs(subproject_path, exist_ok=True)

    files = request.files.getlist('files[]')
    for f in files:
        if f.filename.endswith('.xml') or f.filename.endswith('.nessus'):
            # Save a copy of the raw file in the scan directory
            f.save(os.path.join(SCANS_DIR, f.filename))
            f.seek(0) # Reset pointer for parsing
            
            try:
                tree = ET.parse(f)
                root = tree.getroot()
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
                elif 'NessusClientData' in root.tag:
                     for report_host in root.findall('.//ReportHost'):
                        ip = report_host.get('name')
                        os_name = "Unknown"
                        for item in report_host.findall('ReportItem'):
                            if item.get('port') != "0":
                                db.session.add(ScanResult(
                                    project=p, subproject=s, ip=ip,
                                    port=item.get('port'), protocol=item.get('protocol'),
                                    service=item.get('svc_name'),
                                    os=os_name, note="Imported from Nessus"
                                ))
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

@app.route('/save_to_disk', methods=['POST'])
@login_required
def save_to_disk():
    data = request.json
    project = data.get('project', 'General')
    subproject = data.get('subproject', 'Exports')
    filename = data.get('filename', 'export.txt')
    lines = data.get('ips', [])

    target_dir = SCANS_DIR
    os.makedirs(target_dir, exist_ok=True)
    full_path = os.path.join(target_dir, filename)

    try:
        with open(full_path, 'w') as f:
            f.write("\n".join(lines))
        return jsonify(status='success', full_path=full_path)
    except Exception as e:
        return jsonify(status='error', message=str(e))

@app.route('/save_xlsx', methods=['POST'])
@login_required
def save_xlsx():
    d = request.json
    df = pd.DataFrame(d['rows'])
    if df.empty: return jsonify(status='error', message='No data')
    
    cols_to_include = d.get('columns', [])
    final_df = df[cols_to_include]
    
    target_dir = SCANS_DIR
    os.makedirs(target_dir, exist_ok=True)
    out_path = os.path.join(target_dir, f"Inventory_{datetime.now().strftime('%Y%m%d')}.xlsx")
    
    final_df.to_excel(out_path, index=False)
    return jsonify(status='success', full_path=out_path)

@app.route('/browse/')
@app.route('/browse/<path:p>')
@login_required
def browse(p=''):
    # Browse inside the scans directory for safety and focus
    target_path = os.path.join(SCANS_DIR, p)
    if not os.path.exists(target_path): abort(404)
    
    parts = p.split('/') if p else []
    breadcrumbs = []
    curr_path = ""
    for part in parts:
        curr_path = os.path.join(curr_path, part)
        breadcrumbs.append({'name': part, 'path': curr_path.replace("\\", "/")})
    
    items = []
    for e in os.scandir(target_path):
        items.append({
            "name": e.name, 
            "is_dir": e.is_dir(), 
            "rel": os.path.relpath(e.path, SCANS_DIR).replace("\\", "/")
        })
    return render_template('browse.html', items=items, breadcrumbs=breadcrumbs, current_path=p)

@app.route('/get_file/<path:filename>')
@login_required
def get_file(filename):
    # Serve files specifically from the scans directory
    return send_from_directory(SCANS_DIR, filename)

@app.route('/delete_item', methods=['POST'])
@login_required
def delete_item():
    data = request.json
    rel_path = data.get('path')

    if not rel_path:
        return jsonify(status='error', message='No path provided')

    # Absolute safe path
    target_path = os.path.join(SCANS_DIR, rel_path)

    # Security check: block traversal
    real_scans = os.path.realpath(SCANS_DIR)
    real_target = os.path.realpath(target_path)
    if not real_target.startswith(real_scans):
        return jsonify(status='error', message='Invalid path')

    try:
        if os.path.isfile(real_target):
            os.remove(real_target)
        elif os.path.isdir(real_target):
            shutil.rmtree(real_target)
        else:
            return jsonify(status='error', message='Path not found')

        return jsonify(status='success')
    except Exception as e:
        return jsonify(status='error', message=str(e))

@app.route('/delete_rows_bulk', methods=['POST'])
@login_required
def delete_rows_bulk():
    data = request.json
    ids = data.get('ids', [])

    if not ids:
        return jsonify(status='error', message='No IDs provided')

    try:
        ScanResult.query.filter(ScanResult.id.in_(ids)).delete(synchronize_session=False)
        db.session.commit()
        return jsonify(status='success')
    except Exception as e:
        db.session.rollback()
        return jsonify(status='error', message=str(e))

''' '''

@app.route('/run_batch', methods=['POST'])
@login_required
def run_batch():
    data = request.json
    jobs = data.get('jobs', [])
    
    if not jobs:
        return jsonify({'status': 'error', 'message': 'No jobs received'})

    executed_count = 0
    
    for job in jobs:
        try:
            # 1. Parse Job Details
            target = job.get('target')
            exec_cmd = job.get('command')
            
            # Simple tool name extraction for folder organization
            # Uses the first word of command (e.g. 'nmap', 'gowitness')
            tool_name = exec_cmd.split()[0].lower() if exec_cmd else "batch_tool"
            tool_dir = os.path.join(SCANS_DIR, tool_name)
            os.makedirs(tool_dir, exist_ok=True)

            # 2. Execute Command
            # We set environment variables for color support
            env = os.environ.copy()
            env.update({"TERM": "xterm-256color", "CLICOLOR_FORCE": "1"})
            
            process = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=300, cwd=SCANS_DIR, env=env)
            raw_output = (process.stdout + "\n" + process.stderr).strip()

            # 3. Create Screenshot
            clean_html = conv.convert(raw_output, full=False)
            timestamp = datetime.now().strftime("%H%M%S")
            safe_target = str(target).replace(':', '_').replace('.', '_')
            filename = f"batch_{tool_name}_{safe_target}_{timestamp}.png"
            full_path = os.path.join(tool_dir, filename)

            html_content = f"""
            <html><body style="background-color: #1a1c1e; padding: 20px; color: #f1f1f1; font-family: monospace;">
                <div style="border: 1px solid #45494e; padding: 15px; background: #0d0f11;">
                    <div style="color: #2ecc71;">└─$ {exec_cmd}</div>
                    <pre style="font-size: 11px;">{clean_html}</pre>
                </div>
            </body></html>
            """
            
            # Save the image
            imgkit.from_string(html_content, full_path, options={'quiet': '', 'width': 1200})
            
            executed_count += 1

        except Exception as e:
            print(f"Error executing job for {target}: {e}")
            # We continue to the next job even if one fails
            continue 

    # This return value is what tells the JavaScript to update the counter to "1/1"
    return jsonify({
        'status': 'success', 
        'count': executed_count
    })

''' '''


@app.errorhandler(401)
def unauthorized(e): return render_template('error.html', code=401, title="Unauthorized", message="Credentials required."), 401
@app.errorhandler(404)
def page_not_found(e): return render_template('error.html', code=404, title="Not Found", message="Path does not exist."), 404


if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, host='127.0.0.1', port=5000, ssl_context=('cert.pem', 'key.pem'))
