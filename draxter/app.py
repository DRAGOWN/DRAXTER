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
BASE_DIR = "/home/kali/draxter/scans"
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
        return "Invalid credentials", 401
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

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    p, s = request.form.get('project'), request.form.get('subproject')
    if not p or not s: return redirect(url_for('index'))

    os.makedirs(os.path.join(BASE_DIR, p, s), exist_ok=True)
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
    p_name = data.get('project')
    s_name = data.get('subproject') # Might be null
    
    if s_name:
        # DELETE SUBPROJECT ONLY
        ScanResult.query.filter_by(project=p_name, subproject=s_name).delete()
        path = os.path.join(BASE_DIR, p_name, s_name)
    else:
        # DELETE ENTIRE PROJECT
        ScanResult.query.filter_by(project=p_name).delete()
        path = os.path.join(BASE_DIR, p_name)

    db.session.commit()
    if os.path.exists(path):
        shutil.rmtree(path)
        
    return jsonify(status='success')

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
    return jsonify(status='success', path=out_path)

# --- FILE BROWSER ---
@app.route('/browse')
@app.route('/browse/<path:p>')
@login_required
def browse(p=""):
    full = os.path.join(BASE_DIR, p)
    items = []
    if os.path.exists(full) and os.path.isdir(full):
        for e in os.scandir(full):
            items.append({
                "name": e.name, "is_dir": e.is_dir(), 
                "rel": os.path.relpath(e.path, BASE_DIR).replace("\\", "/")
            })
    return render_template('browse.html', items=items, current=p)

@app.route('/get_file/<path:filepath>')
@login_required
def get_file(filepath):
    return send_from_directory(BASE_DIR, filepath)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='127.0.0.1', port=5000, ssl_context=('cert.pem', 'key.pem'))
