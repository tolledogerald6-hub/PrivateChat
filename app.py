
from flask import Flask, render_template, request, redirect, session, jsonify, send_from_directory, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os, time, json, hashlib, base64
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except Exception:
    AES = None

app = Flask(__name__)
app.secret_key = os.environ.get('CHAT_SECRET','CHANGE_ME_SECRET')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['IMAGE_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'],'images')
app.config['AUDIO_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'],'audio')
os.makedirs(app.config['IMAGE_FOLDER'], exist_ok=True)
os.makedirs(app.config['AUDIO_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(100))
    text = db.Column(db.Text)
    image = db.Column(db.String(300))
    audio = db.Column(db.String(300))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    seen = db.Column(db.Boolean, default=False)
    deleted = db.Column(db.Boolean, default=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(300))

DEFAULT_USERS = {'M':'1234','Y':'1234'}
ADMIN_PASS = os.environ.get('ADMIN_PASS','admin123')

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if 'user' not in session:
            return redirect('/')
        return f(*a, **kw)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if session.get('is_admin') != True:
            return redirect('/')
        return f(*a, **kw)
    return wrap

with app.app_context():
    db.create_all()
    for u,p in DEFAULT_USERS.items():
        if not User.query.filter_by(username=u).first():
            db.session.add(User(username=u, password_hash=hash_pw(p)))
    db.session.commit()

online = {}
typing_users = {}

@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        user = User.query.filter_by(username=u).first()
        if user and user.password_hash == hash_pw(p):
            session['user'] = u
            online[u] = True
            if request.form.get('admin_pass') == ADMIN_PASS:
                session['is_admin'] = True
            return redirect('/chat')
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    u = session.get('user')
    if u and u in online:
        online[u] = False
    session.clear()
    return redirect('/')

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', user=session['user'])

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user = session['user']
    old = request.form.get('old')
    new = request.form.get('new')
    uobj = User.query.filter_by(username=user).first()
    if uobj and uobj.password_hash == hash_pw(old):
        uobj.password_hash = hash_pw(new)
        db.session.commit()
        return jsonify({'ok':True})
    return jsonify({'ok':False}), 400

@app.route('/history')
@login_required
def history():
    msgs = Message.query.filter_by(deleted=False).order_by(Message.timestamp).all()
    out=[]
    for m in msgs:
        out.append({
            'id':m.id, 'sender':m.sender, 'text':m.text, 'image': url_for('uploaded_image', name=m.image) if m.image else None,
            'audio': url_for('uploaded_audio', name=m.audio) if m.audio else None,
            'timestamp': m.timestamp.isoformat(), 'seen':m.seen, 'deleted':m.deleted
        })
    return jsonify(out)

@app.route('/uploads/images/<name>')
def uploaded_image(name):
    return send_from_directory(app.config['IMAGE_FOLDER'], name)

@app.route('/uploads/audio/<name>')
def uploaded_audio(name):
    return send_from_directory(app.config['AUDIO_FOLDER'], name)

@app.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    f = request.files.get('image')
    if not f:
        return "NO"
    filename = secure_filename(f.filename)
    newname = f"img_{int(time.time())}_{filename}"
    path = os.path.join(app.config['IMAGE_FOLDER'], newname)
    f.save(path)
    try:
        from PIL import Image
        img = Image.open(path)
        img.thumbnail((800,800))
        img.save(path,optimize=True,quality=75)
    except Exception as e:
        print('img compress error', e)
    m = Message(sender=session['user'], image=newname)
    db.session.add(m); db.session.commit()
    socketio.emit('new_message', {'id':m.id,'sender':m.sender,'image': url_for('uploaded_image', name=newname), 'timestamp': m.timestamp.isoformat(),'seen':m.seen}, broadcast=True)
    return "OK"

@app.route('/upload_audio', methods=['POST'])
@login_required
def upload_audio():
    f = request.files.get('audio')
    if not f:
        return "NO"
    filename = secure_filename(f.filename)
    newname = f"aud_{int(time.time())}_{filename}"
    path = os.path.join(app.config['AUDIO_FOLDER'], newname)
    f.save(path)
    m = Message(sender=session['user'], audio=newname)
    db.session.add(m); db.session.commit()
    socketio.emit('new_message', {'id':m.id,'sender':m.sender,'audio': url_for('uploaded_audio', name=newname), 'timestamp': m.timestamp.isoformat(),'seen':m.seen}, broadcast=True)
    return "OK"

@app.route('/admin')
@admin_required
def admin_dashboard():
    msgs = Message.query.order_by(Message.timestamp.desc()).limit(200).all()
    return render_template('admin.html', msgs=msgs)

@app.route('/backup', methods=['POST'])
@admin_required
def backup():
    passphrase = request.form.get('pass','')
    if not passphrase:
        return "need pass", 400
    msgs = Message.query.filter_by(deleted=False).all()
    data = []
    for m in msgs:
        data.append({'id':m.id,'sender':m.sender,'text':m.text,'image':m.image,'audio':m.audio,'timestamp':m.timestamp.isoformat()})
    raw = json.dumps(data).encode('utf-8')
    if AES:
        key = hashlib.sha256(passphrase.encode()).digest()
        cipher = AES.new(key,AES.MODE_CBC)
        ct = cipher.encrypt(pad(raw, AES.block_size))
        payload = base64.b64encode(cipher.iv + ct).decode()
    else:
        payload = base64.b64encode(raw).decode()
    filename = f"backups/backup_{int(time.time())}.txt"
    with open(filename,'w') as f:
        f.write(payload)
    return jsonify({'file': filename})

@app.route('/auto_delete_old')
@admin_required
def auto_delete_old():
    days = int(request.args.get('days',30))
    cutoff = datetime.utcnow() - timedelta(days=days)
    old = Message.query.filter(Message.timestamp < cutoff).all()
    for m in old:
        m.deleted = True
    db.session.commit()
    return jsonify({'deleted': len(old)})

@socketio.on('connect')
def on_connect():
    user = session.get('user')
    if user:
        online[user] = True
        emit('online', online, broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    user = session.get('user')
    if user:
        online[user] = False
        emit('online', online, broadcast=True)

@socketio.on('send')
def on_send(data):
    if 'user' not in session: return
    txt = data.get('text','')
    m = Message(sender=session['user'], text=txt)
    db.session.add(m); db.session.commit()
    emit('new_message', {'id':m.id,'sender':m.sender,'text':m.text,'timestamp':m.timestamp.isoformat(),'seen':m.seen}, broadcast=True)

@socketio.on('delete')
def on_delete(data):
    mid = data.get('id')
    m = Message.query.get(mid)
    if m:
        m.deleted = True
        db.session.commit()
        emit('delete_message', {'id': mid}, broadcast=True)

@socketio.on('seen')
def on_seen(data):
    mid = data.get('id')
    m = Message.query.get(mid)
    if m:
        m.seen = True
        db.session.commit()
        emit('message_seen', {'id': mid}, broadcast=True)

@socketio.on('typing')
def on_typing(data):
    user = session.get('user')
    typing_users[user] = data.get('typing',False)
    emit('typing', {'user': user, 'typing': data.get('typing',False)}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
