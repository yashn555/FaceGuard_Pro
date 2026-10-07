"""
FaceGuard Pro - Admin Dashboard Server
Flask-based Web Server for monitoring logs, viewing captured photos, and managing Friend Access.
"""

import os
import sys
import json
import base64
import pickle
import sqlite3
from pathlib import Path
from datetime import datetime
import face_recognition
import numpy as np
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory

# Import path definitions from FaceGuard_Pro
APP_PATH = Path(os.environ.get('USERPROFILE', os.path.expanduser('~'))) / "FaceGuard"
PHOTO_PATH = APP_PATH / "photos"
DB_PATH = APP_PATH / "faceguard.db"
KNOWN_FACE_PATH = PHOTO_PATH / "known_face.pkl"

app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))

# Dynamic import of DatabaseManager and SecureStorage from FaceGuard_Pro
try:
    from FaceGuard_Pro import DatabaseManager, SecureStorage
except ImportError:
    # Inline fallback implementations if executed as standalone script
    from cryptography.fernet import Fernet

    class SecureStorage:
        def __init__(self):
            key_file = APP_PATH / "key.key"
            if key_file.exists():
                with open(key_file, 'rb') as f:
                    self.key = f.read()
            else:
                self.key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(self.key)
            self.cipher = Fernet(self.key)

        def encrypt_data(self, data):
            if isinstance(data, str):
                data = data.encode('utf-8')
            return self.cipher.encrypt(data)

        def decrypt_data(self, encrypted_data):
            return self.cipher.decrypt(encrypted_data)

    class DatabaseManager:
        def __init__(self, db_path=DB_PATH):
            self.db_path = db_path
            self.init_database()

        def init_database(self):
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    photo_path TEXT,
                    attempts INTEGER,
                    ip_address TEXT,
                    computer_name TEXT,
                    username TEXT,
                    notes TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS registered_faces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'friend',
                    face_encoding BLOB NOT NULL,
                    photo_path TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            ''')
            conn.commit()
            conn.close()

db = DatabaseManager()
storage = SecureStorage()

@app.route('/')
def index():
    """Render Admin Dashboard Home"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Return dashboard summary statistics"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM access_attempts")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM access_attempts WHERE status IN ('success', 'unlocked')")
    successful_unlocks = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM access_attempts WHERE status IN ('failed', 'shutdown') OR event_type = 'unauthorized'")
    unauthorized_attempts = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM registered_faces WHERE role != 'owner'")
    friends_count = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'total_logs': total_logs,
        'successful_unlocks': successful_unlocks,
        'unauthorized_attempts': unauthorized_attempts,
        'friends_count': friends_count,
        'computer_name': os.environ.get('COMPUTERNAME', 'Windows PC'),
        'username': os.environ.get('USERNAME', 'User'),
        'ip_address': db.get_ip_address() if hasattr(db, 'get_ip_address') else '127.0.0.1'
    })

@app.route('/api/logs')
def get_logs():
    """Return access activity logs"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, event_type, status, photo_path, attempts, ip_address, computer_name, username, notes
        FROM access_attempts
        ORDER BY id DESC
        LIMIT 100
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for r in rows:
        logs.append({
            'id': r[0],
            'timestamp': r[1],
            'event_type': r[2],
            'status': r[3],
            'photo_path': r[4],
            'attempts': r[5],
            'ip_address': r[6],
            'computer_name': r[7],
            'username': r[8],
            'notes': r[9]
        })
    
    return jsonify({'logs': logs})

@app.route('/api/photos/<path:filename>')
def serve_photo(filename):
    """Serve captured webcam photo securely"""
    p = Path(filename)
    if not p.is_absolute():
        p = PHOTO_PATH / filename
    if p.exists() and p.is_file():
        return send_file(str(p))
    return jsonify({'error': 'Photo not found'}), 404

@app.route('/api/friends')
def get_friends():
    """Get registered friend profiles"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, name, role, photo_path, is_active, created_at
        FROM registered_faces
        ORDER BY id ASC
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    friends = []
    for r in rows:
        rel_photo = ""
        if r[3]:
            rel_photo = Path(r[3]).name
        friends.append({
            'id': r[0],
            'name': r[1],
            'role': r[2],
            'photo_path': rel_photo,
            'is_active': bool(r[4]),
            'created_at': r[5]
        })
    
    return jsonify({'friends': friends})

@app.route('/api/friends/add', methods=['POST'])
def add_friend():
    """Register a new friend face profile"""
    try:
        name = request.form.get('name', '').strip()
        role = request.form.get('role', 'friend').strip().lower()
        
        if not name:
            return jsonify({'success': False, 'error': 'Name is required'}), 400
        
        temp_photo_path = None
        
        # Check photo upload vs webcam base64
        if 'photo' in request.files and request.files['photo'].filename != '':
            file = request.files['photo']
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            filename = f"friend_{name}_{timestamp}.jpg"
            save_path = PHOTO_PATH / filename
            file.save(str(save_path))
            temp_photo_path = str(save_path)
            
        elif 'photo_base64' in request.form and request.form['photo_base64']:
            base64_data = request.form['photo_base64']
            if ',' in base64_data:
                base64_data = base64_data.split(',')[1]
            img_bytes = base64.b64decode(base64_data)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            filename = f"friend_{name}_{timestamp}.jpg"
            save_path = PHOTO_PATH / filename
            with open(save_path, 'wb') as f:
                f.write(img_bytes)
            temp_photo_path = str(save_path)
        else:
            return jsonify({'success': False, 'error': 'No photo provided'}), 400
            
        # Extract face encoding
        image = face_recognition.load_image_file(temp_photo_path)
        face_locations = face_recognition.face_locations(image)
        
        if not face_locations:
            return jsonify({'success': False, 'error': 'No clear face detected in the photo. Please use a well-lit photo looking directly at the camera.'}), 400
            
        encodings = face_recognition.face_encodings(image, face_locations)
        if not encodings:
            return jsonify({'success': False, 'error': 'Could not encode face features'}), 400
            
        face_encoding = encodings[0]
        
        # Encrypt face encoding
        serialized = pickle.dumps(face_encoding)
        encrypted_blob = storage.encrypt_data(serialized)
        
        # Insert into DB
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO registered_faces (name, role, face_encoding, photo_path, is_active, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
        ''', (name, role, encrypted_blob, temp_photo_path, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': f'Friend "{name}" registered successfully!'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/friends/toggle', methods=['POST'])
def toggle_friend():
    """Enable or disable friend access"""
    data = request.json or {}
    face_id = data.get('id')
    is_active = data.get('is_active', 1)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE registered_faces SET is_active = ? WHERE id = ?', (is_active, face_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/friends/<int:face_id>', methods=['DELETE'])
def delete_friend(face_id):
    """Delete a registered friend profile"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if owner
    cursor.execute('SELECT role FROM registered_faces WHERE id = ?', (face_id,))
    res = cursor.fetchone()
    if res and res[0] == 'owner':
        conn.close()
        return jsonify({'success': False, 'error': 'Cannot delete Primary Owner profile'}), 400
        
    cursor.execute('DELETE FROM registered_faces WHERE id = ?', (face_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/lock', methods=['POST'])
def lock_pc():
    """Trigger manual PC workstation lock"""
    try:
        from ctypes import windll
        windll.user32.LockWorkStation()
        return jsonify({'success': True, 'message': 'Workstation locked'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Return all system settings dynamically from DB"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT key, value FROM settings')
        rows = cursor.fetchall()
        conn.close()
        settings = {r[0]: r[1] for r in rows}
        return jsonify({'success': True, 'settings': settings})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/settings', methods=['POST'])
def save_settings():
    """Save system settings dynamically to DB"""
    try:
        data = request.json or request.form.to_dict()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        for k, v in data.items():
            cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (k, str(v)))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Configuration updated dynamically!'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/test-email', methods=['POST'])
def test_email():
    """Test sending an email alert using current dynamic SMTP credentials"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT key, value FROM settings')
        settings = {r[0]: r[1] for r in cursor.fetchall()}
        conn.close()

        sender = settings.get('email_sender', '')
        password = settings.get('email_password', '')
        receiver = settings.get('email_receiver', '')

        if not sender or not password or not receiver:
            return jsonify({'success': False, 'error': 'Sender email, password, and receiver email must all be configured.'}), 400

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = receiver
        msg['Subject'] = '✅ FaceGuard Pro: Test Security Alert'

        body = f"""
        <h2>✅ FaceGuard Pro Test Alert</h2>
        <p>This is a test security alert to verify your dynamic email configuration.</p>
        <p><strong>Sender:</strong> {sender}</p>
        <p><strong>Receiver:</strong> {receiver}</p>
        <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        """
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender, password)
        server.send_message(msg)
        server.quit()

        return jsonify({'success': True, 'message': f'Test email sent successfully to {receiver}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def run_server(port=5000):
    print(f"\n🌐 FaceGuard Pro Admin Dashboard running at: http://127.0.0.1:{port}")
    app.run(host='127.0.0.1', port=port, debug=False)

if __name__ == '__main__':
    run_server()
