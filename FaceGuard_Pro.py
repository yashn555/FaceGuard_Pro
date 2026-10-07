"""
FaceGuard Pro - Complete Offline Face Recognition Security System
Features:
- Instant capture on wake
- Offline face recognition
- Email alerts with photo
- Local storage backup (if email fails)
- Fullscreen lock
- Password fallback
- 3 attempts → shutdown
"""

import cv2
import os
import sys
import time
import json
import shutil
import smtplib
import hashlib
import pickle
import sqlite3
import queue
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import tkinter as tk
from tkinter import messagebox, ttk
import face_recognition
import numpy as np
try:
    import win32api
    import win32con
    import win32gui
except ImportError:
    pass

from ctypes import windll, c_int, byref, sizeof, create_string_buffer
import tempfile
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class NullWriter:
    def write(self, s): pass
    def flush(self): pass

# Configure Windows console encoding / handle GUI pythonw environment
if sys.stdout is None:
    sys.stdout = NullWriter()
elif hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

if sys.stderr is None:
    sys.stderr = NullWriter()
elif hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


# ============================================
# CONFIGURATION
# ============================================
# Load from environment variables with secure defaults
# Create a .env file from .env.example and fill in your values
HARDCODED_PASSWORD = os.environ.get('FALLBACK_PASSWORD', 'CHANGE_ME')      # Fallback unlock password
EMAIL_SENDER = os.environ.get('EMAIL_SENDER', '')                        # YOUR GMAIL
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')                    # GMAIL APP PASSWORD
EMAIL_RECEIVER = os.environ.get('EMAIL_RECEIVER', '')                    # WHERE TO SEND ALERTS
MAX_ATTEMPTS = int(os.environ.get('MAX_ATTEMPTS', '3'))                  # Wrong attempts before shutdown
FACE_TOLERANCE = float(os.environ.get('FACE_TOLERANCE', '0.6'))          # Face match sensitivity (0.5-0.7)
# ============================================

# App paths - use environment variable or default to user profile
APP_PATH = Path(os.environ.get('APP_DATA_PATH', os.environ.get('USERPROFILE', os.path.expanduser('~')))) / "FaceGuard"
APP_PATH.mkdir(exist_ok=True)

# Data directories
PHOTO_PATH = APP_PATH / "photos"
PHOTO_PATH.mkdir(exist_ok=True)

LOG_PATH = APP_PATH / "logs"
LOG_PATH.mkdir(exist_ok=True)

BACKUP_PATH = APP_PATH / "backups"
BACKUP_PATH.mkdir(exist_ok=True)

# Database path
DB_PATH = APP_PATH / "faceguard.db"

# Known face storage
KNOWN_FACE_PATH = PHOTO_PATH / "known_face.pkl"

SINGLE_INSTANCE_MUTEX = None

def ensure_single_instance(mutex_name="Global\\FaceGuardPro_SingleInstance_Mutex"):
    """Ensure only one instance of FaceGuard Pro daemon runs at any given time"""
    global SINGLE_INSTANCE_MUTEX
    try:
        from ctypes import windll
        kernel32 = windll.kernel32
        SINGLE_INSTANCE_MUTEX = kernel32.CreateMutexW(None, False, mutex_name)
        last_error = kernel32.GetLastError()
        ERROR_ALREADY_EXISTS = 183
        if last_error == ERROR_ALREADY_EXISTS:
            print("⚠️ FaceGuard Pro is already running in the background. Exiting duplicate process.")
            return False
        return True
    except Exception as e:
        print(f"Single instance check warning: {e}")
        return True

class WindowsEventListener:
    """Listens for Windows power events (sleep/wake) and session events (lock/unlock)"""
    
    def __init__(self, trigger_callback):
        self.trigger_callback = trigger_callback
        self.hwnd = None
        self.thread = None
        self.running = False
        self.last_trigger_time = 0

        
    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        try:
            import win32gui
            from ctypes import Structure, c_ulong, c_ushort, c_ubyte, byref
            
            class POWER_GUID(Structure):
                _fields_ = [('Data1', c_ulong), ('Data2', c_ushort), ('Data3', c_ushort), ('Data4', c_ubyte * 8)]
            
            wc = win32gui.WNDCLASS()
            wc.hInstance = win32gui.GetModuleHandle(None)
            wc.lpszClassName = "FaceGuardEventListenerClass"
            wc.lpfnWndProc = self._wnd_proc
            
            try:
                win32gui.RegisterClass(wc)
            except Exception:
                pass
                
            self.hwnd = win32gui.CreateWindow(
                "FaceGuardEventListenerClass",
                "FaceGuardEventListenerWindow",
                0, 0, 0, 0, 0,
                0, 0, wc.hInstance, None
            )
            
            try:
                wtsapi32 = windll.wtsapi32
                NOTIFY_FOR_THIS_SESSION = 0
                wtsapi32.WTSRegisterSessionNotification(self.hwnd, NOTIFY_FOR_THIS_SESSION)
            except Exception as e:
                print(f"WTS notification warning: {e}")

            try:
                guid_display = POWER_GUID(0x6FE69556, 0x704A, 0x47A0, (c_ubyte * 8)(0x8F, 0x24, 0xC2, 0x8D, 0x93, 0x6F, 0xDA, 0x47))
                guid_monitor = POWER_GUID(0x02725F71, 0x45E0, 0x410A, (c_ubyte * 8)(0x98, 0x49, 0x34, 0x14, 0xE7, 0x2A, 0x56, 0x09))
                DEVICE_NOTIFY_WINDOW_HANDLE = 0
                windll.user32.RegisterPowerSettingNotification(self.hwnd, byref(guid_display), DEVICE_NOTIFY_WINDOW_HANDLE)
                windll.user32.RegisterPowerSettingNotification(self.hwnd, byref(guid_monitor), DEVICE_NOTIFY_WINDOW_HANDLE)
            except Exception as e:
                print(f"Power notification registration warning: {e}")
                
            win32gui.PumpMessages()
        except Exception as e:
            print(f"Event listener loop error: {e}")

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        try:
            import win32gui
            WM_WTSSESSION_CHANGE = 0x02B1
            WM_POWERBROADCAST = 0x0218
            
            WTS_SESSION_LOCK = 0x7
            WTS_SESSION_UNLOCK = 0x8
            WTS_CONSOLE_CONNECT = 0x1
            WTS_CONSOLE_DISCONNECT = 0x2
            
            PBT_APMRESUMEAUTOMATIC = 0x0012
            PBT_APMRESUMESUSPEND = 0x0007
            PBT_APMSUSPEND = 0x0004
            PBT_APMRESUMECUSTOM = 0x0018
            PBT_POWERSETTINGCHANGE = 0x8013

            now = time.time()
            if msg == WM_WTSSESSION_CHANGE:
                if wparam in (WTS_SESSION_LOCK, WTS_CONSOLE_DISCONNECT):
                    if now - self.last_trigger_time > 2.0:
                        self.last_trigger_time = now
                        print("🔒 Session lock detected!")
                        self.trigger_callback("session_lock")
            elif msg == WM_POWERBROADCAST:
                if wparam in (PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMRESUMECUSTOM, PBT_POWERSETTINGCHANGE):
                    if now - self.last_trigger_time > 2.0:
                        self.last_trigger_time = now
                        print("⚡ System wakeup / power change detected!")
                        self.trigger_callback("system_wake")
                    
            return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)
        except Exception:
            return 0

class DatabaseManager:
    """SQLite database for storing access attempts and photos"""
    
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Create tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create access log table
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
        
        # Create email queue table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                photo_path TEXT NOT NULL,
                subject TEXT,
                body TEXT,
                attempts INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                last_attempt TEXT
            )
        ''')

        # Create registered faces table for multi-user / friend access
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

        # Create settings table for dynamic configuration (no hardcoded constants)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        
        defaults = {
            'fallback_password': os.environ.get('FALLBACK_PASSWORD', 'CHANGE_ME'),
            'email_sender': os.environ.get('EMAIL_SENDER', ''),
            'email_password': os.environ.get('EMAIL_PASSWORD', ''),
            'email_receiver': os.environ.get('EMAIL_RECEIVER', ''),
            'max_attempts': os.environ.get('MAX_ATTEMPTS', '3'),
            'face_tolerance': os.environ.get('FACE_TOLERANCE', '0.6')
        }
        for k, v in defaults.items():
            cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))
        
        conn.commit()
        conn.close()

    def get_setting(self, key, default=None):
        """Get setting dynamically from DB"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
            res = cursor.fetchone()
            conn.close()
            if res:
                return res[0]
            return str(default) if default is not None else ""
        except Exception as e:
            print(f"Error reading setting {key}: {e}")
            return str(default) if default is not None else ""

    def set_setting(self, key, value):
        """Set setting dynamically in DB"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, str(value)))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving setting {key}: {e}")
            return False

    def get_all_settings(self):
        """Get all configuration settings as dict"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT key, value FROM settings')
            rows = cursor.fetchall()
            conn.close()
            return {r[0]: r[1] for r in rows}
        except Exception as e:
            print(f"Error getting settings: {e}")
            return {}

    def migrate_legacy_known_face(self, storage):
        """Migrate legacy known_face.pkl into registered_faces table if table is empty"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM registered_faces')
            count = cursor.fetchone()[0]
            
            if count == 0 and KNOWN_FACE_PATH.exists():
                with open(KNOWN_FACE_PATH, 'rb') as f:
                    encrypted_data = f.read()
                cursor.execute('''
                    INSERT INTO registered_faces (name, role, face_encoding, photo_path, is_active, created_at)
                    VALUES (?, ?, ?, ?, 1, ?)
                ''', ('Primary Owner', 'owner', encrypted_data, '', datetime.now().isoformat()))
                conn.commit()
                print("✅ Migrated primary owner face to database.")
            conn.close()
        except Exception as e:
            print(f"Migration error: {e}")

    def get_registered_faces(self, only_active=True):
        """Get registered face records from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            query = "SELECT id, name, role, face_encoding, photo_path, is_active FROM registered_faces"
            if only_active:
                query += " WHERE is_active = 1"
            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()
            return rows
        except Exception as e:
            print(f"Error fetching registered faces: {e}")
            return []
    
    def log_attempt(self, event_type, status, photo_path=None, attempts=0, notes=""):
        """Log an access attempt"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO access_attempts (
                timestamp, event_type, status, photo_path, attempts,
                ip_address, computer_name, username, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            event_type,
            status,
            photo_path or "",
            attempts,
            self.get_ip_address(),
            os.environ.get('COMPUTERNAME', 'Unknown'),
            os.environ.get('USERNAME', 'Unknown'),
            notes
        ))
        
        conn.commit()
        conn.close()
    
    def queue_email(self, photo_path, subject="", body=""):
        """Queue email for sending"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO email_queue (
                timestamp, photo_path, subject, body, status
            ) VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            photo_path or "",
            subject,
            body,
            'pending'
        ))
        
        conn.commit()
        conn.close()
    
    def get_pending_emails(self):
        """Get all pending emails"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, photo_path, subject, body, attempts
            FROM email_queue
            WHERE status = 'pending'
            ORDER BY timestamp
        ''')
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    def update_email_status(self, email_id, status):
        """Update email status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE email_queue
            SET status = ?, last_attempt = ?
            WHERE id = ?
        ''', (
            status,
            datetime.now().isoformat(),
            email_id
        ))
        
        conn.commit()
        conn.close()
    
    def get_recent_attempts(self, limit=10):
        """Get recent access attempts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, event_type, status, attempts, notes
            FROM access_attempts
            ORDER BY id DESC
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    def cleanup_old_data(self, days=30):
        """Clean up old data (keep last 30 days)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        
        # Delete old logs
        cursor.execute('''
            DELETE FROM access_attempts
            WHERE timestamp < ?
        ''', (cutoff,))
        
        # Delete old emails
        cursor.execute('''
            DELETE FROM email_queue
            WHERE timestamp < ? AND status = 'sent'
        ''', (cutoff,))
        
        conn.commit()
        conn.close()
    
    def get_ip_address(self):
        """Get local IP address"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

class SecureStorage:
    """Secure storage for sensitive data"""
    
    def __init__(self):
        self.key = self.get_or_create_key()
        self.cipher = Fernet(self.key)
    
    def get_or_create_key(self):
        """Get or create encryption key"""
        key_file = APP_PATH / "key.key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def encrypt_data(self, data):
        """Encrypt data (bytes or str)"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.cipher.encrypt(data)
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data to bytes"""
        return self.cipher.decrypt(encrypted_data)

class FaceGuardPro:
    """Main FaceGuard Pro Class"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.storage = SecureStorage()
        self.known_faces = []
        self.known_face_encoding = None
        self.attempts = 0
        self.is_authorized = False
        self.is_running = True
        self.window = None
        self.video_capture = None
        self.webcam_label = None
        self.password_entry = None
        self.status_label = None
        self.attempts_label = None
        self.retry_button = None
        self.face_check_running = False
        self.event_queue = queue.Queue()
        self.last_gui_close_time = 0
        
        # Migrate legacy known_face if needed and load face encodings
        self.db.migrate_legacy_known_face(self.storage)
        self.load_known_face()
        
        # Start email retry thread
        self.start_email_retry_thread()

    @property
    def fallback_password(self):
        return self.db.get_setting('fallback_password', os.environ.get('FALLBACK_PASSWORD', 'CHANGE_ME'))

    @property
    def email_sender(self):
        return self.db.get_setting('email_sender', os.environ.get('EMAIL_SENDER', ''))

    @property
    def email_password(self):
        return self.db.get_setting('email_password', os.environ.get('EMAIL_PASSWORD', ''))

    @property
    def email_receiver(self):
        return self.db.get_setting('email_receiver', os.environ.get('EMAIL_RECEIVER', ''))

    @property
    def max_attempts(self):
        try:
            return int(self.db.get_setting('max_attempts', 3))
        except Exception:
            return 3

    @property
    def face_tolerance(self):
        try:
            return float(self.db.get_setting('face_tolerance', 0.6))
        except Exception:
            return 0.6
    
    def load_known_face(self):
        """Load encrypted face data for Owner and Friends"""
        self.known_faces = []
        rows = self.db.get_registered_faces(only_active=True)
        
        for r in rows:
            face_id, name, role, encrypted_blob, photo_path, is_active = r
            try:
                decrypted_bytes = self.storage.decrypt_data(encrypted_blob)
                encoding = pickle.loads(decrypted_bytes)
                self.known_faces.append({
                    'id': face_id,
                    'name': name,
                    'role': role,
                    'encoding': encoding,
                    'photo_path': photo_path
                })
            except Exception as e:
                print(f"Error decrypting face encoding for {name}: {e}")
                
        if self.known_faces:
            self.known_face_encoding = self.known_faces[0]['encoding']
            return True
            
        if KNOWN_FACE_PATH.exists():
            try:
                with open(KNOWN_FACE_PATH, 'rb') as f:
                    encrypted_data = f.read()
                    decrypted_bytes = self.storage.decrypt_data(encrypted_data)
                    self.known_face_encoding = pickle.loads(decrypted_bytes)
                    self.known_faces.append({
                        'id': 0,
                        'name': 'Primary Owner',
                        'role': 'owner',
                        'encoding': self.known_face_encoding,
                        'photo_path': ''
                    })
                return True
            except Exception as e:
                print(f"Error loading legacy face: {e}")
                return False
        return False
    
    def save_known_face(self, face_encoding, name="Primary Owner", role="owner"):
        """Save face data encrypted to database and legacy pkl"""
        try:
            serialized = pickle.dumps(face_encoding)
            encrypted = self.storage.encrypt_data(serialized)
            
            with open(KNOWN_FACE_PATH, 'wb') as f:
                f.write(encrypted)
                
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO registered_faces (name, role, face_encoding, photo_path, is_active, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
            ''', (name, role, encrypted, '', datetime.now().isoformat()))
            conn.commit()
            conn.close()
            
            self.load_known_face()
            return True
        except Exception as e:
            print(f"Error saving face: {e}")
            return False
    
    def capture_photo(self, prefix="capture"):
        """Capture photo from webcam safely"""
        cap = None
        try:
            for idx in [0, 1, 2]:
                cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
                if cap.isOpened():
                    ret, frame = cap.read()
                    if ret and frame is not None:
                        time.sleep(0.1)
                        ret, frame = cap.read()
                        cap.release()
                        cap = None
                        if ret and frame is not None:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
                            filename = f"{prefix}_{timestamp}.jpg"
                            filepath = PHOTO_PATH / filename
                            cv2.imwrite(str(filepath), frame)
                            return str(filepath)
                if cap is not None:
                    cap.release()
                    cap = None
            return None
        except Exception as e:
            print(f"Capture error: {e}")
            return None
        finally:
            if cap is not None:
                try:
                    cap.release()
                except Exception:
                    pass
    
    def get_face_encoding(self, image_path):
        """Extract face encoding from image"""
        try:
            image = face_recognition.load_image_file(image_path)
            face_locations = face_recognition.face_locations(image)
            
            if not face_locations:
                return None
            
            face_encodings = face_recognition.face_encodings(image, face_locations)
            if not face_encodings:
                return None
            
            return face_encodings[0]
            
        except Exception as e:
            print(f"Face encoding error: {e}")
            return None
    
    def verify_face(self, image_path):
        """Verify if captured face matches any registered face (Owner or Friends)"""
        self.load_known_face()
        if not self.known_faces:
            return False, "No face registered", None
        
        face_encoding = self.get_face_encoding(image_path)
        if face_encoding is None:
            return False, "No face detected", None
        
        known_encodings = [item['encoding'] for item in self.known_faces]
        matches = face_recognition.compare_faces(
            known_encodings, 
            face_encoding, 
            tolerance=self.face_tolerance
        )
        
        if True in matches:
            distances = face_recognition.face_distance(known_encodings, face_encoding)
            best_idx = int(np.argmin(distances))
            matched_user = self.known_faces[best_idx]
            confidence = (1 - distances[best_idx]) * 100
            
            return True, f"Welcome {matched_user['name']}! ({matched_user['role'].capitalize()}) [{confidence:.1f}%]", matched_user
        else:
            return False, "Face doesn't match registered users", None
    
    def send_email_alert(self, photo_path, attempts, is_retry=False):
        """Send email alert with photo"""
        try:
            sender = self.email_sender
            password = self.email_password
            receiver = self.email_receiver
            max_att = self.max_attempts

            if not sender or not password or not receiver:
                print("Email settings missing. Skipping email alert.")
                return False

            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = f"🚨 ALERT: Unauthorized PC Access Attempt!"
            
            body = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .alert {{ background-color: #ff4444; color: white; padding: 10px; }}
                    .info {{ background-color: #f0f0f0; padding: 10px; margin: 10px 0; }}
                    .data {{ color: #333; font-weight: bold; }}
                </style>
            </head>
            <body>
                <div class="alert">
                    <h2>⚠️ SECURITY ALERT</h2>
                    <p>Unauthorized person attempted to access your PC!</p>
                </div>
                
                <div class="info">
                    <h3>📋 Details:</h3>
                    <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Computer:</strong> {os.environ.get('COMPUTERNAME', 'Unknown')}</p>
                    <p><strong>Username:</strong> {os.environ.get('USERNAME', 'Unknown')}</p>
                    <p><strong>IP Address:</strong> {self.db.get_ip_address()}</p>
                    <p><strong>Attempts:</strong> {attempts}/{max_att}</p>
                    <p><strong>Status:</strong> Face verification failed</p>
                </div>
                
                <div class="info">
                    <h3>📸 Captured Photo:</h3>
                    <p>Photo attached to this email</p>
                </div>
                
                <hr>
                <p><em>This is an automated security alert from FaceGuard Pro.</em></p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            if photo_path and os.path.exists(photo_path):
                with open(photo_path, 'rb') as f:
                    img_data = f.read()
                    image = MIMEImage(img_data, name=os.path.basename(photo_path))
                    msg.attach(image)
            
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.login(sender, password)
            server.send_message(msg)
            server.quit()
            
            self.db.log_attempt('email', 'sent', photo_path, attempts, 'Email sent successfully')
            return True
            
        except Exception as e:
            error_msg = f"Email error: {str(e)}"
            print(error_msg)
            
            if not is_retry:
                self.db.queue_email(
                    photo_path,
                    "ALERT: Unauthorized Access",
                    f"Attempts: {attempts}\nError: {error_msg}"
                )
            
            self.db.log_attempt('email', 'queued', photo_path, attempts, error_msg)
            return False
    
    def process_unauthorized_access(self, photo_path):
        """Handle unauthorized access attempt"""
        self.attempts += 1
        
        self.db.log_attempt(
            'unauthorized',
            'failed',
            photo_path,
            self.attempts,
            f'Face verification failed - Attempt {self.attempts}'
        )
        
        self.send_email_alert(photo_path, self.attempts)
        
        if self.attempts >= MAX_ATTEMPTS:
            self.db.log_attempt(
                'system',
                'shutdown',
                photo_path,
                self.attempts,
                'Max attempts exceeded - System shutting down'
            )
            self.shutdown_pc()
            return False
        
        return True
    
    def update_status(self, text, fg='yellow'):
        """Thread-safe status label update"""
        if self.window and self.status_label:
            def _update():
                try:
                    if self.status_label and self.status_label.winfo_exists():
                        self.status_label.config(text=text, fg=fg)
                except Exception:
                    pass
            try:
                self.window.after(0, _update)
            except Exception:
                pass

    def update_attempts_label(self):
        """Thread-safe attempts label update"""
        if self.window and self.attempts_label:
            def _update():
                try:
                    if self.attempts_label and self.attempts_label.winfo_exists():
                        self.attempts_label.config(text=f"Attempts: {self.attempts}/{MAX_ATTEMPTS}")
                except Exception:
                    pass
            try:
                self.window.after(0, _update)
            except Exception:
                pass

    def set_password_entry_state(self, state='normal', focus=True, clear=False):
        """Thread-safe password entry update"""
        if self.window and self.password_entry:
            def _update():
                try:
                    if self.password_entry and self.password_entry.winfo_exists():
                        self.password_entry.config(state=state)
                        if clear:
                            self.password_entry.delete(0, tk.END)
                        if focus:
                            self.password_entry.focus()
                except Exception:
                    pass
            try:
                self.window.after(0, _update)
            except Exception:
                pass

    def set_retry_button_state(self, state='normal'):
        """Thread-safe retry button update"""
        if self.window and self.retry_button:
            def _update():
                try:
                    if self.retry_button and self.retry_button.winfo_exists():
                        self.retry_button.config(state=state)
                except Exception:
                    pass
            try:
                self.window.after(0, _update)
            except Exception:
                pass

    def shutdown_pc(self):
        """Shutdown PC safely"""
        print("\n⚠️ MAX ATTEMPTS EXCEEDED! Shutting down in 5 seconds...")
        self.update_status("⏰ SHUTTING DOWN...", fg='red')
        time.sleep(5)
        os.system("shutdown /s /t 1")
    
    def lock_workstation(self):
        """Lock Windows workstation"""
        try:
            windll.user32.LockWorkStation()
        except Exception:
            pass
    
    def verify_password(self):
        """Verify fallback password"""
        entered = self.password_entry.get()
        max_att = self.max_attempts
        
        if entered == self.fallback_password:
            self.is_authorized = True
            self.db.log_attempt('password', 'success', None, 0, 'Password unlock successful')
            self.unlock_system()
            return True
        else:
            self.attempts += 1
            
            photo_path = self.capture_photo("password_fail")
            if photo_path:
                self.db.log_attempt('password', 'failed', photo_path, self.attempts, 'Wrong password')
                self.send_email_alert(photo_path, self.attempts)
            else:
                self.db.log_attempt('password', 'failed', None, self.attempts, 'Wrong password, no photo')
            
            if self.attempts >= max_att:
                self.db.log_attempt('system', 'shutdown', None, self.attempts, 'Max password attempts')
                self.update_status("⏰ SHUTTING DOWN...", fg='red')
                time.sleep(3)
                self.shutdown_pc()
            else:
                self.update_status(f"❌ Wrong Password! ({self.attempts}/{max_att})", fg='red')
                self.update_attempts_label()
                self.set_password_entry_state(state='normal', focus=True, clear=True)
            
            return False
    
    def check_face_from_webcam(self):
        """Check face from webcam capture"""
        if self.face_check_running:
            return
        
        self.face_check_running = True
        max_att = self.max_attempts
        try:
            self.update_status("📸 Capturing face...", fg='yellow')
            
            photo_path = self.capture_photo("face_check")
            
            if not photo_path:
                self.update_status("❌ Camera error! Use password.", fg='red')
                self.set_password_entry_state(state='normal', focus=True)
                return
            
            success, message, matched_user = self.verify_face(photo_path)
            
            if success:
                person_name = matched_user['name'] if matched_user else 'Authorized User'
                person_role = matched_user['role'] if matched_user else 'owner'
                note = f"Unlocked by {person_name} ({person_role.capitalize()})"
                
                self.db.log_attempt('face', 'success', photo_path, 0, note)
                self.is_authorized = True
                self.update_status(f"✅ {message}", fg='#00ff88')
                time.sleep(0.5)
                self.unlock_system()
            else:
                self.attempts += 1
                self.db.log_attempt('face', 'failed', photo_path, self.attempts, message)
                
                self.send_email_alert(photo_path, self.attempts)
                
                self.update_status(f"❌ {message} ({self.attempts}/{max_att})", fg='red')
                self.update_attempts_label()
                
                if self.attempts >= max_att:
                    self.db.log_attempt('system', 'shutdown', photo_path, self.attempts, 'Max face attempts')
                    self.update_status("⏰ SHUTTING DOWN...", fg='red')
                    time.sleep(3)
                    self.shutdown_pc()
                else:
                    self.set_password_entry_state(state='normal', focus=True)
                    self.set_retry_button_state(state='normal')
        finally:
            self.face_check_running = False
    
    def retry_face_scan(self):
        """Retry face scanning"""
        self.set_password_entry_state(state='disabled', focus=False, clear=True)
        self.set_retry_button_state(state='disabled')
        
        threading.Thread(target=self.check_face_from_webcam, daemon=True).start()
    
    def unlock_system(self):
        """Unlock the system (thread-safe)"""
        self.is_authorized = True
        if self.window:
            def _destroy():
                try:
                    if self.window:
                        self.window.destroy()
                except Exception:
                    pass
                self.window = None
            try:
                self.window.after(0, _destroy)
            except Exception:
                pass
    
    def on_enter_pressed(self, event):
        """Handle Enter key for password"""
        if self.password_entry and self.password_entry['state'] == 'normal':
            self.verify_password()
    
    def create_gui(self):
        """Create fullscreen GUI"""
        self.window = tk.Tk()
        self.window.title("FaceGuard Pro - Security Lock")
        self.window.configure(bg='#0a0a1a')
        
        self.window.attributes('-fullscreen', True)
        self.window.attributes('-topmost', True)
        
        self.window.protocol("WM_DELETE_WINDOW", lambda: None)
        
        def emergency_exit(event):
            if messagebox.askyesno("⚠️ Emergency Exit", 
                "Are you sure you want to exit?\n"
                "This will disable security for this session!\n\n"
                "Only use if you're the authorized user."):
                self.is_authorized = True
                self.unlock_system()
        
        self.window.bind('<Escape>', emergency_exit)
        
        main_frame = tk.Frame(self.window, bg='#0a0a1a')
        main_frame.pack(expand=True, fill='both')
        
        title = tk.Label(main_frame, 
                        text="🔐 FACEGUARD PRO", 
                        font=('Arial', 32, 'bold'),
                        fg='#00ff88', 
                        bg='#0a0a1a')
        title.pack(pady=20)
        
        subtitle = tk.Label(main_frame, 
                           text="Security Verification Required", 
                           font=('Arial', 14),
                           fg='#aaaaaa', 
                           bg='#0a0a1a')
        subtitle.pack(pady=5)
        
        self.status_label = tk.Label(main_frame, 
                                     text="🔍 Starting face verification...", 
                                     font=('Arial', 18, 'bold'),
                                     fg='yellow', 
                                     bg='#0a0a1a')
        self.status_label.pack(pady=30)
        
        self.attempts_label = tk.Label(main_frame, 
                                       text=f"Attempts: {self.attempts}/{MAX_ATTEMPTS}", 
                                       font=('Arial', 12),
                                       fg='#666666', 
                                       bg='#0a0a1a')
        self.attempts_label.pack(pady=5)
        
        pass_label = tk.Label(main_frame, 
                             text="Enter Password (if face fails):", 
                             font=('Arial', 12),
                             fg='#cccccc', 
                             bg='#0a0a1a')
        pass_label.pack(pady=(20, 5))
        
        self.password_entry = tk.Entry(main_frame, 
                                       font=('Arial', 16),
                                       show='•',
                                       width=25,
                                       bg='#1a1a2e',
                                       fg='white',
                                       insertbackground='white',
                                       state='disabled')
        self.password_entry.pack(pady=5)
        self.password_entry.bind('<Return>', self.on_enter_pressed)
        
        btn_frame = tk.Frame(main_frame, bg='#0a0a1a')
        btn_frame.pack(pady=20)
        
        self.retry_button = tk.Button(btn_frame, 
                                     text="🔄 Try Face Again", 
                                     font=('Arial', 12, 'bold'),
                                     command=self.retry_face_scan,
                                     bg='#00ff88',
                                     fg='#0a0a1a',
                                     width=18,
                                     height=2,
                                     state='normal')
        self.retry_button.pack(side='left', padx=10)
        
        unlock_btn = tk.Button(btn_frame, 
                              text="🔓 Unlock", 
                              font=('Arial', 12, 'bold'),
                              command=self.verify_password,
                              bg='#2196F3',
                              fg='white',
                              width=18,
                              height=2)
        unlock_btn.pack(side='left', padx=10)
        
        info = tk.Label(main_frame, 
                       text=f"Max Attempts: {MAX_ATTEMPTS} | System will shutdown after max attempts", 
                       font=('Arial', 9),
                       fg='#444444', 
                       bg='#0a0a1a')
        info.pack(side='bottom', pady=15)
        
        version = tk.Label(main_frame, 
                          text="v3.0 | Offline Face Recognition | Local Storage", 
                          font=('Arial', 8),
                          fg='#333333', 
                          bg='#0a0a1a')
        version.pack(side='bottom', pady=5)
        
        self.window.after(1000, lambda: threading.Thread(target=self.check_face_from_webcam, daemon=True).start())
        
        self.window.mainloop()
    
    def start_email_retry_thread(self):
        """Start thread to retry failed emails"""
        def retry_emails():
            while True:
                try:
                    pending = self.db.get_pending_emails()
                    for email in pending:
                        email_id, timestamp, photo_path, subject, body, attempts = email
                        
                        success = self.send_email_alert(photo_path, attempts, is_retry=True)
                        
                        if success:
                            self.db.update_email_status(email_id, 'sent')
                        else:
                            new_attempts = attempts + 1
                            conn = sqlite3.connect(self.db_path)
                            cursor = conn.cursor()
                            cursor.execute('''
                                UPDATE email_queue
                                SET attempts = ?, last_attempt = ?
                                WHERE id = ?
                            ''', (new_attempts, datetime.now().isoformat(), email_id))
                            conn.commit()
                            conn.close()
                            
                            if new_attempts >= 5:
                                self.db.update_email_status(email_id, 'failed')
                    
                    time.sleep(60)
                    
                except Exception as e:
                    print(f"Email retry error: {e}")
                    time.sleep(60)
        
        thread = threading.Thread(target=retry_emails, daemon=True)
        thread.start()
    
    def register_face(self):
        """Register user's face for first time"""
        print("\n" + "="*60)
        print("  📸 FACEGUARD PRO - FIRST TIME SETUP")
        print("="*60)
        print("Please look at the camera for face registration.")
        print("Ensure good lighting and look straight ahead.")
        print("="*60 + "\n")
        
        print("Capturing face...")
        photos = []
        for i in range(3):
            print(f"  Photo {i+1}/3...")
            photo_path = self.capture_photo(f"register_{i+1}")
            if photo_path:
                photos.append(photo_path)
            time.sleep(0.5)
        
        if not photos:
            print("❌ Camera not accessible! Please check your webcam.")
            return False
        
        face_encoding = None
        for photo in photos:
            encoding = self.get_face_encoding(photo)
            if encoding is not None:
                face_encoding = encoding
                break
        
        if face_encoding is None:
            print("❌ No face detected in any photo!")
            print("Make sure your face is visible and well-lit.")
            return False
        
        if self.save_known_face(face_encoding):
            print("✅ Face registered successfully!")
            
            if photos:
                try:
                    img = cv2.imread(photos[0])
                    if img is not None:
                        cv2.imshow("Registered Face", img)
                        cv2.waitKey(2000)
                        cv2.destroyAllWindows()
                except Exception:
                    pass
            
            for photo in photos:
                try:
                    os.remove(photo)
                except Exception:
                    pass
            
            print(f"\n📁 Data stored at: {APP_PATH}")
            print("✅ Setup complete! Restart the program to use.")
            return True
        else:
            print("❌ Failed to save face data!")
            return False
    
    def view_logs(self):
        """View access logs"""
        print("\n" + "="*60)
        print("  📋 ACCESS LOGS")
        print("="*60)
        
        logs = self.db.get_recent_attempts(20)
        
        if not logs:
            print("No logs found.")
            return
        
        print(f"{'Time':<25} {'Event':<15} {'Status':<12} {'Attempts':<10}")
        print("-"*60)
        
        for log in logs:
            timestamp, event, status, attempts, notes = log
            print(f"{timestamp:<25} {event:<15} {status:<12} {attempts:<10}")
            if notes:
                print(f"  Note: {notes}")
        
        print("="*60)
    
    def run_daemon(self):
        """Run FaceGuard Pro as a continuous background daemon watching wake/lock events"""
        print("\n" + "="*60)
        print("  🔐 FACEGUARD PRO DAEMON ACTIVE")
        print("="*60)
        print(f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}")
        print(f"User: {os.environ.get('USERNAME', 'Unknown')}")
        print("Listening for System Wake, Sleep, and Workstation Lock events...")
        print("Admin Dashboard web server active at http://127.0.0.1:5000")
        print("="*60)
        
        # Start Web Admin Dashboard background server
        try:
            import admin_dashboard
            dash_thread = threading.Thread(target=admin_dashboard.run_server, kwargs={'port': 5000}, daemon=True)
            dash_thread.start()
        except Exception as e:
                print(f"Dashboard thread warning: {e}")
        
        if not self.load_known_face():
            print("\n⚠️ No face registered! Starting setup...")
            if not self.register_face():
                print("❌ Setup failed. Please check your camera and try again.")
                return

        def drain_event_queue():
            """Clear any duplicate pending events from queue"""
            while not self.event_queue.empty():
                try:
                    self.event_queue.get_nowait()
                except queue.Empty:
                    break

        def on_event_triggered(event_type):
            now = time.time()
            if self.window or (now - self.last_gui_close_time < 3.0):
                return
            print(f"\n🔔 Event detected: {event_type}")
            self.lock_workstation()
            self.event_queue.put(event_type)

        listener = WindowsEventListener(on_event_triggered)
        listener.start()

        # On initial daemon start, lock workstation and trigger GUI
        self.lock_workstation()
        self.event_queue.put("initial_start")

        # Main thread loop: waits for events and launches GUI on MAIN THREAD
        try:
            while self.is_running:
                try:
                    event = self.event_queue.get(timeout=1.0)
                    now = time.time()
                    if not self.window and (now - self.last_gui_close_time >= 3.0):
                        drain_event_queue()
                        self.attempts = 0
                        self.is_authorized = False
                        self.create_gui()
                        self.last_gui_close_time = time.time()
                        drain_event_queue()
                except queue.Empty:
                    pass
                except Exception as e:
                    print(f"Daemon main loop error: {e}")
        except KeyboardInterrupt:
            print("\nDaemon stopped by user.")

    def run(self, daemon=True):
        """Main program entry"""
        if daemon:
            self.run_daemon()
            return

        print("\n" + "="*60)
        print("  🔐 FACEGUARD PRO ACTIVE")
        print("="*60)
        print(f"Computer: {os.environ.get('COMPUTERNAME', 'Unknown')}")
        print(f"User: {os.environ.get('USERNAME', 'Unknown')}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        if not self.load_known_face():
            print("\n⚠️ No face registered! Starting setup...")
            if self.register_face():
                return
            else:
                print("❌ Setup failed. Please check your camera and try again.")
                return
        
        self.lock_workstation()
        self.create_gui()
        
        if self.is_authorized:
            print("\n✅ Access granted! System unlocked.")
            self.db.log_attempt('system', 'unlocked', None, 0, 'System unlocked by authorized user')
        else:
            print("\n❌ Access denied! Check logs for details.")

# ============================================
# COMMAND LINE INTERFACE
# ============================================

def main():
    """Command line interface"""
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ['--help', '-h']:
            print("\n" + "="*60)
            print("  FACEGUARD PRO - Security System")
            print("="*60)
            print("\nCommands:")
            print("  --daemon, -d   : Run persistent background security daemon")
            print("  --dashboard,-b : Run Web Admin Dashboard server")
            print("  --setup, -s    : Register your face (first time)")
            print("  --logs, -l     : View access logs")
            print("  --help, -h     : Show this help")
            print("  --uninstall,-u : Uninstall FaceGuard Pro")
            print("  (no args)      : Run security system daemon")
            print("="*60)
            return
        elif arg in ['--dashboard', '-b']:
            try:
                import admin_dashboard
                admin_dashboard.run_server()
            except Exception as e:
                print(f"Error starting dashboard: {e}")
            return
        elif arg in ['--daemon', '-d']:
            if not ensure_single_instance():
                return
            guard = FaceGuardPro()
            guard.run_daemon()
            return
        elif arg in ['--logs', '-l']:
            db = DatabaseManager()
            logs = db.get_recent_attempts(20)
            print("\n" + "="*60)
            print("  📋 ACCESS LOGS")
            print("="*60)
            if not logs:
                print("No logs found.")
            else:
                print(f"{'Time':<25} {'Event':<15} {'Status':<12} {'Attempts':<10}")
                print("-"*60)
                for log in logs:
                    timestamp, event, status, attempts, notes = log
                    print(f"{timestamp:<25} {event:<15} {status:<12} {attempts:<10}")
                    if notes:
                        print(f"  Note: {notes}")
            print("="*60)
            return
        elif arg in ['--uninstall', '-u']:
            uninstall()
            return
        elif arg in ['--setup', '-s']:
            guard = FaceGuardPro()
            guard.register_face()
            return
        else:
            print(f"Unknown command: {sys.argv[1]}")
            print("Use --help for available commands")
            return
    else:
        if not ensure_single_instance():
            return
        guard = FaceGuardPro()
        guard.run_daemon()

def uninstall():
    """Safe uninstallation"""
    print("\n" + "="*60)
    print("  🗑️ FACEGUARD PRO - UNINSTALL")
    print("="*60)
    print("This will remove FaceGuard Pro completely.")
    print("All logs and photos will be preserved (unless you choose to delete).")
    print("="*60)
    
    confirm = input("\nAre you sure? (yes/NO): ").strip().lower()
    if confirm != 'yes':
        print("❌ Uninstall cancelled.")
        return
    
    keep_data = input("Keep logs and photos? (Y/n): ").strip().lower()
    
    if keep_data == 'n':
        shutil.rmtree(APP_PATH, ignore_errors=True)
        print("✅ All data removed.")
    else:
        print("✅ Data preserved at: " + str(APP_PATH))
    
    print("✅ FaceGuard Pro uninstalled successfully!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        input("\nPress Enter to exit...")
