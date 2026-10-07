# FaceGuard Pro 🔐

**Offline Face Recognition Security System for Windows**

FaceGuard Pro is a complete offline security system that uses face recognition to protect your computer. It automatically locks your screen on wake, sleep, and workstation lock events, requiring face verification to unlock. Features email alerts with photos, local backup storage, and a web-based admin dashboard.

## ✨ Features

- **🔒 Instant Lock on Wake/Sleep/Lock** - Automatically secures your computer
- **👤 Offline Face Recognition** - No internet required, uses `face_recognition` library
- **📧 Email Alerts with Photos** - Sends intruder photos via Gmail (with app password)
- **💾 Local Backup Storage** - Saves alerts locally if email fails
- **🖥️ Fullscreen Lock Screen** - Cannot be bypassed with Alt+Tab or Task Manager
- **🔑 Password Fallback** - Emergency unlock with configurable password
- **⚡ 3 Attempts → Shutdown** - Configurable security policy
- **📊 Web Admin Dashboard** - Monitor logs, view photos, manage friend access
- **👥 Friend Access Management** - Register trusted faces for shared access
- **🔐 Encrypted Storage** - Face encodings and sensitive data encrypted with Fernet
- **📱 SQLite Database** - Persistent logging of all access attempts
- **⚙️ Windows Task Scheduler Integration** - Auto-starts on logon

## 📋 Requirements

- **Windows 10/11** (uses Windows APIs for lock screen detection)
- **Python 3.8+**
- **Webcam** (for face capture)
- **Gmail Account** (for email alerts - requires App Password)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/FaceGuardPro.git
cd FaceGuardPro
```

### 2. Create Virtual Environment & Install Dependencies

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
# Copy example files
copy .env.example .env
copy config.example.json config.json

# Edit .env with your settings
notepad .env
```

**Required `.env` settings:**
```env
FALLBACK_PASSWORD=YourSecurePassword
EMAIL_SENDER=your_email@gmail.com
EMAIL_PASSWORD=your_gmail_app_password
EMAIL_RECEIVER=your_email@gmail.com
```

> **Gmail App Password**: Enable 2FA on your Google account, then generate an App Password at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)

### 4. Register Your Face (First Run)

```bash
python FaceGuard_Pro.py --register
```
Follow the on-screen instructions to capture your face.

### 5. Test the System

```bash
# Test face recognition
python FaceGuard_Pro.py --test

# Test lock screen
python FaceGuard_Pro.py --lock
```

### 6. Start the Daemon (Background Protection)

```bash
# Option 1: Manual start
start_security_daemon.bat

# Option 2: Auto-start on Windows logon (run as Administrator)
setup_autostart.bat
```

### 7. Access Admin Dashboard

```bash
start_admin_dashboard.bat
```
Then open: **http://127.0.0.1:5000**

## 📁 Project Structure

```
FaceGuardPro/
├── FaceGuard_Pro.py          # Main application (daemon + lock screen)
├── admin_dashboard.py        # Flask web dashboard
├── requirements.txt          # Python dependencies
├── config.example.json       # Example configuration
├── .env.example              # Example environment variables
├── .gitignore                # Git ignore rules
├── templates/
│   └── dashboard.html        # Dashboard UI template
├── setup_autostart.bat       # Windows Task Scheduler setup
├── start_admin_dashboard.bat # Start dashboard server
├── start_security_daemon.bat # Start background daemon
└── stop_security_daemon.bat  # Stop background daemon
```

## ⚙️ Configuration

### Environment Variables (`.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `FALLBACK_PASSWORD` | Emergency unlock password | `CHANGE_ME` |
| `MAX_ATTEMPTS` | Failed attempts before shutdown | `3` |
| `FACE_TOLERANCE` | Face match sensitivity (0.5-0.7) | `0.6` |
| `EMAIL_ENABLED` | Enable email alerts | `true` |
| `EMAIL_SENDER` | Gmail address | *required* |
| `EMAIL_PASSWORD` | Gmail App Password | *required* |
| `EMAIL_RECEIVER` | Alert recipient | *required* |
| `DASHBOARD_PORT` | Dashboard port | `5000` |

### Configuration File (`config.json`)

For advanced settings, copy `config.example.json` to `config.json` and modify.

## 🎯 Usage

### Command Line Options

```bash
python FaceGuard_Pro.py [OPTIONS]

Options:
  --daemon          Run as background daemon (listens for wake/sleep/lock)
  --lock            Trigger lock screen immediately
  --register        Register new face (owner or friend)
  --test            Test face recognition
  --dashboard       Start admin dashboard server
  --help            Show help message
```

### Admin Dashboard Features

- **📊 Statistics** - Total attempts, success rate, recent activity
- **📸 Photo Gallery** - View all captured intruder photos
- **📋 Access Logs** - Filterable log of all access attempts
- **👥 Friend Management** - Add/remove trusted faces
- **⚙️ Settings** - Configure security parameters

## 🔧 Development

### Running Tests

```bash
# Syntax check
python -m py_compile FaceGuard_Pro.py admin_dashboard.py

# Run with debug
python FaceGuard_Pro.py --test
```

### Code Style

- Follows PEP 8
- Type hints where applicable
- Comprehensive error handling

## 📦 Building Executable (Optional)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=icon.ico FaceGuard_Pro.py
```

## 🛡️ Security Notes

- **Never commit** `.env`, `key.key`, `faceguard.db`, `photos/`, `logs/`, `backups/`
- Encryption key (`key.key`) is generated on first run
- Face encodings are encrypted at rest
- Email credentials stored in environment variables only
- All sensitive files are in `.gitignore`

## 🐛 Troubleshooting

### Camera not detected
```bash
# Check camera index (usually 0)
python -c "import cv2; cap=cv2.VideoCapture(0); print(cap.isOpened())"
```

### Face recognition not working
- Ensure good lighting
- Face tolerance: lower = stricter (0.5), higher = lenient (0.7)
- Re-register face with `--register`

### Email not sending
- Verify Gmail App Password (not regular password)
- Check "Less secure apps" or use App Password with 2FA enabled
- Check firewall/antivirus

### Daemon not starting on boot
- Run `setup_autostart.bat` as Administrator
- Check Task Scheduler: `taskschd.msc` → Task Scheduler Library → FaceGuardPro

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/FaceGuardPro/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/FaceGuardPro/discussions)

---

**⚠️ Disclaimer**: This software is for educational and personal use. Test thoroughly before relying on it for security. The authors are not responsible for any lockouts or data loss.