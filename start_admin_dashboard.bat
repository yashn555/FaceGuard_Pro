@echo off
echo Starting FaceGuard Pro Admin Dashboard...
echo Dashboard URL: http://127.0.0.1:5000
echo.

powershell -Command "Start-Process http://127.0.0.1:5000"
python "%~dp0FaceGuard_Pro.py" --dashboard

pause
