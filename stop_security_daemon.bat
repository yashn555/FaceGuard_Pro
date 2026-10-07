@echo off
echo Stopping FaceGuard Pro background daemon...
powershell -Command "Stop-Process -Name 'pythonw' -ErrorAction SilentlyContinue"
powershell -Command "Stop-Process -Name 'python' -ErrorAction SilentlyContinue"
echo.
echo ✅ FaceGuard Pro security daemon stopped.
echo.
pause
