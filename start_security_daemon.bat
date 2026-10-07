@echo off
echo Starting FaceGuard Pro background security daemon...

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"

powershell -Command "Start-Process pythonw.exe -ArgumentList '\"%SCRIPT_DIR%FaceGuard_Pro.py\" --daemon' -WindowStyle Hidden"
echo.
echo ✅ FaceGuard Pro security daemon is now running in the background!
echo System will automatically lock and require face verification on sleep, wake, and lock.
echo Working directory: %SCRIPT_DIR%
echo.
pause
