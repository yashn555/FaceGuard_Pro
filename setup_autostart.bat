@echo off
echo Setting up FaceGuard Pro auto-start...

:: Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"

:: Remove duplicate startup folder shortcut if present
if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\FaceGuardPro.lnk" (
    del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\FaceGuardPro.lnk"
)

:: Create Task Scheduler entry for user logon
:: Uses the script directory as the working directory
schtasks /create /tn "FaceGuardPro" /tr "python \"%SCRIPT_DIR%FaceGuard_Pro.py\" --daemon" /sc onlogon /delay 0000:00 /f

echo Done! FaceGuard Pro scheduled task created successfully.
echo Working directory: %SCRIPT_DIR%
pause


