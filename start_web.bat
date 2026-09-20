@echo off
chcp 65001 >nul
echo ===================================================
echo   Core Defense -- Autonomous SOC & Firewall Engine
echo ===================================================
echo.

rem Auto-detect and activate virtualenv if present
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

rem Run pre-flight check before opening port
python server.py --check
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Pre-flight validation failed. Check your .env configuration.
    pause
    exit /b %ERRORLEVEL%
)

echo Starting web console on http://localhost:8888...
python server.py
pause
