@echo off
title SecurityShells SOC Server (https://securityshells.com)
cd /d "%~dp0"
echo ========================================================
echo   Launching SecurityShells SOC Application
echo   URL: https://securityshells.com
echo   Alternate URL: http://localhost:8000
echo ========================================================
echo.
"%~dp0.venv\Scripts\python.exe" "%~dp0run_server.py"
pause
