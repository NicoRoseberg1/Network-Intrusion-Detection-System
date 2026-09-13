@echo off
:: Self-elevation script to configure securityshells.com and install SSL certificate
title SecurityShells Setup

echo ========================================================
echo   Configuring https://securityshells.com Domain & SSL
echo ========================================================
echo.

:: Check for administrative privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run_setup
) else (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c `"%~f0`"' -Verb RunAs"
    exit /b
)

:run_setup
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_securityshells.ps1"

echo.
echo ========================================================
echo   Configuration Completed!
echo   You can now access: https://securityshells.com
echo ========================================================
echo.
pause
