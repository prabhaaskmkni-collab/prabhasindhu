@echo off
title EmailPulse Server
echo ===================================================
echo   Starting EmailPulse Backend Server...
echo ===================================================
cd /d "%~dp0"
npm start
echo.
echo Server stopped or failed to start.
pause
