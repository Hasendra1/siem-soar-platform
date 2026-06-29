@echo off
title IoT/OT SIEM+SOAR Platform - Full Startup
color 0A

echo ============================================
echo   IoT/OT SIEM+SOAR PLATFORM STARTUP
echo   Ashan Weerasinghe - KIU Final Year Project
echo ============================================
echo.

echo [1/5] Starting Docker containers...
cd /d C:\iot-ot-demo
start "Docker" cmd /k docker-compose up -d
timeout /t 5 /nobreak >nul
echo Docker containers started.
echo.

echo [2/5] Starting Flask backend (SIEM API)...
cd /d C:\siem-soar-platform
start "Flask API" cmd /k python api\app.py
timeout /t 3 /nobreak >nul
echo Flask API started on port 5000.
echo.

echo [3/5] Starting WebSocket server...
start "WebSocket" cmd /k python api\websocket_server.py
timeout /t 2 /nobreak >nul
echo WebSocket server started.
echo.

echo [4/5] Starting React dashboard...
cd /d C:\siem-soar-platform\frontend-react
start "React Dashboard" cmd /k npm run dev
timeout /t 5 /nobreak >nul
echo React dashboard started on port 5173.
echo.

echo [5/5] Opening dashboard in browser...
timeout /t 3 /nobreak >nul
start http://localhost:5173
echo.

echo ============================================
echo   ALL SYSTEMS STARTED SUCCESSFULLY
echo ============================================
echo.
echo   Dashboard:  http://localhost:5173
echo   Flask API:  http://localhost:5000
echo.
echo   Run attack: python agents\live_attack_simulator.py --full-sequence
echo ============================================
pause
