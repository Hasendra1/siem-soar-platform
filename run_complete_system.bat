@echo off
title SIEM+SOAR Platform - System Orchestrator
color 0A
echo ============================================================
echo   SIEM+SOAR Platform - Complete System Startup
echo   IoT/OT Cybersecurity Research Environment
echo ============================================================
echo.

set BASE=C:\siem-soar-platform

:: Step 1: Initialize Database
echo [1/8] Initializing database...
python "%BASE%\database\init_database.py"
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] Database init returned non-zero, may already exist
)
echo [OK] Database ready
echo.

:: Step 2: Train ML Models
echo [2/8] Training ML clustering models...
python "%BASE%\ml_models\clustering_engine.py"
echo [OK] ML models trained
echo.

:: Step 3: Train Inference Models
echo [3/8] Initializing inference engine...
python -c "from ml_models.real_time_inference import RealTimeInferenceEngine; e=RealTimeInferenceEngine(); print('[OK] Inference engine ready' if e.is_ready else '[FAIL]')"
echo.

:: Step 4: Start Docker (if available)
echo [4/8] Starting Docker containers...
docker-compose -f "%BASE%\docker-compose.yml" up -d 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] Docker not available - running in standalone mode
) else (
    echo [OK] Docker containers started
)
echo.

:: Step 5: Start Flask Dashboard (background)
echo [5/8] Starting Dashboard Server...
start "SIEM Dashboard" cmd /k "cd /d %BASE%\api && python app.py"
timeout /t 3 /nobreak >nul
echo [OK] Dashboard starting at http://localhost:5000
echo.

:: Step 6: Wait for API
echo [6/8] Verifying API...
timeout /t 2 /nobreak >nul
curl -s http://localhost:5000/health >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] API responding
) else (
    echo [WARN] API may still be starting
)
echo.

:: Step 7: Open Dashboard
echo [7/8] Opening dashboard in browser...
start http://localhost:5000
echo [OK] Browser opened
echo.

:: Step 8: Ready
echo [8/8] System ready!
echo.
echo ============================================================
echo   SYSTEM STATUS: OPERATIONAL
echo ============================================================
echo   Dashboard:    http://localhost:5000
echo   API Health:   http://localhost:5000/health
echo   API Summary:  http://localhost:5000/api/dashboard/summary
echo.
echo   To run attack simulation:
echo     python agents\live_attack_simulator.py --full-sequence
echo.
echo   To identify attacker:
echo     python ml_models\attacker_identification.py
echo.
echo   To auto-isolate:
echo     python enforcement\ml_based_segmentation.py
echo.
echo   To run full attack + detect + isolate pipeline:
echo     python run_full_pipeline.py
echo ============================================================
echo.
pause
