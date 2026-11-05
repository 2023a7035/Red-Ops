@echo off
title RedOps Platform Launcher
echo ===================================================================
echo  REDOPS - AUTOMATED ENTERPRISE RED TEAM ASSESSMENT PLATFORM
echo ===================================================================
echo [*] Initializing RedOps Security Application...

set "PYTHONPATH=%~dp0;%PYTHONPATH%"

if exist "C:\Users\NITRO\AppData\Local\Programs\Python311\python.exe" (
    "C:\Users\NITRO\AppData\Local\Programs\Python311\python.exe" app.py
) else (
    python app.py
)

pause
