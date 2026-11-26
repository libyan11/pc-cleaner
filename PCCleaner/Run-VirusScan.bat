@echo off
title PC Cleaner - Virus Scan Only
cd /d "%~dp0"
echo.
echo  Starting virus scan (Microsoft Defender)...  (click YES on the administrator prompt)
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PCCleaner.ps1" -Action Scan -ScanType Full %*
if errorlevel 1 (
  pause
)
