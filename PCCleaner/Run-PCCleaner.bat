@echo off
title PC Cleaner
cd /d "%~dp0"
echo.
echo  Starting PC Cleaner (scan + clean)...  (click YES on the administrator prompt)
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PCCleaner.ps1" -Action Both %*
if errorlevel 1 (
  echo.
  echo  ---------------------------------------------------------------
  echo  The tool could not start. If the message above says "running
  echo  scripts is disabled" or "not digitally signed" and mentions
  echo  Group Policy, this PC is controlled by a company policy.
  echo  ---------------------------------------------------------------
  pause
)
