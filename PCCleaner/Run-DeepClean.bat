@echo off
title PC Cleaner - Deep Clean
cd /d "%~dp0"
echo.
echo  Starting deep clean (temp files, cache, Recycle Bin, Windows Update
echo  leftovers, and an offer to remove Windows.old)...
echo  You will be asked to confirm each thing that gets deleted.
echo  (click YES on the administrator prompt)
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PCCleaner.ps1" -Action Clean -Deep %*
if errorlevel 1 (
  pause
)
