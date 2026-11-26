@echo off
setlocal
title PC Cleaner
cd /d "%~dp0"
if not exist "%~dp0PCCleaner.ps1" goto nofiles
set /a tries=0

:menu
set /a tries+=1
if %tries% GTR 10 exit /b 1
cls
echo.
echo   ==========================================================
echo                         PC CLEANER
echo   ==========================================================
echo.
echo    1  Scan + fix + clean      recommended, about 10 minutes.
echo                               Viruses, fake virus pop-ups, spam
echo                               notifications, adware, junk files
echo    2  Full virus scan only    thorough, can take 1-2 hours
echo    3  Deep clean only         also Windows Update leftovers,
echo                               crash dumps and Windows.old
echo    4  EVERYTHING              full virus scan + fix + deep clean
echo    5  Offline virus scan      restarts the PC, about 15 minutes -
echo                               use it if a threat will not go away
echo    6  Recent downloads        review files downloaded and programs
echo       and programs            installed in the last few weeks and
echo                               remove the ones you don't want
echo    7  Fresh start             how to reset Windows to like-new
echo    8  Exit
echo.
echo   All questions are asked at the start, then it runs by itself.
echo   Your own files - documents, photos, passwords - are never touched
echo   unless you pick option 6 and choose them yourself.
echo.
set "choice="
set "ARGS="
set /p "choice=  Type a number and press Enter: "
if "%choice%"=="1" set "ARGS=-Action Both -ScanType Quick"
if "%choice%"=="2" set "ARGS=-Action Scan -ScanType Full"
if "%choice%"=="3" set "ARGS=-Action Clean -Deep"
if "%choice%"=="4" set "ARGS=-Action Both -ScanType Full -Deep"
if "%choice%"=="5" set "ARGS=-Action Scan -ScanType Quick -OfflineScan"
if "%choice%"=="6" goto recent
if "%choice%"=="7" set "ARGS=-Action FreshStart"
if "%choice%"=="8" exit /b 0
if not defined ARGS goto menu
goto run

:recent
echo.
set "weeks="
set /a w=0
set /p "weeks=  How many weeks back should it look? Press Enter for 2: "
set /a w=weeks 2>nul
if %w% LSS 1 set /a w=2
if %w% GTR 520 set /a w=520
set "ARGS=-Action Recent -Weeks %w%"

:run
echo.
echo   Starting... click YES when Windows asks for administrator permission.
echo   A new window opens and does the work - this one will close.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PCCleaner.ps1" %ARGS% %*
if errorlevel 1 goto failed
exit /b 0

:failed
echo.
echo   ---------------------------------------------------------------
echo   PC Cleaner could not start. See "Troubleshooting" in README.md.
echo.
echo   - "running scripts is disabled" or "not digitally signed" and it
echo     mentions Group Policy: a company or school controls this PC.
echo   - "Smart App Control blocked": unblock the ZIP before extracting
echo     it - see READ ME FIRST.txt. Do NOT switch Smart App Control off.
echo   ---------------------------------------------------------------
pause
exit /b 1

:nofiles
echo.
echo   PCCleaner.ps1 was not found next to this file.
echo.
echo   You probably opened this from INSIDE the downloaded ZIP file,
echo   and Windows cannot run it from there. Instead:
echo.
echo     1. Close this window.
echo     2. Right-click the ZIP file, choose Properties, tick "Unblock"
echo        if you see it, and click OK.
echo     3. Right-click the ZIP again and choose "Extract All...".
echo     4. Open the extracted PCCleaner folder and double-click
echo        START HERE.bat
echo.
pause
exit /b 1
