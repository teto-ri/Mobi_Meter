@echo off
setlocal enabledelayedexpansion

title [Mobinogi Meter Launcher]
echo ============================
echo Launching Mabinogi Meter...
echo ============================

REM === Get local IPv4 address using PowerShell ===
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /i "IPv4"') do (
    set ip=%%A
    set ip=!ip:~1!
    goto :found
)

:found
if not defined ip (
    echo [ERROR] Could not detect local IP.
) else (
    echo Detected Local VM IP: !ip!
)

REM [1] Start MDM.exe
echo [1] Launching MDM.exe...
start "" /min cmd /c "start /b MDM.exe"
timeout /t 3 > nul

REM [2] Start WebSocket proxy
echo [2] Launching WebSocket proxy...
start "" /min cmd /c "start /b python proxy.py"
timeout /t 3 > nul

REM [3] Start local HTML server
echo [3] Launching HTML server at http://!ip!:8080 ...
start "" /min cmd /c "start /b python -m http.server 8080"

echo ============================
echo All services have started successfully.
echo Open your browser and go to:
echo     http://!ip!:8080
echo ============================



echo.
echo ============================
echo Press any key to terminate all services.
echo ============================
pause > nul

echo Terminating all background processes...
taskkill /im MDM.exe /f > nul 2>&1
taskkill /im python.exe /f > nul 2>&1
taskkill /im pythonw.exe /f > nul 2>&1
timeout /t 3 > nul
echo Done.
timeout /t 2 > nul
endlocal
exit
