@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
 echo Node.js is required. Install Node.js LTS, then run this file again.
 pause
 exit /b 1
)
if not exist node_modules (
 echo Installing dependencies...
 call npm install
)
if not defined ADMIN_EMAIL set ADMIN_EMAIL=admin@enginex.com
if not defined ADMIN_PASSWORD set /p ADMIN_PASSWORD=Choose an administrator password: 
echo Starting ENGINEX Engineering Marketplace...
start "ENGINEX" cmd /k "node server.js"
timeout /t 2 >nul
start "" http://localhost:3000
