@echo off
echo =========================================================================
echo  Starting Recon-ng OSINT Web Dashboard...
echo  Access Web UI at:    http://127.0.0.1:5000
echo  Access REST API at:  http://127.0.0.1:5000/api/
echo  Press Ctrl+C to stop the server.
echo =========================================================================
echo.
"%~dp0venv\Scripts\python.exe" "%~dp0recon-web" %*
