#!/usr/bin/env bash
set -e
export PYTHONDONTWRITEBYTECODE=1

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "======================================================"
echo "    Recon-ng OSINT Web Dashboard - Local Runner"
echo "======================================================"

# 1. Initialize virtual environment if missing
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment in ./venv..."
    python3 -m venv venv
fi

# 2. Activate virtual environment
source venv/bin/activate

# 3. Check and install dependencies if not present
if ! python3 -c "import flask, flasgger, yaml" &>/dev/null; then
    echo "[*] Installing Python dependencies from REQUIREMENTS..."
    pip install --upgrade pip
    pip install -r REQUIREMENTS
fi

# 4. Fix permissions on ~/.recon-ng if previously created by Docker
if [ -d "$HOME/.recon-ng" ] && [ ! -w "$HOME/.recon-ng" ]; then
    echo "[!] Fixing permissions on $HOME/.recon-ng..."
    sudo chown -R "$USER:$USER" "$HOME/.recon-ng" 2>/dev/null || true
fi

# 5. Start the web application
echo ""
echo "[*] Starting Recon-ng OSINT Web Server (Frontend + Backend)..."
echo "[*] Web Dashboard:    http://127.0.0.1:5000"
echo "[*] Swagger REST API: http://127.0.0.1:5000/api/"
echo ""

exec python3 ./recon-web --host 127.0.0.1 --port 5000

