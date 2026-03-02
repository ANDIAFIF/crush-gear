#!/bin/bash
# CrushGear Smart Startup Script
# Auto-detects, installs, and starts everything needed

set -e

CRUSHGEAR_ROOT="/home/rahmat/mvp/crush-gear"
WEB_DIR="$CRUSHGEAR_ROOT/web"
LOG_FILE="$WEB_DIR/startup.log"
SYSTEM_SERVICE_DIR="/etc/systemd/system"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log "╔═══════════════════════════════════════════════════════╗"
log "║     🚀 CrushGear Smart Startup Script 🚀            ║"
log "╚═══════════════════════════════════════════════════════╝"

# ═══════════════════════════════════════════════════════════
# STEP 1: Check and Install System Services
# ═══════════════════════════════════════════════════════════
log ""
log "📦 STEP 1: Checking System Services..."

if [ ! -f "$SYSTEM_SERVICE_DIR/crushgear-backend.service" ] || [ ! -f "$SYSTEM_SERVICE_DIR/crushgear-frontend.service" ]; then
    warn "System services not found in $SYSTEM_SERVICE_DIR"
    info "Installing system services (requires sudo)..."
    
    # Copy service files
    sudo cp "$WEB_DIR/crushgear-backend.service" "$SYSTEM_SERVICE_DIR/" || {
        error "Failed to copy backend service. Make sure you have sudo access."
        exit 1
    }
    sudo cp "$WEB_DIR/crushgear-frontend.service" "$SYSTEM_SERVICE_DIR/" || {
        error "Failed to copy frontend service."
        exit 1
    }
    
    log "✅ Service files copied to $SYSTEM_SERVICE_DIR"
    
    # Reload systemd
    sudo systemctl daemon-reload
    log "✅ Systemd daemon reloaded"
    
    # Enable services
    sudo systemctl enable crushgear-backend.service crushgear-frontend.service
    log "✅ Services enabled for auto-start on boot"
else
    log "✅ System services already installed"
fi

# ═══════════════════════════════════════════════════════════
# STEP 2: Check and Install CrushGear Tools
# ═══════════════════════════════════════════════════════════
log ""
log "🔧 STEP 2: Checking CrushGear Tools..."

# Check if virtual environment exists and is valid
if [ ! -f "$CRUSHGEAR_ROOT/.venv/bin/activate" ]; then
    warn "Virtual environment not found or invalid. Creating new one..."
    cd "$CRUSHGEAR_ROOT"
    rm -rf .venv
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip > /dev/null 2>&1
    pip install -r requirements.txt > /dev/null 2>&1
    log "✅ Virtual environment created"
else
    log "✅ Virtual environment exists"
    source "$CRUSHGEAR_ROOT/.venv/bin/activate"
fi

# Check if tools are installed
cd "$CRUSHGEAR_ROOT"
info "Running tool check..."

if python3 crushgear.py --check 2>&1 | tee -a "$LOG_FILE" | grep -qE "missing|not found|SKIPPED"; then
    warn "Some tools are missing or not installed"
    info "Running automatic installation (this may take 5-10 minutes)..."
    
    bash "$CRUSHGEAR_ROOT/install.sh" 2>&1 | tee -a "$LOG_FILE"
    
    # Verify installation
    if python3 crushgear.py --check 2>&1 | grep -qE "missing|not found"; then
        error "Tool installation failed. Check logs at $LOG_FILE"
        exit 1
    fi
    
    log "✅ All tools installed successfully"
else
    log "✅ All CrushGear tools are ready"
fi

# ═══════════════════════════════════════════════════════════
# STEP 3: Start Services
# ═══════════════════════════════════════════════════════════
log ""
log "🚀 STEP 3: Starting Services..."

# Check if services are running
BACKEND_RUNNING=$(sudo systemctl is-active crushgear-backend 2>/dev/null || echo "inactive")
FRONTEND_RUNNING=$(sudo systemctl is-active crushgear-frontend 2>/dev/null || echo "inactive")

if [ "$BACKEND_RUNNING" != "active" ]; then
    info "Starting backend service..."
    sudo systemctl start crushgear-backend
    sleep 2
    log "✅ Backend service started"
else
    log "✅ Backend service already running"
fi

if [ "$FRONTEND_RUNNING" != "active" ]; then
    info "Starting frontend service..."
    sudo systemctl start crushgear-frontend
    sleep 2
    log "✅ Frontend service started"
else
    log "✅ Frontend service already running"
fi

# ═══════════════════════════════════════════════════════════
# STEP 4: Verify Everything is Running
# ═══════════════════════════════════════════════════════════
log ""
log "🔍 STEP 4: Verification..."

sleep 3

# Check backend
if sudo systemctl is-active --quiet crushgear-backend; then
    if curl -s http://localhost:8000/api/scans > /dev/null 2>&1; then
        log "✅ Backend API responding at http://localhost:8000"
    else
        warn "Backend service running but API not responding yet (may need more time)"
    fi
else
    error "Backend service failed to start. Check: sudo journalctl -u crushgear-backend -n 50"
fi

# Check frontend
if sudo systemctl is-active --quiet crushgear-frontend; then
    if curl -s http://localhost:5173 > /dev/null 2>&1; then
        log "✅ Frontend responding at http://localhost:5173"
    else
        warn "Frontend service running but not responding yet (may need more time)"
    fi
else
    error "Frontend service failed to start. Check: sudo journalctl -u crushgear-frontend -n 50"
fi

# ═══════════════════════════════════════════════════════════
# FINAL STATUS
# ═══════════════════════════════════════════════════════════
log ""
log "╔═══════════════════════════════════════════════════════╗"
log "║              ✨ Startup Complete! ✨                 ║"
log "╚═══════════════════════════════════════════════════════╝"
log ""
log "🌐 Access Points:"
log "   • Backend API:  http://localhost:8000"
log "   • API Docs:     http://localhost:8000/docs"
log "   • Frontend UI:  http://localhost:5173"
log ""
log "📊 Service Status:"
sudo systemctl status crushgear-backend --no-pager -l | head -3
sudo systemctl status crushgear-frontend --no-pager -l | head -3
log ""
log "📝 Useful Commands:"
log "   • Status:   sudo systemctl status crushgear-backend crushgear-frontend"
log "   • Stop:     sudo systemctl stop crushgear-backend crushgear-frontend"
log "   • Restart:  sudo systemctl restart crushgear-backend crushgear-frontend"
log "   • Logs:     sudo journalctl -u crushgear-backend -f"
log ""
log "💾 Logs saved to: $LOG_FILE"
log ""

exit 0
