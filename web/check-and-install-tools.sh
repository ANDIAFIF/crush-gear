#!/bin/bash
# CrushGear Tools Pre-Installation Check
# This script checks if all CrushGear tools are installed
# If not, it will automatically install them

set -e

CRUSHGEAR_ROOT="/home/rahmat/mvp/crush-gear"
LOG_FILE="$CRUSHGEAR_ROOT/web/tools-setup.log"
LOCK_FILE="/tmp/crushgear-setup.lock"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Prevent concurrent installations
if [ -f "$LOCK_FILE" ]; then
    log "⚠️  Another installation is in progress. Skipping..."
    exit 0
fi

touch "$LOCK_FILE"
trap "rm -f $LOCK_FILE" EXIT

log "=== CrushGear Tools Check Started ==="

# Check if virtual environment exists
if [ ! -d "$CRUSHGEAR_ROOT/.venv" ]; then
    log "📦 Creating virtual environment..."
    cd "$CRUSHGEAR_ROOT"
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    log "✅ Virtual environment created"
else
    log "✅ Virtual environment exists"
fi

# Activate virtual environment
source "$CRUSHGEAR_ROOT/.venv/bin/activate"

# Check if CrushGear tools are installed
log "🔍 Checking CrushGear tools..."
cd "$CRUSHGEAR_ROOT"

# Run check command and capture output
if python3 crushgear.py --check 2>&1 | tee -a "$LOG_FILE" | grep -q "missing\|not found\|SKIPPED"; then
    log "⚠️  Some tools are missing. Running setup..."
    
    # Run setup/installation
    log "📥 Installing CrushGear tools (this may take a while)..."
    bash "$CRUSHGEAR_ROOT/install.sh" 2>&1 | tee -a "$LOG_FILE"
    
    # Verify installation
    if python3 crushgear.py --check 2>&1 | grep -q "missing\|not found"; then
        log "❌ Tool installation failed. Please check logs."
        exit 1
    fi
    
    log "✅ All tools installed successfully"
else
    log "✅ All CrushGear tools are ready"
fi

log "=== CrushGear Tools Check Completed ==="
exit 0
