#!/bin/bash
# Install CrushGear System Services
# This script installs services to /etc/systemd/system/ (requires sudo)

set -e

SERVICE_DIR="/home/rahmat/mvp/crush-gear/web"
SYSTEM_DIR="/etc/systemd/system"

echo "🔧 Installing CrushGear System Services..."

# Copy service files
sudo cp "$SERVICE_DIR/crushgear-backend.service" "$SYSTEM_DIR/"
sudo cp "$SERVICE_DIR/crushgear-frontend.service" "$SYSTEM_DIR/"

echo "✅ Service files copied to $SYSTEM_DIR"

# Reload systemd daemon
sudo systemctl daemon-reload

echo "✅ Systemd daemon reloaded"

# Enable services
sudo systemctl enable crushgear-backend.service
sudo systemctl enable crushgear-frontend.service

echo "✅ Services enabled for auto-start on boot"

# Start services
sudo systemctl start crushgear-backend.service
sudo systemctl start crushgear-frontend.service

echo "✅ Services started"

# Show status
echo ""
echo "📊 Service Status:"
sudo systemctl status crushgear-backend.service --no-pager -l || true
echo ""
sudo systemctl status crushgear-frontend.service --no-pager -l || true

echo ""
echo "🎉 Installation complete!"
echo ""
echo "Commands:"
echo "  Status:  sudo systemctl status crushgear-backend crushgear-frontend"
echo "  Stop:    sudo systemctl stop crushgear-backend crushgear-frontend"
echo "  Restart: sudo systemctl restart crushgear-backend crushgear-frontend"
echo "  Logs:    sudo journalctl -u crushgear-backend -f"
