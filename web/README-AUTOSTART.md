# CrushGear Auto-Start Setup

## 🚀 Status

✅ **Auto-start is ENABLED and CONFIGURED**

Both backend and frontend will automatically start when you login.

## 📦 Components

### 1. Systemd Services (User Services)
- **Backend**: `~/.config/systemd/user/backend.service`
- **Frontend**: `~/.config/systemd/user/frontend.service`

### 2. Desktop Autostart
- **Entry**: `~/.config/autostart/crushgear.desktop`
- **Script**: `/home/rahmat/mvp/crush-gear/web/start.sh`

### 3. Service Files (Templates)
- `backend.service` - FastAPI/Uvicorn service
- `frontend.service` - Vite/React dev server
- `start.sh` - Startup verification script

## 🎯 How It Works

1. **On Login**: Desktop autostart runs `start.sh`
2. **start.sh checks**:
   - CrushGear tools are installed and ready
   - Backend service is running
   - Frontend service is running
3. **Services auto-restart** on failure (every 10 seconds)
4. **Logs** are saved to:
   - Backend: `web/backend/backend.log`
   - Frontend: `web/frontend/frontend.log`
   - Startup: `web/startup.log`

## 📋 Commands

### Check Status
```bash
systemctl --user status backend frontend
```

### Start Services
```bash
systemctl --user start backend frontend
```

### Stop Services
```bash
systemctl --user stop backend frontend
```

### Restart Services
```bash
systemctl --user restart backend frontend
```

### View Logs (Real-time)
```bash
journalctl --user -u backend -f
journalctl --user -u frontend -f
```

### Disable Auto-start
```bash
systemctl --user disable backend frontend
rm ~/.config/autostart/crushgear.desktop
```

### Re-enable Auto-start
```bash
systemctl --user enable backend frontend
cp crushgear.desktop ~/.config/autostart/
```

## 🔗 Access Points

- **Backend API**: http://localhost:8000
- **Frontend UI**: http://localhost:5173
- **API Docs**: http://localhost:8000/docs

## 🛠️ Troubleshooting

### Services not starting?
```bash
# Check logs
journalctl --user -u backend -n 50
journalctl --user -u frontend -n 50

# Manual start
systemctl --user restart backend frontend
```

### Port already in use?
```bash
# Check what's using the ports
lsof -i :8000
lsof -i :5173

# Kill old processes
pkill -9 uvicorn
pkill -9 vite
```

### Tools not working?
```bash
# Run CrushGear setup
cd /home/rahmat/mvp/crush-gear
python3 crushgear.py --check
python3 crushgear.py --setup
```

## 📝 Notes

- Services run as user `rahmat` (not root)
- Services restart automatically on failure
- Frontend runs in development mode with hot-reload
- Backend uses system Python with user-installed packages
