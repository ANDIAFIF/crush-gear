# CrushGear System Service Installation

## ⚡ Quick Install

Jalankan script ini untuk install system services:

```bash
cd /home/rahmat/mvp/crush-gear/web
bash install-system-services.sh
```

Script akan:
1. ✅ Copy service files ke `/etc/systemd/system/`
2. ✅ Enable auto-start on boot
3. ✅ Check dan install CrushGear tools jika belum ada
4. ✅ Start backend dan frontend services

---

## 🔧 Manual Installation (Alternative)

Jika prefer manual install:

### 1. Copy Service Files
```bash
sudo cp crushgear-backend.service /etc/systemd/system/
sudo cp crushgear-frontend.service /etc/systemd/system/
```

### 2. Reload Systemd
```bash
sudo systemctl daemon-reload
```

### 3. Enable Services (Auto-start on boot)
```bash
sudo systemctl enable crushgear-backend.service
sudo systemctl enable crushgear-frontend.service
```

### 4. Start Services
```bash
sudo systemctl start crushgear-backend.service
sudo systemctl start crushgear-frontend.service
```

### 5. Check Status
```bash
sudo systemctl status crushgear-backend crushgear-frontend
```

---

## 🎯 Features

### Auto Tool Installation
Service backend punya `ExecStartPre` yang run script:
```bash
/home/rahmat/mvp/crush-gear/web/check-and-install-tools.sh
```

Script ini akan:
- ✅ Check semua CrushGear tools (nmap, amass, httpx, dll)
- ✅ Jika ada yang missing → auto run `install.sh`
- ✅ Create virtual environment jika belum ada
- ✅ Install Python dependencies

**Jadi setiap boot, sistem akan:**
1. Check tools
2. Install jika perlu
3. Start backend
4. Start frontend

---

## 📋 Service Management

### Check Status
```bash
sudo systemctl status crushgear-backend crushgear-frontend
```

### Stop Services
```bash
sudo systemctl stop crushgear-backend crushgear-frontend
```

### Restart Services
```bash
sudo systemctl restart crushgear-backend crushgear-frontend
```

### View Logs (Real-time)
```bash
# Backend logs
sudo journalctl -u crushgear-backend -f

# Frontend logs
sudo journalctl -u crushgear-frontend -f

# Tool installation logs
tail -f /home/rahmat/mvp/crush-gear/web/tools-setup.log
```

### Disable Auto-start
```bash
sudo systemctl disable crushgear-backend crushgear-frontend
```

---

## 🔍 Troubleshooting

### Service gagal start?
```bash
# Lihat error detail
sudo journalctl -u crushgear-backend -n 50
sudo journalctl -u crushgear-frontend -n 50

# Check manual
cd /home/rahmat/mvp/crush-gear
python3 crushgear.py --check
```

### Tools belum install?
```bash
# Run manual
bash /home/rahmat/mvp/crush-gear/web/check-and-install-tools.sh
```

### Port conflict?
```bash
# Check apa yang pake port
sudo lsof -i :8000
sudo lsof -i :5173

# Kill process
sudo pkill -9 uvicorn
sudo pkill -9 vite
```

---

## 🚀 Next Steps

Setelah install, test dengan:

```bash
# Check service status
sudo systemctl status crushgear-backend crushgear-frontend

# Test endpoints
curl http://localhost:8000/api/scans
curl http://localhost:5173

# Reboot test
sudo reboot
# Services should auto-start after reboot
```

---

## 📝 Files Created

```
/etc/systemd/system/crushgear-backend.service  → System service
/etc/systemd/system/crushgear-frontend.service → System service
/home/rahmat/mvp/crush-gear/web/check-and-install-tools.sh → Pre-start check
```

All logs saved to:
- Backend: `web/backend/backend.log`
- Frontend: `web/frontend/frontend.log`
- Tools setup: `web/tools-setup.log`
