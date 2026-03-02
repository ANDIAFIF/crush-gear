# 🚀 CrushGear Web Dashboard - Quick Start

## ⚡ One Command to Rule Them All

```bash
bash /home/rahmat/mvp/crush-gear/web/start.sh
```

**Itu aja!** Script ini akan otomatis:

✅ **Check** apakah system services sudah installed  
✅ **Install** system services jika belum ada (ke `/etc/systemd/system/`)  
✅ **Check** apakah CrushGear tools sudah lengkap  
✅ **Install** tools yang missing (nmap, amass, httpx, nuclei, dll)  
✅ **Start** backend + frontend services  
✅ **Verify** semua berjalan dengan baik  

---

## 🎯 Kapan Pakai?

### Pertama Kali Setup
```bash
bash /home/rahmat/mvp/crush-gear/web/start.sh
```
Script akan install semua yang dibutuhkan.

### Setelah Reboot
**Tidak perlu run lagi!** Services sudah auto-start saat boot.

### Manual Start (Jika Perlu)
```bash
bash /home/rahmat/mvp/crush-gear/web/start.sh
```
Script pintar: kalau sudah installed, cuma start aja.

---

## 📊 What It Does

### STEP 1: System Services Check
- Cek apakah service files ada di `/etc/systemd/system/`
- Jika belum → copy & enable auto-start
- Jika sudah → skip

### STEP 2: Tools Check
- Cek virtual environment
- Cek semua CrushGear tools (8 tools)
- Jika ada yang missing → run `install.sh`
- Jika lengkap → skip

### STEP 3: Start Services
- Start `crushgear-backend.service`
- Start `crushgear-frontend.service`

### STEP 4: Verification
- Test backend API: `http://localhost:8000`
- Test frontend: `http://localhost:5173`
- Show status & logs

---

## 🌐 Access Points

After startup:

- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Frontend Dashboard**: http://localhost:5173

---

## 📋 Management Commands

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

# Startup script logs
tail -f /home/rahmat/mvp/crush-gear/web/startup.log
```

### Disable Auto-start
```bash
sudo systemctl disable crushgear-backend crushgear-frontend
```

### Re-enable Auto-start
```bash
sudo systemctl enable crushgear-backend crushgear-frontend
```

---

## 🛠️ Files Structure

```
web/
├── start.sh                          ← 🚀 RUN THIS!
├── crushgear-backend.service         ← System service (backend)
├── crushgear-frontend.service        ← System service (frontend)
├── check-and-install-tools.sh        ← Auto-install tools script
├── startup.log                       ← Startup logs
├── README.md                         ← This file
└── backend/
    └── backend.log                   ← Backend runtime logs
└── frontend/
    └── frontend.log                  ← Frontend runtime logs
```

---

## 🔍 Troubleshooting

### Script meminta sudo password
Itu normal! Diperlukan untuk:
- Copy files ke `/etc/systemd/system/`
- Start/stop system services

### Tools installation gagal
```bash
# Check logs
cat /home/rahmat/mvp/crush-gear/web/startup.log

# Manual install
cd /home/rahmat/mvp/crush-gear
bash install.sh
```

### Service gagal start
```bash
# Check error detail
sudo journalctl -u crushgear-backend -n 50
sudo journalctl -u crushgear-frontend -n 50
```

### Port sudah dipakai
```bash
# Check apa yang pakai port
sudo lsof -i :8000
sudo lsof -i :5173

# Kill old processes
sudo pkill -9 uvicorn
sudo pkill -9 vite
```

---

## 💡 Tips

1. **First time**: Script mungkin butuh 5-10 menit untuk install semua tools
2. **After reboot**: Services auto-start, tidak perlu run script lagi
3. **Development**: Frontend run dengan hot-reload (auto-refresh on code change)
4. **Production**: Ganti frontend service ke build mode (edit service file)

---

## 🎉 That's It!

**Jalankan:**
```bash
bash /home/rahmat/mvp/crush-gear/web/start.sh
```

**Enjoy!** 🚀
