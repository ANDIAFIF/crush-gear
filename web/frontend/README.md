# CrushGear Web Dashboard - Frontend

Modern React + TypeScript frontend for CrushGear penetration testing automation.

## Tech Stack

- **React 18** + **TypeScript**
- **Vite** - Fast build tool
- **React Router** - Client-side routing
- **TanStack Query** (React Query) - Server state management
- **Axios** - HTTP client
- **TailwindCSS** - Utility-first CSS framework
- **WebSocket** - Real-time updates

## Getting Started

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

Copy `.env.example` to `.env` and adjust if needed:

```bash
cp .env.example .env
```

Default values:
- `VITE_API_URL=http://localhost:8000`
- `VITE_WS_URL=ws://localhost:8000`

### 3. Start Development Server

```bash
npm run dev
```

Frontend akan berjalan di `http://localhost:5173`

### 4. Build for Production

```bash
npm run build
```

Output akan ada di folder `dist/`

## Project Structure

```
src/
├── api/
│   └── client.ts          # Axios API client
├── hooks/
│   ├── useScans.ts        # React Query hooks
│   └── useWebSocket.ts    # WebSocket hook
├── pages/
│   ├── DashboardPage.tsx  # Scan list
│   ├── NewScanPage.tsx    # Start new scan
│   └── ScanDetailPage.tsx # Real-time monitoring
├── components/
│   ├── ScanStatusBadge.tsx
│   ├── PhaseProgress.tsx
│   ├── ToolStatusCard.tsx
│   └── ToolOutput.tsx
├── types/
│   └── index.ts           # TypeScript types
├── App.tsx                # Main app with routing
├── main.tsx               # Entry point
└── index.css              # Global styles
```

## Features

✅ **Real-time Monitoring** - Live tool output via WebSocket
✅ **Scan Management** - Create, view, delete scans
✅ **Phase Progress** - Visual timeline of 4-phase execution
✅ **Tool Status** - Individual status cards for 8 tools
✅ **Terminal Output** - Terminal-like output with filtering
✅ **Host Discovery** - View discovered hosts and ports
✅ **Vulnerability Report** - CVE findings with severity

## Development

### Available Scripts

- `npm run dev` - Start dev server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

### API Integration

Frontend menggunakan environment variables untuk konfigurasi backend:

- Development: `http://localhost:8000` (default)
- WebSocket: `ws://localhost:8000` (default)

Pastikan backend sudah running sebelum start frontend!
