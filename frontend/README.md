# APK Malware Analyzer — Frontend

React + Vite frontend for the APK extraction and RAG analysis backend.

## Development

```bash
cd frontend
npm install
npm run dev
```

Runs at `http://localhost:5173`. API requests are proxied to `http://localhost:8000`.

Start the backend first:

```bash
cd ../strings_and_decompiled_zip_from_apk
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Production build

```bash
npm run build
npm run preview
```

Set the backend URL before building:

```bash
VITE_API_BASE_URL=https://your-api.example.com npm run build
```

Copy `.env.example` to `.env` for local overrides.

## Deploy

### Vercel / Netlify

1. Set root directory to `frontend`
2. Build command: `npm run build`
3. Output directory: `dist`
4. Environment variable: `VITE_API_BASE_URL` = your FastAPI backend URL

`vercel.json` is included for SPA routing.

### Static hosting

Upload the `dist/` folder to any static host. Ensure CORS is enabled on the backend.
