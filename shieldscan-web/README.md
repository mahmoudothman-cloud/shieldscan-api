# shieldscan-web

React dashboard for ShieldScan (M11). Vite · React 19 · TypeScript · Tailwind 4 · TanStack Query · React Router 7.

```sh
npm ci
npm run dev        # http://localhost:5173, proxies /v1 → http://127.0.0.1:8000
npm test           # vitest (jsdom)
npm run lint       # eslint + prettier --check
npm run build      # tsc -b && vite build → dist/
```

Session model: the API sets the refresh token as an httpOnly cookie on `/v1/auth/*`; the
access token lives only in memory (`src/lib/api.ts`). No localStorage (CONSTITUTION §13.4/§14.2).

Production: Caddy serves `dist/` on the app host and proxies `/v1` to the API so the cookie is
first-party. See `shieldscan-docs/OPERATIONS-RUNBOOK.md`.
