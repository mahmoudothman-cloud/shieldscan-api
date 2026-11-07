/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

// Dev: the API runs on :8000 (uvicorn); /v1 is proxied so the session
// cookie is first-party and CORS never enters the picture locally.
// Prod: Caddy serves dist/ on app.<domain> and proxies /v1 to the API.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  server: {
    port: 5173,
    proxy: { "/v1": { target: "http://127.0.0.1:8000", changeOrigin: false } },
  },
  build: { sourcemap: false, target: "es2022" },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
