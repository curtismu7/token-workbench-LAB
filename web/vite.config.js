import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: the API runs on TW_PORT (default 5910) and Vite on VITE_PORT (default 5930); /api is proxied.
const api = { target: `http://127.0.0.1:${Number(process.env.TW_PORT) || 5910}` };

export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: Number(process.env.VITE_PORT) || 5930, strictPort: true, proxy: { "/api": api } },
  test: { environment: "jsdom", globals: true, setupFiles: "./src/testSetup.js" },
});
