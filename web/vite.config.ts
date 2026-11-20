import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// NETRA_DEV_API points the dev proxy at another controller (e.g. a lab's
// https://host:30870 with its self-signed cert) instead of a local netrad.
const api = process.env.NETRA_DEV_API || 'http://127.0.0.1:8080';
const upstream = { target: api, secure: false, changeOrigin: true };

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { ...upstream, ws: true },
      '/healthz': upstream,
    },
  },
  optimizeDeps: {
    include: ['@novnc/novnc/lib/rfb.js'],
  },
});
