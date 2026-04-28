import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In production the Flask app serves the built SPA from the same origin,
// so the dev proxy is dev-only.
export default defineConfig(({ command }) => ({
  plugins: [react()],
  server: command === 'serve' ? {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8787',
        changeOrigin: true,
      },
    },
  } : undefined,
}))
