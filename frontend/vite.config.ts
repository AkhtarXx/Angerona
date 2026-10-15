import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// AngeronaLabs public website configuration.
//
// This site is separate from the local product control panel in `src/web/`.
// Its normal production output stays under `frontend/dist/`, which is ignored.
const BACKEND = process.env.ANGERONA_BACKEND ?? 'http://127.0.0.1:8765'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: BACKEND, changeOrigin: true },
      '/static': { target: BACKEND, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          // Split React core, react-dom, and scheduler into separate chunks so
          // the large react-dom bundle is not evaluated in one long task on the
          // main thread. React core is tiny and needed immediately; react-dom
          // parsing can be scheduled by the browser more granularly.
          if (id.includes('node_modules/react-dom')) return 'react-dom'
          if (id.includes('node_modules/scheduler')) return 'react-dom'
          if (id.includes('node_modules/react/')) return 'react'
        },
      },
    },
  },
})
