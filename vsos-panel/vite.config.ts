import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Tauri expects a fixed port
  server: {
    port: 1420,
    strictPort: true,
  },
  // 浮窗面板尺寸
  build: {
    target: 'esnext',
  },
})
