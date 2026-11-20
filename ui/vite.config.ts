import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves the dev server over plain HTTP on a fixed port; anything that
// needs `crossOriginIsolated` (nothing here today) would have to change this.
export default defineConfig({
  plugins: [react()],
  // Relative asset URLs: the same bundle must work under the Tauri custom
  // protocol, under a plain static server, and when opened from disk.
  base: "./",
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    host: "127.0.0.1",
  },
  build: {
    target: "es2021",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 800,
  },
});
