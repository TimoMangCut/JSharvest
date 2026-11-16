import { defineConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';

// Same app as vite-vanilla, plus a Workbox service worker that precaches every
// built file: its precache manifest (self.__WB_MANIFEST) lists all chunks.
export default defineConfig({
  worker: { format: 'es' },
  build: { outDir: 'dist', emptyOutDir: true },
  plugins: [
    VitePWA({
      registerType: 'autoUpdate',
      injectRegister: 'script',
      workbox: { globPatterns: ['**/*.{js,html}'] },
      manifest: false,
    }),
  ],
});
