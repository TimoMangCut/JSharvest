import { defineConfig } from 'vite';

export default defineConfig({
  // The worker lazy-loads a chunk of its own, which needs ES module output.
  worker: { format: 'es' },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Keep the defaults that matter here: hashed chunk names under assets/,
    // and module preload of each lazy chunk's dependencies (__vite__mapDeps).
  },
});
