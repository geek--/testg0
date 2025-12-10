// vite.config.ts
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  server: {
    host: "0.0.0.0",
    port: 4173,
    strictPort: true,
    proxy: {
      // Todo lo que empiece con /api se envía al natu-core en 127.0.0.1:5010
      "/api": {
        target: "http://127.0.0.1:5010",
        changeOrigin: true,
      },
    },
  },
  build: {
    sourcemap: false,
  },
});
