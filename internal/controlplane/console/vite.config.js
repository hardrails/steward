import {defineConfig} from "vite";

export default defineConfig({
  base: "/console/",
  publicDir: "public",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "assets",
    assetsInlineLimit: 0,
    sourcemap: false,
    target: "es2022",
    rolldownOptions: {
      output: {
        entryFileNames: "assets/control-room-[hash].js",
        chunkFileNames: "assets/chunk-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]"
      }
    }
  }
});
