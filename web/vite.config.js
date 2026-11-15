import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'node:path'
import fs from 'node:fs'
import zlib from 'node:zlib'

const ROOT = process.cwd()

// 构建期预压缩：为静态资源生成 .br / .gz，由 Rust 侧 assets.rs 按
// Accept-Encoding 直接返回，省掉运行时压缩开销。
function precompress() {
  return {
    name: 'vane-precompress',
    apply: 'build',
    closeBundle() {
      const out = path.join(ROOT, 'dist')
      if (!fs.existsSync(out)) return
      const exts = new Set(['.js', '.css', '.html', '.svg', '.json', '.webmanifest'])
      const walk = (dir) => {
        for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
          const p = path.join(dir, ent.name)
          if (ent.isDirectory()) { walk(p); continue }
          if (!exts.has(path.extname(ent.name))) continue
          const buf = fs.readFileSync(p)
          if (buf.length < 1024) continue
          fs.writeFileSync(p + '.br', zlib.brotliCompressSync(buf, {
            params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 }
          }))
          fs.writeFileSync(p + '.gz', zlib.gzipSync(buf, { level: 9 }))
        }
      }
      walk(out)
    }
  }
}

export default defineConfig({
  plugins: [vue(), precompress()],
  resolve: {
    alias: { '@': path.resolve(ROOT, './src') }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (/node_modules\/(vue|@vue|pinia|vue-router)\//.test(id)) return 'vendor'
        }
      }
    }
  },
  server: {
    proxy: {
      '/api': 'http://localhost:4455'
    }
  }
})
