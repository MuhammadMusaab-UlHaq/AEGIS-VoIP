import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    host: true, // Listen on all addresses
    allowedHosts: [
      '.trycloudflare.com', // Allow all Cloudflare tunnel subdomains
      'localhost',
      '127.0.0.1',
      '.ngrok-free.dev'
    ]
  }
})
