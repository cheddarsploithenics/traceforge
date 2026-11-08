import react from "@vitejs/plugin-react";
import type { PreviewOptions } from "vite";
import { defineConfig } from "vitest/config";

// The dashboard is always served same-origin with the API: Vite proxies the
// API paths, so the browser never makes a cross-origin request and the API
// needs no CORS at all. See docs/THREAT_MODEL.md.
const apiTarget = process.env.TRACEFORGE_API_URL ?? "http://127.0.0.1:8000";
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);
if (!LOOPBACK.has(new URL(apiTarget).hostname)) {
  throw new Error(`TRACEFORGE_API_URL must point to a loopback address, got ${apiTarget}`);
}

const apiProxy = {
  target: apiTarget,
  // Rewrite Host to the API's own address so its trusted-host check passes.
  // Origin and Sec-Fetch-* are forwarded untouched for the API to verify.
  changeOrigin: true,
  xfwd: false,
};
const proxy = { "^/api/": apiProxy, "^/health$": apiProxy };

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
};
// The production build has no inline scripts, so the preview server can use a
// strict policy. (The dev server cannot: React Fast Refresh injects inline code.)
const contentSecurityPolicy = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const common: PreviewOptions = {
  host: "127.0.0.1",
  strictPort: true,
  proxy,
  // No CORS: other origins must not read dashboard sources or proxied API data.
  cors: false,
  // Only localhost/IP Host headers (Vite's built-in default); never `true`,
  // which would re-open DNS rebinding.
  allowedHosts: [],
};

export default defineConfig({
  plugins: [react()],
  server: { ...common, port: 5173, headers: securityHeaders },
  preview: {
    ...common,
    port: 4173,
    headers: { ...securityHeaders, "Content-Security-Policy": contentSecurityPolicy },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
  },
});
