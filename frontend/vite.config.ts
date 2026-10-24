import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Link previews need an absolute og:image URL. VITE_SITE_URL wins; on Vercel the production domain is known at build time.
const siteUrl = (
  process.env.VITE_SITE_URL ??
  (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : "")
).replace(/\/$/, "");

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    { name: "site-url", transformIndexHtml: (html) => html.replaceAll("%SITE_URL%", siteUrl) },
  ],
  server: { port: 5173 },
});
