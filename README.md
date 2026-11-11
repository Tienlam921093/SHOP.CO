# Bài 2 — SHOP.CO

This folder contains the separate Bài 2 implementation. Bài 1 remains in the `figma` folder.

## Run locally

Requires Node.js 22 or newer. From this folder:

```powershell
npm start
```

Open `http://localhost:4173/shop.html` (if port 4173 is occupied, the server reports another available port).

Email registration and login use the local server. To enable Google Sign-In, copy `.env.example` to `.env`, set your Web application OAuth `GOOGLE_CLIENT_ID` and a random `SESSION_SECRET`, then restart the server. Existing deployment environment variables take precedence. Add the exact browser origin (including port) to that OAuth client's authorized JavaScript origins. Never commit `.env`.

Product images used by this site are stored in `assets/shop2/`.
