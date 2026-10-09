ENGINEX v2 — shared server version (accounts, ads, messages, tickets, payments, admin)

RUN (needs Node.js 22.13 or newer — nodejs.org, no npm install)
  Double-click START_ENGINEX.bat  (or:  node server.js)  ->  http://localhost:3000
  All data is saved in enginex.db, shared by every visitor/device. Back this file up.

ADMIN   Set ADMIN_EMAIL and ADMIN_PASSWORD before starting the server (see .env.example). There is no default password.
        (Opening index.html directly from disk, with no server, runs an offline preview with a demo admin.)
  Admin tabs: Payments (approve/reject), Users, All ads, Support desk.

PAYMENTS
  Bank transfer (works now): set  BANK_NAME, BANK_ACCOUNT, BANK_IBAN  environment variables.
    Member pays, enters the transfer reference, admin approves in Dashboard > Payments,
    and the plan upgrades automatically.
  Card / mada / Apple Pay: create a Moyasar account (moyasar.com), then start with
    MOYASAR_SECRET=sk_live_xxx  PUBLIC_URL=https://yourdomain.com  node server.js
    The gateway webhook is verified with Moyasar before any plan is activated.
  Card payments are NOT tested against a live gateway in this build — test with Moyasar test keys first.

GOING LIVE: host on a VPS/Render/Railway with HTTPS and a persistent disk for enginex.db.

STILL TO DO BEFORE PUBLIC LAUNCH
  - Move remaining per-user permission checks (editing others' ads/profiles) from the browser to the server.
  - Featured-ad purchase button + featured-first sorting (server side is ready; UI not added).
  - Email sending (password reset, notifications), image uploads, Arabic/RTL, Mourjan-style categories & ad moderation queue.
