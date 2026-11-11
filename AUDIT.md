# Functional audit — 2026-11-09

Changes: account-scoped cart/favorites/coupon, hidden guest counts, login requirement for shopping mutations, preserved size/color when toggling favorites, product-specific galleries, decimal currency, payload-scoped order retry keys, duplicate-submit guard, delegated checkout handler after session loading, checkout success notice on home, authenticated order history and order creation.

Verified:
- `npm test`: JavaScript syntax checks.
- `node .preview/server-audit.cjs`: isolated real server, email signup/login, wrong password rejection, session cookie, unauthenticated order rejection, 30 concurrent identical requests producing one order, isolated order history, logout response. Temporary fixture data is separate from project data.
- `node .preview/auth-flow.cjs`: Chrome via CDP on port 9226, app on 4175. Google callbacks and API responses are simulated. Login/signup, home, reload, account/logout, single-quantity add, thumbnail change, retained variant, account isolation, checkout redirect/empty cart.
- Chrome layout/image checks at 1440 and 390 pixels: home, category, jeans detail, empty cart, login; no horizontal overflow or broken images in those checks.

Limits: real Google OAuth still requires user interaction and a correctly synchronized server clock. Bank transfer is a demo selection, not a banking integration. Checkout currently persists order items/totals but does not persist shipping form or bank fields. This audit does not certify all routes, accessibility, or production payment/security readiness. No deployment was performed.
