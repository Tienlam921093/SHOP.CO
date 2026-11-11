const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const scrypt = promisify(crypto.scrypt);

const ROOT = __dirname;
// Deployment environment variables take precedence over local configuration.
if (fs.existsSync(path.join(ROOT, '.env'))) process.loadEnvFile(path.join(ROOT, '.env'));
const DEFAULT_PORT = Number(process.env.PORT || 4173);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_TTL = 7 * 24 * 60 * 60;
const USERS_FILE = path.join(ROOT, 'data', 'users.json');
const ORDERS_FILE = process.env.ORDERS_FILE || path.join(ROOT, 'data', 'orders.json');
const MIME_TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.ico': 'image/x-icon' };
let googleKeysCache;

function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify(body));
}

function parseCookies(header = '') {
  return Object.fromEntries(header.split(';').map((part) => part.trim().split('=').map(decodeURIComponent)).filter((parts) => parts.length >= 2));
}

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function makeSession(user) {
  const payload = Buffer.from(JSON.stringify({ sub: user.id, exp: Math.floor(Date.now() / 1000) + SESSION_TTL })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function sessionCookie(user) {
  return `exclusive_session=${encodeURIComponent(makeSession(user))}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
}

function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

async function registerWithEmail(body) {
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const email = normalizeEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : '';
  if (name.length < 2 || name.length > 100) throw Object.assign(new Error('Enter a name between 2 and 100 characters.'), { status: 400 });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw Object.assign(new Error('Enter a valid email address.'), { status: 400 });
  if (password.length < 8 || password.length > 256) throw Object.assign(new Error('Password must be at least 8 characters.'), { status: 400 });

  await fs.promises.mkdir(path.dirname(USERS_FILE), { recursive: true });
  let users = [];
  try { users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!Array.isArray(users)) users = [];
  if (users.some((user) => user.email === email && user.provider === 'email')) throw Object.assign(new Error('An account with this email already exists. Please log in.'), { status: 409 });
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
  const user = { id: `email:${crypto.randomUUID()}`, provider: 'email', email, name, passwordSalt: salt, passwordHash, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  users.push(user);
  await fs.promises.writeFile(USERS_FILE, JSON.stringify(users, null, 2), { mode: 0o600 });
  return user;
}

async function loginWithEmail(body) {
  const email = normalizeEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : '';
  let users;
  try { users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8')); } catch (error) {
    if (error.code === 'ENOENT') users = [];
    else throw error;
  }
  const user = Array.isArray(users) ? users.find((item) => item.provider === 'email' && item.email === email) : null;
  if (!user || !user.passwordSalt || !user.passwordHash) throw Object.assign(new Error('Email or password is incorrect.'), { status: 401 });
  const actual = await scrypt(password, user.passwordSalt, 64);
  const expected = Buffer.from(user.passwordHash, 'hex');
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) throw Object.assign(new Error('Email or password is incorrect.'), { status: 401 });
  return user;
}

function readSession(req) {
  const token = parseCookies(req.headers.cookie).exclusive_session || '';
  const [payload, signature, extra] = token.split('.');
  if (!payload || !signature || extra) return null;
  const expected = Buffer.from(sign(payload));
  const received = Buffer.from(signature);
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!session.sub || session.exp <= Math.floor(Date.now() / 1000)) return null;
    return session;
  } catch {
    return null;
  }
}

async function readJson(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 20_000) throw Object.assign(new Error('Request body is too large.'), { status: 413 });
  }
  try { return JSON.parse(body || '{}'); } catch { throw Object.assign(new Error('Invalid JSON body.'), { status: 400 }); }
}

function normalizeOrder(body) {
  if (!Array.isArray(body.items) || body.items.length < 1 || body.items.length > 50) {
    throw Object.assign(new Error('An order must contain between 1 and 50 items.'), { status: 400 });
  }
  const items = body.items.map((item) => {
    const name = typeof item.name === 'string' ? item.name.trim() : '';
    const price = typeof item.price === 'string' ? item.price.trim() : '';
    const quantity = Number(item.quantity);
    const image = typeof item.image === 'string' ? item.image : '';
    if (!name || name.length > 120 || !/^\$\d+(?:\.\d{1,2})?$/.test(price) || !Number.isInteger(quantity) || quantity < 1 || quantity > 999 || !/^[\w./-]{1,200}$/.test(image) || image.includes('..')) {
      throw Object.assign(new Error('One or more order items are invalid.'), { status: 400 });
    }
    return { name, price, quantity, image };
  });
  return { items };
}

async function withOrdersLock(callback) {
  const lockPath = `${ORDERS_FILE}.lock`;
  await fs.promises.mkdir(path.dirname(ORDERS_FILE), { recursive: true });
  const startedAt = Date.now();
  let handle;
  while (!handle) {
    try {
      handle = await fs.promises.open(lockPath, 'wx', 0o600);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      try {
        const lockStat = await fs.promises.stat(lockPath);
        if (Date.now() - lockStat.mtimeMs > 30_000) {
          await fs.promises.unlink(lockPath);
          continue;
        }
      } catch (statError) { if (statError.code === 'ENOENT') continue; throw statError; }
      if (Date.now() - startedAt > 10_000) throw Object.assign(new Error('Order service is busy. Please retry with the same idempotency key.'), { status: 503 });
      await new Promise((resolve) => setTimeout(resolve, 15));
    }
  }
  try { return await callback(); }
  finally {
    await handle.close();
    await fs.promises.unlink(lockPath).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  }
}

async function createOrder(body, idempotencyKey, userId = 'guest') {
  if (typeof idempotencyKey !== 'string' || !/^[\w-]{16,128}$/.test(idempotencyKey)) {
    throw Object.assign(new Error('A valid Idempotency-Key header is required.'), { status: 400 });
  }
  const normalized = normalizeOrder(body);
  const requestHash = crypto.createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
  const scopedKey = crypto.createHash('sha256').update(`${userId}:${idempotencyKey}`).digest('hex');
  return withOrdersLock(async () => {
    let store = { orders: [], idempotency: {} };
    try {
      store = JSON.parse(await fs.promises.readFile(ORDERS_FILE, 'utf8'));
      if (!Array.isArray(store.orders) || !store.idempotency || typeof store.idempotency !== 'object') throw new Error('Order store is invalid.');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const previous = store.idempotency[scopedKey];
    if (previous) {
      if (previous.requestHash !== requestHash) throw Object.assign(new Error('This Idempotency-Key was already used for a different order.'), { status: 409 });
      return { order: previous.order, replayed: true };
    }
    const totalCents = normalized.items.reduce((sum, item) => sum + Math.round(Number(item.price.slice(1)) * 100) * item.quantity, 0);
    const order = { id: crypto.randomUUID(), userId, createdAt: new Date().toISOString(), status: 'Processing', items: normalized.items, total: totalCents / 100 };
    store.orders.unshift(order);
    store.idempotency[scopedKey] = { requestHash, order };
    const temporaryFile = `${ORDERS_FILE}.${process.pid}.${crypto.randomUUID()}.tmp`;
    await fs.promises.writeFile(temporaryFile, JSON.stringify(store, null, 2), { mode: 0o600 });
    await fs.promises.rename(temporaryFile, ORDERS_FILE);
    return { order, replayed: false };
  });
}

async function getGoogleKeys() {
  if (googleKeysCache && googleKeysCache.expiresAt > Date.now()) return googleKeysCache.keys;
  try {
    const response = await fetch('https://www.googleapis.com/oauth2/v3/certs');
    if (!response.ok) throw Object.assign(new Error(`Google's signing key service returned HTTP ${response.status}.`), { status: 502 });
    const data = await response.json();
    const maxAge = Number(response.headers.get('cache-control')?.match(/max-age=(\d+)/)?.[1] || 3600);
    googleKeysCache = { keys: data.keys, expiresAt: Date.now() + maxAge * 1000 };
    return data.keys;
  } catch (error) {
    if (error.status) throw error;
    throw Object.assign(new Error('Could not reach Google to verify the sign-in. Check the server internet connection and try again.'), { status: 502, cause: error });
  }
}

async function verifyGoogleIdToken(token) {
  if (!GOOGLE_CLIENT_ID) throw Object.assign(new Error('Google Sign-In is not configured yet. Add GOOGLE_CLIENT_ID to your environment.'), { status: 503 });
  if (typeof token !== 'string' || token.length > 12_000) throw Object.assign(new Error('Invalid Google credential.'), { status: 400 });
  const parts = token.split('.');
  if (parts.length !== 3) throw Object.assign(new Error('Invalid Google credential.'), { status: 401 });
  let header;
  let claims;
  try {
    const decodeJwtPart = (part) => JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    header = decodeJwtPart(parts[0]);
    claims = decodeJwtPart(parts[1]);
  } catch { throw Object.assign(new Error('Invalid Google credential.'), { status: 401 }); }
  if (header.alg !== 'RS256' || !header.kid) throw Object.assign(new Error('Unsupported Google credential.'), { status: 401 });
  const keys = await getGoogleKeys();
  const jwk = keys.find((key) => key.kid === header.kid && key.kty === 'RSA');
  if (!jwk) {
    googleKeysCache = null;
    throw Object.assign(new Error('Google credential key has expired. Please try again.'), { status: 401 });
  }
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const validSignature = crypto.verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2], 'base64url'));
  const now = Math.floor(Date.now() / 1000);
  const validIssuer = ['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss);
  const validAudience = claims.aud === GOOGLE_CLIENT_ID || (Array.isArray(claims.aud) && claims.aud.includes(GOOGLE_CLIENT_ID));
  const rejectCredential = (message) => { throw Object.assign(new Error(message), { status: 401 }); };
  if (!validSignature || !validIssuer) rejectCredential('Invalid Google credential signature or issuer. Please sign in again.');
  if (!validAudience) rejectCredential('Google Client ID mismatch. Reload this page; check that the frontend and server use the same GOOGLE_CLIENT_ID.');
  if (!Number.isFinite(claims.exp) || !Number.isFinite(claims.iat)) rejectCredential('Invalid Google credential timestamps. Please sign in again.');
  if (claims.exp <= now) rejectCredential('Google credential has expired. Sign in again and check the server date and time.');
  if (claims.iat > now + 60) rejectCredential('Google credential is newer than the server clock. Synchronize the server date and time, then retry.');
  if (!claims.sub || !claims.email || claims.email_verified !== true) rejectCredential('Google account email could not be verified.');
  return { id: claims.sub, email: claims.email, name: String(claims.name || claims.email).slice(0, 200), picture: typeof claims.picture === 'string' ? claims.picture : '' };
}

async function saveUser(googleUser) {
  await fs.promises.mkdir(path.dirname(USERS_FILE), { recursive: true });
  let users = [];
  try { users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!Array.isArray(users)) users = [];
  const existing = users.find((user) => user.provider === 'google' && user.id === googleUser.id);
  const user = { ...existing, ...googleUser, createdAt: existing?.createdAt || new Date().toISOString(), updatedAt: new Date().toISOString() };
  if (existing) Object.assign(existing, user);
  else users.push(user);
  const temporaryFile = `${USERS_FILE}.${process.pid}.tmp`;
  await fs.promises.writeFile(temporaryFile, JSON.stringify(users, null, 2), { mode: 0o600 });
  await fs.promises.rename(temporaryFile, USERS_FILE);
  return user;
}

async function handleApi(req, res, url) {
  if (req.method === 'POST' && url.pathname === '/api/orders') {
    const session = readSession(req);
    if (!session) return sendJson(res, 401, { error: 'Please log in before placing an order.' });
    const result = await createOrder(await readJson(req), req.headers['idempotency-key'], session?.sub || 'guest');
    return sendJson(res, result.replayed ? 200 : 201, result, { 'idempotency-replayed': String(result.replayed) });
  }
  if (req.method === 'GET' && url.pathname === '/api/orders') {
    const session = readSession(req);
    if (!session) return sendJson(res, 401, { error: 'Please log in to view your orders.' });
    let store = { orders: [] };
    try { store = JSON.parse(await fs.promises.readFile(ORDERS_FILE, 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    return sendJson(res, 200, { orders: store.orders.filter(order => order.userId === session.sub) });
  }
  if (req.method === 'GET' && url.pathname === '/api/config') return sendJson(res, 200, { googleClientId: GOOGLE_CLIENT_ID, authMethods: { email: true, google: Boolean(GOOGLE_CLIENT_ID) } });
  if (req.method === 'POST' && url.pathname === '/api/auth/signup') {
    const user = await registerWithEmail(await readJson(req));
    return sendJson(res, 201, { user: { id: user.id, email: user.email, name: user.name } }, { 'set-cookie': sessionCookie(user) });
  }
  if (req.method === 'POST' && url.pathname === '/api/auth/login') {
    const user = await loginWithEmail(await readJson(req));
    return sendJson(res, 200, { user: { id: user.id, email: user.email, name: user.name } }, { 'set-cookie': sessionCookie(user) });
  }
  if (req.method === 'POST' && url.pathname === '/api/auth/google') {
    const body = await readJson(req);
    const googleUser = await verifyGoogleIdToken(body.credential);
    let user = await saveUser({ ...googleUser, provider: 'google' });
    if (!user.name) user.name = googleUser.email;
    return sendJson(res, 200, { user: { id: user.id, email: user.email, name: user.name, picture: user.picture } }, { 'set-cookie': sessionCookie(user) });
  }
  if (req.method === 'GET' && url.pathname === '/api/session') {
    const session = readSession(req);
    if (!session) return sendJson(res, 200, { user: null });
    try {
      const users = JSON.parse(await fs.promises.readFile(USERS_FILE, 'utf8'));
      const user = users.find((item) => item.id === session.sub);
      return sendJson(res, 200, { user: user ? { id: user.id, email: user.email, name: user.name, picture: user.picture } : null });
    } catch { return sendJson(res, 200, { user: null }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/logout') {
    return sendJson(res, 200, { ok: true }, { 'set-cookie': `exclusive_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${process.env.NODE_ENV === 'production' ? '; Secure' : ''}` });
  }
  return sendJson(res, 404, { error: 'Not found.' });
}

const server = http.createServer(async (req, res) => {
  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'Method not allowed.' });
    const requested = decodeURIComponent(url.pathname === '/' ? '/shop.html' : url.pathname);
    if (!path.extname(requested)) {
      const page = path.basename(requested).replace(/\.html$/i, '');
      if (['signup', 'login', 'wishlist', 'cart', 'checkout', 'account', 'orders', 'about', 'contact', 'detail', '404'].includes(page)) {
        return res.writeHead(302, { location: `/index.html?page=${encodeURIComponent(page)}` }).end();
      }
    }
    const filePath = path.resolve(ROOT, `.${requested}`);
    const relativePath = path.relative(ROOT, filePath);
    const privateFile = relativePath.split(/[\\/]/).some(part => part.startsWith('.') || ['data', 'node_modules'].includes(part.toLowerCase())) || !['.html', '.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.webp', '.ico', '.woff', '.woff2'].includes(path.extname(filePath).toLowerCase()) || ['server.js', 'auth-smoke-test.js'].includes(relativePath.toLowerCase());
    if (privateFile || !filePath.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end('Not found.');
    }
    res.writeHead(200, { 'content-type': MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream', 'x-content-type-options': 'nosniff' });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(filePath).pipe(res);
  } catch (error) {
    const status = error.status || 500;
    if (status >= 500 && url?.pathname.startsWith('/api/')) console.error(`[${status}] ${req.method} ${url.pathname}:`, error);
    if (!res.headersSent) sendJson(res, status, { error: status === 500 ? 'Something went wrong. Please try again.' : error.message });
    else res.destroy();
  }
});

if (require.main === module) {
  const openBrowser = (url) => {
    if (process.env.NO_OPEN === '1') return;
    const { spawn } = require('node:child_process');
    const command = process.platform === 'win32' ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
    const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
    const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
    child.on('error', () => {});
    child.unref();
  };

  server.once('listening', () => {
    const port = server.address().port;
    const url = `http://localhost:${port}`;
    console.log(`SHOP.CO is running at ${url}`);
    openBrowser(url);
  });

  const listen = (port) => {
    server.once('error', (error) => {
      if (error.code === 'EADDRINUSE' && !process.env.PORT && port < DEFAULT_PORT + 20) {
        console.warn(`Port ${port} is busy. Trying ${port + 1}...`);
        listen(port + 1);
        return;
      }
      console.error(`Could not start SHOP.CO on port ${port}: ${error.message}`);
      if (error.code === 'EADDRINUSE') {
        console.error(`Choose an unused port, for example: $env:PORT=${port + 1}; npm start`);
      }
      process.exitCode = 1;
    });
    server.listen(port);
  };

  listen(DEFAULT_PORT);
}

module.exports = { registerWithEmail, loginWithEmail, verifyGoogleIdToken, makeSession, readSession, saveUser, createOrder, server };
