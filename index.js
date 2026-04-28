/**
 * Smart Billing License Server v2.0
 * Cloud Sprint | contact@cloudsprint.in
 *
 * Run: node index.js
 * Dashboard: http://localhost:3000/?token=YOUR_SECRET
 */

require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const path       = require('path');
const db         = require('./models/db');

// Railway uses port 8080 by default
const PORT = process.env.PORT || 8080;
const app  = express();

// ── Security Headers ────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false  // allow dashboard inline scripts
}));

// ── Body Parser ─────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ── Trust proxy (for Railway/Render) ───────────────────────────
app.set('trust proxy', false); // set to false for local PC use

// ── Request logger ────────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/admin')) {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  }
  next();
});

// ── Rate Limiting ────────────────────────────────────────────────
// Activation: max 20 attempts per IP per 15 minutes
const activationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      20,
  message:  { success: false, error: 'Too many activation attempts. Please wait 15 minutes.' },
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator:    (req) => req.ip || 'unknown'
});

// Validation ping: max 200 per hour per IP
const validationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max:      200,
  message:  { success: false, error: 'Validation rate limit exceeded.' },
  standardHeaders: true,
  legacyHeaders:   false
});

// Admin endpoints: max 100 per hour per IP
const adminLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max:      100,
  message:  { success: false, error: 'Admin rate limit exceeded.' }
});

// ── Apply Rate Limits ────────────────────────────────────────────
app.use('/api/activate',   activationLimiter);
app.use('/api/validate',   validationLimiter);
app.use('/admin',          adminLimiter);

// ── CORS ────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  next();
});

// ── Routes ───────────────────────────────────────────────────────
const licenseRoutes = require('./routes/license');
const adminRoutes   = require('./routes/admin');

app.use('/api',    licenseRoutes);
app.use('/admin',  adminRoutes);

// ── Static files ─────────────────────────────────────────────
app.use('/public', express.static(path.join(__dirname, 'public')));

// ── Test page (open from phone browser to check connectivity) ─
app.get('/test', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'test.html'));
});
app.get('/', (req, res) => {
  const token = req.query.token || req.headers['authorization']?.replace('Bearer ', '');
  if (token !== (process.env.API_SECRET || 'cs_admin_2024_secure')) {
    return res.status(401).send(`
      <html><head><title>Smart Billing Admin</title>
      <style>body{background:#0a0f1e;color:#f1f5f9;font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:12px}
      h2{font-size:22px}p{color:#94a3b8;font-size:14px}code{background:#1e293b;padding:4px 8px;border-radius:4px;font-family:monospace}</style></head>
      <body><div style="font-size:48px">🔑</div>
      <h2>Smart Billing License Admin</h2>
      <p>Access requires admin token</p>
      <p>URL format: <code>http://your-server:3000/?token=YOUR_SECRET</code></p>
      </body></html>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ── Health Check ─────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    service:   'SmartBilling License Server',
    version:   '2.0.0',
    timestamp: new Date().toISOString()
  });
});

// ── 404 ──────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Not found' });
});

// ── Error handler ────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────
db.init().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[SmartBilling License Server] Running on port ${PORT}`);
    console.log(`[Health] http://localhost:${PORT}/health`);
    const secret = process.env.API_SECRET || 'cs_admin_2024_secure';
    console.log(`[Admin]  http://localhost:${PORT}/?token=${secret}`);
  });
}).catch(err => {
  console.error('[FATAL] DB init failed:', err.message);
  process.exit(1);
});
