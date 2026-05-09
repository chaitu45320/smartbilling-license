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

// Login endpoint: max 10 attempts per 15 minutes per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      10,
  message:  { success: false, error: 'Too many login attempts. Please wait 15 minutes.' },
  standardHeaders: true,
  legacyHeaders:   false
});

// ── Apply Rate Limits ────────────────────────────────────────────
app.use('/api/activate',   activationLimiter);
app.use('/api/validate',   validationLimiter);
app.use('/admin',          adminLimiter);
app.use('/admin-login',    loginLimiter);

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

// ── Login endpoint ────────────────────────────────────────────
app.post('/admin-login', (req, res) => {
  const { username, password } = req.body;
  const validUser = process.env.ADMIN_USERNAME || 'CloudSprint';
  const validPass = process.env.ADMIN_PASSWORD || 'CloudSprint_Admin_2024_Secure';
  if (username === validUser && password === validPass) {
    return res.json({ success: true, token: process.env.API_SECRET || 'cs_admin_2024_secure' });
  }
  console.log(`[LOGIN FAILED] username="${username}" ip=${req.ip}`);
  return res.status(401).json({ success: false, error: 'Invalid username or password' });
});

// ── Dashboard / Login page ────────────────────────────────────
app.get('/', (req, res) => {
  const token = req.query.token || req.headers['authorization']?.replace('Bearer ', '');

  // If valid token provided, serve dashboard directly
  if (token && token === (process.env.API_SECRET || 'cs_admin_2024_secure')) {
    return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  }

  // Otherwise show login form
  res.status(401).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>SmartBilling Admin Login</title>
      <meta charset="UTF-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          background: #0a0f1e;
          color: #f1f5f9;
          font-family: Arial, sans-serif;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          padding: 16px;
        }
        .card {
          background: #1e293b;
          border-radius: 12px;
          padding: 40px 36px;
          width: 100%;
          max-width: 380px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }
        .logo { text-align: center; font-size: 44px; margin-bottom: 10px; }
        h2 { text-align: center; font-size: 20px; margin-bottom: 4px; }
        .subtitle { text-align: center; color: #94a3b8; font-size: 13px; margin-bottom: 32px; }
        label { display: block; font-size: 13px; color: #94a3b8; margin-bottom: 6px; }
        input {
          width: 100%;
          padding: 11px 14px;
          background: #0f172a;
          border: 1px solid #334155;
          border-radius: 8px;
          color: #f1f5f9;
          font-size: 15px;
          margin-bottom: 18px;
          outline: none;
          transition: border-color 0.2s;
        }
        input:focus { border-color: #3b82f6; }
        button {
          width: 100%;
          padding: 12px;
          background: #3b82f6;
          color: #fff;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          cursor: pointer;
          font-weight: bold;
          transition: background 0.2s;
        }
        button:hover { background: #2563eb; }
        button:disabled { background: #1e40af; cursor: not-allowed; opacity: 0.7; }
        .err {
          background: #450a0a;
          border: 1px solid #ef4444;
          color: #f87171;
          border-radius: 8px;
          padding: 10px 14px;
          font-size: 13px;
          margin-bottom: 16px;
          display: none;
        }
        .footer {
          text-align: center;
          color: #475569;
          font-size: 12px;
          margin-top: 24px;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="logo">🔑</div>
        <h2>SmartBilling Admin</h2>
        <p class="subtitle">Cloud Sprint License Portal</p>

        <div class="err" id="err"></div>

        <label for="user">Username</label>
        <input
          type="text"
          id="user"
          placeholder="Enter username"
          autocomplete="username"
          onkeydown="if(event.key==='Enter')document.getElementById('pass').focus()"
        />

        <label for="pass">Password</label>
        <input
          type="password"
          id="pass"
          placeholder="Enter password"
          autocomplete="current-password"
          onkeydown="if(event.key==='Enter')login()"
        />

        <button id="btn" onclick="login()">Login</button>

        <div class="footer">Cloud Sprint &copy; 2024 &nbsp;|&nbsp; contact@cloudsprint.in</div>
      </div>

      <script>
        // Auto-focus username field
        window.onload = function() {
          document.getElementById('user').focus();
        };

        function login() {
          const u   = document.getElementById('user').value.trim();
          const p   = document.getElementById('pass').value.trim();
          const err = document.getElementById('err');
          const btn = document.getElementById('btn');

          err.style.display = 'none';

          if (!u || !p) {
            err.textContent   = 'Please enter username and password.';
            err.style.display = 'block';
            return;
          }

          btn.disabled    = true;
          btn.textContent = 'Logging in...';

          fetch('/admin-login', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ username: u, password: p })
          })
          .then(function(r) { return r.json(); })
          .then(function(d) {
            if (d.success) {
              window.location.href = '/?token=' + encodeURIComponent(d.token);
            } else {
              err.textContent   = 'Invalid username or password.';
              err.style.display = 'block';
              btn.disabled      = false;
              btn.textContent   = 'Login';
              document.getElementById('pass').value = '';
              document.getElementById('pass').focus();
            }
          })
          .catch(function() {
            err.textContent   = 'Server error. Please try again.';
            err.style.display = 'block';
            btn.disabled      = false;
            btn.textContent   = 'Login';
          });
        }
      </script>
    </body>
    </html>
  `);
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
    console.log(`[Admin]  http://localhost:${PORT}/`);
  });
}).catch(err => {
  console.error('[FATAL] DB init failed:', err.message);
  process.exit(1);
});
