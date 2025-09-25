
require('dotenv').config();


const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const { parse } = require('pg-connection-string');
const bcrypt = require('bcryptjs');



const raw = process.env.PG_CONNECTION_STRING || process.env.DATABASE_URL;
if (!raw) throw new Error('PG_CONNECTION_STRING (or DATABASE_URL) is not set');

// Windows-friendly: always use TLS but skip cert verification in dev
const pool = new Pool({
  connectionString: raw.replace(/\?sslmode=require\b/i, ''), // strip flag if present
  ssl: { rejectUnauthorized: false }
});







const crypto = require('crypto');

const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
// === Email (SMTP first, then Resend fallback) ===
const nodemailer = require('nodemailer');
const { Resend } = require('resend');



const smtpTransport = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT || 587) === 465, // SSL for 465
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
    })
  : null;

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

async function sendEmailPlain(to, subject, text, from = (process.env.EMAIL_FROM || 'PlotNama <no-reply@plotnama.com>')) {
  // 1) Try SMTP
  if (smtpTransport) {
    try {
      await smtpTransport.sendMail({ from, to, subject, text });
      console.log('SMTP email sent');
      return true;
    } catch (err) {
      console.error('SMTP error:', err?.message || err);
    }
  }
  // 2) Fallback to Resend (if configured)
  if (resend) {
    try {
      const r = await resend.emails.send({ from, to, subject, text });
      console.log('Resend ok:', r?.id || r);
      return true;
    } catch (err) {
      console.error('Resend send error:', err?.message || err);
    }
  }
  // 3) Nothing worked
  console.warn('No email provider configured; dev fallback will return values to client');
  return false;
}

async function sendOtpEmail(to, code) {
  const subject = 'Your PlotNama OTP';
  const text = `Your PlotNama code is: ${code}\n\nIt expires in 10 minutes.`;
  return sendEmailPlain(to, subject, text);
}


const app = express();
app.set('trust proxy', 1);

// CORS (Express 5 friendly)
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Device-Id','X-Device-Type','X-Admin-Secret']

}));

// Preflight handler for ALL paths (no wildcards that break in Express 5)
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Device-Id, X-Device-Type, X-Admin-Secret');

    return res.sendStatus(204);
  }
  next();
});



app.use(express.json());

// Writable uploads dir: use /tmp on Vercel serverless, local folder otherwise
const UPLOAD_DIR =
  process.env.VERCEL === '1'
    ? '/tmp/uploads'
    : path.join(__dirname, process.env.UPLOAD_DIR || 'uploads');

try {
  // Will succeed locally; on Vercel we create /tmp/uploads (writable)
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
} catch (e) {
  console.warn('UPLOAD_DIR create skipped:', e.code || e.message);
}

// Only expose a static /uploads route when running NOT on Vercel
if (process.env.VERCEL !== '1') {
  app.use('/uploads', express.static(UPLOAD_DIR));
}


console.log('PG_CONNECTION_STRING =', process.env.PG_CONNECTION_STRING || '(missing)');







const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const TRIAL_DAYS = Number(process.env.TRIAL_DAYS || 3);


// helper: issue JWT
function sign(user, device_id) {
  return jwt.sign(
    { uid: user.id, email: user.email, device_id },
    JWT_SECRET,
    { expiresIn: '15d' }
  );
}
// ===== Device helpers =====
function guessDeviceType(ua) {
  return /Mobi|Android|iPhone|iPad/i.test(ua || '') ? 'mobile' : 'desktop';
}

async function upsertDeviceOnLogin({ user_id, device_id, device_type, ua, ip, replace = false }) {
  // Is there already an ACTIVE device of this type for this user?
  const existing = await pool.query(
    `select id, device_id
       from user_devices
      where user_id = $1
        and device_type = $2
        and status = 'active'
      limit 1`,
    [user_id, device_type]
  );

  if (existing.rows.length === 0) {
    await pool.query(
      `insert into user_devices(user_id, device_id, device_type, ua, ip)
       values ($1,$2,$3,$4,$5)`,
      [user_id, device_id, device_type, ua, ip]
    );
    return;
  }

  const current = existing.rows[0];

  // Same physical device logging in again -> just bump last_seen
  if (current.device_id === device_id) {
    await pool.query(
      `update user_devices
          set last_seen_at = now(), ua = $2, ip = $3
        where id = $1`,
      [current.id, ua, ip]
    );
    return;
  }

  // Different device of the same TYPE (mobile/desktop)
  if (!replace) {
    const err = new Error('device_limit');
    err.status = 403;
    err.details = { type: device_type }; // 'mobile' or 'desktop'
    throw err;
  }

  // Replace the old device
  await pool.query(`update user_devices set status='revoked' where id=$1`, [current.id]);
  await pool.query(
    `insert into user_devices(user_id, device_id, device_type, ua, ip)
     values ($1,$2,$3,$4,$5)`,
    [user_id, device_id, device_type, ua, ip]
  );
}

async function ensureTokenDeviceStillActive({ user_id, device_id }) {
  const r = await pool.query(
    `select 1
       from user_devices
      where user_id = $1
        and device_id = $2
        and status = 'active'
      limit 1`,
    [user_id, device_id]
  );
  if (r.rows.length === 0) {
    const err = new Error('device_revoked');
    err.status = 401;
    throw err;
  }
}





// auth middleware
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Make sure the device that owns this token is still active
    await ensureTokenDeviceStillActive({ user_id: payload.uid, device_id: payload.device_id });
    req.user = payload;
    next();
  } catch (e) {
    const code = e && e.status ? e.status : 500;

    res.status(code).json({ error: e.message || 'unauthorized' });
  }
}

// Only allow admins (or fallback via X-Admin-Secret for emergencies)
async function requireAdmin(req, res, next) {
  // admin secret override (optional)
  if ((req.header('x-admin-secret') || '') === (process.env.ADMIN_SECRET || '')) return next();

  if (!req.user?.uid) return res.status(401).json({ error: 'unauthorized' });
  const r = await pool.query('select is_admin from app_users where id=$1', [req.user.uid]);
  if (r.rows[0]?.is_admin) return next();
  return res.status(403).json({ error: 'forbidden' });
}

// compute subscription (trial if no active sub)
async function getSubscriptionStatus(userId) {
  const { rows } = await pool.query(
    `select *
       from subscriptions
      where user_id = $1
        and now() between start_at and end_at
      order by end_at desc
      limit 1`,
    [userId]
  );
 





  if (rows.length) {
    const end = new Date(rows[0].end_at);
    const daysLeft = Math.ceil((end - new Date()) / (1000*60*60*24));
    return { mode: 'paid', days_left: Math.max(daysLeft, 0), end_at: rows[0].end_at };
  }
  // fallback trial: from user.created_at
  const u = await pool.query('select created_at from app_users where id=$1', [userId]);
  const created = new Date(u.rows[0].created_at);
  const trialEnd = new Date(created.getTime() + TRIAL_DAYS*24*60*60*1000);
  const daysLeft = Math.ceil((trialEnd - new Date()) / (1000*60*60*24));
  return { mode: 'trial', days_left: Math.max(daysLeft, 0), end_at: trialEnd.toISOString() };
}

function readOnlyMiddleware() {
  return async (req, res, next) => {
    const { uid } = req.user || {};
    if (!uid) return res.status(401).json({ error: 'unauthorized' });
    const sub = await getSubscriptionStatus(uid);
    const expired = sub.days_left <= 0;
    // only block mutating requests if expired
    if (expired && ['POST','PUT','PATCH','DELETE'].includes(req.method)) {
      return res.status(402).json({ error: 'subscription_expired', message: 'Your plan has expired. App is read-only.' });
    }
    next();
  };
}
// ---- OTP helper (one place) ----
function randomOtp() {
  // 6-digit string, e.g. "482913"
  return String(Math.floor(100000 + Math.random() * 900000));
}

/* ============ AUTH (prototype OTP) ============ */

/**
 * POST /auth/signup { email }
 * Creates/updates user, creates an OTP, returns it (for prototype use).
 * In production: send the OTP via email and DO NOT return it.
 */
app.post('/auth/signup', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email_required' });

  // upsert user
  const u = await pool.query(
    `insert into app_users (email) values ($1)
     on conflict (email) do update set email=excluded.email
     returning *`,
    [email]
  );

  // issue OTP (6-digit, 10 min)
const code = randomOtp();
await pool.query(
  `insert into otps (email, code, expires_at)
   values ($1, $2, NOW() + INTERVAL '10 minutes')
   on conflict (email) do update set code = EXCLUDED.code, expires_at = EXCLUDED.expires_at`,
  [email, code]
);


  // try to email; if no RESEND key, fall back to dev behavior
  const emailed = await sendOtpEmail(email, code);
  if (!emailed) {
    return res.json({ ok: true, otp_for_testing: code }); // DEV fallback
  }
  return res.json({ ok: true, message: 'OTP sent' });
});


/**
 * POST /auth/verify { email, code }
 * Verifies OTP and returns JWT.
 */
app.post('/auth/verify', async (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: 'missing_fields' });

  const { rows } = await pool.query('select * from otps where email=$1', [email]);
  if (!rows.length) return res.status(400).json({ error: 'invalid_otp' });
  const row = rows[0];
  if (row.code !== code) return res.status(400).json({ error: 'invalid_otp' });
  if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: 'otp_expired' });

  // Get the user
  const u = await pool.query('select * from app_users where email=$1', [email]);
  const user = u.rows[0];

  // ---- Device info coming from client ----
  // DealerBook already sends X-Device-Id; if it’s missing, we generate one.
  const device_id   = req.header('x-device-id') || `web-${crypto.randomUUID()}`;
const ua          = req.header('user-agent') || '';
const ip          = req.ip;
const rawType     = String(req.header('x-device-type') || '').toLowerCase();
const device_type = (rawType === 'mobile' || rawType === 'desktop') ? rawType : guessDeviceType(ua);
const replace     = String(req.header('x-replace-device') || '') === '1';


  try {
    await upsertDeviceOnLogin({
      user_id: user.id,
      device_id,
      device_type,
      ua,
      ip,
      replace
    });
  } catch (e) {
    if (e.message === 'device_limit') {
      return res.status(e.status || 403).json({
        error: 'device_limit',
        details: e.details || { type: device_type } // which type is blocked
      });
    }
    throw e;
  }
  // Invalidate OTP after successful use
  await pool.query('delete from otps where email=$1', [email]);

  // Issue token bound to this device
  const token = sign(user, device_id);
  res.json({ token, device_id, device_type });
});

/* ============ AUTH (password + OTP 2FA) ============ */
/**
 * POST /auth/register { email, password, confirm }
 * Creates/updates user with password, then sends OTP for second factor.
 */
app.post('/auth/register', async (req, res) => {
  try {
    const { email, name } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email_required' });

    // Upsert user (keep whatever columns you already have)
    const u = await pool.query(
      `insert into app_users (email, name)
       values ($1, $2)
       on conflict (email) do update set name = coalesce(excluded.name, app_users.name)
       returning *`,
      [email, name || null]
    );

    // --- issue OTP (6-digit, 10 minutes) ---
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      `insert into otps (email, code, expires_at)
       values ($1, $2, $3)
       on conflict (email) do update set code = $2, expires_at = $3`,
      [email, code, expiresAt.toISOString()]
    );

    // --- try to email the OTP (uses the helper we added earlier) ---
    const emailed = await sendOtpEmail(email, code);

    if (!emailed) {
      // DEV fallback if RESEND_API_KEY not set: return OTP so you can still test
      return res.json({ ok: true, next: 'otp', otp_for_testing: code });
    }

    // Production behavior: do NOT reveal the OTP
    return res.json({ ok: true, next: 'otp', message: 'OTP sent' });
  } catch (err) {
    console.error('register error', err);
    return res.status(500).json({ error: 'server_error' });
  }
});


/**
 * POST /auth/login { email, password }
 * Verifies password, then sends OTP. Final login is /auth/verify (same as before).
 */
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });

  const { rows } = await pool.query('select id,email,password_hash from app_users where email=$1', [email]);
  if (!rows.length || !rows[0].password_hash) return res.status(400).json({ error: 'no_such_user_or_no_password' });
  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.status(400).json({ error: 'bad_credentials' });

  const code = String(Math.floor(100000 + Math.random()*900000));
  const expiresAt = new Date(Date.now() + 10*60*1000);
  await pool.query(
    `insert into otps (email, code, expires_at)
     values ($1,$2,$3)
     on conflict (email) do update set code=$2, expires_at=$3`,
    [email, code, expiresAt.toISOString()]
  );

  // try to email; if Resend isn’t set up, keep dev fallback
  const emailed = await sendOtpEmail(email, code);
  if (!emailed) return res.json({ ok: true, next: 'otp', otp_for_testing: code });

  return res.json({ ok: true, next: 'otp', message: 'OTP sent' });
});


/**
 * POST /auth/forgot { email }
 * Creates a reset token (1 hour). In prod: email this; in dev we return it.
 */
app.post('/auth/forgot', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email_required' });

  const { rows } = await pool.query('select id from app_users where email=$1', [email]);
  if (!rows.length) return res.json({ ok: true }); // do not leak

  const userId = rows[0].id;
  const token = crypto.randomBytes(24).toString('hex');
  const expiresAt = new Date(Date.now() + 60*60*1000); // 1 hour

  await pool.query(
    `insert into password_resets (user_id, token, expires_at) values ($1,$2,$3)`,
    [userId, token, expiresAt.toISOString()]
  );

    const emailed = await sendEmailPlain(
    email,
    'Reset your PlotNama password',
    `Use this code to reset your password: ${token}\n\nValid for 1 hour.`
  );

  if (emailed) {
    return res.json({ ok: true, message: 'If that email exists, a reset message was sent.' });
  } else {
    // DEV fallback: return token in response so you can test without email
    return res.json({ ok: true, reset_token_for_testing: token });
  }

});


/**
 * POST /auth/reset { token, password, confirm }
 * Consumes reset token and sets a new password.
 */
app.post('/auth/reset', async (req, res) => {
  const { token, password, confirm } = req.body || {};
  if (!token || !password || !confirm) return res.status(400).json({ error: 'missing_fields' });
  if (password !== confirm) return res.status(400).json({ error: 'password_mismatch' });
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });

  const { rows } = await pool.query('select * from password_resets where token=$1', [token]);
  if (!rows.length) return res.status(400).json({ error: 'invalid_token' });

  const r = rows[0];
  if (r.used) return res.status(400).json({ error: 'token_used' });
  if (new Date(r.expires_at) < new Date()) return res.status(400).json({ error: 'token_expired' });

  const hash = await bcrypt.hash(password, 10);
  await pool.query('update app_users set password_hash=$1 where id=$2', [hash, r.user_id]);
  await pool.query('update password_resets set used=true where id=$1', [r.id]);

  res.json({ ok: true });
});

/* ============ ME / SUBSCRIPTION ============ */

app.get('/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    'select id,email,name,created_at,status,is_admin from app_users where id=$1',
    [req.user.uid]
  );
  const me = rows[0];
  const sub = await getSubscriptionStatus(req.user.uid);
  res.json({ user: me, subscription: sub });
});



app.get('/subscription', requireAuth, async (req, res) => {
  const sub = await getSubscriptionStatus(req.user.uid);
  res.json(sub);
});
/* ============ PUBLIC SETTINGS (read-only) ============ */
app.get('/public/settings', async (req, res) => {
  try {
    const { rows } = await pool.query(`select key, value from settings`);
    const out = {};
    for (const r of rows) out[r.key] = r.value;
    res.json(out); // e.g. { billing: { bank:{...}, wallets:{...}, whatsapp:"...", note:"..." } }
  } catch (e) {
    console.error('GET /public/settings failed:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

/* ============ DICTIONARY (societies) ============ */
// GET all default + user-specific societies
app.get('/societies', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `select id, name, city, aliases
       from societies
      where user_id is null or user_id = $1
      order by name asc`,
    [req.user.uid]
  );
  res.json(rows);
});

// Bulk upsert user-specific societies
// body: { items: [{ name, city, aliases: string[] }, ...] }
app.post('/societies', requireAuth, async (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  for (const it of items) {
    await pool.query(
      `insert into societies (user_id, name, city, aliases)
         values ($1,$2,$3,$4)
       on conflict (user_id, name)
         do update set city = excluded.city, aliases = excluded.aliases`,
      [req.user.uid, it.name || '', it.city || null, it.aliases || []]
    );
  }
  res.json({ ok: true, count: items.length });
});


/* ============ LISTINGS ============ */
/* Unified: if a valid JWT is present, return that user's filtered feed.
 * If not authenticated, fall back to a public recent feed.
 */
app.get('/listings', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '200', 10), 500);

    // Try to authenticate (optional)
    let uid = null;
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (token) {
      try {
        const payload = jwt.verify(token, JWT_SECRET);
        await ensureTokenDeviceStillActive({ user_id: payload.uid, device_id: payload.device_id });
        uid = payload.uid;
      } catch { /* ignore => fall back to public */ }
    }

    // Authenticated (per-user) feed
    if (uid) {
      const { soc, blk, unit, min, max, q, nature } = req.query;
      const params = [uid];
      let where = 'user_id=$1';
      if (soc)   { params.push(soc);   where += ` and society_name=$${params.length}`; }
      if (blk)   { params.push(blk);   where += ` and phase_block=$${params.length}`; }
      if (unit)  { params.push(unit);  where += ` and plot_size_unit=$${params.length}`; }
      if (nature){ params.push(nature);where += ` and coalesce(attributes->>'land_nature','')=$${params.length}`; }
      if (min)   { params.push(Number(min)); where += ` and coalesce(demand_amount_pkr,0) >= $${params.length}`; }
      if (max)   { params.push(Number(max)); where += ` and coalesce(demand_amount_pkr,0) <= $${params.length}`; }
      if (q) {
        const like = `%${String(q).toLowerCase()}%`;
        params.push(like, like, like, like, like);
        where += ` and (lower(coalesce(society_name,'')) like $${params.length-4}
                      or lower(coalesce(phase_block,'')) like $${params.length-3}
                      or lower(coalesce(plot_number,'')) like $${params.length-2}
                      or lower(coalesce(notes,'')) like $${params.length-1}
                      or lower(coalesce(demand_text,'')) like $${params.length})`;
      }
      const { rows } = await pool.query(
        `select * from listings where ${where} order by created_at desc limit $${params.length+1}`,
        [...params, limit]
      );
      return res.json(rows);
    }

    // Public (unauthenticated) feed
    const { rows } = await pool.query(
      `select id, society_name, phase_block, plot_size_value, plot_size_unit, plot_number, demand_amount_pkr
         from listings
        order by created_at desc
        limit $1`,
      [limit]
    );
    res.json(rows);
  } catch (e) {
    console.error('GET /listings failed:', e);
    res.status(500).json({ error: 'server_error' });
  }
});


// Create a listing (user-scoped)
app.post('/listings', requireAuth, readOnlyMiddleware(), express.json(), async (req, res) => {
  try {
    const uid = req.user.uid; // set by requireAuth
    const {
      society_name,
      phase_block,
      plot_size_value,
      plot_size_unit,
      plot_number,
      demand_amount_pkr,
      phone,
      notes,
      attributes
    } = req.body || {};

    const { rows } = await pool.query(
      `insert into listings
         (user_id, society_name, phase_block, plot_size_value, plot_size_unit,
          plot_number, demand_amount_pkr, phone, notes, attributes)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       returning id`,
      [
        uid,
        society_name || null,
        phase_block || null,
        plot_size_value ?? null,
        plot_size_unit || 'Marla',
        plot_number || null,
        demand_amount_pkr ?? null,
        phone || null,
        notes || null,
        attributes || null
      ]
    );

    res.status(201).json({ id: rows[0].id });
  } catch (e) {
    console.error('POST /listings error', e);
    res.status(500).json({ error: 'server_error' });
  }
});




/* ============ PAYMENTS (screenshot upload) ============ */

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file?.originalname || '');
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  },
});
const upload = multer({ storage });

app.post('/payments', requireAuth, upload.single('screenshot'), async (req, res) => {
  const { method, amount, period_days } = req.body || {};
  const fileUrl = req.file
  ? (process.env.VERCEL === '1'
      ? null                                 // stored in /tmp, not publicly served
      : `/uploads/${req.file.filename}`)     // local/dev: served statically
  : null;


  const { rows } = await pool.query(
    `insert into payments (user_id, method, amount, period_days, screenshot_url, verification_status)
     values ($1,$2,$3,$4,$5,'pending') returning *`,
    [ req.user.uid, method || null, amount ? Number(amount) : null, period_days ? Number(period_days) : null, fileUrl ]
  );
  res.json(rows[0]);
});
// Admin: approve a payment by ID (fires the DB trigger)
// Admin: approve (idempotent)
app.post('/admin/payments/:id/approve', requireAuth, requireAdmin, async (req, res) => {

  if ((req.header('x-admin-secret') || '') !== (process.env.ADMIN_SECRET || '')) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const id = Number(req.params.id);
  const { rowCount } = await pool.query(
    `update payments
        set verification_status='approved'
      where id=$1 and verification_status='pending'`,
    [id]
  );
  res.json({ ok: true, id, changed: rowCount });
});

// Admin: reject (optional)
app.post('/admin/payments/:id/reject', requireAuth, requireAdmin, async (req, res) => {

  if ((req.header('x-admin-secret') || '') !== (process.env.ADMIN_SECRET || '')) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const id = Number(req.params.id);
  const { rowCount } = await pool.query(
    `update payments
        set verification_status='rejected'
      where id=$1 and verification_status='pending'`,
    [id]
  );
  res.json({ ok: true, id, changed: rowCount });
});

// Admin: list (default pending)
app.get('/admin/payments', requireAuth, requireAdmin, async (req, res) => {

  if ((req.header('x-admin-secret') || '') !== (process.env.ADMIN_SECRET || '')) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const status = String(req.query.status || 'pending');
  const { rows } = await pool.query(
    `select p.id, p.user_id, u.email,
            p.method, p.amount, p.period_days, p.screenshot_url,
            p.verification_status, p.created_at
       from payments p
  left join app_users u on u.id = p.user_id
      where p.verification_status = $1
      order by p.created_at desc
      limit 200`,
    [status]
  );
  res.json(rows);
});
/* ============ ADMIN: USERS & PLANS ============ */

// Helper: admin-secret check (we already gate with requireAuth+requireAdmin)
function requireAdminSecret(req, res) {
  if ((req.header('x-admin-secret') || '') !== (process.env.ADMIN_SECRET || '')) {
    res.status(401).json({ error: 'unauthorized' });
    return false;
  }
  return true;
}

// GET /admin/users?query=abc   -> minimal profile + subscription snapshot
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  if (!requireAdminSecret(req, res)) return;

  const q = String(req.query.query || '').trim();
  const rows = q
    ? (await pool.query(
        `select id, email, name, created_at, status, is_admin
           from app_users
          where email ilike $1
          order by email asc
          limit 100`,
        [`%${q}%`]
      )).rows
    : (await pool.query(
        `select id, email, name, created_at, status, is_admin
           from app_users
          order by created_at desc
          limit 50`
      )).rows;

  // attach subscription snapshot
  const out = [];
  for (const u of rows) {
    const sub = await getSubscriptionStatus(u.id);
    out.push({ ...u, subscription: sub });
  }
  res.json(out);
});

// POST /admin/users { email } -> create if not exists, return row
app.post('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  if (!requireAdminSecret(req, res)) return;
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email_required' });

  const r = await pool.query(
    `insert into app_users(email) values($1)
       on conflict (email) do update set email=excluded.email
     returning id, email, name, created_at, status, is_admin`,
    [email]
  );
  res.json(r.rows[0]);
});

// POST /admin/users/:id/subscription/extend { period_days, plan? , idem_key? }
app.post('/admin/users/:id/subscription/extend', requireAuth, requireAdmin, async (req, res) => {
  if (!requireAdminSecret(req, res)) return;
  const userId = Number(req.params.id);
  const period = Number(req.body?.period_days || 0);
  const plan   = String(req.body?.plan || '').trim() || (
      period === 31  ? 'monthly' :
      period === 180 ? 'halfyear' :
      period === 365 ? 'yearly'  : 'custom'
  );
  const idem   = String(req.body?.idem_key || '');

  if (!userId || period <= 0) return res.status(400).json({ error: 'bad_args' });

  // optional idempotency (ledger) — create table once
  await pool.query(`
    create table if not exists subscription_ledger (
      idem_key   text primary key,
      user_id    bigint not null,
      period_days int not null,
      created_at timestamptz not null default now()
    )`);

  if (idem) {
    const ins = await pool.query(
      `insert into subscription_ledger(idem_key, user_id, period_days)
       values ($1,$2,$3)
       on conflict (idem_key) do nothing`,
      [idem, userId, period]
    );
    if (ins.rowCount === 0) {
      return res.json({ ok: true, changed: 0, reason: 'duplicate' });
    }
  }

  // extend (or start) subscription
  const now = new Date();
  const { rows } = await pool.query(
    `select start_at, end_at
       from subscriptions
      where user_id=$1 and end_at >= now()
      order by end_at desc
      limit 1`,
    [userId]
  );

  if (!rows.length) {
    await pool.query(
      `insert into subscriptions(user_id, mode, plan, start_at, end_at)
       values ($1,'paid',$2, now(), now() + ($3 || ' days')::interval)`,
      [userId, plan, period]
    );
  } else {
    await pool.query(
      `update subscriptions
          set mode='paid',
              plan=$2,
              end_at = end_at + ($3 || ' days')::interval
        where user_id=$1`,
      [userId, plan, period]
    );
  }
  const sub = await getSubscriptionStatus(userId);
  res.json({ ok: true, changed: 1, subscription: sub });
});

// POST /admin/users/:id/devices/reset  -> revoke active sessions
app.post('/admin/users/:id/devices/reset', requireAuth, requireAdmin, async (req, res) => {
  if (!requireAdminSecret(req, res)) return;
  const userId = Number(req.params.id);
  const r = await pool.query(
    `update user_devices set status='revoked'
      where user_id=$1 and status='active'`,
    [userId]
  );
  res.json({ ok: true, revoked: r.rowCount });
});


/* ============ START ============ */
const PORT = process.env.PORT || 8080;

// simple homepage
app.get('/', (req, res) => {
  res.type('text').send(
    'DealerBook API is running.\n\n' +
    'POST /auth/signup  { email }\n' +
    'POST /auth/verify  { email, code }\n' +
    'GET  /me           (Authorization: Bearer <token>)\n' +
    'GET  /listings     ?soc=&blk=&unit=&nature=&min=&max=&q=\n' +
    'POST /listings     (Authorization: Bearer <token>)\n' +
    'POST /payments     (Authorization: Bearer <token>, multipart form)\n' +
    'GET  /db-ping'
  );
});

// DB ping route (checks connection to Supabase)
app.get('/db-ping', async (req, res) => {
  try {
    const r = await pool.query('select now() as now');
    res.json({ ok: true, now: r.rows[0].now });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});
// ===== TEMP TEST: hit /debug-email?to=someone@example.com =====
app.get('/debug-email', async (req, res) => {
  try {
    const to = (req.query.to || '').trim();
    if (!to) return res.status(400).json({ ok: false, error: 'set ?to=email@example.com' });
    const ok = await sendOtpEmail(to, randomOtp());

    if (!ok) return res.status(500).json({ ok: false, error: 'send failed (see logs)' });
    res.json({ ok: true, sent: to });
  } catch (e) {
    console.error('debug-email error', e);
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
});



if (process.env.VERCEL !== '1') {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`API on http://0.0.0.0:${PORT}`);
  });
}
module.exports = app;



