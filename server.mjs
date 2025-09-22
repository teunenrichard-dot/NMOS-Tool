// server.mjs
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { q } from './db.js';

const app = express();
app.use(express.json({ limit: '1mb' }));

/* ---------- CORS ---------- */
const origins = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: origins.length ? origins : true, credentials: false }));

/* ---------- Utils ---------- */
const now = () => new Date();
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const DEV_TTL_HOURS = Number(process.env.JWT_DEVICE_TTL_HOURS || 24);

function signAdminJWT(payload){
  return jwt.sign(payload, process.env.ADMIN_JWT_SECRET || 'dev-admin-secret', { expiresIn: '8h' });
}
function signDeviceJWT(payload){
  return jwt.sign(payload, process.env.JWT_SECRET || 'dev-device-secret', { expiresIn: `${DEV_TTL_HOURS}h` });
}

/* ---------- Auth middlewares ---------- */
function requireAdmin(req, res, next){
  try{
    const h = req.headers.authorization || '';
    const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!tok) return res.status(401).json({ error: 'missing_token' });
    const dec = jwt.verify(tok, process.env.ADMIN_JWT_SECRET || 'dev-admin-secret');
    if (!dec?.adm) return res.status(403).json({ error: 'forbidden' });
    req.admin = dec;
    next();
  }catch(e){ return res.status(401).json({ error: 'invalid_token' }); }
}
function requireDevice(req, res, next){
  try{
    const h = req.headers.authorization || '';
    const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!tok) return res.status(401).json({ error: 'missing_token' });
    const dec = jwt.verify(tok, process.env.JWT_SECRET || 'dev-device-secret');
    if (!dec?.sub || dec.typ !== 'device') return res.status(403).json({ error: 'forbidden' });
    req.device = dec;
    next();
  }catch(e){ return res.status(401).json({ error: 'invalid_token' }); }
}

/* =================================================================================
   0) ADMIN LOGIN (protect /admin/*)
   ================================================================================= */
app.post('/admin/login', async (req, res) => {
  const body = z.object({
    email: z.string().email(),
    password: z.string().min(6)
  }).parse(req.body || {});

  const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
  const adminHash  = process.env.ADMIN_PASSWORD_HASH || '';

  if (body.email.toLowerCase() !== adminEmail.toLowerCase()) {
    return res.status(401).json({ error: 'bad_credentials' });
  }
  const ok = adminHash && await bcrypt.compare(body.password, adminHash);
  if (!ok) return res.status(401).json({ error: 'bad_credentials' });

  const token = signAdminJWT({ adm: true, sub: body.email });
  res.json({ token, expires_in: 8*3600 });
});

/* =================================================================================
   1) Enrollment (unchanged API, still open)
   ================================================================================= */
// 1.a Nonce
app.post('/device/nonce', async (req, res) => {
  const body = z.object({ email: z.string().email().optional() }).parse(req.body || {});
  const nonce = crypto.randomBytes(24).toString('base64url');
  await q('INSERT INTO nonces(nonce,email,created_at) VALUES ($1,$2,now())', [nonce, body.email || null]);
  res.json({ nonce, expires_in: 600 });
});

// 1.b Enroll (verify P-256 sig over `${nonce}.${sha256(fingerprint)}`)
app.post('/device/enroll', async (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    public_key_jwk: z.any(),
    fingerprint: z.string().min(8),
    nonce: z.string(),
    signature: z.string(),
    reason: z.string().max(500).optional()
  });
  const b = schema.parse(req.body);

  // Nonce
  const nr = await q('SELECT nonce, created_at, used_at FROM nonces WHERE nonce=$1', [b.nonce]);
  if (!nr.rowCount) return res.status(400).json({ error: 'bad_nonce' });
  const nrow = nr.rows[0];
  if (nrow.used_at) return res.status(400).json({ error: 'nonce_used' });
  if ((now() - nrow.created_at) > 10 * 60 * 1000) return res.status(400).json({ error: 'nonce_expired' });

  // Verify signature
  const verifier = crypto.createVerify('SHA256');
  const msg = `${b.nonce}.${sha256hex(b.fingerprint)}`;
  verifier.update(msg); verifier.end();
  let pubKey;
  try {
    pubKey = crypto.createPublicKey({ key: Buffer.from(JSON.stringify(b.public_key_jwk)), format: 'jwk' });
  } catch { return res.status(400).json({ error: 'bad_public_key' }); }
  const ok = verifier.verify(pubKey, Buffer.from(b.signature, 'base64url'));
  if (!ok) return res.status(400).json({ error: 'bad_signature' });

  // Default org
  const org = await q('SELECT id FROM orgs WHERE name=$1 LIMIT 1', ['Default Org']);
  const orgId = org.rows[0]?.id;

  // Upsert user
  const u = await q(
    'INSERT INTO users(email, org_id) VALUES ($1,$2) ON CONFLICT (email) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING id',
    [b.email, orgId]
  );
  const userId = u.rows[0].id;

  // Create device (pending)
  const fpHash = sha256hex(b.fingerprint);
  const dev = await q(
    `INSERT INTO devices(org_id,user_id,public_key_jwk,fingerprint_hash,status)
     VALUES ($1,$2,$3,$4,'pending') RETURNING id, status`,
    [orgId, userId, b.public_key_jwk, fpHash]
  );
  const deviceId = dev.rows[0].id;

  // Request row
  await q(
    `INSERT INTO requests(org_id,user_email,device_id,reason,status)
     VALUES ($1,$2,$3,$4,'pending')`,
    [orgId, b.email, deviceId, b.reason || null]
  );

  await q('UPDATE nonces SET used_at=now() WHERE nonce=$1', [b.nonce]);

  res.json({ device_id: deviceId, status: 'pending' });
});

/* =================================================================================
   2) DEVICE LICENSE MINT (possession proof)
   ================================================================================= */
/**
 * POST /device/license
 * Body:
 * {
 *   device_id: "<uuid>",
 *   fingerprint: "<raw string>",
 *   proof: "<base64url DER sig of `${device_id}.${sha256(fingerprint)}` with stored public_key_jwk>"
 * }
 * Returns: { token, expires_in }
 *//* =================================================================================
   2) DEVICE LICENSE MINT (possession proof)
   ================================================================================= */
/**
 * POST /device/license
 * Body:
 * {
 *   device_id: "<uuid>",
 *   fingerprint: "<raw string>",
 *   proof: "<base64url DER sig of `${device_id}.${sha256(fingerprint)}`>"
 * }
 * Returns: { token, expires_in }
 */
app.post('/device/license', async (req, res) => {
  const schema = z.object({
    device_id: z.string().min(6),
    fingerprint: z.string().min(8),
    proof: z.string().min(32)
  });
  const b = schema.parse(req.body);

  // --- sanitize device_id (handle accidental extra quotes) ---
  const devIdRaw = String(b.device_id).trim();
  const devId = devIdRaw.replace(/^"+|"+$/g, ''); // strip leading/trailing quotes

  // Validate UUID format after sanitizing
  const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRe.test(devId)) return res.status(400).json({ error: 'bad_device_id' });

  // Load device
  const dr = await q(
    'SELECT d.id, d.status, d.user_id, d.org_id, d.public_key_jwk, u.email AS user_email FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=$1',
    [devId]
  );
  if (!dr.rowCount) return res.status(404).json({ error: 'unknown_device' });
  const d = dr.rows[0];
  if (d.status !== 'active') return res.status(403).json({ error: 'device_not_active' });

  // Verify possession of stored public key
  const verifier = crypto.createVerify('SHA256');
  const msg = `${devId}.${sha256hex(b.fingerprint)}`;
  verifier.update(msg); verifier.end();
  let pubKey;
  try {
    pubKey = crypto.createPublicKey({ key: Buffer.from(JSON.stringify(d.public_key_jwk)), format: 'jwk' });
  } catch { return res.status(400).json({ error: 'bad_public_key_on_server' }); }
  const ok = verifier.verify(pubKey, Buffer.from(b.proof, 'base64url'));
  if (!ok) return res.status(400).json({ error: 'bad_proof' });

  // Issue device JWT
  const token = signDeviceJWT({
    typ: 'device',
    sub: String(d.id),
    org: String(d.org_id),
    uid: String(d.user_id),
    email: d.user_email,
    scope: ['nmos:scout'],
  });

  await q('UPDATE devices SET license_issued_at=now() WHERE id=$1', [d.id]);

  res.json({ token, expires_in: DEV_TTL_HOURS * 3600 });
});


/* =================================================================================
   3) HEARTBEAT (device)
   ================================================================================= */
/**
 * POST /device/heartbeat
 * Header: Authorization: Bearer <device-jwt>
 * Body: { info?: { version, hostname, ... } }
 */
app.post('/device/heartbeat', requireDevice, async (req, res) => {
  const devId = req.device?.sub;
  if (!devId) return res.status(401).json({ error: 'bad_token' });

  // Optionally check revoked after token was issued
  const rr = await q('SELECT status FROM devices WHERE id=$1', [devId]);
  if (!rr.rowCount) return res.status(404).json({ error: 'unknown_device' });
  if (rr.rows[0].status !== 'active') return res.status(403).json({ error: 'device_revoked' });

  await q('UPDATE devices SET last_seen_at=now() WHERE id=$1', [devId]);
  res.json({ ok: true, server_time: now().toISOString() });
});

/* =================================================================================
   4) License status (client polls initial state)
   ================================================================================= */
app.get('/license/status', async (req, res) => {
  const deviceId = req.query.device_id;
  if (!deviceId) return res.status(400).json({ error: 'missing_device_id' });
  const r = await q('SELECT status FROM devices WHERE id=$1', [deviceId]);
  if (!r.rowCount) return res.status(404).json({ error: 'unknown_device' });
  res.json({ status: r.rows[0].status });
});

/* =================================================================================
   5) Admin: protected endpoints
   ================================================================================= */
// Pending requests
app.get('/admin/requests', requireAdmin, async (_req, res) => {
  const r = await q(
    `SELECT r.id, r.user_email, r.device_id, r.reason, r.status, r.created_at,
            d.status as device_status
     FROM requests r
     JOIN devices d ON d.id=r.device_id
     WHERE r.status='pending'
     ORDER BY r.created_at ASC`
  );
  res.json(r.rows);
});

// Resolved requests
app.get('/admin/requests/resolved', requireAdmin, async (req, res) => {
  const { status, search, since_days = 30, limit = 200 } = req.query;

  const params = [];
  const where = [`r.status IN ('approved','denied')`, `r.resolved_at IS NOT NULL`];

  if (status && ['approved','denied'].includes(String(status))) {
    params.push(status);
    where.push(`r.status = $${params.length}`);
  }

  const days = Math.max(1, Math.min(3650, Number(since_days || 30)));
  params.push(days);
  where.push(`r.resolved_at >= NOW() - ($${params.length}::int || ' days')::interval`);

  if (search && String(search).trim()) {
    const s = `%${String(search).trim()}%`;
    params.push(s, s, s);
    where.push(`(r.user_email ILIKE $${params.length-2} OR r.device_id::text ILIKE $${params.length-1} OR r.reason ILIKE $${params.length})`);
  }

  const lim = Math.max(1, Math.min(1000, Number(limit || 200)));
  params.push(lim);

  const sql = `
    SELECT r.id, r.user_email, r.device_id, r.reason, r.status, r.created_at, r.resolved_at,
           d.status AS device_status
    FROM requests r
    LEFT JOIN devices d ON d.id = r.device_id
    WHERE ${where.join(' AND ')}
    ORDER BY r.resolved_at DESC
    LIMIT $${params.length}
  `;
  const rset = await q(sql, params);
  res.json(rset.rows);
});

// Devices list
app.get('/admin/devices', requireAdmin, async (req, res) => {
  const { status, search, user_id } = req.query;
  const params = [];
  const where = [];

  if (status && ['active','pending','revoked'].includes(String(status))) {
    params.push(status);
    where.push(`d.status = $${params.length}`);
  }
  if (user_id && String(user_id).trim()) {
    params.push(String(user_id).trim());
    where.push(`u.id::text = $${params.length}`);
  }
  if (search && String(search).trim()) {
    const s = `%${String(search).trim()}%`;
    params.push(s, s, s);
    where.push(`(u.email ILIKE $${params.length-2} OR d.id::text ILIKE $${params.length-1} OR d.fingerprint_hash ILIKE $${params.length})`);
  }

  const sql = `
    SELECT d.id, d.status, d.created_at, d.updated_at, d.fingerprint_hash,
           u.email AS user_email, u.id AS user_id,
           o.name  AS org_name, o.id AS org_id,
           d.last_seen_at, d.license_issued_at
    FROM devices d
    JOIN users   u ON u.id = d.user_id
    LEFT JOIN orgs o ON o.id = d.org_id
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY d.updated_at DESC NULLS LAST, d.created_at DESC
    LIMIT 500
  `;
  const r = await q(sql, params);
  res.json(r.rows);
});

// Approve / Deny
app.post('/admin/requests/:id/approve', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const r = await q('SELECT device_id, org_id FROM requests WHERE id=$1', [id]);
  if (!r.rowCount) return res.status(404).json({ error: 'not_found' });
  const { device_id, org_id } = r.rows[0];

  await q('UPDATE devices SET status=\'active\', updated_at=now() WHERE id=$1', [device_id]);
  await q('UPDATE requests SET status=\'approved\', resolved_at=now(), updated_at=now() WHERE id=$1', [id]);
  await q(`INSERT INTO audits(org_id, action, target_type, target_id, metadata)
           VALUES ($1,'approve_request','device',$2,$3)`, [org_id, device_id, { by: 'MVP-admin' }]);

  res.json({ ok: true });
});
app.post('/admin/requests/:id/deny', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const r = await q('SELECT device_id, org_id FROM requests WHERE id=$1', [id]);
  if (!r.rowCount) return res.status(404).json({ error: 'not_found' });
  const { device_id, org_id } = r.rows[0];

  await q('UPDATE devices SET status=\'revoked\', updated_at=now() WHERE id=$1', [device_id]);
  await q('UPDATE requests SET status=\'denied\', resolved_at=now(), updated_at=now() WHERE id=$1', [id]);
  await q(`INSERT INTO audits(org_id, action, target_type, target_id, metadata)
           VALUES ($1,'deny_request','device',$2,$3)`, [org_id, device_id, { by: 'MVP-admin' }]);

  res.json({ ok: true });
});

// Activate / Revoke device directly
app.post('/admin/devices/:id/activate', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const r = await q('UPDATE devices SET status=\'active\', updated_at=now() WHERE id=$1 RETURNING org_id', [id]);
  if (!r.rowCount) return res.status(404).json({ error: 'not_found' });
  await q(`INSERT INTO audits(org_id, action, target_type, target_id, metadata)
           VALUES ($1,'activate_device','device',$2,$3)`, [r.rows[0].org_id, id, { by: 'MVP-admin' }]);
  res.json({ ok: true });
});
app.post('/admin/devices/:id/revoke', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const r = await q('UPDATE devices SET status=\'revoked\', updated_at=now() WHERE id=$1 RETURNING org_id', [id]);
  if (!r.rowCount) return res.status(404).json({ error: 'not_found' });
  await q(`INSERT INTO audits(org_id, action, target_type, target_id, metadata)
           VALUES ($1,'revoke_device','device',$2,$3)`, [r.rows[0].org_id, id, { by: 'MVP-admin' }]);
  res.json({ ok: true });
});

/* ---------- Boot ---------- */
const port = process.env.PORT || 8088;
app.listen(port, () => console.log(`Licensing service listening on :${port}`));
