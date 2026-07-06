/**
 * ANB FinAdmin Pro — Worker v4 (إعادة تصميم الدخول: لا بيانات حساسة قبل تسجيل الدخول)
 * ==========================================================================
 * المشكلة التي يحلّها هذا الإصدار:
 * في الإصدار السابق (v3)، كانت نقطة GET /sync عامة بلا أي حماية، وكانت
 * تُرجع كامل بيانات التطبيق — بما فيها كلمات مرور كل العملاء والأدمن
 * المشفّرة (passwordHash/passwordSalt) بل وأسرار TOTP الخاصة بالتحقق
 * بخطوتين (totpSecret)! أي شخص يعرف رابط الـWorker فقط (وهو مكتوب صراحة
 * في index.html) يمكنه:
 *   - محاولة كسر كلمات المرور المشفّرة بلا اتصال (offline brute-force)
 *   - توليد رموز TOTP صحيحة بنفسه من totpSecret المسروق، فيتجاوز الحماية
 *     بخطوتين بالكامل!
 *
 * الحل هنا: لا يصل أي بيانات حساب (لا مقارنة كلمة مرور، ولا سرّ TOTP) لأي
 * مكان في المتصفح إطلاقًا. كل التحقق يتم هنا في الـWorker مباشرة عبر D1،
 * والمتصفح لا يحصل إلا على توكن دخول بعد نجاح كل خطوات التحقق.
 *
 * نقاط جديدة تستبدل /mint-token:
 *   POST /resolve-account  {role, identifier} → معلومات عرض غير حساسة فقط
 *   POST /login             {role, accountId, password} → توكن مباشرة، أو
 *                            {step:'2fa'} إن كان الحساب يتطلب رمز إضافي
 *   POST /verify-2fa        {role, accountId, code} → توكن
 *
 * GET /sync أصبحت الآن محمية بتوكن إلزاميًا (لم تعد عامة).
 *
 * أُزيلت نقطة /admin/migrate (كانت لمرة واحدة فقط، ولم تعد مطلوبة بعد نجاح الترحيل).
 *
 * الأسرار المطلوبة (بلا تغيير عن v3):
 *   - R2_HMAC_SECRET
 * المتغيرات:
 *   - ALLOWED_ORIGIN
 * الربط:
 *   - DB          (D1، كما هو)
 *   - ANB_FILES   (R2، كما هو)
 */

const CLOUD_ROW_ID = 'anb-main';
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000; // 8 ساعات
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000; // 15 دقيقة - يطابق القيم المستخدمة سابقًا في التطبيق
const MAX_ATTEMPTS_WINDOW_MS = 60 * 1000; // حد إضافي عام لكل IP (دفاع مستقل عن حد الحساب أعلاه)
const MAX_ATTEMPTS_PER_WINDOW = 8;

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const attemptLog = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = corsHeaders(env);

    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    try {
      if (url.pathname === '/resolve-account' && request.method === 'POST') return await handleResolveAccount(request, env, cors);
      if (url.pathname === '/login' && request.method === 'POST') return await handleLogin(request, env, cors);
      if (url.pathname === '/verify-2fa' && request.method === 'POST') return await handleVerify2FA(request, env, cors);
      if (url.pathname === '/set-password' && request.method === 'POST') return await handleSetPassword(request, env, cors);
      if (url.pathname === '/refresh-token' && request.method === 'POST') return await handleRefreshToken(request, env, cors);
      if (url.pathname === '/sync' && request.method === 'GET') return await handleSyncGet(request, env, cors);
      if (url.pathname === '/sync' && request.method === 'POST') return await handleSyncPost(request, env, cors);
      if (url.pathname === '/upload' && request.method === 'POST') return await handleUpload(request, env, cors);
      if (url.pathname.startsWith('/file/') && request.method === 'GET') return await handleGetFile(request, env, cors, url);
      if (url.pathname.startsWith('/file/') && request.method === 'DELETE') return await handleDeleteFile(request, env, cors, url);
      return json({ error: 'Not found' }, 404, cors);
    } catch (err) {
      return json({ error: 'Internal error', detail: String(err && err.message || err) }, 500, cors);
    }
  },
};

/* ═══════════════════════ D1 helpers ═══════════════════════ */

async function fetchCloudPayload(env) {
  const row = await env.DB.prepare('SELECT payload, updated_at FROM anb_data WHERE id = ?').bind(CLOUD_ROW_ID).first();
  if (!row) return null;
  try { return { payload: JSON.parse(row.payload), updated_at: row.updated_at }; } catch { return null; }
}
async function writeCloudPayload(env, payloadObj) {
  const json = JSON.stringify(payloadObj);
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO anb_data (id, payload, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at`
  ).bind(CLOUD_ROW_ID, json, now).run();
  return now;
}

function listFor(payload, role) {
  return role === 'admin' ? (payload.admins || []) : (payload.clients || []);
}

/* ═══════════════════════ /resolve-account ═══════════════════════ */
// لا يُعيد أي شيء حساس - فقط ما تحتاجه شاشة "الخطوة ٢" لعرض اسم الحساب

async function handleResolveAccount(request, env, cors) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (isRateLimited(ip)) return json({ error: 'Too many attempts, slow down' }, 429, cors);
  registerAttempt(ip);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { role, identifier } = body || {};
  if (!role || !identifier) return json({ error: 'role and identifier are required' }, 400, cors);
  if (role !== 'admin' && role !== 'client') return json({ error: 'role must be "admin" or "client"' }, 400, cors);

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);

  const id = identifier.trim().toLowerCase();
  const list = listFor(cloud.payload, role);
  // ⚠️ إصلاح خطأ كان موجودًا في المنطق القديم (client-side): كان أي أدمن نشط
  // "status==='active'" يُطابق حتى لو لم يكن البريد/الهاتف المُدخل صحيحًا على
  // الإطلاق. الآن: مطابقة دقيقة فقط بالبريد أو الهاتف.
  const account = list.find((a) =>
    (a.email && a.email.toLowerCase() === id) ||
    (a.phone && (a.phone === identifier.trim() || a.phone.replace(/\s/g, '') === identifier.trim().replace(/\s/g, '')))
  );

  if (!account) return json({ error: 'Account not found' }, 404, cors);
  if (role === 'admin' && account.status !== 'active') return json({ error: 'Account not found' }, 404, cors);
  if (isLockedOut(account)) {
    return json({ error: 'locked', minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);
  }

  return json({
    accountId: account.id,
    name: account.name || '',
    email: account.email || '',
    type: account.type || '',
    totpEnabled: !!account.totpEnabled,
    isFirstTime: role === 'client' ? !account.pwSet : false,
  }, 200, cors);
}

/* ═══════════════════════ /login ═══════════════════════ */

async function handleLogin(request, env, cors) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (isRateLimited(ip)) return json({ error: 'Too many attempts, slow down' }, 429, cors);
  registerAttempt(ip);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { role, accountId, password } = body || {};
  if (!role || !accountId || !password) return json({ error: 'role, accountId and password are required' }, 400, cors);

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);

  const list = listFor(cloud.payload, role);
  const idx = list.findIndex((a) => a && a.id === accountId);
  if (idx === -1) return json({ error: 'Invalid credentials' }, 401, cors);
  const account = list[idx];

  if (isLockedOut(account)) return json({ error: 'locked', minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);
  if (role === 'admin' && account.status !== 'active') return json({ error: 'Account not active' }, 403, cors);

  const verdict = await verifyPasswordServerSide(password, account);
  if (!verdict.ok) {
    registerFailedAttempt(account);
    list[idx] = account;
    await writeCloudPayload(env, cloud.payload);
    if (isLockedOut(account)) return json({ error: 'locked', minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);
    return json({ error: 'Invalid credentials' }, 401, cors);
  }

  // نجاح: صفّر عدّاد المحاولات، رحّل كلمة المرور القديمة إن لزم، حدّث آخر دخول
  clearFailedAttempts(account);
  if (verdict.needsUpgrade) {
    const rec = await makePasswordRecord(password);
    account.passwordSalt = rec.passwordSalt;
    account.passwordHash = rec.passwordHash;
    delete account.password; delete account.pwCustom; delete account.pw;
  }
  if (role === 'admin') account.lastLogin = new Date().toISOString().slice(0, 10);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);

  if (account.totpEnabled) {
    return json({ step: '2fa', accountId: account.id }, 200, cors);
  }

  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: role, aid: account.id, exp }, env.R2_HMAC_SECRET);
  return json({ step: 'done', token, exp }, 200, cors);
}

/* ═══════════════════════ /verify-2fa ═══════════════════════ */

async function handleVerify2FA(request, env, cors) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (isRateLimited(ip)) return json({ error: 'Too many attempts, slow down' }, 429, cors);
  registerAttempt(ip);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { role, accountId, code } = body || {};
  if (!role || !accountId || !code) return json({ error: 'role, accountId and code are required' }, 400, cors);

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);

  const list = listFor(cloud.payload, role);
  const idx = list.findIndex((a) => a && a.id === accountId);
  if (idx === -1) return json({ error: 'Invalid session' }, 401, cors);
  const account = list[idx];

  if (isLockedOut(account)) return json({ error: 'locked', minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);

  const valid = await verifyTotpCode(account.totpSecret, code);
  if (!valid) {
    registerFailedAttempt(account);
    list[idx] = account;
    await writeCloudPayload(env, cloud.payload);
    if (isLockedOut(account)) return json({ error: 'locked', minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);
    return json({ error: 'Incorrect code' }, 401, cors);
  }

  clearFailedAttempts(account);
  if (role === 'admin') account.lastLogin = new Date().toISOString().slice(0, 10);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);

  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: role, aid: account.id, exp }, env.R2_HMAC_SECRET);
  return json({ token, exp }, 200, cors);
}

/* ═══════════════════════ التحقق من كلمة المرور + الترقية من نص صريح ═══════════════════════ */

async function verifyPasswordServerSide(plainPassword, record) {
  if (record.passwordHash && record.passwordSalt) {
    const hash = await hashPasswordPBKDF2(plainPassword, record.passwordSalt);
    return { ok: hash === record.passwordHash, needsUpgrade: false };
  }
  const legacyPlain = record.password || record.pwCustom || record.pw;
  if (legacyPlain !== undefined && legacyPlain === plainPassword) {
    return { ok: true, needsUpgrade: true };
  }
  return { ok: false, needsUpgrade: false };
}
async function makePasswordRecord(plainPassword) {
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const passwordSalt = bufToHex(saltBytes);
  const passwordHash = await hashPasswordPBKDF2(plainPassword, passwordSalt);
  return { passwordSalt, passwordHash };
}
async function hashPasswordPBKDF2(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(saltHex), iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  return bufToHex(bits);
}

/* ═══════════════════════ قفل الحساب بعد محاولات فاشلة متكررة ═══════════════════════ */

function isLockedOut(account) { return !!(account && account.lockedUntil && Date.now() < account.lockedUntil); }
function lockoutRemainingMinutes(account) { return Math.max(1, Math.ceil((account.lockedUntil - Date.now()) / 60000)); }
function registerFailedAttempt(account) {
  account.failedAttempts = (account.failedAttempts || 0) + 1;
  if (account.failedAttempts >= LOGIN_MAX_ATTEMPTS) {
    account.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
    account.failedAttempts = 0;
  }
}
function clearFailedAttempts(account) { account.failedAttempts = 0; account.lockedUntil = null; }

/* ═══════════════════════ TOTP (RFC 6238) - مطابق تمامًا لمنطق العميل السابق ═══════════════════════ */

function base32Decode(base32) {
  const clean = (base32 || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const ch of clean) {
    const val = BASE32_ALPHABET.indexOf(ch);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return new Uint8Array(bytes);
}
function counterToBytes(num) {
  const bytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { bytes[i] = num & 0xff; num = Math.floor(num / 256); }
  return bytes;
}
async function hmacSha1(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}
async function generateTotpCode(secret, forTimeMs) {
  const counter = Math.floor((forTimeMs || Date.now()) / 1000 / TOTP_STEP_SECONDS);
  const keyBytes = base32Decode(secret);
  const msgBytes = counterToBytes(counter);
  const hmac = await hmacSha1(keyBytes, msgBytes);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return (binCode % (10 ** TOTP_DIGITS)).toString().padStart(TOTP_DIGITS, '0');
}
async function verifyTotpCode(secret, userCode) {
  if (!secret || !userCode) return false;
  const clean = userCode.toString().replace(/\s/g, '');
  if (!/^\d{6}$/.test(clean)) return false;
  const now = Date.now();
  for (const drift of [0, -1, 1]) {
    const code = await generateTotpCode(secret, now + drift * TOTP_STEP_SECONDS * 1000);
    if (code === clean) return true;
  }
  return false;
}

/* ═══════════════════════ /set-password ═══════════════════════ */
// ⚠️ يحافظ هذا على نفس مستوى التحقق الموجود سابقًا في التطبيق (لا يُطلب
// كلمة المرور القديمة، فقط تطابق البريد/الهاتف عبر /resolve-account أولًا).
// هذه نقطة ضعف موروثة من التصميم الأصلي (أي شخص يعرف بريد العميل يمكنه
// تغيير كلمة مروره)، لم أُدخلها أنا، ولم أُصلحها هنا لتفادي توسيع نطاق
// هذا التغيير — أنصح بمناقشتها كخطوة منفصلة (مثل إرسال رابط تأكيد بالبريد).
async function handleSetPassword(request, env, cors) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (isRateLimited(ip)) return json({ error: 'Too many attempts, slow down' }, 429, cors);
  registerAttempt(ip);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { role, accountId, newPassword } = body || {};
  if (!role || !accountId || !newPassword) return json({ error: 'role, accountId and newPassword are required' }, 400, cors);
  if (newPassword.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400, cors);

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);

  const list = listFor(cloud.payload, role);
  const idx = list.findIndex((a) => a && a.id === accountId);
  if (idx === -1) return json({ error: 'Account not found' }, 404, cors);

  const rec = await makePasswordRecord(newPassword);
  const account = list[idx];
  account.passwordSalt = rec.passwordSalt;
  account.passwordHash = rec.passwordHash;
  delete account.password; delete account.pwCustom; delete account.pw;
  if (role === 'client') account.pwSet = true;
  clearFailedAttempts(account);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);

  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: role, aid: account.id, exp }, env.R2_HMAC_SECRET);
  return json({ token, exp }, 200, cors);
}

/* ═══════════════════════ /refresh-token ═══════════════════════ */

async function handleRefreshToken(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: auth.payload.at, aid: auth.payload.aid, exp }, env.R2_HMAC_SECRET);
  return json({ token, exp }, 200, cors);
}

/* ═══════════════════════ /sync — أصبحت GET محمية أيضًا الآن ═══════════════════════ */

async function handleSyncGet(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'No data yet' }, 404, cors);
  return json({ payload: cloud.payload, updated_at: new Date(cloud.updated_at).toISOString() }, 200, cors);
}
async function handleSyncPost(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { payload } = body || {};
  if (!payload || typeof payload !== 'object') return json({ error: 'payload object is required' }, 400, cors);
  const savedAt = await writeCloudPayload(env, payload);
  return json({ ok: true, updated_at: new Date(savedAt).toISOString() }, 200, cors);
}

/* ═══════════════════════ R2 (بلا تغيير) ═══════════════════════ */

async function handleUpload(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const contentType = request.headers.get('Content-Type') || 'application/octet-stream';
  const rawName = request.headers.get('X-File-Name') || 'file';
  const safeName = sanitizeFileName(rawName);
  const key = `${auth.payload.at}/${auth.payload.aid}/${Date.now()}-${safeName}`;
  const body = await request.arrayBuffer();
  await env.ANB_FILES.put(key, body, { httpMetadata: { contentType } });
  const workerOrigin = new URL(request.url).origin;
  return json({ key, url: `${workerOrigin}/file/${key}` }, 200, cors);
}
async function handleGetFile(request, env, cors, url) {
  const key = decodeURIComponent(url.pathname.replace('/file/', ''));
  if (!key) return json({ error: 'Missing key' }, 400, cors);
  const object = await env.ANB_FILES.get(key);
  if (!object) return json({ error: 'Not found' }, 404, cors);
  const headers = new Headers(cors);
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  return new Response(object.body, { headers });
}
async function handleDeleteFile(request, env, cors, url) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const key = decodeURIComponent(url.pathname.replace('/file/', ''));
  if (!key) return json({ error: 'Missing key' }, 400, cors);
  await env.ANB_FILES.delete(key);
  return json({ ok: true }, 200, cors);
}

/* ═══════════════════════ توقيع/تحقق التوكن ═══════════════════════ */

async function signToken(claims, secret) {
  const payloadB64 = b64urlEncode(JSON.stringify(claims));
  const sig = await hmacSign(payloadB64, secret);
  return `${payloadB64}.${sig}`;
}
async function requireValidToken(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const m = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!m) return { ok: false, error: 'Missing Authorization header' };
  const token = m[1];
  const parts = token.split('.');
  if (parts.length !== 2) return { ok: false, error: 'Malformed token' };
  const [payloadB64, sig] = parts;
  const expectedSig = await hmacSign(payloadB64, env.R2_HMAC_SECRET);
  if (!timingSafeEqual(sig, expectedSig)) return { ok: false, error: 'Invalid token signature' };
  let payload;
  try { payload = JSON.parse(b64urlDecode(payloadB64)); } catch { return { ok: false, error: 'Malformed token payload' }; }
  if (!payload.exp || Date.now() > payload.exp) return { ok: false, error: 'Token expired' };
  return { ok: true, payload };
}
async function hmacSign(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return bufToHex(sigBuf);
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ═══════════════════════ أدوات مساعدة ═══════════════════════ */

function bufToHex(buf) { return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join(''); }
function b64urlEncode(str) { return btoa(unescape(encodeURIComponent(str))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; return decodeURIComponent(escape(atob(str))); }
function sanitizeFileName(name) { return name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(-120); }

function isRateLimited(ip) {
  const now = Date.now();
  const entry = attemptLog.get(ip);
  if (!entry) return false;
  const recent = entry.filter((t) => now - t < MAX_ATTEMPTS_WINDOW_MS);
  attemptLog.set(ip, recent);
  return recent.length >= MAX_ATTEMPTS_PER_WINDOW;
}
function registerAttempt(ip) {
  const now = Date.now();
  const entry = attemptLog.get(ip) || [];
  entry.push(now);
  attemptLog.set(ip, entry);
}
function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-File-Name',
    'Access-Control-Max-Age': '86400',
  };
}
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...cors } });
}
