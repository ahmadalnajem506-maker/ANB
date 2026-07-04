/**
 * ANB FinAdmin Pro — Worker v3 (D1 بدل Supabase + R2 كما هو)
 * ==========================================================================
 * التغييرات الجوهرية عن النسخة السابقة (v2، القائمة على Supabase):
 *
 *  1) لا حاجة بعد الآن لـ SUPABASE_SERVICE_ROLE_KEY ولا SUPABASE_URL إطلاقًا.
 *     التحقق من كلمات المرور وقراءة/كتابة بيانات التطبيق تتم مباشرة عبر
 *     ربط D1 (env.DB) المرتبط بهذا الـWorker — وصول مباشر وآمن بدون أي
 *     مفتاح خارجي منفصل.
 *
 *  2) نقطة جديدة GET /sync — تُعيد كامل بيانات التطبيق (JSON) من D1.
 *     ⚠️ تبقى هذه النقطة عامة (بلا توكن) عمدًا فقط للحفاظ على نفس سلوك
 *     Supabase الحالي (الذي كان يسمح بالقراءة لأي شخص يملك anon key)
 *     دون تغيير شاشة تسجيل الدخول الحالية التي تعتمد على وجود قائمة
 *     العملاء/الأدمن محليًا قبل تسجيل الدخول. هذه نقطة ضعف موروثة من
 *     التصميم الأصلي، وليست جديدة هنا — ناقشها مع فريقك كخطوة تحسين
 *     منفصلة لاحقًا (إعادة تصميم الدخول بحيث لا يُشحن أي بيانات حساسة
 *     للمتصفح قبل التحقق من الهوية).
 *
 *  3) نقطة جديدة POST /sync — محمية بتوكن Bearer (نفس نظام R2)، ترفض أي
 *     كتابة بدون تسجيل دخول صحيح. هذا تحسين حقيقي عن الوضع الحالي في
 *     Supabase حيث يمكن لأي شخص يملك anon key الكتابة أيضًا.
 *
 *  4) نقطة جديدة POST /refresh-token — تسمح بتجديد توكن سارٍ (غير منتهٍ)
 *     دون الحاجة لإعادة إدخال كلمة المرور، حتى لا تتعطل المزامنة التلقائية
 *     في الجلسات الطويلة.
 *
 *  5) نقطة مؤقتة لمرة واحدة POST /admin/migrate — لاستيراد بياناتك الحالية
 *     من Supabase إلى D1 دفعة واحدة. **احذفها من الكود بعد الانتقال بنجاح
 *     وتأكيد عمل كل شيء لعدة أيام.**
 *
 * الأسرار المطلوبة الآن (أقل من السابق):
 *   - R2_HMAC_SECRET       (كما في السابق - نفس القيمة إن كانت موجودة، أو
 *                           جديدة إن كنت تُعدّ الحساب لأول مرة)
 *   - MIGRATION_SECRET     سرّ مؤقت تخترعه أنت فقط لتفعيل /admin/migrate مرة
 *                           واحدة، ثم يمكنك حذف هذا المتغير لاحقًا
 * المتغيرات العادية:
 *   - ALLOWED_ORIGIN
 * الربط (Bindings):
 *   - DB          ربط D1 Database (وليس R2). أنشئه عبر: wrangler d1 create anb-db
 *   - ANB_FILES   ربط R2 (بلا تغيير - هذا اسمه الفعلي في wrangler.toml عندك)
 */

const CLOUD_ROW_ID = 'anb-main';
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000; // 8 ساعات (يوم عمل كامل) بدل ساعتين سابقًا
const REFRESH_MIN_REMAINING_MS = 30 * 60 * 1000; // يمكن التجديد إن تبقّى أقل من 30 دقيقة أو أي وقت قبل الانتهاء
const MAX_ATTEMPTS_WINDOW_MS = 60 * 1000;
const MAX_ATTEMPTS_PER_WINDOW = 8;

const attemptLog = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = corsHeaders(env);

    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    try {
      if (url.pathname === '/mint-token' && request.method === 'POST') return await handleMintToken(request, env, cors);
      if (url.pathname === '/refresh-token' && request.method === 'POST') return await handleRefreshToken(request, env, cors);
      if (url.pathname === '/sync' && request.method === 'GET') return await handleSyncGet(request, env, cors);
      if (url.pathname === '/sync' && request.method === 'POST') return await handleSyncPost(request, env, cors);
      if (url.pathname === '/upload' && request.method === 'POST') return await handleUpload(request, env, cors);
      if (url.pathname.startsWith('/file/') && request.method === 'GET') return await handleGetFile(request, env, cors, url);
      if (url.pathname.startsWith('/file/') && request.method === 'DELETE') return await handleDeleteFile(request, env, cors, url);
      if (url.pathname === '/admin/migrate' && request.method === 'POST') return await handleAdminMigrate(request, env, cors);
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
  try {
    return { payload: JSON.parse(row.payload), updated_at: row.updated_at };
  } catch {
    return null;
  }
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

/* ═══════════════════════ /mint-token ═══════════════════════ */

async function handleMintToken(request, env, cors) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (isRateLimited(ip)) return json({ error: 'Too many attempts, slow down' }, 429, cors);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }

  const { accountType, accountId, password } = body || {};
  if (!accountType || !accountId || !password) {
    return json({ error: 'accountType, accountId and password are required' }, 400, cors);
  }
  if (accountType !== 'admin' && accountType !== 'client') {
    return json({ error: 'accountType must be "admin" or "client"' }, 400, cors);
  }

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);

  const list = accountType === 'admin' ? (cloud.payload.admins || []) : (cloud.payload.clients || []);
  const account = list.find((a) => a && a.id === accountId);
  registerAttempt(ip);

  if (!account) return json({ error: 'Invalid credentials' }, 401, cors);

  const ok = await verifyPasswordServerSide(password, account);
  if (!ok) return json({ error: 'Invalid credentials' }, 401, cors);

  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: accountType, aid: accountId, exp }, env.R2_HMAC_SECRET);
  return json({ token, exp }, 200, cors);
}

async function verifyPasswordServerSide(plainPassword, record) {
  if (record.passwordHash && record.passwordSalt) {
    const hash = await hashPasswordPBKDF2(plainPassword, record.passwordSalt);
    return hash === record.passwordHash;
  }
  const legacyPlain = record.password || record.pwCustom || record.pw;
  return legacyPlain !== undefined && legacyPlain === plainPassword;
}

async function hashPasswordPBKDF2(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(saltHex), iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256
  );
  return bufToHex(bits);
}

/* ═══════════════════════ /refresh-token ═══════════════════════ */

async function handleRefreshToken(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);

  // يُسمح بالتجديد فقط إن كان التوكن الحالي لا يزال ساريًا فعليًا (تحقق requireValidToken من ذلك أصلًا)
  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: auth.payload.at, aid: auth.payload.aid, exp }, env.R2_HMAC_SECRET);
  return json({ token, exp }, 200, cors);
}

/* ═══════════════════════ GET /sync (عام، بلا توكن — انظر الشرح أعلى الملف) ═══════════════════════ */

async function handleSyncGet(request, env, cors) {
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'No data yet' }, 404, cors);
  return json({ payload: cloud.payload, updated_at: new Date(cloud.updated_at).toISOString() }, 200, cors);
}

/* ═══════════════════════ POST /sync (محمي بتوكن) ═══════════════════════ */

async function handleSyncPost(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }

  const { payload } = body || {};
  if (!payload || typeof payload !== 'object') {
    return json({ error: 'payload object is required' }, 400, cors);
  }

  const savedAt = await writeCloudPayload(env, payload);
  return json({ ok: true, updated_at: new Date(savedAt).toISOString() }, 200, cors);
}

/* ═══════════════════════ /upload (بلا تغيير عن v2) ═══════════════════════ */

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

/* ═══════════════════════ /admin/migrate (استخدم مرة واحدة فقط ثم احذفها) ═══════════════════════ */

async function handleAdminMigrate(request, env, cors) {
  if (!env.MIGRATION_SECRET) return json({ error: 'Migration disabled' }, 403, cors);
  const provided = request.headers.get('X-Migration-Secret') || '';
  if (!timingSafeEqual(provided, env.MIGRATION_SECRET)) {
    return json({ error: 'Invalid migration secret' }, 401, cors);
  }
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { payload } = body || {};
  if (!payload || typeof payload !== 'object') return json({ error: 'payload object is required' }, 400, cors);

  const savedAt = await writeCloudPayload(env, payload);
  return json({ ok: true, updated_at: new Date(savedAt).toISOString(), note: 'احذف MIGRATION_SECRET ونقطة /admin/migrate بعد التأكد من نجاح النقل' }, 200, cors);
}

/* ═══════════════════════ توقيع/تحقق التوكن (بلا تغيير) ═══════════════════════ */

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
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-File-Name, X-Migration-Secret',
    'Access-Control-Max-Age': '86400',
  };
}

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...cors } });
}
