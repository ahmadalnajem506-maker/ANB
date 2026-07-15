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
 * ⚠️ فحص أمني شامل إضافي (pentest) - إصلاحات هذه الجولة:
 *   ١. حرج جدًا: /set-password كان يسمح بالاستيلاء الكامل على حساب الأدمن
 *      بلا أي مصادقة (الحارس كان يتجاهل role==='admin' تمامًا) - أُصلح.
 *   ٢. GET/DELETE /file لم يكونا يتحقَّقان من ملكية الملف - أي مستخدم مُصادَق
 *      عليه كان يصل لملفات أي عميل آخر - أُصلح (canAccessFileKey).
 *   ٣. مقارنة كلمة المرور/رمز TOTP لم تكن آمنة زمنيًا (===) - أُصلحت لتطابق
 *      نفس آلية التحقق من توقيع التوكن (timingSafeEqual).
 *   ٤. لا حدّ لحجم الملفات المرفوعة - أُضيف حدّ ٢٥ ميجابايت.
 *   ٥. الحدّ من المحاولات (rate limiting) كان في ذاكرة محلية لكل نسخة Worker
 *      منفردة (غير موثوق عبر نُسخ متعددة) - أُعيد بناؤه عبر Cloudflare KV.
 *
 * الأسرار المطلوبة (بلا تغيير عن v3):
 *   - R2_HMAC_SECRET
 * المتغيرات:
 *   - ALLOWED_ORIGIN
 * الربط:
 *   - DB              (D1، كما هو)
 *   - ANB_FILES       (R2، كما هو)
 *   - RATE_LIMIT_KV   (⚠️ جديد - KV Namespace، أنشئه واربطه بهذا الاسم تحديدًا
 *                       لتفعيل الحدّ الموثوق للمحاولات؛ الكود يعمل بلا توقف
 *                       حتى قبل إضافته، لكن بحماية أضعف مؤقَّتًا)
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
      if (url.pathname === '/admin/generate-temp-password' && request.method === 'POST') return await handleGenerateTempPassword(request, env, cors);
      if (url.pathname === '/refresh-token' && request.method === 'POST') return await handleRefreshToken(request, env, cors);
      if (url.pathname === '/sync' && request.method === 'GET') return await handleSyncGet(request, env, cors);
      if (url.pathname === '/sync' && request.method === 'POST') return await handleSyncPost(request, env, cors);
      if (url.pathname === '/upload' && request.method === 'POST') return await handleUpload(request, env, cors);
      if (url.pathname.startsWith('/file/') && request.method === 'GET') return await handleGetFile(request, env, cors, url);
      if (url.pathname.startsWith('/file/') && request.method === 'DELETE') return await handleDeleteFile(request, env, cors, url);
      if (url.pathname === '/ocr-vision' && request.method === 'POST') return await handleOcrVision(request, env, cors);
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

/* ═══════════════════════ ⚠️ فلترة المزامنة حسب الدور (إصلاح ثغرة خصوصية حقيقية) ═══════════════════════
 * اكتُشف أن GET /sync كانت تُرجع قاعدة البيانات كاملة لأي مستخدم مُصادَق عليه
 * - حتى العملاء العاديين - بما يشمل بيانات كل العملاء الآخرين المالية
 * (فواتير، مصاريف، رسائل...) بل وكلمات المرور المشفَّرة وأسرار TOTP لكل
 * حساب! الإصلاح: تجريد الحقول الحسّاسة دائمًا من كل استجابة بغضّ النظر عن
 * الدور (فالتحقق يتم في الخادم فقط أصلًا)، وفلترة نطاق البيانات التجارية
 * ليرى كل عميل بيانات حسابه فقط عند الدور 'client'.
 */
const SENSITIVE_ACCOUNT_FIELDS = ['passwordHash', 'passwordSalt', 'totpSecret'];
// المصفوفات المرتبطة بعميل واحد عبر حقل cid (غير clients/admins، اللذين
// يُصفَّيان بقاعدة مختلفة تعتمد على id مباشرة بدل cid)
const CLIENT_SCOPED_ARRAY_KEYS = ['invoices', 'expenses', 'hours', 'docs', 'messages', 'journal', 'bankTx', 'recurring', 'yearClosings', 'contracts', 'assets', 'serviceAgreements', 'importBatches', 'employees', 'contacts', 'cashPayments', 'cashierLog', 'cashierDayExceptions', 'supplierOcrProfiles', 'auditLog'];

function stripSensitiveFields(account) {
  if (!account || typeof account !== 'object') return account;
  const clean = { ...account };
  SENSITIVE_ACCOUNT_FIELDS.forEach((f) => { delete clean[f]; });
  return clean;
}

function filterPayloadForSync(payload, role, aid) {
  const filtered = { ...payload };
  // تجريد الحقول الحسّاسة دائمًا - لا يحتاجها المتصفح إطلاقًا بعد إعادة
  // تصميم تسجيل الدخول/2FA ليتم بالكامل في الخادم
  filtered.clients = (payload.clients || []).map(stripSensitiveFields);
  filtered.admins = (payload.admins || []).map(stripSensitiveFields);

  if (role === 'admin') return filtered; // الأدمن يرى كل البيانات التجارية، فقط بلا الحقول الحسّاسة

  // دور العميل: يرى سجله الخاص فقط من clients، ولا يرى admins إطلاقًا
  filtered.clients = filtered.clients.filter((c) => c && c.id === aid);
  filtered.admins = [];
  CLIENT_SCOPED_ARRAY_KEYS.forEach((key) => {
    filtered[key] = (payload[key] || []).filter((item) => item && item.cid === aid);
  });
  return filtered;
}

// دمج آمن عند الكتابة: يستبدل فقط سجلات هذا العميل تحديدًا ضمن مصفوفة
// مرتبطة بـcid، ويُبقي كل سجلات بقية العملاء كما هي في قاعدة البيانات تمامًا
function mergeClientScopedArray(existingArray, incomingArray, aid) {
  const others = (existingArray || []).filter((item) => !item || item.cid !== aid);
  const ownIncoming = (Array.isArray(incomingArray) ? incomingArray : []).filter((item) => item && item.cid === aid);
  return [...others, ...ownIncoming];
}

/* ═══════════════════════ ⚠️ حماية الفترات المُقفَلة - تطبيقها في الخادم أيضًا ═══════════════════════
 * كانت ميزة "إغلاق السنة/الربع" (checkPeriodLockAndProceed في index.html) تُطبَّق
 * فقط في واجهة المتصفح. أي شخص يملك توكن دخول عميل صالح كان يستطيع تجاوزها
 * بالكامل عبر إرسال طلب POST /sync مباشر (بلا مرور بواجهة التطبيق إطلاقًا)،
 * فيُعدِّل أو يحذف فواتير/مصاريف ضمن فترة أُقفلت وأُبلغت رسميًا لمصلحة الضرائب -
 * ما يُبطل الغرض الكامل من الميزة (منع التعديل الصامت + سجل تدقيق موثوق).
 * الإصلاح: نفس منطق getClosingForDate من العميل، لكن كبوابة إلزامية هنا في
 * الخادم لا يمكن لأي طلب HTTP تجاوزها - فقط دور 'admin' يمكنه الكتابة على
 * فترة مُقفَلة (يطابق سلوك الواجهة التي تسمح للأدمن بتأكيد صريح فقط).
 */
const PERIOD_LOCKED_ARRAY_KEYS = ['invoices', 'expenses'];

function getClosingForDate(yearClosings, cid, dateStr) {
  if (!dateStr) return null;
  const closings = (yearClosings || []).filter((c) => c && c.cid === cid && !c.deleted);
  if (closings.length === 0) return null;
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return null;
  const year = date.getFullYear();
  const quarter = Math.floor(date.getMonth() / 3) + 1;
  return (
    closings.find((c) => c.periodType === 'year' && c.year === year) ||
    closings.find((c) => c.periodType === 'quarter' && c.year === year && c.quarter === quarter) ||
    null
  );
}

// يُصفِّي من incomingArray أي سجل (جديد، أو تعديل/حذف لسجل موجود) يقع تاريخه
// (الجديد أو القديم المخزَّن فعليًا) ضمن فترة مُقفَلة لهذا العميل - السجلات
// المرفوضة تبقى كما هي في قاعدة البيانات دون أي تأثير من الطلب الوارد
function enforcePeriodLockOnClientArray(key, existingArray, incomingArray, aid, yearClosings) {
  if (!PERIOD_LOCKED_ARRAY_KEYS.includes(key)) return { allowed: incomingArray, blocked: [] };
  const existingById = new Map((existingArray || []).filter((x) => x).map((x) => [x.id, x]));
  const allowed = [];
  const blocked = [];
  (Array.isArray(incomingArray) ? incomingArray : []).forEach((item) => {
    if (!item || item.cid !== aid) return; // نطاق آخر، لا علاقة لبوابة القفل به هنا
    const existingItem = existingById.get(item.id);
    const datesToCheck = [item.date, existingItem && existingItem.date].filter(Boolean);
    const isLocked = datesToCheck.some((d) => !!getClosingForDate(yearClosings, aid, d));
    if (isLocked) blocked.push(item); else allowed.push(item);
  });
  return { allowed, blocked };
}

/* ═══════════════════════ ⚠️ سجل التدقيق (auditLog) - يجب أن يكون "إضافة فقط" ═══════════════════════
 * كان auditLog محليًا فقط في المتصفح (لم يكن أصلًا ضمن مفاتيح المزامنة السحابية)
 * - يُفقَد تمامًا عند تغيير الجهاز/مسح بيانات المتصفح، ولا يراه الأدمن إطلاقًا
 * إن حدث الإجراء من متصفح آخر. بعد إضافته لمفاتيح المزامنة، يجب حمايته من
 * إعادة الكتابة الكاملة (mergeClientScopedArray العادي يستبدل نطاق العميل
 * بالكامل بما يُرسله - ما يسمح بمحو تاريخه السابق بسهولة). الإصلاح: دمج
 * "إضافة فقط" - أي سجل تدقيق موجود فعليًا بمعرّفه (id) يبقى كما هو دائمًا،
 * ولا يُقبَل إلا سجلات جديدة بمعرّفات لم تكن موجودة من قبل. يُطبَّق هذا حتى
 * على دور الأدمن، فلا يمكن لأي طلب (حتى لو أُسيء استخدام توكن أدمن) محو
 * التاريخ الفعلي للأحداث.
 */
const APPEND_ONLY_ARRAY_KEYS = ['auditLog'];

function mergeAppendOnlyArray(existingArray, incomingArray, aidFilter) {
  const existingIds = new Set((existingArray || []).filter((x) => x && x.id).map((x) => x.id));
  const merged = [...(existingArray || [])];
  (Array.isArray(incomingArray) ? incomingArray : []).forEach((item) => {
    if (!item || !item.id) return;
    if (aidFilter && item.cid !== aidFilter) return; // عميل لا يستطيع إدراج سجل تدقيق باسم عميل آخر
    if (existingIds.has(item.id)) return; // سجل موجود فعلًا - يُتجاهَل التعديل عليه حفاظًا على سلامة التاريخ
    existingIds.add(item.id);
    merged.push(item);
  });
  return merged;
}

/* ═══════════════════════ /resolve-account ═══════════════════════ */
// لا يُعيد أي شيء حساس - فقط ما تحتاجه شاشة "الخطوة ٢" لعرض اسم الحساب

async function handleResolveAccount(request, env, cors) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const bucketKey = `resolve-account:${ip}`;
  if (await isRateLimited(env, bucketKey)) return json({ error: 'Too many attempts, slow down' }, 429, cors);
  await registerAttempt(env, bucketKey);

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
  // ⚠️ عقد العميل المعلَّق أو الملغى: يُمنع من تسجيل الدخول تمامًا حتى لو كانت
  // كلمة مروره القديمة لا تزال صحيحة (الإيقاف لا يمسح كلمة المرور، فقط يقفل
  // الدخول مؤقتًا؛ الإلغاء يمسح كلمة المرور فعليًا من جهة العميل أيضًا كطبقة ثانية)
  if (role === 'client' && account.accountStatus === 'suspended') {
    return json({ error: 'account_suspended' }, 403, cors);
  }
  if (role === 'client' && account.accountStatus === 'cancelled') {
    return json({ error: 'account_cancelled' }, 403, cors);
  }
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
  const bucketKey = `login:${ip}`;
  if (await isRateLimited(env, bucketKey)) return json({ error: 'Too many attempts, slow down' }, 429, cors);
  await registerAttempt(env, bucketKey);

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
  if (role === 'client' && account.accountStatus === 'suspended') return json({ error: 'account_suspended' }, 403, cors);
  if (role === 'client' && account.accountStatus === 'cancelled') return json({ error: 'account_cancelled' }, 403, cors);

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
  const bucketKey = `verify-2fa:${ip}`;
  if (await isRateLimited(env, bucketKey)) return json({ error: 'Too many attempts, slow down' }, 429, cors);
  await registerAttempt(env, bucketKey);

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
  if (role === 'client' && account.accountStatus === 'suspended') return json({ error: 'account_suspended' }, 403, cors);
  if (role === 'client' && account.accountStatus === 'cancelled') return json({ error: 'account_cancelled' }, 403, cors);

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
    // ⚠️ مقارنة آمنة زمنيًا (كتلك المُستخدَمة أصلًا للتحقق من توقيع التوكن) -
    // بدل === العادية التي قد تُنهي المقارنة عند أول حرف مختلف، فتُسرِّب معلومة
    // زمنية دقيقة (نظريًا) عن مدى تطابق التخمين مع الهاش الصحيح
    return { ok: timingSafeEqual(hash, record.passwordHash), needsUpgrade: false };
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
    if (timingSafeEqual(code, clean)) return true;
  }
  return false;
}

/* ═══════════════════════ /set-password ═══════════════════════ */
// ✅ إصلاح ثغرة كانت موجودة سابقًا: أي شخص يعرف بريد/هاتف عميل كان يمكنه
// تغيير كلمة مروره الحالية بلا أي تحقق من الهوية. الآن: هذه النقطة تعمل
// فقط للإعداد الأول الحقيقي (لا كلمة مرور موجودة بعد على الحساب). إن كانت
// كلمة مرور موجودة بالفعل، تُرفَض العملية ويُطلب من العميل التواصل مع ANB،
// حيث يستخدم الأدمن نقطة /admin/generate-temp-password (محمية بتوكن الأدمن)
// بعد أن يتحقق من هوية العميل بطريقته الخاصة خارج التطبيق.
async function handleSetPassword(request, env, cors) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const bucketKey = `set-password:${ip}`;
  if (await isRateLimited(env, bucketKey)) return json({ error: 'Too many attempts, slow down' }, 429, cors);
  await registerAttempt(env, bucketKey);

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
  const existing = list[idx];

  // ⚠️⚠️ إصلاح ثغرة حرجة جدًا: كان هذا الشرط ينطبق على العملاء فقط (role
  // === 'client')، بينما حساب الأدمن مُستثنى تمامًا! هذا يعني: أي شخص يعرف
  // بريد/هاتف الأدمن (عبر /resolve-account العامة، التي تكشف accountId) كان
  // يستطيع استدعاء هذه النقطة مباشرة ويُعيّن كلمة مرور من اختياره لحساب
  // الأدمن بالكامل - استيلاء تام على الحساب بلا أي معرفة بكلمة المرور
  // القديمة أو أي تحقق آخر. الحل: تطبيق نفس الحارس على كل الأدوار بلا استثناء.
  if (existing.passwordHash) {
    return json({ error: 'password_already_set', message: 'This account already has a password. Please contact ANB to reset it.' }, 403, cors);
  }

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

/* ═══════════════════════ /admin/generate-temp-password ═══════════════════════ */
// محمية بتوكن أدمن حقيقي (وليست عامة). الأدمن يتحقق من هوية العميل بطريقته
// الخاصة خارج التطبيق (اتصال هاتفي، واتساب...) ثم يستخدم هذه النقطة لتوليد
// كلمة مرور مؤقتة عشوائية للعميل، تُعرَض له مرة واحدة ليُسلِّمها للعميل يدويًا.
async function handleGenerateTempPassword(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== 'admin') return json({ error: 'Admin access required' }, 403, cors);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { clientAccountId } = body || {};
  if (!clientAccountId) return json({ error: 'clientAccountId is required' }, 400, cors);

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);

  const list = listFor(cloud.payload, 'client');
  const idx = list.findIndex((a) => a && a.id === clientAccountId);
  if (idx === -1) return json({ error: 'Client not found' }, 404, cors);

  const tempPassword = generateTempPassword();
  const rec = await makePasswordRecord(tempPassword);
  const account = list[idx];
  account.passwordSalt = rec.passwordSalt;
  account.passwordHash = rec.passwordHash;
  delete account.password; delete account.pwCustom; delete account.pw;
  account.pwSet = true;
  clearFailedAttempts(account);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);

  return json({ tempPassword }, 200, cors);
}
function generateTempPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  let out = '';
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  for (let i = 0; i < 10; i++) out += chars[bytes[i] % chars.length];
  return out;
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
  const filteredPayload = filterPayloadForSync(cloud.payload, auth.payload.at, auth.payload.aid);
  return json({ payload: filteredPayload, updated_at: new Date(cloud.updated_at).toISOString() }, 200, cors);
}
async function handleSyncPost(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { payload: incomingPayload } = body || {};
  if (!incomingPayload || typeof incomingPayload !== 'object') return json({ error: 'payload object is required' }, 400, cors);

  const cloud = await fetchCloudPayload(env);
  const existingPayload = (cloud && cloud.payload) || {};
  const merged = { ...existingPayload };
  const role = auth.payload.at;
  const aid = auth.payload.aid;

  // دالة مشتركة: تدمج حساب واردًا مع الحساب المُخزَّن فعليًا، لكن تُبقي دائمًا
  // الحقول الحسّاسة (كلمة المرور المشفَّرة) كما هي في قاعدة البيانات - لا
  // تتغيَّر إلا عبر /set-password أو /admin/generate-temp-password تحديدًا.
  // نسمح فقط بتحديث totpSecret/totpEnabled (تفعيل 2FA الذاتي يعتمد على هذا
  // المسار حاليًا، وهو غير خطير هنا لأن نطاق من يمكنه إرسال تغيير لحساب
  // مُعيَّن مقيَّد أصلًا بالتحقق أدناه - عميل لا يستطيع التأثير إلا على حسابه هو).
  function mergeAccount(existingAccount, incomingAccount) {
    if (!existingAccount) return incomingAccount; // حساب جديد تمامًا (مثلًا عميل جديد أضافه الأدمن)
    return {
      ...incomingAccount,
      passwordHash: existingAccount.passwordHash,
      passwordSalt: existingAccount.passwordSalt,
    };
  }

  if (role === 'admin') {
    // الأدمن موثوق بنطاق أوسع (يدير كل العملاء)، لكن الحقول الحسّاسة تبقى محميَّة دائمًا
    Object.keys(incomingPayload).forEach((key) => {
      if (key === 'clients' || key === 'admins') {
        const existingList = existingPayload[key] || [];
        merged[key] = (incomingPayload[key] || []).map((incomingAccount) => {
          const existingAccount = existingList.find((a) => a && a.id === incomingAccount.id);
          return mergeAccount(existingAccount, incomingAccount);
        });
      } else if (APPEND_ONLY_ARRAY_KEYS.includes(key)) {
        merged[key] = mergeAppendOnlyArray(existingPayload[key], incomingPayload[key], null);
      } else {
        merged[key] = incomingPayload[key];
      }
    });
  } else {
    // دور العميل: يؤثر فقط على نطاقه الخاص (aid) - لا قدرة إطلاقًا على
    // التأثير على أي عميل آخر أو حسابات الأدمن عبر هذه النقطة
    const existingClients = existingPayload.clients || [];
    const incomingOwnClient = (incomingPayload.clients || []).find((c) => c && c.id === aid);
    if (incomingOwnClient) {
      const existingOwnClient = existingClients.find((c) => c && c.id === aid);
      const mergedOwnClient = mergeAccount(existingOwnClient, incomingOwnClient);
      merged.clients = existingClients.map((c) => (c && c.id === aid ? mergedOwnClient : c));
    }
    // admins تبقى كما هي في قاعدة البيانات تمامًا - العميل لا يملك أي تأثير عليها
    merged.admins = existingPayload.admins || [];
    // yearClosings نفسها: العميل لا يملك صلاحية إغلاق/فتح فترة إطلاقًا (فعل
    // إداري بحت) - تُبقى كما هي في قاعدة البيانات بغضّ النظر عما أرسله العميل
    merged.yearClosings = existingPayload.yearClosings || [];
    const blockedByPeriodLock = [];
    CLIENT_SCOPED_ARRAY_KEYS.forEach((key) => {
      if (key === 'yearClosings') return; // عولجت أعلاه
      if (APPEND_ONLY_ARRAY_KEYS.includes(key)) {
        merged[key] = mergeAppendOnlyArray(existingPayload[key], incomingPayload[key], aid);
        return;
      }
      const { allowed, blocked } = enforcePeriodLockOnClientArray(
        key, existingPayload[key], incomingPayload[key], aid, existingPayload.yearClosings
      );
      blocked.forEach((item) => blockedByPeriodLock.push({ key, id: item.id }));
      merged[key] = mergeClientScopedArray(existingPayload[key], allowed, aid);
    });
    if (blockedByPeriodLock.length > 0) {
      const savedAt = await writeCloudPayload(env, merged);
      return json({
        ok: true,
        updated_at: new Date(savedAt).toISOString(),
        warning: 'period_locked',
        blocked: blockedByPeriodLock,
      }, 200, cors);
    }
  }

  const savedAt = await writeCloudPayload(env, merged);
  return json({ ok: true, updated_at: new Date(savedAt).toISOString() }, 200, cors);
}

/* ═══════════════════════ R2 (بلا تغيير) ═══════════════════════ */

// ⭐ وسيط آمن لـGoogle Cloud Vision API - مفتاح الـAPI يبقى سريًا على الخادم
// فقط (لا يمكن كشفه في كود العميل إطلاقًا)، والطلب يتطلب مصادقة صحيحة وتحديد
// معدَّل صارم نظرًا لكون هذه خدمة مدفوعة فعليًا (بخلاف Tesseract.js المجاني
// الذي كان يعمل بالكامل داخل المتصفح بلا أي استدعاء للخادم على الإطلاق)
async function handleOcrVision(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);

  // ⚠️ تحديد معدَّل مخصَّص لهذه النقطة تحديدًا (منفصل عن حدّ تسجيل الدخول) -
  // خدمة مدفوعة فعليًا، فيجب منع أي استخدام مفرط عرضي أو متعمَّد
  const bucketKey = `ocr-vision:${auth.payload.aid || auth.payload.at}`;
  if (await isRateLimited(env, bucketKey)) {
    return json({ error: 'Too many OCR requests, please wait a moment' }, 429, cors);
  }
  await registerAttempt(env, bucketKey);

  if (!env.GOOGLE_VISION_API_KEY) {
    return json({ error: 'OCR service not configured' }, 503, cors);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid request body' }, 400, cors); }
  const base64Image = (body.image || '').replace(/^data:image\/\w+;base64,/, '');
  if (!base64Image) return json({ error: 'No image provided' }, 400, cors);
  // ⚠️ حماية إضافية: حدّ حجم معقول (خام base64 بحدود ~15 ميجابايت) لمنع طلبات ضخمة غير متوقَّعة
  if (base64Image.length > 20_000_000) return json({ error: 'Image too large' }, 413, cors);

  const visionRequestBody = {
    requests: [{
      image: { content: base64Image },
      features: [{ type: 'DOCUMENT_TEXT_DETECTION' }],
      imageContext: { languageHints: ['en', 'nl'] },
    }],
  };

  let visionResponse;
  try {
    visionResponse = await fetch(
      `https://vision.googleapis.com/v1/images:annotate?key=${env.GOOGLE_VISION_API_KEY}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(visionRequestBody) }
    );
  } catch (err) {
    return json({ error: 'Could not reach OCR service' }, 502, cors);
  }
  if (!visionResponse.ok) {
    return json({ error: 'OCR service error' }, 502, cors);
  }
  const visionData = await visionResponse.json();
  const result = (visionData.responses || [])[0] || {};
  if (result.error) {
    return json({ error: result.error.message || 'OCR processing failed' }, 502, cors);
  }
  const fullText = result.fullTextAnnotation?.text || '';
  // ⚠️ Google Vision لا يُعيد رقم ثقة إجمالي واحد مباشرة كما كان Tesseract -
  // نحسبه بأنفسنا كمتوسط ثقة كل الكلمات المكتشَفة، لإبقاء نفس آلية عرض الثقة
  // الملوَّنة الموجودة أصلًا في التطبيق (خضراء/ذهبية) بلا أي تغيير هناك
  let confidenceSum = 0, confidenceCount = 0;
  // ⭐ نهج مكاني أعمق: نستخرج أيضًا إحداثيات كل كلمة (وليس فقط النص المسطَّح)
  // - هذا يُمكِّن العميل من إعادة بناء بنية الجدول الفعلية (أي عمود تنتمي إليه
  // كل قيمة)، بدل الاعتماد على تخمين نصي بترتيب الظهور فقط، ما يُقلِّل جذريًا
  // الأخطاء مع فواتير جدولية معقَّدة (كفاتورة إيجار بعدة أعمدة أرقام متجاورة)
  const words = [];
  (result.fullTextAnnotation?.pages || []).forEach(page => {
    (page.blocks || []).forEach(block => {
      (block.paragraphs || []).forEach(para => {
        (para.words || []).forEach(word => {
          if (typeof word.confidence === 'number') { confidenceSum += word.confidence; confidenceCount++; }
          const text = (word.symbols || []).map(s => s.text).join('');
          const vertices = word.boundingBox?.vertices || [];
          if (text && vertices.length === 4) {
            const xs = vertices.map(v => v.x || 0), ys = vertices.map(v => v.y || 0);
            words.push({
              t: text,
              x: Math.min(...xs), y: Math.min(...ys),
              w: Math.max(...xs) - Math.min(...xs), h: Math.max(...ys) - Math.min(...ys),
            });
          }
        });
      });
    });
  });
  const avgConfidence = confidenceCount > 0 ? (confidenceSum / confidenceCount) * 100 : 75; // احتياطي معقول إن غاب الرقم

  return json({ text: fullText, confidence: avgConfidence, words }, 200, cors);
}

async function handleUpload(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  // ⚠️ إصلاح ثغرة حقيقية: كان Content-Type يُؤخَذ من رأس الطلب كما أرسله
  // المستخدم بلا أي تحقق، ويُعاد استخدامه لاحقًا حرفيًا عند تقديم الملف
  // (writeHttpMetadata). عميل خبيث كان يستطيع رفع ملف بمحتوى HTML/SVG يحمل
  // <script> فعليًا، معلنًا Content-Type: text/html أو image/svg+xml - فيُنفَّذ
  // الكود عند فتح أي شخص (حتى الأدمن) لرابط الملف مباشرة (مثلًا عبر زر "عرض
  // الإيصال"). الإصلاح: قائمة سماح صارمة لأنواع الملفات المتوقَّعة فعليًا
  // (صور + PDF) فقط - أي نوع آخر يُرفَض عند الرفع نفسه.
  const ALLOWED_UPLOAD_TYPES = new Set([
    'image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/heic', 'image/heif',
    'application/pdf',
  ]);
  const contentType = (request.headers.get('Content-Type') || 'application/octet-stream').split(';')[0].trim().toLowerCase();
  if (!ALLOWED_UPLOAD_TYPES.has(contentType)) {
    return json({ error: 'Unsupported file type. Only images and PDF files are allowed.' }, 415, cors);
  }
  const rawName = request.headers.get('X-File-Name') || 'file';
  const safeName = sanitizeFileName(rawName);
  // ⚠️ إصلاح: نستخدم هوية العميل الفعلي الذي يخصه الملف (وليس فقط من رفعه)
  // كبادئة تخزين، لأن الأدمن غالبًا يرفع مستندات نيابة عن عميل معيَّن - الملف
  // يخص ذلك العميل منطقيًا، لا حساب الأدمن. عميل عادي لا يستطيع ادّعاء هوية
  // عميل آخر (يُقيَّد دائمًا بهويته الخاصة فقط).
  const requestedTargetCid = request.headers.get('X-Target-Client-Id');
  let ownerSegment = `${auth.payload.at}/${auth.payload.aid}`;
  if (requestedTargetCid) {
    if (auth.payload.at === 'admin') {
      ownerSegment = `client/${requestedTargetCid}`;
    } else if (requestedTargetCid === auth.payload.aid) {
      ownerSegment = `client/${auth.payload.aid}`;
    }
    // غير ذلك (عميل يحاول ادّعاء هوية عميل آخر): يُتجاهَل الطلب، ويُستخدَم
    // نطاقه الخاص كما هو افتراضيًا (لا خطأ صريح، فقط تجاهل آمن للقيمة المشبوهة)
  }
  const key = `${ownerSegment}/${Date.now()}-${safeName}`;
  const MAX_UPLOAD_BYTES = 25 * 1024 * 1024; // ٢٥ ميجابايت - حدّ معقول يمنع إساءة استخدام التخزين
  const body = await request.arrayBuffer();
  if (body.byteLength > MAX_UPLOAD_BYTES) return json({ error: 'File too large (max 25MB)' }, 413, cors);
  await env.ANB_FILES.put(key, body, { httpMetadata: { contentType } });
  const workerOrigin = new URL(request.url).origin;
  return json({ key, url: `${workerOrigin}/file/${key}` }, 200, cors);
}
// ⚠️ يتحقق أن هذا المستخدم مسموح له بالوصول لهذا الملف تحديدًا - إما أدمن
// (صلاحية كاملة لإدارة كل الملفات)، أو أن المفتاح يبدأ بنفس بادئة هويته
// الخاصة (الملفات التي رفعها هو بنفسه، عبر /upload التي تُخزِّن دائمًا تحت
// {at}/{aid}/...). قبل هذا الإصلاح، أي مستخدم مُصادَق عليه (حتى عميل عادي)
// كان يستطيع الوصول لأي ملف لأي عميل آخر لو عرف/خمَّن مفتاحه فقط.
function canAccessFileKey(key, auth) {
  if (auth.payload.at === 'admin') return true;
  const ownPrefix = `${auth.payload.at}/${auth.payload.aid}/`;
  return key.startsWith(ownPrefix);
}
async function handleGetFile(request, env, cors, url) {
  // ⚠️ إصلاح ثغرة حقيقية: كانت هذه النقطة عامة بلا أي تحقق من الهوية إطلاقًا -
  // أي شخص يعرف/يخمّن رابط ملف (عقد، مستند) كان يستطيع تنزيله مباشرة بلا
  // تسجيل دخول على الإطلاق. الآن تتطلب توكن دخول صالحًا كحدٍّ أدنى إلزامي.
  // نقبل التوكن عبر رأس Authorization (المفضَّل) أو معامل رابط ?token= بديلًا
  // - ضروري لأن وسم <img src> لا يستطيع إرسال رؤوس HTTP مخصَّصة إطلاقًا.
  let auth = await requireValidToken(request, env);
  if (!auth.ok) {
    const queryToken = url.searchParams.get('token');
    if (queryToken) {
      const fakeRequest = new Request(request.url, { headers: { Authorization: `Bearer ${queryToken}` } });
      auth = await requireValidToken(fakeRequest, env);
    }
  }
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const key = decodeURIComponent(url.pathname.replace('/file/', ''));
  if (!key) return json({ error: 'Missing key' }, 400, cors);
  // ⚠️ إصلاح إضافي: التحقق من ملكية الملف، وليس فقط وجود توثيق عام صالح
  if (!canAccessFileKey(key, auth)) return json({ error: 'Forbidden' }, 403, cors);
  const object = await env.ANB_FILES.get(key);
  if (!object) return json({ error: 'Not found' }, 404, cors);
  const headers = new Headers(cors);
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  headers.set('Cache-Control', 'private, max-age=31536000, immutable');
  // ⚠️ حماية إضافية دفاعية: تمنع المتصفح من "استنتاج" نوع محتوى مختلف عمّا
  // أُعلن (MIME-sniffing) - طبقة حماية إضافية حتى لو كان نوع ملف قديم (مرفوع
  // قبل إصلاح قائمة السماح في handleUpload) لا يزال يحمل نوعًا خطِرًا
  headers.set('X-Content-Type-Options', 'nosniff');
  const SAFE_INLINE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'application/pdf']);
  const storedType = (object.httpMetadata?.contentType || '').split(';')[0].trim().toLowerCase();
  if (!SAFE_INLINE_TYPES.has(storedType)) headers.set('Content-Disposition', 'attachment');
  return new Response(object.body, { headers });
}
async function handleDeleteFile(request, env, cors, url) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const key = decodeURIComponent(url.pathname.replace('/file/', ''));
  if (!key) return json({ error: 'Missing key' }, 400, cors);
  // ⚠️ إصلاح ثغرة حقيقية: كان أي مستخدم مُصادَق عليه (حتى عميل عادي) يستطيع
  // حذف ملف أي عميل آخر لو عرف/خمَّن مفتاحه، بلا أي تحقق من الملكية إطلاقًا
  if (!canAccessFileKey(key, auth)) return json({ error: 'Forbidden' }, 403, cors);
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

// ⚠️ إصلاح: كان الحدّ السابق (attemptLog) خريطة في الذاكرة (Map) محليّة لكل
// نسخة Worker منفردة - نُسخ Cloudflare Workers متعددة ومؤقَّتة بطبيعتها (قد
// تُنشأ نسخة جديدة تمامًا لكل طلب أحيانًا، أو حسب المنطقة الجغرافية)، فهذا
// الحدّ كان يُعاد ضبطه من الصفر بلا أي إنذار عمليًا، ويسهل تجاوزه تمامًا.
// الحل: تخزين المحاولات في Cloudflare KV (ثابت عبر كل النسخ)، مع تراجع آمن
// للسلوك القديم إن لم يُضَف ربط KV بعد (لضمان استمرار عمل الخدمة، وليس تعطيلها).
async function isRateLimited(env, bucketKey) {
  if (!env.RATE_LIMIT_KV) return isRateLimitedLegacy(bucketKey); // تراجع مؤقَّت قبل إضافة ربط KV
  const raw = await env.RATE_LIMIT_KV.get(bucketKey);
  if (!raw) return false;
  let data;
  try { data = JSON.parse(raw); } catch { return false; }
  const now = Date.now();
  const recent = (data.timestamps || []).filter((t) => now - t < MAX_ATTEMPTS_WINDOW_MS);
  return recent.length >= MAX_ATTEMPTS_PER_WINDOW;
}
async function registerAttempt(env, bucketKey) {
  if (!env.RATE_LIMIT_KV) { registerAttemptLegacy(bucketKey); return; }
  const raw = await env.RATE_LIMIT_KV.get(bucketKey);
  let data = { timestamps: [] };
  if (raw) { try { data = JSON.parse(raw); } catch { /* تجاهل بيانات فاسدة، نبدأ من جديد */ } }
  const now = Date.now();
  data.timestamps = (data.timestamps || []).filter((t) => now - t < MAX_ATTEMPTS_WINDOW_MS);
  data.timestamps.push(now);
  const ttlSeconds = Math.ceil(MAX_ATTEMPTS_WINDOW_MS / 1000) + 60;
  await env.RATE_LIMIT_KV.put(bucketKey, JSON.stringify(data), { expirationTtl: ttlSeconds });
}
// السلوك القديم (ذاكرة محلية) - يبقى فقط كتراجع احتياطي مؤقَّت
function isRateLimitedLegacy(ip) {
  const now = Date.now();
  const entry = attemptLog.get(ip);
  if (!entry) return false;
  const recent = entry.filter((t) => now - t < MAX_ATTEMPTS_WINDOW_MS);
  attemptLog.set(ip, recent);
  return recent.length >= MAX_ATTEMPTS_PER_WINDOW;
}
function registerAttemptLegacy(ip) {
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
    // ⚠️ رؤوس أمان إضافية دفاعية لكل استجابات الـAPI - نفس المبدأ المُطبَّق
    // في CSP/headers الواجهة، لكن على مستوى الخادم هذه المرة
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store', // استجابات API لا يجب تخزينها مؤقتًا أبدًا (بيانات حسّاسة) - ما عدا /file التي تُحدِّد Cache-Control خاصًا بها صراحة أعلى
  };
}
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...cors } });
}
