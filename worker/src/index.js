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
      if (url.pathname === '/admin/set-password' && request.method === 'POST') return await handleAdminSetPassword(request, env, cors);
      if (url.pathname === '/account/set-own-password' && request.method === 'POST') return await handleSetOwnPassword(request, env, cors);
      if (url.pathname === '/admin/generate-temp-password' && request.method === 'POST') return await handleGenerateTempPassword(request, env, cors);
      if (url.pathname === '/refresh-token' && request.method === 'POST') return await handleRefreshToken(request, env, cors);
      if (url.pathname === '/sync' && request.method === 'GET') return await handleSyncGet(request, env, cors);
      if (url.pathname === '/sync' && request.method === 'POST') return await handleSyncPost(request, env, cors);
      if (url.pathname === '/upload' && request.method === 'POST') return await handleUpload(request, env, cors);
      if (url.pathname.startsWith('/file/') && request.method === 'GET') return await handleGetFile(request, env, cors, url);
      if (url.pathname.startsWith('/file/') && request.method === 'DELETE') return await handleDeleteFile(request, env, cors, url);
      if (url.pathname === '/ocr-vision' && request.method === 'POST') return await handleOcrVision(request, env, cors);
      if (url.pathname === '/admin/backup-now' && request.method === 'POST') return await handleBackupNow(request, env, cors);
      if (url.pathname === '/admin/backups' && request.method === 'GET') return await handleListBackups(request, env, cors);
      if (url.pathname === '/admin/restore-backup' && request.method === 'POST') return await handleRestoreBackup(request, env, cors);
      if (url.pathname === '/payment/save-provider' && request.method === 'POST') return await handleSavePaymentProvider(request, env, cors);
      if (url.pathname === '/payment/provider-status' && request.method === 'GET') return await handlePaymentProviderStatus(request, env, cors);
      if (url.pathname === '/payment/create' && request.method === 'POST') return await handleCreatePayment(request, env, cors);
      if (url.pathname === '/payment/status' && request.method === 'GET') return await handlePaymentStatus(request, env, cors, url);
      if (url.pathname === '/admin/assistant' && request.method === 'POST') return await handleAdminAssistant(request, env, cors);
      return json({ error: 'Not found' }, 404, cors);
    } catch (err) {
      return json({ error: 'Internal error', detail: String(err && err.message || err) }, 500, cors);
    }
  },

  // ⭐ نسخ احتياطي تلقائي - يُستدعى تلقائيًا في الموعد المحدَّد في wrangler.toml
  // (crons)، بلا أي طلب HTTP أو تدخل بشري إطلاقًا
  async scheduled(event, env, ctx) {
    // ⭐ جدولتان منفصلتان الآن: النسخ الاحتياطي (3 صباحًا) وترحيل أيام الكاشير
    // المتروكة تلقائيًا (منتصف الليل بالضبط) - event.cron يُميِّز بينهما
    if (event.cron === '0 0 * * *') {
      ctx.waitUntil(autoPostStaleCashierDaysServer(env));
    } else {
      ctx.waitUntil(performBackup(env, 'scheduled'));
    }
  },
};

/* ═══════════════════════ ترحيل أيام الكاشير المتروكة تلقائيًا ═══════════════════════ */
// ⭐ يعمل بجدولة خادم مستقلة عند منتصف الليل بالضبط - وليس معتمدًا على أن
// يُسجِّل أحد الدخول (بعكس المحاولة الأولى للميزة، التي كانت تعمل فقط عند
// تسجيل الدخول). يُعيد استخدام بالضبط نفس المنطق المحاسبي الذي يستخدمه العميل
// (postCashierDayForDate) لكن مُعاد كتابته هنا للعمل مباشرة على كائن البيانات
// الكامل (payload) بدل الاعتماد على حالة متصفح العميل S.
async function autoPostStaleCashierDaysServer(env) {
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return; // لا داعي للمحاولة إن تعذَّر الوصول لقاعدة البيانات هذه المرة - ستُعالَج تلقائيًا في الدورة القادمة (أو عند دخول أي مستخدم لاحقًا)
  const payload = cloud.payload;
  const today = new Date().toISOString().slice(0, 10);

  const cashierLog = payload.cashierLog || [];
  const staleGroups = new Map(); // "cid|date" -> true
  cashierLog.forEach((e) => {
    if (!e.posted && e.date && e.date < today) staleGroups.set(e.cid + '|' + e.date, true);
  });
  if (staleGroups.size === 0) return;

  if (!payload.invoices) payload.invoices = [];
  if (!payload.cashPayments) payload.cashPayments = [];
  if (!payload.contacts) payload.contacts = [];
  const now = new Date().toISOString();
  let postedCount = 0;

  for (const key of staleGroups.keys()) {
    const [cid, date] = key.split('|');
    const unposted = cashierLog.filter((e) => e.cid === cid && e.date === date && !e.posted);
    if (unposted.length === 0) continue;
    const alreadyPosted = cashierLog.some((e) => e.cid === cid && e.date === date && e.posted);
    if (alreadyPosted) continue; // ⚠️ نفس القفل الصارم الموجود بالمنطق الأصلي: لا ترحيل مزدوج لنفس اليوم

    const total = unposted.reduce((s, e) => s + (e.price || 0), 0);
    const totalCash = unposted.reduce((s, e) => s + (e.cashAmount || 0), 0);
    const r = 21;

    // getOrCreateGeneralDebtor المكافئة
    let gd = payload.contacts.find((c) => c.type === 'debtor' && c.isGeneral && c.cid === cid && !c.deleted);
    if (!gd) {
      gd = { id: genId(), cid, type: 'debtor', name: 'General Debtors', isGeneral: true, accountNumber: '4999' };
      payload.contacts.push(gd);
    }

    // nextNum/getInvoiceCounter المكافئة
    const client = (payload.clients || []).find((c) => c.id === cid);
    if (client && typeof client.invoiceCounter !== 'number') {
      client.invoiceCounter = payload.invoices.filter((i) => i.cid === cid).length;
    }
    const counter = client ? client.invoiceCounter : payload.invoices.filter((i) => i.cid === cid).length;
    const clientName = client ? client.name.substring(0, 3).toUpperCase() : 'CLI';
    const num = `${clientName}-${String(counter + 1).padStart(3, '0')}`;
    if (client) client.invoiceCounter = counter + 1;

    const ni = {
      id: genId(), cid, num,
      desc: 'Cashier daily takings — ' + date,
      date, due: date, status: 'Openstaand',
      amount: total / (1 + r / 100), btw: total - total / (1 + r / 100), total, btwRate: r,
      amountPaid: 0, billTo: gd.name, billToId: gd.id, billToManual: null,
      isDailyRevenue: true, isCashierPosting: true,
    };
    payload.invoices.push(ni);

    if (totalCash > 0.005) {
      payload.cashPayments.push({
        id: genId(), cid: ni.cid, invoiceId: ni.id, direction: 'in', date: ni.date,
        amount: totalCash, note: 'Auto-posted (day was left open)', recordedBy: 'system', createdAt: now,
      });
      // applyAllocationToTarget المكافئة (حالة الفاتورة فقط، بلا احتفال بصري هنا)
      ni.amountPaid = (ni.amountPaid || 0) + totalCash;
      if (ni.amountPaid >= ni.total - 0.005) { ni.status = 'Betaald'; ni.paidDate = ni.paidDate || date; }
    }

    unposted.forEach((e) => { e.posted = true; e.postedAt = now; e.postedInvoiceId = ni.id; e.autoPosted = true; });
    postedCount++;
  }

  if (postedCount > 0) {
    await writeCloudPayload(env, payload);
  }
}
function genId() { return Math.random().toString(36).slice(2, 8).toUpperCase(); }

/* ═══════════════════════ نظام النسخ الاحتياطي ═══════════════════════ */
// ⚠️ لماذا هذا ضروري: كل بيانات العمل الحقيقية تعيش في صف واحد بقاعدة بيانات
// واحدة (D1) بلا أي نسخة احتياطية دورية. أي خطأ (بشري أو برمجي، كخطأ في منطق
// دمج المزامنة، أو استعلام SQL خاطئ يُنفَّذ يدويًا بالخطأ) قد يُتلف أو يمحو
// هذا الصف بلا أي طريقة "تراجع" جاهزة. النسخ الاحتياطي يُخزَّن في R2 منفصل
// تمامًا عن قاعدة البيانات نفسها (فشل D1 لا يؤثر على البيانات المُخزَّنة فيه).
const BACKUP_RETENTION_COUNT = 60; // الاحتفاظ بآخر 60 نسخة (~شهرين عند نسخ يومي) قبل حذف الأقدم تلقائيًا

async function performBackup(env, trigger) {
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return { ok: false, error: 'Could not read database' };
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const key = `backup-${timestamp}${trigger === 'manual' ? '-manual' : ''}.json`;
  const body = JSON.stringify({ backedUpAt: new Date().toISOString(), trigger: trigger || 'scheduled', payload: cloud.payload });
  await env.BACKUPS.put(key, body, { httpMetadata: { contentType: 'application/json' } });

  // ⭐ تنظيف تلقائي: حذف أي نسخ أقدم من آخر BACKUP_RETENTION_COUNT، لمنع تراكم
  // تخزين لا نهائي - النسخ الاحتياطية القديمة جدًا نادرًا ما تكون مفيدة عمليًا
  const listed = await env.BACKUPS.list();
  const sorted = listed.objects.map((o) => o.key).sort().reverse(); // الأحدث أولًا (التوقيت في اسم الملف يضمن الترتيب الأبجدي = الزمني)
  const toDelete = sorted.slice(BACKUP_RETENTION_COUNT);
  for (const oldKey of toDelete) {
    await env.BACKUPS.delete(oldKey);
  }

  return { ok: true, key, deletedOldBackups: toDelete.length };
}

// محمي بتوكن أدمن - يسمح بأخذ نسخة احتياطية فورية (مثلًا قبل إجراء خطر أو
// تغيير جوهري)، بدل انتظار الموعد التلقائي التالي
/* ═══════════════════════ نظام الدفع الإلكتروني ═══════════════════════ */
// ⭐ طبقة تجريد عامة لمزوِّدي الدفع - Mollie مُفعَّل بالكامل الآن (الأنسب
// لهولندا: توثيق ممتاز، iDEAL مدعوم أصلًا). Stripe وSumUp لهما نفس البنية
// جاهزة أدناه (حالة إضافية في كل دالة + استدعاء API مكافئ) لإضافتهما لاحقًا
// بلا أي تعديل على الواجهة أو منطق الحفظ - فقط تنفيذ استدعاء API الفعلي.
const SUPPORTED_PAYMENT_PROVIDERS = {
  mollie: { name: 'Mollie', live: true },
  stripe: { name: 'Stripe', live: false },
  sumup: { name: 'SumUp', live: true },
};

// حفظ إعداد مزوِّد الدفع لعميل مُحدَّد - العميل يعدِّل حسابه هو فقط، الأدمن يعدِّل أي عميل
async function handleSavePaymentProvider(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { cid, provider, apiKey, merchantCode } = body || {};
  if (!cid || !provider) return json({ error: 'cid and provider are required' }, 400, cors);
  if (!SUPPORTED_PAYMENT_PROVIDERS[provider]) return json({ error: 'Unsupported provider' }, 400, cors);
  if (auth.payload.at === 'client' && auth.payload.aid !== cid) {
    return json({ error: 'Clients can only configure their own account' }, 403, cors);
  }

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);
  const clients = cloud.payload.clients || [];
  const idx = clients.findIndex((c) => c && c.id === cid);
  if (idx === -1) return json({ error: 'Client not found' }, 404, cors);
  clients[idx].paymentProvider = provider;
  // ⚠️ لا نُفرِّغ مفتاحًا محفوظًا سابقًا لمجرد أن هذا الطلب لم يتضمَّن مفتاحًا
  // جديدًا (مثلًا: تعديل عادي دون نية تغيير المفتاح نفسه)
  if (apiKey) clients[idx].paymentApiKey = apiKey;
  // ⭐ بعض المزوِّدين (SumUp) يحتاجون معرِّفًا إضافيًا غير سرّي (رمز التاجر)
  // بجانب المفتاح - يُحفَظ مباشرة بلا حاجة لحمايته كسرّ
  if (merchantCode !== undefined) clients[idx].paymentMerchantCode = merchantCode;
  await writeCloudPayload(env, cloud.payload);
  return json({ ok: true }, 200, cors);
}

// حالة الإعداد الحالية فقط (هل مُهيَّأ ولأي مزوِّد) - لا يُعاد المفتاح نفسه أبدًا
async function handlePaymentProviderStatus(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const reqUrl = new URL(request.url);
  const cid = reqUrl.searchParams.get('cid');
  if (!cid) return json({ error: 'cid is required' }, 400, cors);
  if (auth.payload.at === 'client' && auth.payload.aid !== cid) {
    return json({ error: 'Clients can only view their own configuration' }, 403, cors);
  }
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);
  const client = (cloud.payload.clients || []).find((c) => c && c.id === cid);
  if (!client) return json({ error: 'Client not found' }, 404, cors);
  return json({
    provider: client.paymentProvider || null,
    configured: !!(client.paymentProvider && client.paymentApiKey),
  }, 200, cors);
}

// إنشاء طلب دفع فعلي عبر مزوِّد العميل المحفوظ، يُعاد رابط دفع (يتحوَّل لرمز QR بالواجهة)
async function handleCreatePayment(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { cid, amount, description } = body || {};
  if (!cid || !amount) return json({ error: 'cid and amount are required' }, 400, cors);
  if (auth.payload.at === 'client' && auth.payload.aid !== cid) {
    return json({ error: 'Clients can only create payments for their own account' }, 403, cors);
  }

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);
  const client = (cloud.payload.clients || []).find((c) => c && c.id === cid);
  if (!client || !client.paymentProvider || !client.paymentApiKey) {
    return json({ error: 'no_provider_configured', message: 'No payment provider configured for this account yet.' }, 400, cors);
  }

  const originHeader = request.headers.get('Origin') || env.ALLOWED_ORIGIN || 'https://anb-1cw.pages.dev';

  if (client.paymentProvider === 'mollie') {
    try {
      const res = await fetch('https://api.mollie.com/v2/payments', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + client.paymentApiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amount: { currency: 'EUR', value: Number(amount).toFixed(2) },
          description: description || 'Payment',
          redirectUrl: originHeader,
          method: 'ideal,creditcard,bancontact,applepay',
        }),
      });
      const data = await res.json();
      if (!res.ok) return json({ error: 'provider_error', message: data.detail || 'Payment provider rejected the request' }, 502, cors);
      return json({ paymentId: data.id, checkoutUrl: data._links && data._links.checkout && data._links.checkout.href }, 200, cors);
    } catch (err) {
      return json({ error: 'provider_error', message: String(err && err.message || err) }, 502, cors);
    }
  }

  // ⭐ SumUp - Hosted Checkout: SumUp يستضيف صفحة الدفع بنفسه (نفس مبدأ Mollie)،
  // لكنه يحتاج merchant_code إضافيًا بجانب مفتاح API (رمز حساب التاجر نفسه،
  // وليس سرًّا يجب حمايته بنفس درجة المفتاح، لذا يُحفَظ كحقل عادي)
  if (client.paymentProvider === 'sumup') {
    if (!client.paymentMerchantCode) {
      return json({ error: 'no_provider_configured', message: 'SumUp requires a Merchant Code in addition to the API key — please add it in the client\'s payment settings.' }, 400, cors);
    }
    try {
      const checkoutRef = 'anb-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
      const res = await fetch('https://api.sumup.com/v0.1/checkouts', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + client.paymentApiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          checkout_reference: checkoutRef,
          amount: Number(amount),
          currency: 'EUR',
          merchant_code: client.paymentMerchantCode,
          description: description || 'Payment',
          redirect_url: originHeader,
          hosted_checkout: { enabled: true },
        }),
      });
      const data = await res.json();
      if (!res.ok) return json({ error: 'provider_error', message: (data && (data.message || data.error_message)) || 'Payment provider rejected the request' }, 502, cors);
      return json({ paymentId: data.id, checkoutUrl: data.hosted_checkout_url }, 200, cors);
    } catch (err) {
      return json({ error: 'provider_error', message: String(err && err.message || err) }, 502, cors);
    }
  }

  // ⚠️ Stripe: نقطة التوسعة - أضِف حالة هنا تستدعي Stripe Checkout Sessions
  // وتُعيد نفس الشكل {paymentId, checkoutUrl} بالضبط - لا حاجة لتغيير أي شيء آخر
  return json({ error: 'provider_not_implemented', message: `${SUPPORTED_PAYMENT_PROVIDERS[client.paymentProvider]?.name || client.paymentProvider} support is coming soon — Mollie and SumUp are fully supported now.` }, 501, cors);
}

// التحقق من حالة دفع سابق - تُستقصى دوريًا من الواجهة حتى تصبح 'paid'
async function handlePaymentStatus(request, env, cors, url) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const cid = url.searchParams.get('cid');
  const paymentId = url.searchParams.get('paymentId');
  if (!cid || !paymentId) return json({ error: 'cid and paymentId are required' }, 400, cors);
  if (auth.payload.at === 'client' && auth.payload.aid !== cid) {
    return json({ error: 'Clients can only check their own payments' }, 403, cors);
  }
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);
  const client = (cloud.payload.clients || []).find((c) => c && c.id === cid);
  if (!client || !client.paymentApiKey) return json({ error: 'no_provider_configured' }, 400, cors);

  if (client.paymentProvider === 'mollie') {
    try {
      const res = await fetch('https://api.mollie.com/v2/payments/' + paymentId, {
        headers: { 'Authorization': 'Bearer ' + client.paymentApiKey },
      });
      const data = await res.json();
      if (!res.ok) return json({ error: 'provider_error' }, 502, cors);
      return json({ status: data.status }, 200, cors); // 'open' | 'paid' | 'expired' | 'canceled' | 'failed'...
    } catch (err) {
      return json({ error: 'provider_error', message: String(err && err.message || err) }, 502, cors);
    }
  }

  // ⭐ SumUp: مفردات حالة مختلفة عن Mollie (PENDING/PAID/FAILED) - نُحوِّلها
  // لنفس المفردات التي يتوقعها كود الاستقصاء بالواجهة بالفعل، فلا حاجة لتعديل
  // منطق الاستقصاء نفسه إطلاقًا
  if (client.paymentProvider === 'sumup') {
    try {
      const res = await fetch('https://api.sumup.com/v0.1/checkouts/' + paymentId, {
        headers: { 'Authorization': 'Bearer ' + client.paymentApiKey },
      });
      const data = await res.json();
      if (!res.ok) return json({ error: 'provider_error' }, 502, cors);
      const statusMap = { PAID: 'paid', FAILED: 'failed', EXPIRED: 'expired', PENDING: 'open' };
      return json({ status: statusMap[data.status] || 'open' }, 200, cors);
    } catch (err) {
      return json({ error: 'provider_error', message: String(err && err.message || err) }, 502, cors);
    }
  }
  return json({ error: 'provider_not_implemented' }, 501, cors);
}

/* ═══════════════════════ مساعد الأدمن بالذكاء الاصطناعي ═══════════════════════ */
// ⭐ يستخدم Cloudflare Workers AI (مجاني ضمن 10,000 طلب/يوم تقريبًا) - لا
// يحتاج مفتاح API خارجي أو حساب منفصل، يعمل مباشرة عبر ربط env.AI. مخصَّص
// لمساعدة الأدمن في حالات محاسبية/ضريبية/قانونية غامضة - وليس بديلًا عن
// استشاري حقيقي لأي قرار نهائي فعلي.
const ADMIN_ASSISTANT_MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';

// ⭐ دليل مرجعي بميزات تطبيق ANB الفعلية - بدونه، المساعد يُخمِّن إجابات عامة
// قد لا تطابق التطبيق إطلاقًا (خطر توجيه لزر/شاشة غير موجودة). يُحدَّث هذا
// النص يدويًا كلما أُضيفت ميزة جوهرية جديدة للتطبيق.
const ANB_APP_REFERENCE = `ANB FinAdmin Pro — comprehensive reference of how the app actually works (verified against its source code), organized by section. Use this to give specific, accurate guidance about where and how to record things — never invent screens, buttons, fields, or numbers not listed here.

INVOICES (per client):
- BTW/VAT types on each invoice: "normal" (standard rate applied), "verlegd_nl" (domestic reverse charge, must state "BTW verlegd — art. 12 lid 3 Wet OB 1968", goes in rubriek 1e, no VAT charged), "eu_b2b" (EU business customer reverse charge, must state "BTW verlegd" + customer's valid EU VAT number, rubriek 3b), "export" (outside EU, outside scope of Dutch VAT, rubriek 3a).
- Status tracked as paid/unpaid; can be settled by cash payment (see Cash Ledger) or matched against a bank transaction.
- Recurring invoice schedules can be set up and stopped (already-generated invoices are kept when stopped).

EXPENSES (per client):
- Has a category and supplier. Reverse-charge purchases received (domestic or foreign supplier) are their own BTW type: "verlegd_received" — no VAT was actually paid to the supplier; the rate is used only to self-assess VAT for the return (net effect €0 on the return, appears in reverse-charge-received rubrieken 2a/4b).
- Receipts can be photographed and read automatically via OCR (Google Cloud Vision). The system "learns" per-supplier typical VAT rate and amount over time (Settings → Manage Learned Suppliers) and flags amounts that deviate significantly from what's usually paid to that supplier, asking for manual verification.
- OCR confidence is shown per field (color-coded); low-quality scans are flagged for careful manual review.

HOURS:
- Timer-based logging (start/pause/stop & log) with a task description, or manual entry.
- Categories are customizable per client (Settings → Manage Categories) to match their actual work (photography, consulting, construction, etc.)
- Tracks progress toward the Dutch "urencriterium" — 1,225 hours/year required for the self-employed deduction (Zelfstandigenaftrek). The app shows whether the client is on pace and whether the criterion is currently met.

CASH LEDGER (distinct from Cashier — for businesses that occasionally get paid in cash, not walk-in service businesses):
- Record Cash Payment: settles a specific existing invoice partially or fully in cash; invoice only shows "Paid" once fully covered.
- Daily Revenue Entry: for businesses with many small daily payments (retail counters) — one total takings figure per day (excl. BTW) instead of itemizing every sale, ready to match against the bank. This is ONLY available/shown when Cashier is NOT enabled for that client — if Cashier is enabled, this button is hidden and blocked (with an explanatory message if somehow triggered anyway), because daily income is already posted from the Cashier itself; having both active at once would double-count the same day's revenue.
- Cash Withdrawal / Cash Deposit: recording money moved between the bank and the physical cash till.
- Personal Drawing: money taken from the till for personal (non-business) use — affects the owner's capital account, NOT the profit & loss statement, and is NOT a business expense.
- A warning appears if a cash entry is backdated by more than 1 day, since the Belastingdienst expects daily logging of cash takings.
- Cash amounts that came from a Cashier day posting are labeled clearly (e.g. "🧾 Cashier — 18/07/2026 (invoice number)") in the Cash Ledger list, not just a bare invoice number, so the connection between the two features is visible at a glance.

CASHIER (separate feature, for walk-in/service businesses — driving instructors, hairdressers, barbers, etc.):
- Admin (or the client themselves) configures quick-tap "Services" with a name, a color (chosen from a preset palette, shown as a left accent stripe and tinted card background — not an emoji), and price (which can be marked editable at time of use, e.g. for a custom amount).
- Payment methods per transaction: cash (fully paid now), bank transfer (pending, matched later), split (part cash / part pending bank), or card/QR (only shown if the client has connected their own Mollie or SumUp account — see Electronic Payment below).
- "Post Today" performs the daily reconciliation: requires counting the actual physical cash on hand first (flags a discrepancy if it doesn't match expected), then creates one invoice for the day's takings and locks the entries. Can only be done once per day.
- AUTOMATIC POSTING OF FORGOTTEN DAYS: if a day's Cashier entries are never manually posted, they are posted automatically — a scheduled server job runs exactly at midnight and posts any previous day (never the current day) that still has unposted entries, for every client, using the exact same accounting logic as the manual "Post Today" button (invoice + cash-ledger entry), marked internally as auto-posted. As a backup safety net, the same check also runs client-side the next time anyone logs in, in case the midnight job was ever missed — both are safe to run repeatedly (a day already posted is simply skipped, never posted twice).
- If a day has zero entries when trying to post manually, the client must explain why first (no activity that day, or a genuine recording error) — a "missing day exception" that requires ANB admin approval before the client can continue using the Cashier. (The automatic midnight/login posting only ever acts on days that DO have unposted entries — empty days are a separate manual-only flow.)
- Cashier Log (admin-only screen): full history of all cashier transactions with a reprint button per entry.
- Receipt printing: after any cashier sale, the app offers to print a physical receipt via the browser's native print dialog (works with AirPrint on iOS or any connected printer on Android) — this is not a direct Bluetooth connection, it uses standard printing so it works across devices without special hardware pairing.

ELECTRONIC PAYMENT (Cashier add-on):
- Either the admin or the client themselves can connect the CLIENT's OWN payment provider account (their money goes directly to them, never through ANB): Mollie (live) or SumUp (live, additionally requires a "Merchant Code" alongside the API key) — Stripe is not yet implemented.
- Generates a real payment request with the provider, shown to the customer as a QR code; the app polls for payment confirmation and auto-logs the Cashier entry once paid.

BANK:
- Bank statement transactions are reconciled against invoices/expenses via suggested matches, manual search, or marking "no match needed" (internal transfers, bank fees).

ASSETS (Vaste Activa — any purchased asset, not just vehicles):
- Categories include Equipment, Furniture, Vehicle, Goodwill, and others.
- Any asset costing under €450 (excl. BTW) must be expensed immediately as a regular expense, NOT capitalized/depreciated as an asset (Dutch tax rule) — the app flags this and suggests using "Add Expense" instead.
- Dutch tax law's minimum useful life for depreciation: 5 years for ordinary assets, 10 years for Goodwill. The app auto-adjusts a shorter entered life up to this legal minimum.
- Depreciation is straight-line: (acquisition cost − residual value) ÷ useful life years. A "Generate Depreciation" button creates the year's journal entries per client (skips ones already created).
- KIA (Kleinschaligheidsinvesteringsaftrek / Small-Scale Investment Deduction) is flagged as potentially applicable when total investment for the period falls within the current range (app shows a hint; exact percentage must be checked against the current official Belastingdienst table).
- LOAN FINANCING (applies to ANY asset type, not just vehicles): mark an asset as financed by a loan with a remaining balance and annual interest rate. Logging a payment (one total amount entered) automatically splits it into interest (tax-deductible, posted as an actual journal entry) and principal (reduces the loan balance only, never expensed) using standard amortization: interest = remaining balance × annual rate ÷ 12.
- VEHICLE-specific fields (only for category = Vehicle): a private-use percentage, and a mileage-log note. Private use above a de-minimis threshold typically triggers "Bijtelling" (added taxable income) under Dutch rules — the app flags this but does NOT calculate the exact amount (needs confirmation from a tax advisor); a detailed mileage log can support a claim of under 500 km/year private use.
- "Loan Overview" report (under Reports, not the Assets screen itself) aggregates every financed asset for a client: total outstanding balance, interest paid this year and all-time, a progress bar per loan, and full payment history.

EMPLOYEES / PAYROLL:
- Salary types: Fixed Monthly or Variable Hourly.
- Benefits: Vacation money (Vakantiegeld, 8% of gross annual salary, typically paid out once in May, or accrued monthly and shown as a running liability until then), 13th month bonus (accrues 1/12 of gross monthly, paid as a lump sum in December, same accrual principle as vacation money), homework allowance (tax-free up to the official rate, based on homework days per month), travel allowance (tax-free per-km rate or fixed monthly amount), pension percentage.
- Payroll tax (Loonheffing) is estimated using official tax brackets — the app explicitly disclaims this needs verification before official use.
- Payslips can be generated (status: CONCEPT while the month hasn't ended yet, then CONFIRMED) and exported as PDF, alongside a payslip history per employee.
- Contract types: Permanent (Onbepaalde tijd) or Fixed-term (Bepaalde tijd) — fixed-term contracts ending within 90 days are flagged in the Employee Statistics report.
- Reports: "Employee Financial Report" (payroll costs & payments, YTD gross/loonheffing/pension, outstanding accrued liabilities, per-employee breakdown) and "Employee Statistics Report" (headcount, average cost/tenure, contract-type/salary-type/job-title/nationality breakdowns, upcoming fixed-term contract endings). There's also a general "Payroll Report".

CONTRACTS & SERVICE AGREEMENTS:
- Per-client service contracts (monthly or annual rate, start/end dates, subscription package). New clients go through a signing workflow (agreement sent → client reviews & can request changes or sign → admin approves) before their accounting tabs unlock — while pending, the client only sees a waiting screen plus the ability to review/sign the agreement.
- "Add Contract" always creates a brand-new client together with the contract (all the same required legal fields as "Add Client" — see NEW CLIENT CREATION below) — it does NOT offer a way to attach a new contract to an already-existing client. An existing client who needs a new/updated contract uses the 🔁 Renew or ✏ Edit buttons on their own current contract instead, never "Add Contract".
- Subscription packages themselves are customizable (Settings) — existing signed contracts keep their price even if package definitions change later.

DEBTORS / CREDITORS:
- Contacts are tagged as "debtor" (customer who owes money) or "creditor" (supplier owed money), each with a ledger account number. A "General Debtors"/"General Creditors" catch-all contact exists per client for entries not tied to a specific named contact.

REPORTS available (Reports screen, grouped): Summary, Profit & Loss (P&L), BTW report (VAT return by official Belastingdienst rubrieken — 1e domestic reverse charge issued, 2a/4b reverse charge received self-assessed [combined for simplicity in the UI, admin should verify the exact box before filing], 3a export outside EU, 3b EU B2B reverse charge), Tax Liability (estimated personal Inkomstenbelasting or corporate Vennootschapsbelasting — includes urencriterium/starter-status detection, KVK registration date auto-detects starter status for startersaftrek eligibility within first 5 years, customer-base setting [mostly B2B vs 90%+ B2C] determines VAT accounting basis: invoice-basis/factuurstelsel for B2B vs cash-basis/kasstelsel eligibility for mostly-consumer businesses), Cash Flow, Debtors, Expenses, Employee Financial, Employee Statistics, Payroll, and Loan Overview (only appears if the client has at least one financed asset).

PERIOD LOCKING: Once a year or quarter is "closed" for a client (after filing that period's BTW return), transactions dated within it are protected — clients can no longer edit/delete them, and admins must explicitly confirm an override for any genuine correction. Periods can be reopened if needed.

IMPORT: A template-based workflow (download template → fill with data from the client's previous accounting office → upload) to migrate historical data in, with required supporting files (bank statements, prior reports) and a full import history that can be reversed (removes all records + the journal entry created by that batch).

NEW CLIENT CREATION & PASSWORD SECURITY:
- Every new client (created via "Add Client" or "Add Contract" — both require the exact same legal fields: company name, email, contact person, KVK number, BTW number, IBAN, full address) automatically gets a one-time, randomly-generated temporary password immediately after creation, shown once to the admin in a dialog to copy and share with the client through a trusted channel (phone, in person) — it is never shown again after that.
- The exact same one-time-password mechanism is used whenever an admin resets an existing client's password (Settings → Clients tab, or the client's own screen → "Reset Password") for a forgotten-password situation — self-service "forgot password" is NOT available; only an admin can issue a new temporary password.
- Any account that logs in with such a temporary password is immediately shown a mandatory, non-dismissible "Set Your Password" screen before anything else in the app becomes usable — there is no way to skip, close, or work around this screen; the account cannot proceed until a new password (min. 6 characters, confirmed twice) is successfully saved. This applies identically whether the temporary password came from brand-new client creation or from an admin-initiated password reset.
- Separately, a client can voluntarily change their own password any time from their dashboard's Security card ("Change Password") — this requires entering their CURRENT password correctly first (server-verified) before the new password (min. 6 characters, confirmed twice) is accepted. This is a self-service option distinct from the admin-issued temporary-password flow above, and does not require contacting ANB.

SETTINGS is organized into three tabs now (the previous separate "Company" tab was removed):
- Admins tab: the list of admin accounts (add/remove — Super Admin role is protected from being reset or removed by regular admins), each admin's password reset button, and Two-Factor Authentication (2FA) setup for the currently logged-in admin's own account.
- Clients tab: the list of client accounts with a password-reset button per client and a button to view a copy of their signed contract (PDF), plus Subscription Packages management (the plans offered when creating new client contracts).
- Danger Zone tab: automatic daily Backups (stored completely separately from the live database, with manual "Backup Now", a list of available backups, and Restore which takes an automatic safety backup of the current state first), and permanent client deletion (gated by re-entering the admin's own password).
- ANB's own company details (company name, KVK, BTW, IBAN, address, tagline, website, and Professional Indemnity Insurance details referenced in service agreement liability clauses) now live in ANB's own record under Edit Client — reached the same way as editing any other client (ANB is modeled as a special client itself) — rather than a separate Settings tab. Saving this screen for ANB automatically keeps the underlying data used by invoice/contract generation in sync, with no separate step needed.

TRASH & ARCHIVE: Deleted items go to Trash first; after 30 days they move to a separate Archived view (kept for the legal 7-year retention period from the record date, even though no longer in Trash).

CLIENT-SIDE FEATURES: A first-time Welcome onboarding (3 short animated slides) shown once per client account, plus a "Quick Start" checklist on their dashboard (log first hours/expense, create first invoice, message ANB) that tracks real progress and disappears once complete or dismissed. A searchable Help Center (collapsible FAQ topics: invoices, expenses, hours, cashier, BTW report, messaging, documents) automatically filtered to only show topics for sections that client actually has enabled — accessed via a floating "❓" button visible on every screen. Clients can manage their own Cashier services and their own Electronic Payment provider connection.

ROLES: Admin (ANB staff) sees and manages everything for every client, including a company-wide dashboard, messages, documents, and contracts overview across all clients. Clients only see their own data; which optional sections they can see (Reports, Employees, Bank, Assets, Client Activity log, Cashier, etc.) is individually toggled per client by the admin in Edit Client → Configuration → Visible Sections.

AI ASSISTANT: This chatbot itself (admin-only, via a floating "🤖" button) — free via Cloudflare Workers AI, for accounting/tax/admin guidance including "how do I record X in this app" questions.`;

const ADMIN_ASSISTANT_SYSTEM_PROMPT = `You are an internal assistant for ANB Financial Services, a Dutch bookkeeping and financial administration firm serving freelancers (ZZP) and small businesses. You help the firm's own admin staff think through accounting, tax (Dutch BTW/Belastingdienst rules), and general business-administration questions they run into during daily work — including questions about how to record something in their own ANB FinAdmin Pro application.

${ANB_APP_REFERENCE}

Important rules you must always follow:
- You are a helpful starting point for reasoning through a question, NOT a substitute for a qualified accountant, tax advisor, or lawyer for any final decision with real financial, tax, or legal consequences.
- Always end your answer with a brief reminder to verify anything consequential with a qualified professional before acting on it, especially for Dutch tax filings or legal matters.
- Be concise, practical, and specific. If the question is about Dutch tax rules (BTW, KOR, aftrekbaarheid, etc.), reason from general principles you're confident about, and clearly flag anything you are not fully certain about instead of guessing confidently.
- If a question is about where/how to do something in the app, use the app reference above precisely — do not invent screens, buttons, or fields that aren't described there.
- If the admin writes in Arabic or Dutch, reply in the same language they used.`;

async function handleAdminAssistant(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== 'admin') return json({ error: 'Admin access required' }, 403, cors);

  // ⚠️ حماية بسيطة من إساءة استخدام سريعة تستنزف الحصة اليومية المجانية
  // بالكامل خلال دقائق - ليست بديلًا عن حد Cloudflare اليومي نفسه، فقط طبقة
  // إضافية ضد الاستهلاك السريع غير المقصود (كضغط متكرر بالخطأ)
  const bucketKey = `assistant:${auth.payload.aid}`;
  if (await isRateLimited(env, bucketKey)) {
    return json({ error: 'Too many requests, please wait a bit before asking again' }, 429, cors);
  }
  await registerAttempt(env, bucketKey);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { question } = body || {};
  if (!question || typeof question !== 'string' || !question.trim()) {
    return json({ error: 'question is required' }, 400, cors);
  }
  if (question.length > 2000) {
    return json({ error: 'Question is too long (max 2000 characters)' }, 400, cors);
  }

  try {
    const aiResponse = await env.AI.run(ADMIN_ASSISTANT_MODEL, {
      messages: [
        { role: 'system', content: ADMIN_ASSISTANT_SYSTEM_PROMPT },
        { role: 'user', content: question.trim() },
      ],
    });
    const answer = (aiResponse && (aiResponse.response || aiResponse.result)) || '';
    if (!answer) return json({ error: 'assistant_error', message: 'No response from the assistant — please try again.' }, 502, cors);
    return json({ answer }, 200, cors);
  } catch (err) {
    return json({ error: 'assistant_error', message: String(err && err.message || err) }, 502, cors);
  }
}

async function handleBackupNow(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== 'admin') return json({ error: 'Admin access required' }, 403, cors);

  const result = await performBackup(env, 'manual');
  if (!result.ok) return json(result, 502, cors);
  return json(result, 200, cors);
}

// محمي بتوكن أدمن - عرض كل النسخ الاحتياطية المتوفرة (بلا تحميل محتواها
// الكامل، فقط الاسم والحجم والتاريخ) لاختيار نسخة للاسترجاع لاحقًا
async function handleListBackups(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== 'admin') return json({ error: 'Admin access required' }, 403, cors);

  const listed = await env.BACKUPS.list();
  const backups = listed.objects
    .map((o) => ({ key: o.key, size: o.size, uploaded: o.uploaded }))
    .sort((a, b) => (a.key < b.key ? 1 : -1)); // الأحدث أولًا
  return json({ backups }, 200, cors);
}

// محمي بتوكن أدمن - استرجاع نسخة احتياطية مُحدَّدة كاملةً، مع أخذ نسخة
// احتياطية إضافية "قبل الاسترجاع" تلقائيًا من الحالة الحالية أولًا - لو تبيَّن
// أن الاسترجاع كان خطأً، لا يزال بالإمكان العودة للحالة التي كانت قائمة قبله
async function handleRestoreBackup(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== 'admin') return json({ error: 'Admin access required' }, 403, cors);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { backupKey } = body || {};
  if (!backupKey) return json({ error: 'backupKey is required' }, 400, cors);

  const backupObj = await env.BACKUPS.get(backupKey);
  if (!backupObj) return json({ error: 'Backup not found' }, 404, cors);
  const backupData = JSON.parse(await backupObj.text());

  // ⭐ شبكة أمان: نسخة احتياطية فورية من الحالة الحالية (قبل الكتابة فوقها)
  await performBackup(env, 'pre-restore-safety');

  await writeCloudPayload(env, backupData.payload);
  return json({ ok: true, restoredFrom: backupKey, restoredBackupTimestamp: backupData.backedUpAt }, 200, cors);
}

/* ═══════════════════════ D1 helpers ═══════════════════════ */

// ⭐⭐ إعادة بناء معمارية التخزين: بدل خانة JSON واحدة ضخمة تحوي كل شيء (كل
// عميل، كل فاتورة، كل مصروف...)، أصبحت البيانات موزَّعة على جداول منفصلة لكل
// نوع (tbl_clients، tbl_invoices، tbl_expenses...)، كل سجل بصف مستقل. هذا يحل
// مشكلتين حقيقيتين ستظهران مع نمو عدد العملاء: (1) سرعة القراءة/الكتابة -
// عملية بسيطة لن تعود تنقل كامل بيانات الشركة في كل مرة، (2) تضارب التعديلات
// المتزامنة - تعديل سجلَّين مختلفين الآن لا يتنافسان على نفس الصف إطلاقًا.
//
// ⚠️ الدالتان أدناه تحافظان على نفس التوقيع الخارجي تمامًا (نفس المدخلات
// والمخرجات) الذي كانتا عليه في النظام القديم - فكل الكود الذي يستخدمهما
// (١٧ موضعًا عبر هذا الملف، بما فيها منطق الدمج المعقَّد في handleSyncPost)
// يستمر بالعمل بلا أي تعديل إطلاقًا. فقط ما بداخل الدالتين تغيَّر.
async function fetchCloudPayload(env) {
  try {
    const payload = {};
    let maxUpdatedAt = 0;

    for (const key of ALL_ARRAY_TABLE_KEYS) {
      const table = 'tbl_' + key;
      const { results } = await env.DB.prepare(`SELECT payload, updated_at FROM ${table}`).all();
      payload[key] = results.map((r) => JSON.parse(r.payload));
      results.forEach((r) => { if (r.updated_at > maxUpdatedAt) maxUpdatedAt = r.updated_at; });
    }

    const settingsRow = await env.DB.prepare(`SELECT payload, updated_at FROM tbl_settings WHERE id = 'main'`).first();
    payload.settings = settingsRow ? JSON.parse(settingsRow.payload) : {};
    if (settingsRow && settingsRow.updated_at > maxUpdatedAt) maxUpdatedAt = settingsRow.updated_at;

    return { payload, updated_at: maxUpdatedAt || Date.now() };
  } catch (err) {
    return null;
  }
}

async function writeCloudPayload(env, payloadObj) {
  const now = Date.now();
  const statements = [];

  for (const key of ALL_ARRAY_TABLE_KEYS) {
    const table = 'tbl_' + key;
    const items = (payloadObj[key] || []).filter((it) => it && it.id);
    const currentIds = new Set(items.map((it) => it.id));

    // ⚠️ حذف أي سجل كان موجودًا سابقًا في هذا الجدول ولم يعد موجودًا في
    // القائمة الواردة (يعني حُذف فعليًا) - يحافظ هذا على تطابق الجدول تمامًا
    // مع ما يُفترض أن يحتويه، تمامًا كما كان الاستبدال الكامل للمصفوفة يفعل
    // في النظام القديم القائم على خانة واحدة
    const { results: existingRows } = await env.DB.prepare(`SELECT id FROM ${table}`).all();
    for (const row of existingRows) {
      if (!currentIds.has(row.id)) {
        statements.push(env.DB.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(row.id));
      }
    }

    for (const item of items) {
      const json = JSON.stringify(item);
      if (ALL_SINGLE_TABLE_KEYS.includes(key)) {
        statements.push(env.DB.prepare(
          `INSERT INTO ${table} (id, payload, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at`
        ).bind(item.id, json, now));
      } else {
        const cid = item.cid || null;
        statements.push(env.DB.prepare(
          `INSERT INTO ${table} (id, cid, payload, updated_at) VALUES (?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET cid = excluded.cid, payload = excluded.payload, updated_at = excluded.updated_at`
        ).bind(item.id, cid, json, now));
      }
    }
  }

  statements.push(env.DB.prepare(
    `INSERT INTO tbl_settings (id, payload, updated_at) VALUES ('main', ?, ?)
     ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at`
  ).bind(JSON.stringify(payloadObj.settings || {}), now));

  // ⚠️ D1 batch() تُنفِّذ كل الاستعلامات في جولة واحدة (أسرع بكثير من استعلام
  // منفصل لكل جدول)، لكنها ليست معاملة (transaction) ذرِّية كاملة عبر جداول
  // متعددة - مقبول هنا لأن كل جدول مستقل تمامًا عن الآخر منطقيًا
  if (statements.length > 0) await env.DB.batch(statements);

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
const SENSITIVE_ACCOUNT_FIELDS = ['passwordHash', 'passwordSalt', 'totpSecret', 'paymentApiKey'];
// المصفوفات المرتبطة بعميل واحد عبر حقل cid (غير clients/admins، اللذين
// يُصفَّيان بقاعدة مختلفة تعتمد على id مباشرة بدل cid)
const CLIENT_SCOPED_ARRAY_KEYS = ['invoices', 'expenses', 'hours', 'docs', 'messages', 'journal', 'bankTx', 'recurring', 'yearClosings', 'contracts', 'assets', 'serviceAgreements', 'importBatches', 'employees', 'contacts', 'cashPayments', 'cashierLog', 'cashierDayExceptions', 'supplierOcrProfiles', 'auditLog'];
// ⚠️ يجب أن يُعرَّفا هنا تحديدًا - بعد CLIENT_SCOPED_ARRAY_KEYS مباشرة وليس
// قبله - وإلا يقع الكود في نفس فخ "استخدام قبل التعريف" (TDZ) الذي واجهناه
// سابقًا مع كلمة async اليتيمة: أي ثابت من نوع const يُحسَب فورًا لحظة
// تحميل الملف، فلو استخدم متغيرًا لم يُعرَّف بعد نصيًا، يرمي خطأً فوريًا
// يُسقِط تشغيل الـWorker بالكامل من هذه النقطة فصاعدًا
const ALL_SINGLE_TABLE_KEYS = ['clients', 'admins']; // جداول تُطابَق بـid مباشرة (لا cid)
const ALL_ARRAY_TABLE_KEYS = [...ALL_SINGLE_TABLE_KEYS, ...CLIENT_SCOPED_ARRAY_KEYS];

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

// ⚠️⚠️ إصلاح خلل فقدان بيانات حقيقي: كانت المزامنة تستبدل مصفوفة العميل
// كاملة بما يملكه المتصفح محليًا وقت الحفظ - فلو كان لدى المتصفح نسخة قديمة
// (لم تلحق بتغيير حدث من جهاز آخر بين الجلبين)، كان الحفظ يمحو ذلك التغيير
// الآخر صامتًا بلا أي تحذير. الحل: الدمج الآن بالمعرِّف (upsert) - كل سجل
// موجود في قاعدة البيانات ولم يُرسِله المتصفح الحالي يبقى كما هو، بدل افتراض
// أن غيابه من الإرسال الحالي يعني حذفه (التطبيق أصلًا يعتمد الحذف الناعم عبر
// حقل deleted:true وليس إزالة العنصر من المصفوفة، فهذا الافتراض آمن تمامًا)
function mergeArrayByIdUpsert(existingArray, incomingArray) {
  const result = [...(existingArray || [])];
  const idxById = new Map();
  result.forEach((item, idx) => { if (item && item.id != null) idxById.set(item.id, idx); });
  (Array.isArray(incomingArray) ? incomingArray : []).forEach((incomingItem) => {
    if (!incomingItem || incomingItem.id == null) return;
    const idx = idxById.get(incomingItem.id);
    if (idx !== undefined) {
      result[idx] = incomingItem;
    } else {
      result.push(incomingItem);
      idxById.set(incomingItem.id, result.length - 1);
    }
  });
  return result;
}

// دمج آمن عند الكتابة: يستبدل فقط سجلات هذا العميل تحديدًا ضمن مصفوفة
// مرتبطة بـcid، ويُبقي كل سجلات بقية العملاء كما هي في قاعدة البيانات تمامًا.
// ⚠️ داخل نطاق هذا العميل نفسه، الدمج الآن بالمعرِّف (upsert) أيضًا بدل
// الاستبدال الكامل - لنفس سبب mergeArrayByIdUpsert أعلاه (مثلًا لو فتح
// العميل التطبيق من جهازين مختلفين في نفس الوقت تقريبًا)
function mergeClientScopedArray(existingArray, incomingArray, aid) {
  const others = (existingArray || []).filter((item) => !item || item.cid !== aid);
  const existingOwn = (existingArray || []).filter((item) => item && item.cid === aid);
  const incomingOwn = (Array.isArray(incomingArray) ? incomingArray : []).filter((item) => item && item.cid === aid);
  const mergedOwn = mergeArrayByIdUpsert(existingOwn, incomingOwn);
  return [...others, ...mergedOwn];
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
    // ⚠️ إصلاح خلل حقيقي: كانت isFirstTime دائمًا false للأدمن بلا أي تحقق
    // فعلي من وجود كلمة مرور مسبقة - ما جعل شاشة "نسيت كلمة المرور" تصل
    // بالأدمن حتى نهاية النموذج قبل أن يرفضها الخادم في اللحظة الأخيرة بخطأ
    // غامض، بدل توجيهه من البداية بوضوح
    isFirstTime: role === 'client' ? !account.pwSet : !account.passwordHash,
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
    account.passwordIterations = rec.passwordIterations;
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
  return json({ step: 'done', token, exp, mustChangePassword: !!account.mustChangePassword }, 200, cors);
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
  return json({ token, exp, mustChangePassword: !!account.mustChangePassword }, 200, cors);
}

/* ═══════════════════════ التحقق من كلمة المرور + الترقية من نص صريح ═══════════════════════ */

// ⚠️ رفع عدد تكرارات PBKDF2 من 100,000 إلى 600,000 (توصية OWASP الحالية
// لـPBKDF2-HMAC-SHA256، 2023). المشكلة: كلمات المرور الموجودة فعليًا الآن
// مُخزَّنة بهاش محسوب بـ100,000 تكرار فقط - لو غيّرنا الرقم مباشرة في دالة
// التحقق، ستفشل كل عمليات تسجيل الدخول القديمة فورًا! الحل: نُخزِّن عدد
// التكرارات المُستخدَم فعليًا مع كل سجل كلمة مرور (passwordIterations)،
// ونتحقق باستخدام نفس العدد الذي حُسب به الهاش أصلًا (افتراضيًا 100,000
// للسجلات القديمة التي لا تحمل هذا الحقل بعد). أي حساب لا يزال على العدد
// القديم يُعاد تجزئته تلقائيًا بالعدد الجديد الأعلى عند أول دخول ناجح له
// (نفس آلية "needsUpgrade" المُستخدَمة أصلًا لترقية كلمات المرور النصية
// القديمة) - ترقية تدريجية ذاتية بلا أي انقطاع خدمة لأي مستخدم.
// ⚠️⚠️ إصلاح عاجل: Cloudflare Workers نفسها تفرض حدًا أقصى صارمًا 100,000
// تكرار لـPBKDF2 على مستوى بيئة التشغيل (workerd) - أي رقم أعلى يرمي
// NotSupportedError فورًا من crypto.subtle.deriveBits، بغضّ النظر عن الخطة
// أو إعدادات CPU. رفع هذا الرقم لـ600,000 (توصية OWASP القياسية) كان يبدو
// تحسينًا أمنيًا سليمًا نظريًا، لكنه في الواقع كان يُعطِّل كل عملية تعيين/
// تغيير كلمة مرور فورًا بخطأ "Internal error" غامض - وهذا بالضبط ما حدث هنا.
// 100,000 هو الحد الأقصى الفعلي المسموح به في هذه البيئة تحديدًا.
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_LEGACY_ITERATIONS = 100000; // للسجلات القديمة السابقة لهذا التحديث

async function verifyPasswordServerSide(plainPassword, record) {
  if (record.passwordHash && record.passwordSalt) {
    const iterations = record.passwordIterations || PBKDF2_LEGACY_ITERATIONS;
    const hash = await hashPasswordPBKDF2(plainPassword, record.passwordSalt, iterations);
    // ⚠️ مقارنة آمنة زمنيًا (كتلك المُستخدَمة أصلًا للتحقق من توقيع التوكن) -
    // بدل === العادية التي قد تُنهي المقارنة عند أول حرف مختلف، فتُسرِّب معلومة
    // زمنية دقيقة (نظريًا) عن مدى تطابق التخمين مع الهاش الصحيح
    const ok = timingSafeEqual(hash, record.passwordHash);
    return { ok, needsUpgrade: ok && iterations < PBKDF2_ITERATIONS };
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
  const passwordHash = await hashPasswordPBKDF2(plainPassword, passwordSalt, PBKDF2_ITERATIONS);
  return { passwordSalt, passwordHash, passwordIterations: PBKDF2_ITERATIONS };
}
async function hashPasswordPBKDF2(password, saltHex, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(saltHex), iterations: iterations || PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMaterial, 256);
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
/* ═══════════════════════ /set-password — أُلغيت كنقطة عامة ═══════════════════════ */
// ⚠️⚠️ إصلاح ثغرة استيلاء على الحسابات (Account Takeover): كانت هذه النقطة
// عامة تمامًا - أي شخص يعرف بريد/هاتف أي حساب (أدمن أو عميل) كان يستطيع
// استدعاءها مباشرة (عبر /resolve-account العامة أولًا لمعرفة accountId، ثم
// هنا) ويُعيّن كلمة مرور من اختياره - طالما الحساب لا كلمة مرور مُسجَّلة له
// بعد (حساب جديد، أو حساب أُعيد تعيينه). هذا استيلاء تام على الحساب بلا أي
// إثبات هوية إطلاقًا. الحل: إلغاء هذا المسار العام نهائيًا - كل كلمات المرور
// الأولى/المُعاد تعيينها يجب أن تصدر عن أدمن موثَّق فقط (انظر handleAdminSetPassword
// أدناه)، الذي يتحقق من هوية صاحب الحساب بطريقته الخاصة خارج التطبيق (اتصال
// هاتفي، لقاء شخصي...) قبل تسليمه كلمة المرور.
async function handleSetPassword(request, env, cors) {
  return json({
    error: 'self_service_disabled',
    message: 'Self-service password setup has been disabled for security. Please contact your ANB administrator to receive your login credentials.',
  }, 410, cors);
}

/* ═══════════════════════ /account/set-own-password ═══════════════════════ */
// ⭐ نقطة منفصلة تمامًا عن /admin/set-password: هذه للمستخدم نفسه (أدمن أو
// عميل، بحسب هويته في التوكن الخاص به فقط - لا يُقرَأ أي معرِّف حساب من نص
// الطلب إطلاقًا) ليُعيِّن كلمة مرور جديدة خاصة به. تُستخدَم تحديدًا في شاشة
// "حدِّد كلمة مرورك" الإلزامية عند أول دخول بكلمة مرور مؤقتة.
async function handleSetOwnPassword(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { newPassword, currentPassword } = body || {};
  if (!newPassword || newPassword.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400, cors);

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);

  const list = listFor(cloud.payload, auth.payload.at);
  const idx = list.findIndex((a) => a && a.id === auth.payload.aid);
  if (idx === -1) return json({ error: 'Account not found' }, 404, cors);
  const account = list[idx];

  // ⭐ لو أُرسلت كلمة المرور الحالية (تغيير طوعي أثناء جلسة عادية)، تحقَّق
  // منها أولًا - يمنع أي شخص يستولي على جهاز مفتوح من تغيير كلمة المرور
  // بلا معرفة القديمة. لا يُطلَب هذا التحقق في تدفق "التغيير الإلزامي" بعد
  // كلمة مرور مؤقتة (لا توجد "قديمة" منطقية هناك، والمستخدم أثبت هويته للتو
  // باستخدام تلك الكلمة المؤقتة نفسها بنجاح قبل لحظات).
  if (currentPassword) {
    const verdict = await verifyPasswordServerSide(currentPassword, account);
    if (!verdict.ok) return json({ error: 'Current password is incorrect' }, 401, cors);
  }

  const rec = await makePasswordRecord(newPassword);
  account.passwordSalt = rec.passwordSalt;
  account.passwordHash = rec.passwordHash;
  account.passwordIterations = rec.passwordIterations;
  delete account.password; delete account.pwCustom; delete account.pw;
  if (auth.payload.at === 'client') account.pwSet = true;
  account.mustChangePassword = false; // ⚠️ هذا هو ما يُنهي فرض شاشة التغيير الإلزامية
  clearFailedAttempts(account);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);

  return json({ ok: true }, 200, cors);
}
// محمية بتوكن أدمن حقيقي - النقطة الوحيدة الآن القادرة على تعيين/إعادة تعيين
// كلمة مرور أي حساب (أدمن أو عميل). تحلّ محل كل من: النقطة العامة الملغاة
// أعلاه، وآلية "Reset" في شاشة الإعدادات التي كانت تعتمد خطأً على مزامنة
// عادية (/sync) لا تنجح فعليًا لأن الخادم يحمي حقول كلمة المرور من الكتابة
// فوقها عبر ذلك المسار تحديدًا (لمنع عميل خبيث من حقن هاش كلمة مرور مزوَّر) -
// هذه النقطة المخصَّصة هي الاستثناء الوحيد المشروع لتلك الحماية.
async function handleAdminSetPassword(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== 'admin') return json({ error: 'Admin access required' }, 403, cors);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, cors); }
  const { targetRole, targetAccountId, newPassword } = body || {};
  if (!targetRole || !targetAccountId) return json({ error: 'targetRole and targetAccountId are required' }, 400, cors);
  if (targetRole !== 'admin' && targetRole !== 'client') return json({ error: 'targetRole must be "admin" or "client"' }, 400, cors);
  if (newPassword && newPassword.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400, cors);

  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: 'Could not reach database' }, 502, cors);

  const list = listFor(cloud.payload, targetRole);
  const idx = list.findIndex((a) => a && a.id === targetAccountId);
  if (idx === -1) return json({ error: 'Account not found' }, 404, cors);
  const account = list[idx];

  // ⚠️ لا يمكن لأي أدمن إعادة تعيين كلمة مرور Super Admin *غيره* عبر هذه
  // الواجهة - يحمي من أن يُسقِط أدمن عادي مُخترَق صلاحيات الحساب الأعلى.
  // لكن يبقى مسموحًا دائمًا للمستخدم تغيير كلمة مروره الخاصة هو (بصرف
  // النظر عن دوره)، وإلا لن يستطيع الـsuper_admin نفسه تغيير كلمة مروره أبدًا
  const isSelf = targetRole === 'admin' && targetAccountId === auth.payload.aid;
  if (!isSelf && targetRole === 'admin' && account.role === 'super_admin') {
    return json({ error: 'Cannot reset a Super Admin password this way' }, 403, cors);
  }

  const finalPassword = newPassword || generateTempPassword();
  const rec = await makePasswordRecord(finalPassword);
  account.passwordSalt = rec.passwordSalt;
  account.passwordHash = rec.passwordHash;
  account.passwordIterations = rec.passwordIterations;
  delete account.password; delete account.pwCustom; delete account.pw;
  if (targetRole === 'client') account.pwSet = true;
  // ⭐ كلمة مرور مؤقتة مُولَّدة عشوائيًا (وليست كلمة مرور مُحدَّدة يدويًا من
  // الأدمن) تعني أن الحساب يجب أن يُجبَر على تعيين كلمة مرور خاصة به في أول
  // تسجيل دخول - يُفحَص هذا العلم عند تسجيل الدخول (handleLogin) لعرض شاشة
  // "حدِّد كلمة مرورك" الإلزامية قبل السماح بالدخول للتطبيق
  account.mustChangePassword = !newPassword;
  clearFailedAttempts(account);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);

  return json({ ok: true, tempPassword: newPassword ? undefined : finalPassword }, 200, cors);
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
  account.passwordIterations = rec.passwordIterations;
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
        // ⚠️ الأدمن هنا أيضًا قد يرسل نسخة لا تحوي حسابًا أضافه أدمن آخر للتو -
        // احتفظ بأي حساب موجود في القاعدة ولم يُذكَر إطلاقًا في الوارد
        const incomingIds = new Set((incomingPayload[key] || []).map((a) => a && a.id));
        existingList.forEach((existingAccount) => {
          if (existingAccount && !incomingIds.has(existingAccount.id)) merged[key].push(existingAccount);
        });
      } else if (APPEND_ONLY_ARRAY_KEYS.includes(key)) {
        merged[key] = mergeAppendOnlyArray(existingPayload[key], incomingPayload[key], null);
      } else if (key === 'settings') {
        merged[key] = incomingPayload[key]; // كائن مفرد (وليس مصفوفة) - لا معنى لدمج بالمعرِّف هنا
      } else {
        // ⚠️⚠️ إصلاح خلل فقدان بيانات: كان هذا يستبدل المصفوفة كاملة بما لدى
        // متصفح هذا الأدمن محليًا - فلو كانت لديه نسخة أقدم من تعديل حدث من
        // جهاز/أدمن آخر بين آخر جلب وهذا الحفظ، كان يُمحى صامتًا بلا تحذير.
        // الآن: دمج بالمعرِّف (upsert) بدل الاستبدال الكامل.
        merged[key] = mergeArrayByIdUpsert(existingPayload[key], incomingPayload[key]);
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
