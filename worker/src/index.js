// src/index.js
var TOKEN_TTL_MS = 4 * 60 * 60 * 1e3;
var LOGIN_MAX_ATTEMPTS = 5;
var LOGIN_LOCKOUT_MS = 15 * 60 * 1e3;
var MAX_ATTEMPTS_WINDOW_MS = 60 * 1e3;
var MAX_ATTEMPTS_PER_WINDOW = 8;
var TOTP_STEP_SECONDS = 30;
var TOTP_DIGITS = 6;
var BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
var attemptLog = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = corsHeaders(env);
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    try {
      if (url.pathname === "/resolve-account" && request.method === "POST") return await handleResolveAccount(request, env, cors);
      if (url.pathname === "/login" && request.method === "POST") return await handleLogin(request, env, cors);
      if (url.pathname === "/verify-2fa" && request.method === "POST") return await handleVerify2FA(request, env, cors);
      if (url.pathname === "/set-password" && request.method === "POST") return await handleSetPassword(request, env, cors);
      if (url.pathname === "/admin/set-password" && request.method === "POST") return await handleAdminSetPassword(request, env, cors);
      if (url.pathname === "/account/set-own-password" && request.method === "POST") return await handleSetOwnPassword(request, env, cors);
      if (url.pathname === "/admin/generate-temp-password" && request.method === "POST") return await handleGenerateTempPassword(request, env, cors);
      if (url.pathname === "/refresh-token" && request.method === "POST") return await handleRefreshToken(request, env, cors);
      if (url.pathname === "/sync" && request.method === "GET") return await handleSyncGet(request, env, cors);
      if (url.pathname === "/sync" && request.method === "POST") return await handleSyncPost(request, env, cors);
      if (url.pathname === "/upload" && request.method === "POST") return await handleUpload(request, env, cors);
      if (url.pathname.startsWith("/file/") && request.method === "GET") return await handleGetFile(request, env, cors, url);
      if (url.pathname.startsWith("/file/") && request.method === "DELETE") return await handleDeleteFile(request, env, cors, url);
      if (url.pathname === "/ocr-vision" && request.method === "POST") return await handleOcrVision(request, env, cors);
      if (url.pathname === "/admin/backup-now" && request.method === "POST") return await handleBackupNow(request, env, cors);
      if (url.pathname === "/admin/backups" && request.method === "GET") return await handleListBackups(request, env, cors);
      if (url.pathname === "/admin/restore-backup" && request.method === "POST") return await handleRestoreBackup(request, env, cors);
      if (url.pathname === "/payment/save-provider" && request.method === "POST") return await handleSavePaymentProvider(request, env, cors);
      if (url.pathname === "/payment/provider-status" && request.method === "GET") return await handlePaymentProviderStatus(request, env, cors);
      if (url.pathname === "/payment/create" && request.method === "POST") return await handleCreatePayment(request, env, cors);
      if (url.pathname === "/payment/status" && request.method === "GET") return await handlePaymentStatus(request, env, cors, url);
      if (url.pathname === "/admin/assistant" && request.method === "POST") return await handleAdminAssistant(request, env, cors);
      if (url.pathname === "/push/vapid-public-key" && request.method === "GET") return await handlePushVapidKey(request, env, cors);
      if (url.pathname === "/push/subscribe" && request.method === "POST") return await handlePushSubscribe(request, env, cors);
      if (url.pathname === "/push/unsubscribe" && request.method === "POST") return await handlePushUnsubscribe(request, env, cors);
      if (url.pathname === "/agreement/by-token" && request.method === "GET") return await handleAgreementByToken(request, env, cors, url);
      if (url.pathname === "/agreement/sign-by-token" && request.method === "POST") return await handleAgreementSignByToken(request, env, cors);
      if (url.pathname === "/agreement/send-signing-link" && request.method === "POST") return await handleSendSigningLink(request, env, cors);
      return json({ error: "Not found" }, 404, cors);
    } catch (err) {
      return json({ error: "Internal error", detail: String(err && err.message || err) }, 500, cors);
    }
  },
  async scheduled(event, env, ctx) {
    if (event.cron === "0 0 * * *") {
      ctx.waitUntil(remindStaleCashierDaysServer(env));
    } else if (event.cron === "0 7 * * *") {
      ctx.waitUntil(sendDailyReminderPushes(env));
    } else if (event.cron === "0 11 1 * *") {
      ctx.waitUntil(sendMonthlyDocumentReminders(env));
    } else {
      ctx.waitUntil(performBackup(env, "scheduled"));
    }
  }
};

async function remindStaleCashierDaysServer(env) {
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return;
  const payload = cloud.payload;
  const today = (new Date()).toISOString().slice(0, 10);
  const cashierLog = payload.cashierLog || [];
  const staleCidsWithDates = new Map();
  cashierLog.forEach((e) => {
    if (!e.posted && e.date && e.date < today) {
      const existing = staleCidsWithDates.get(e.cid);
      if (!existing || e.date < existing) staleCidsWithDates.set(e.cid, e.date);
    }
  });
  if (staleCidsWithDates.size === 0) return;
  for (const [cid, earliestDate] of staleCidsWithDates.entries()) {
    await sendPushToAccount(env, "client", cid, {
      title: "ANB — يوم كاشير بانتظار الإغلاق",
      body: `لديك مقبوضات كاشير غير مُرحَّلة منذ ${earliestDate} — افتح التطبيق وجرد الكاش لإغلاق ذلك اليوم.`
    });
  }
}

var BACKUP_RETENTION_COUNT = 60;
async function performBackup(env, trigger) {
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return { ok: false, error: "Could not read database" };
  const timestamp = (new Date()).toISOString().replace(/[:.]/g, "-");
  const key = `backup-${timestamp}${trigger === "manual" ? "-manual" : ""}.json`;
  const body = JSON.stringify({ backedUpAt: (new Date()).toISOString(), trigger: trigger || "scheduled", payload: cloud.payload });
  await env.BACKUPS.put(key, body, { httpMetadata: { contentType: "application/json" } });
  const listed = await env.BACKUPS.list();
  const sorted = listed.objects.map((o) => o.key).sort().reverse();
  const toDelete = sorted.slice(BACKUP_RETENTION_COUNT);
  for (const oldKey of toDelete) {
    await env.BACKUPS.delete(oldKey);
  }
  return { ok: true, key, deletedOldBackups: toDelete.length };
}

var SUPPORTED_PAYMENT_PROVIDERS = {
  mollie: { name: "Mollie", live: true },
  stripe: { name: "Stripe", live: false },
  sumup: { name: "SumUp", live: true }
};
async function handleSavePaymentProvider(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { cid, provider, apiKey, merchantCode } = body || {};
  if (!cid || !provider) return json({ error: "cid and provider are required" }, 400, cors);
  if (!SUPPORTED_PAYMENT_PROVIDERS[provider]) return json({ error: "Unsupported provider" }, 400, cors);
  if (auth.payload.at === "client" && auth.payload.aid !== cid) {
    return json({ error: "Clients can only configure their own account" }, 403, cors);
  }
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const clients = cloud.payload.clients || [];
  const idx = clients.findIndex((c) => c && c.id === cid);
  if (idx === -1) return json({ error: "Client not found" }, 404, cors);
  clients[idx].paymentProvider = provider;
  if (apiKey) clients[idx].paymentApiKey = apiKey;
  if (merchantCode !== void 0) clients[idx].paymentMerchantCode = merchantCode;
  await writeCloudPayload(env, cloud.payload);
  return json({ ok: true }, 200, cors);
}
async function handlePaymentProviderStatus(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const reqUrl = new URL(request.url);
  const cid = reqUrl.searchParams.get("cid");
  if (!cid) return json({ error: "cid is required" }, 400, cors);
  if (auth.payload.at === "client" && auth.payload.aid !== cid) {
    return json({ error: "Clients can only view their own configuration" }, 403, cors);
  }
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const client = (cloud.payload.clients || []).find((c) => c && c.id === cid);
  if (!client) return json({ error: "Client not found" }, 404, cors);
  return json({
    provider: client.paymentProvider || null,
    configured: !!(client.paymentProvider && client.paymentApiKey)
  }, 200, cors);
}
async function handleCreatePayment(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { cid, amount, description } = body || {};
  if (!cid || !amount) return json({ error: "cid and amount are required" }, 400, cors);
  if (auth.payload.at === "client" && auth.payload.aid !== cid) {
    return json({ error: "Clients can only create payments for their own account" }, 403, cors);
  }
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const client = (cloud.payload.clients || []).find((c) => c && c.id === cid);
  if (!client || !client.paymentProvider || !client.paymentApiKey) {
    return json({ error: "no_provider_configured", message: "No payment provider configured for this account yet." }, 400, cors);
  }
  const originHeader = request.headers.get("Origin") || env.ALLOWED_ORIGIN || "https://anb-1cw.pages.dev";
  if (client.paymentProvider === "mollie") {
    try {
      const res = await fetch("https://api.mollie.com/v2/payments", {
        method: "POST",
        headers: { "Authorization": "Bearer " + client.paymentApiKey, "Content-Type": "application/json" },
        body: JSON.stringify({
          amount: { currency: "EUR", value: Number(amount).toFixed(2) },
          description: description || "Payment",
          redirectUrl: originHeader,
          method: "ideal,creditcard,bancontact,applepay"
        })
      });
      const data = await res.json();
      if (!res.ok) return json({ error: "provider_error", message: data.detail || "Payment provider rejected the request" }, 502, cors);
      return json({ paymentId: data.id, checkoutUrl: data._links && data._links.checkout && data._links.checkout.href }, 200, cors);
    } catch (err) {
      return json({ error: "provider_error", message: String(err && err.message || err) }, 502, cors);
    }
  }
  if (client.paymentProvider === "sumup") {
    if (!client.paymentMerchantCode) {
      return json({ error: "no_provider_configured", message: "SumUp requires a Merchant Code in addition to the API key — please add it in the client's payment settings." }, 400, cors);
    }
    try {
      const checkoutRef = "anb-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8);
      const res = await fetch("https://api.sumup.com/v0.1/checkouts", {
        method: "POST",
        headers: { "Authorization": "Bearer " + client.paymentApiKey, "Content-Type": "application/json" },
        body: JSON.stringify({
          checkout_reference: checkoutRef,
          amount: Number(amount),
          currency: "EUR",
          merchant_code: client.paymentMerchantCode,
          description: description || "Payment",
          redirect_url: originHeader,
          hosted_checkout: { enabled: true }
        })
      });
      const data = await res.json();
      if (!res.ok) return json({ error: "provider_error", message: data && (data.message || data.error_message) || "Payment provider rejected the request" }, 502, cors);
      return json({ paymentId: data.id, checkoutUrl: data.hosted_checkout_url }, 200, cors);
    } catch (err) {
      return json({ error: "provider_error", message: String(err && err.message || err) }, 502, cors);
    }
  }
  return json({ error: "provider_not_implemented", message: `${SUPPORTED_PAYMENT_PROVIDERS[client.paymentProvider]?.name || client.paymentProvider} support is coming soon — Mollie and SumUp are fully supported now.` }, 501, cors);
}
async function handlePaymentStatus(request, env, cors, url) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const cid = url.searchParams.get("cid");
  const paymentId = url.searchParams.get("paymentId");
  if (!cid || !paymentId) return json({ error: "cid and paymentId are required" }, 400, cors);
  if (auth.payload.at === "client" && auth.payload.aid !== cid) {
    return json({ error: "Clients can only check their own payments" }, 403, cors);
  }
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const client = (cloud.payload.clients || []).find((c) => c && c.id === cid);
  if (!client || !client.paymentApiKey) return json({ error: "no_provider_configured" }, 400, cors);
  if (client.paymentProvider === "mollie") {
    try {
      const res = await fetch("https://api.mollie.com/v2/payments/" + paymentId, {
        headers: { "Authorization": "Bearer " + client.paymentApiKey }
      });
      const data = await res.json();
      if (!res.ok) return json({ error: "provider_error" }, 502, cors);
      return json({ status: data.status }, 200, cors);
    } catch (err) {
      return json({ error: "provider_error", message: String(err && err.message || err) }, 502, cors);
    }
  }
  if (client.paymentProvider === "sumup") {
    try {
      const res = await fetch("https://api.sumup.com/v0.1/checkouts/" + paymentId, {
        headers: { "Authorization": "Bearer " + client.paymentApiKey }
      });
      const data = await res.json();
      if (!res.ok) return json({ error: "provider_error" }, 502, cors);
      const statusMap = { PAID: "paid", FAILED: "failed", EXPIRED: "expired", PENDING: "open" };
      return json({ status: statusMap[data.status] || "open" }, 200, cors);
    } catch (err) {
      return json({ error: "provider_error", message: String(err && err.message || err) }, 502, cors);
    }
  }
  return json({ error: "provider_not_implemented" }, 501, cors);
}

var ADMIN_ASSISTANT_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
var ANB_APP_REFERENCE = `ANB FinAdmin Pro — comprehensive reference of how the app actually works (verified against its source code), organized by section. Use this to give specific, accurate guidance about where and how to record things — never invent screens, buttons, fields, or numbers not listed here.

INVOICES (per client):
- BTW/VAT types on each invoice: "normal" (standard rate applied), "verlegd_nl" (domestic reverse charge, must state "BTW verlegd — art. 12 lid 3 Wet OB 1968", goes in rubriek 1e, no VAT charged), "eu_b2b" (EU business customer reverse charge, must state "BTW verlegd" + customer's valid EU VAT number, rubriek 3b), "export" (outside EU, outside scope of Dutch VAT, rubriek 3a).
- Status tracked as paid/unpaid; can be settled by cash payment (see Cash Ledger) or matched against a bank transaction.
- Recurring invoice schedules can be set up and stopped (already-generated invoices are kept when stopped).
- Invoice numbers are sequential per client and never reused, even after deletion — the counter only ever moves forward. Saving a duplicate/manually-typed number that collides with another invoice for the same client is blocked.
- CREDIT NOTES (Creditnota): any invoice can have a credit note issued against it ("↩ Issue Credit Note" button) instead of editing or deleting it — the correct legal way to correct an already-issued Dutch invoice. A credit note references the original invoice's number, is capped at the invoice's remaining creditable amount (accounting for any prior partial credit notes), automatically copies the original's BTW rate/type so it nets out correctly in the BTW report, and is clearly labeled "↩ Credit Note" in the invoice list (with a link back to the original). The original invoice itself is never modified. Credit note PDFs are titled "CREDITNOTA" and reference the original invoice number instead of a due date.
- PROOF OF RETURN: issuing a credit note requires the date of the original transaction (mandatory) and, separately, at least one of a note or an attached photo/document as evidence (one of the two is mandatory, not both) — an optional free-text reference to the original transaction can also be added. This applies the same way to expense credit notes received (below).

EXPENSES (per client):
- Has a category and supplier. Reverse-charge purchases received (domestic or foreign supplier) are their own BTW type: "verlegd_received" — no VAT was actually paid to the supplier; the rate is used only to self-assess VAT for the return (net effect €0 on the return, appears in reverse-charge-received rubrieken 2a/4b).
- Categories include a dedicated "Representatie/Relaties" (representation/entertainment/gifts) category. Selecting it shows a warning that BTW on these costs is generally not deductible (art. 16 BUA) and income/corporate tax deductibility is limited (a threshold or a flat 80% election) — the app automatically excludes this expense's BTW from the reclaimable VAT total in the BTW report (both when creating and when editing an expense).
- CREDIT NOTES RECEIVED: if a supplier issues a credit note against an already-recorded expense (e.g. returned goods, a pricing correction), use "↩ Log Credit Note Received" on that expense instead of editing/deleting it — creates a separate negative record referencing the original expense, copying its BTW type/rate automatically so it nets out correctly in the BTW report, without touching the original. Same proof-of-return requirement as invoice credit notes (see above): original transaction date is mandatory, plus a note or an attached photo/document (at least one of the two).
- Receipts can be photographed and read automatically via OCR (Google Cloud Vision). The system "learns" per-supplier typical VAT rate and amount over time (Settings → Manage Learned Suppliers) and flags amounts that deviate significantly from what's usually paid to that supplier, asking for manual verification.
- OCR confidence is shown per field (color-coded); low-quality scans are flagged for careful manual review.
- Recurring expense schedules (e.g. rent, fixed monthly subscriptions) can be set up when adding a new manual expense (checkbox + monthly/quarterly/yearly frequency) and stopped later; already-generated expenses are kept when a schedule is stopped. Shown in a "Recurring expense schedules" table on the client's Expenses screen (admin-only), same pattern as recurring invoices.

HOURS:
- Timer-based logging (start/pause/stop & log) with a task description, or manual entry with a start time and an optional end time (hours auto-calculate from the time range, still editable/overridable afterward).
- Categories are customizable per client (Settings → Manage Categories) to match their actual work (photography, consulting, construction, etc.)
- Tracks progress toward the Dutch "urencriterium" — 1,225 hours/year required for the self-employed deduction (Zelfstandigenaftrek), and separately the 525-hour "Meewerkaftrek" threshold for an unpaid helping partner (used for ANB's own internal hour tracking between its owner and helping partner).
- Every hour entry creation, edit, and deletion is recorded in the audit log, and is protected by the same closed-period lock as invoices/expenses — editing/deleting an hour entry dated within an already-closed accounting period requires an explicit admin override (clients are blocked outright). This matters because the hour log is the direct evidentiary record for urencriterium/Meewerkaftrek tax claims.
- A soft plausibility check warns (without blocking) if logging an entry would bring one person's total for a single day above 16 hours.
- Hours Register is a standalone optional add-on billed at a flat €10/month — available on any subscription package, not tied to a specific one (see CONTRACTS & PRICING below). If not added at all for a client, neither the floating timer widget nor the "Unbilled Hours" dashboard indicator appears for them.

CASH LEDGER (distinct from Cashier — for businesses that occasionally get paid in cash, not walk-in service businesses):
- Record Cash Payment: settles a specific existing invoice partially or fully in cash; invoice only shows "Paid" once fully covered.
- Daily Revenue Entry: for businesses with many small daily payments (retail counters) — one total takings figure per day (excl. BTW) instead of itemizing every sale, ready to match against the bank. This is ONLY available/shown when Cashier is NOT enabled for that client — if Cashier is enabled, this button is hidden and blocked (with an explanatory message if somehow triggered anyway), because daily income is already posted from the Cashier itself; having both active at once would double-count the same day's revenue.
- Cash Withdrawal / Cash Deposit: recording money moved between the bank and the physical cash till.
- Personal Drawing: money taken from the till for personal (non-business) use — affects the owner's capital account, NOT the profit & loss statement, and is NOT a business expense.
- A warning appears if a cash entry is backdated by more than 1 day, since the Belastingdienst expects daily logging of cash takings.
- Cash amounts that came from a Cashier day posting are labeled clearly (e.g. "🧾 Cashier — 18/07/2026 (invoice number)") in the Cash Ledger list, not just a bare invoice number, so the connection between the two features is visible at a glance.
- If a client has Cashier enabled, the Cash Ledger screen is hidden entirely for them (they use the Cashier's own Personal Drawing button instead — see below) to avoid the two features overlapping.

CASHIER (separate feature, for walk-in/service businesses — driving instructors, hairdressers, barbers, etc.):
- Admin (or the client themselves) configures quick-tap "Services" with a name, a color (chosen from a preset palette, shown as a left accent stripe and tinted card background — not an emoji), and price (which can be marked editable at time of use, e.g. for a custom amount).
- Payment methods per transaction: cash (fully paid now), bank transfer (pending, matched later), split (part cash / part pending bank), or card/QR (only shown if the client has connected their own Mollie or SumUp account — see Electronic Payment below).
- "Post Today" performs the daily reconciliation: requires counting the actual physical cash on hand first (compared against everything currently unposted regardless of which date it was logged under, since that cash is still physically in the drawer either way; flags a discrepancy — beyond a small €5 tolerance — without revealing which direction it's off, to prevent "solving for" the expected number instead of counting for real), then creates one invoice for the day's takings and locks the entries. Can only be done once per day.
- STALE/FORGOTTEN DAYS: if a previous day's Cashier entries were never manually posted, the client is blocked from doing anything new in the Cashier the next time they open it — they must first go through the same mandatory cash-count gate for that specific stale day before continuing. There is NO automatic silent posting of forgotten days — a real physical cash count is always required before a day is posted, no matter how old. As a courtesy, a once-daily scheduled server job also sends a push notification to the client if a stale unposted day exists, reminding them to open the app and close it out — this reminder never posts anything itself, it only nudges the client to do the count.
- If a day has zero entries when trying to post manually (a genuinely empty day, as opposed to a stale unposted one), the client must explain why first (no activity that day, or a genuine recording error) — a "missing day exception" that requires ANB admin approval before the client can continue using the Cashier.
- LOG RETURN: a dedicated "↩ Log Return" button records a refund as a negative entry, always dated today (since the cash physically leaves the till today regardless of when the original sale happened) — automatically flows into today's unposted total and the next cash count. Requires the date of the original transaction (mandatory), an optional reference to it, and a note or attached photo/document as evidence (at least one of the two).
- PERSONAL DRAWING: also available directly from the Cashier screen itself (same "🏠 Personal Drawing" button and behavior as the Cash Ledger's) — no need to switch screens for this.
- Cashier Log (admin-only screen): full history of all cashier transactions with a reprint button per entry.
- Receipt printing: after any cashier sale, the app offers to print a physical receipt via the browser's native print dialog (works with AirPrint on iOS or any connected printer on Android) — this is not a direct Bluetooth connection, it uses standard printing so it works across devices without special hardware pairing.
- Cashier is a standalone optional add-on billed at a flat €20/month — available on any subscription package, not tied to a specific one (see CONTRACTS & PRICING below).

LIVE CASH BALANCE: the admin sees a real-time cash balance card directly under the client info card whenever viewing a client that has Cash Ledger or Cashier enabled (hidden entirely otherwise, and never shown for ANB's own account) — no button or click needed, it's always visible and always current. Shows the same "expected cash balance" figure the client will be asked to count against during their next Cashier day-close, so admin and client are always looking at the same number.

ELECTRONIC PAYMENT (Cashier add-on):
- Either the admin or the client themselves can connect the CLIENT's OWN payment provider account (their money goes directly to them, never through ANB): Mollie (live) or SumUp (live, additionally requires a "Merchant Code" alongside the API key) — Stripe is not yet implemented.
- Generates a real payment request with the provider, shown to the customer as a QR code; the app polls for payment confirmation and auto-logs the Cashier entry once paid.

BANK:
- Bank statement transactions can be imported from six banks (ING, ABN AMRO, Rabobank, Bunq, Knab, Revolut) in CSV or Excel format, plus MT940 and CAMT.053 (XML) from any bank — format and bank are auto-detected from the file itself, with a manual override dropdown available if auto-detection ever gets it wrong. A preview screen shows exactly what will be imported (with duplicates and invalid rows flagged) before anything is committed — nothing is saved silently.
- Reconciliation against invoices/expenses happens via suggested matches, manual search, or marking "no match needed" (internal transfers, bank fees). Auto-matching first requires an exact amount match; when more than one candidate shares that same amount (common with recurring invoices/expenses), it then tries to disambiguate using the counterparty name found in the transaction, and failing that, the oldest outstanding item (FIFO) — only if that's unambiguous. Anything still ambiguous after that is left for manual review, never guessed.
- Duplicate detection on import is layered by priority: an end-to-end payment reference (from MT940/CAMT.053 SEPA data) first, then a bank-provided reference/transaction ID, and only as a last resort a fingerprint of date + amount + description — so the same transaction is never imported twice even across different file formats for the same underlying bank account.
- MULTIPLE BANK ACCOUNTS PER CLIENT: any IBAN found in an imported file is automatically registered as a named account for that client the first time it appears (default label from the last 4 digits of the IBAN, renameable anytime via "⚙️ Manage Accounts" on the Bank screen). The Bank screen has an account filter (All accounts / a specific one / "Unassigned" for older imports before this existed) that also filters the summary totals, not just the transaction list.
- A bank transaction can also be typed in manually for cases not covered by an import. Manual entries are clearly labeled "✍ Manual" in the transaction list (distinct from real imported bank data) and logged in the audit trail, since — unlike an imported statement — they aren't independently verified against the actual bank.
- Individual imported transactions cannot be edited or deleted (only an entire import batch can be reversed) — this preserves the integrity of the bank statement as a source of truth.

ASSETS (Vaste Activa — any purchased asset, not just vehicles):
- Categories include Equipment, Furniture, Vehicle, Goodwill, and others.
- Any asset costing under €450 (excl. BTW) must be expensed immediately as a regular expense, NOT capitalized/depreciated as an asset (Dutch tax rule) — the app flags this and suggests using "Add Expense" instead.
- Dutch tax law's minimum useful life for depreciation: 5 years for ordinary assets, 10 years for Goodwill. The app auto-adjusts a shorter entered life up to this legal minimum.
- Depreciation is straight-line: (acquisition cost − residual value) ÷ useful life years. A "Generate Depreciation" button creates the year's journal entries per client (skips ones already created).
- KIA (Kleinschaligheidsinvesteringsaftrek / Small-Scale Investment Deduction) is flagged as potentially applicable when total investment for the period falls within the current range (app shows a hint; exact percentage must be checked against the current official Belastingdienst table).
- LOAN FINANCING (applies to ANY asset type, not just vehicles): mark an asset as financed by a loan with a remaining balance and annual interest rate. Logging a payment (one total amount entered) automatically splits it into interest (tax-deductible, posted as an actual journal entry) and principal (reduces the loan balance only, never expensed) using standard amortization: interest = remaining balance × annual rate ÷ 12.
- VEHICLE-specific fields (only for category = Vehicle): a private-use percentage, and a mileage-log note. Private use above a de-minimis threshold typically triggers "Bijtelling" (added taxable income) under Dutch rules — the app flags this but does NOT calculate the exact amount (needs confirmation from a tax advisor); a detailed mileage log can support a claim of under 500 km/year private use.
- "Loan Overview" report (under Reports, not the Assets screen itself) aggregates every financed asset for a client: total outstanding balance, interest paid this year and all-time, a progress bar per loan, and full payment history.
- DISPOSAL: any depreciable asset can be marked as disposed (sold or written off) via a "Dispose / Sell Asset" action — records the disposal date and sale proceeds, calculates the taxable gain or deductible loss automatically (proceeds vs. book value at that date), and posts a journal entry for it. The asset's full depreciation history is kept (never deleted); depreciation simply stops accumulating past the disposal date.

EMPLOYEES / PAYROLL:
- Salary types: Fixed Monthly or Variable Hourly.
- Benefits: Vacation money (Vakantiegeld, 8% of gross annual salary, typically paid out once in May, or accrued monthly and shown as a running liability until then), 13th month bonus (accrues 1/12 of gross monthly, paid as a lump sum in December, same accrual principle as vacation money), homework allowance (tax-free up to the official rate, based on homework days per month), travel allowance (tax-free per-km rate or fixed monthly amount), pension percentage.
- Payroll tax (Loonheffing) is estimated using official tax brackets — the app explicitly disclaims this needs verification before official use.
- Payslips can be generated (status: CONCEPT while the month hasn't ended yet, then CONFIRMED) and exported as PDF, alongside a payslip history per employee. Generating a payslip automatically posts a matching payroll-cost journal entry (gross pay plus vacation money and 13th-month amounts accrued that month, plus allowances) so payroll actually reduces taxable profit in the P&L and Tax Liability reports — it no longer sits isolated from the rest of the accounting.
- Contract types: Permanent (Onbepaalde tijd) or Fixed-term (Bepaalde tijd) — fixed-term contracts ending within 90 days are flagged in the Employee Statistics report.
- LEGAL COMPLIANCE BUILT INTO THE EMPLOYEE SCREENS (all verified against 2026 Dutch labor law figures):
  - Minimum wage check: compares the employee's effective hourly rate (converted from a monthly salary if needed) against the current statutory minimum by age, warning at save time if it's below the legal minimum.
  - Probation period (proeftijd): the maximum allowed is calculated live from the contract's actual length — none allowed for a fixed-term contract of 6 months or less (the whole clause is void if used), max 1 month for 6 months–2 years, max 2 months for 2+ years or permanent contracts. Saving an illegal combination is blocked, not just warned.
  - Employer notice period (opzegtermijn): automatically calculated from actual tenure per m. 7:672 BW (1/2/3/4 months at 0/5/10/15 years) and shown as read-only, recalculating as tenure grows.
  - Ketenregeling (chain rule): tracks the count of consecutive fixed-term contracts and total months for each employee; warns as the 3-contract/3-year legal limit approaches, and blocks issuing a further "extension" once exceeded (only "convert to indefinite term" remains available, since by law the employee is already permanent past that point).
  - Transitievergoeding (transition payment): estimated automatically (1/3 gross monthly salary per full year of service, due from day one for an employer-initiated termination) and shown both on the employee's detail screen (running estimate) and in the End Employment dialog, which also asks for the reason (employer-initiated / mutual consent / employee resignation / serious misconduct) since the payment isn't due in every case.
  - Aanzegplicht (notification obligation): an active reminder fires when a fixed-term contract of 6+ months is within 30 days of its end date, since Dutch law requires written notice of renewal intent by then (or a one-month-salary penalty applies).
  - Vacation days and sick leave: each employee has a vacation-day entitlement (defaulting to the legal minimum of 4× weekly work days) with a log of days taken and a running remaining balance, and a separate sick-leave log per period with a reminder of the employer's minimum 70%-continued-pay obligation (up to 2 years) per period logged.
- Reports: "Employee Financial Report" (payroll costs & payments, YTD gross/loonheffing/pension, outstanding accrued liabilities, per-employee breakdown) and "Employee Statistics Report" (headcount, average cost/tenure, contract-type/salary-type/job-title/nationality breakdowns, upcoming fixed-term contract endings). There's also a general "Payroll Report".
- EMPLOYEE/PAYROLL PRICING: managed and quoted separately from the standard subscription packages — priced per tier by headcount (up to 2 / up to 3 / up to 7 employees, each with a Manual price and an Admin add-on, applied to employees and payroll together). More than 7 employees is treated as a genuine change in the nature of the work and is deliberately NOT auto-priced — it requires a custom quote set manually on the contract, since managing that many employees is a materially bigger undertaking than the standard tiers.

CONTRACTS & PRICING (ZZP Compleet / +Advies — flat pricing, no volume limits):
- Every client contract selects one of two flat packages: "ZZP Compleet" (€85/month) or "ZZP Compleet + Advies" (€115/month — adds monthly financial reporting instead of quarterly, plus a quarterly 30-minute personal tax advisory session held before each BTW filing, timed so tax-saving suggestions can still affect that quarter's return). Both packages include, with NO monthly volume limit or usage cap of any kind: unlimited client-issued invoices, unlimited expense uploads/scans, unlimited bank transaction reconciliation, quarterly BTW filing, and the annual business income tax return, all ANB-managed. This deliberately mirrors how Dutch accountants' own preferred software (e.g. SnelStart) works, rather than the artificial per-transaction caps some competing bookkeeping SaaS products use.
- There is no "Manual vs Admin" data-entry mode anymore (this was removed) — ANB staff always handles the client's bookkeeping data entry as standard practice; the client is only ever responsible for issuing their own invoices and uploading/scanning their own expense receipts.
- VOF / MAATSCHAP PARTNERSHIP SURCHARGE: the "VOF Partnership" field on a contract only appears when that client's legal form (Client Type) is set to "VOF" or "Maatschap" — for any other legal form (Eenmanszaak, BV, etc.) it stays hidden. When shown, it asks for the total number of partners and adds €15/month for each partner beyond the first, because — unlike BTW, which is filed once for the whole partnership — every partner needs their own separate annual income tax (IB) filing.
- HOURS REGISTER and CASHIER are both fully independent, optional add-ons available on ANY package (not tied to a specific one), each now a single flat monthly price rather than tiered — see the HOURS and CASHIER sections above for their current prices.
- EMPLOYEE/PAYROLL PRICING: managed separately from the subscription package and quoted as one flat price per headcount tier, covering employees and payroll together: up to 2 employees €30/month, up to 3 employees €55/month, up to 7 employees €130/month. More than 7 employees is deliberately not auto-priced and requires a custom monthly quote set manually on the contract.
- AGREED OVERAGE FEE (optional, always manual, never automatic): a contract can optionally have an agreed overage term configured (a percentage of the base plan, or a fixed € amount) — but simply having this configured does not itself charge anything. There is no automatic usage-based billing of any kind on this app anymore — no counting of invoices/expenses/bank transactions against any threshold, no tolerance percentage, nothing fires on its own. If a specific client's real usage becomes genuinely excessive in a way ANB judges worth billing extra for, the admin discusses it with the client directly first, then deliberately applies a one-time charge for that specific month using the ⚠️ button on the contract's card — this creates a record that is added automatically to the client's next monthly subscription invoice as its own line item, and is marked so the same charge is never billed twice. If no overage is ever manually applied, nothing beyond the flat monthly price is ever charged, no matter how much the client actually uses the app.
- The contract document itself (and the client-facing signed agreement) shows only the total monthly price plus a plain-language list of what's included — it never breaks down the price per service/component, by design, to avoid per-item price negotiation. If an agreed overage term is configured, it appears in that same list, explicitly worded as being by mutual agreement and never automatic.
- Contracts are open-ended by default (no fixed end date) — they only stop via explicit termination (1-month statutory notice), not through any "renewal" step. New clients go through a signing workflow (agreement sent → client reviews & can request changes or sign → admin approves) before their accounting tabs unlock — while pending, the client only sees a waiting screen plus the ability to review/sign the agreement.
- PRICE CHANGES vs UPGRADES: an admin directly editing an existing contract's price (package, VOF partner count, addons, or overage terms) re-locks the client's accounting immediately until they sign the updated agreement, same as a brand-new contract — since that's a unilateral change to what they owe. By contrast, an admin can "🔼 Propose Upgrade" a new package/price to a client — this does NOT lock anything; the client keeps using their current plan completely uninterrupted, and only sees the proposed upgrade as a card on their contract with Approve/Decline buttons. The new terms only take effect once the client explicitly approves. If a proposed upgrade sits unanswered for 7+ days, the admin gets an automatic reminder on next login so it doesn't get forgotten.
- "Add Contract" attaches a brand-new contract to an already-existing client. Creating a new client together with their very first contract in one step is done instead via the client-creation form, which uses the exact same required legal fields (company name, email, contact person, KVK, BTW, IBAN, full address) plus the same package/VOF/addon/overage selection described above.

LIJFRENTE (RETIREMENT SAVINGS) CALCULATOR: an internal admin-only tool, toggled on per client (Edit Client), never visible to the client. When enabled, a "🧮 Lijfrente Calculator" button appears on that client's Info screen — it estimates the client's tax-deductible "jaarruimte" (annual retirement-savings deduction room) from their prior-year profit using the current year's official percentage/franchise/cap, and separately estimates unused "reserveringsruimte" carried over from previous years actually tracked in the app (up to 10 years back). Every calculation is saved per client per year so the next year's calculation can show the prior year's figure for comparison. This is explicitly framed as an approximate figure to prepare for the quarterly tax advisory session (part of the "+Advies" package) — never a substitute for the official Belastingdienst calculation.

DEBTORS / CREDITORS:
- Contacts are tagged as "debtor" (customer who owes money) or "creditor" (supplier owed money), each with a ledger account number. A "General Debtors"/"General Creditors" catch-all contact exists per client for entries not tied to a specific named contact.

REPORTS available (Reports screen, admin-only — this entire section, including Income Verification Statement, is never shown to clients under any configuration): Summary, Profit & Loss (P&L), BTW report (VAT return by official Belastingdienst rubrieken — 1e domestic reverse charge issued, 2a/4b reverse charge received self-assessed [combined for simplicity in the UI, admin should verify the exact box before filing], 3a export outside EU, 3b EU B2B reverse charge, 5b deductible input VAT which automatically excludes non-deductible representation-cost VAT), Tax Liability (estimated personal Inkomstenbelasting or corporate Vennootschapsbelasting — both now correctly reduced by actual payroll costs, not just operating expenses and depreciation), Cash Flow, Debtors, Expenses, Employee Financial, Employee Statistics, Payroll, Loan Overview (only appears if the client has at least one financed asset), Hours by Category, and Income Verification Statement (a client-facing, one-page formal statement of net business income for a chosen period — meant to be handed directly to a bank, embassy, or IND for mortgage/visa/residency-permit purposes; even though the document itself is client-facing, it is only ever generated by an admin after review, never accessed or triggered by the client directly). Year-over-year comparison is available on the Summary, P&L, and Cash Flow reports.

PERIOD LOCKING: Once a year or quarter is "closed" for a client (after filing that period's BTW return), transactions dated within it are protected — clients can no longer edit/delete them, and admins must explicitly confirm an override for any genuine correction. Periods can be reopened if needed. This protection covers invoices, expenses, and hour entries.

IMPORT: A template-based workflow (download template → fill with data from the client's previous accounting office → upload) to migrate historical data in, with required supporting files (bank statements, prior reports) and a full import history that can be reversed (removes all records + the journal entry created by that batch). Not applicable to ANB's own account (it isn't switching from a previous bookkeeper).

NEW CLIENT CREATION & PASSWORD SECURITY:
- Every brand-new client (created via the client-creation form, which requires the exact legal fields and walks through the same package/VOF/addon/overage selection described in CONTRACTS & PRICING above) automatically gets a one-time, randomly-generated temporary password immediately after creation, shown once to the admin in a dialog to copy and share with the client through a trusted channel (phone, in person) — it is never shown again after that. "Add Contract" (for an already-existing client getting a new/additional contract) does not create a new password, since the client account already exists.
- KVK and BTW numbers are validated for correct Dutch format before saving (KVK: exactly 8 digits; BTW: NL + 9 characters + B + 2 digits, e.g. NL123456789B01), and checked for duplicates against every other existing client — saving a KVK/BTW number already used by another client is blocked with a clear message naming the conflicting client.
- The exact same one-time-password mechanism is used whenever an admin resets an existing client's password (Settings → Clients tab, or the client's own screen → "Reset Password") for a forgotten-password situation — self-service "forgot password" is NOT available; only an admin can issue a new temporary password. The login screen's "Need access?" link does not let anyone set a password themselves — it only shows a message directing them to contact ANB (or, for admins, another administrator) directly.
- Any account that logs in with such a temporary password is immediately shown a mandatory, non-dismissible "Set Your Password" screen before anything else in the app becomes usable — there is no way to skip, close, or work around this screen; the account cannot proceed until a new password (min. 6 characters, confirmed twice) is successfully saved. This applies identically whether the temporary password came from brand-new client creation or from an admin-initiated password reset.
- Separately, a client can voluntarily change their own password any time from their dashboard's Security card ("Change Password") — this requires entering their CURRENT password correctly first (server-verified) before the new password (min. 6 characters, confirmed twice) is accepted. Changing a password this way (or having it reset by an admin) immediately invalidates any other active login sessions for that account on other devices — only the device that just set the new password stays signed in.
- Login sessions last 4 hours before needing a refresh (handled automatically in the background while the user is active); an inactive session on the same device signs out automatically after 20 minutes of no activity.

APPEARANCE: A dark mode toggle (🌙/☀️ icon) sits next to the language switcher (EN/NL/AR) at the bottom of the sidebar, available to both admins and clients on every screen. It is a personal, per-device preference saved in the browser (not synced across devices or shared with other users), and takes effect immediately without needing to reload. ANB's core brand colors (dark green, gold) stay the same in both modes — only backgrounds, borders, and body text switch between light and dark.

SETTINGS is organized into three tabs (the previous separate "Company" tab was removed):
- Admins tab: the list of admin accounts (add/remove — Super Admin role is protected from being reset or removed by regular admins), each admin's password reset button, and Two-Factor Authentication (2FA) setup for the currently logged-in admin's own account.
- Clients tab: the list of client accounts with a password-reset button per client and a button to view a copy of their signed contract (PDF).
- Danger Zone tab: automatic daily Backups (stored completely separately from the live database, with manual "Backup Now", a list of available backups, and Restore which takes an automatic safety backup of the current state first), and permanent client deletion (gated by re-entering the admin's own password).
- ANB's own company details (company name, KVK, BTW, IBAN, address, tagline, website, and Professional Indemnity Insurance details referenced in service agreement liability clauses) live in ANB's own record under Edit Client — reached the same way as editing any other client (ANB is modeled as a special client itself) — rather than a separate Settings tab. Billing/price/package fields do not apply to ANB's own record and are hidden there.
- A client's price, package, and monthly transaction limits are no longer editable from the client's own Configuration tab (that used to silently bypass the price-change lock) — they are managed exclusively from that client's Contract.

TRASH & ARCHIVE: Deleted items go to Trash first; after 30 days non-financial records (clients, contacts) are archived (hidden but never actually deleted) while financial records (invoices, expenses, hours, documents) are archived and kept for the full legal 7-year retention period from the record's own date before being permanently purged.

CLIENT-SIDE FEATURES: A first-time Welcome onboarding (3 short animated slides) shown once per client account, plus a "Quick Start" checklist on their dashboard, a searchable Help Center, and messaging with ANB that supports file/image attachments (reusing the same upload mechanism as Documents) with a full edit history preserved on any edited message.

ROLES: Admin (ANB staff) sees and manages everything for every client. Clients only see their own data; which optional sections they can see is individually toggled per client by the admin in Edit Client → Configuration → Visible Sections (Reports is the one exception — it is always admin-only and cannot be toggled visible for any client).

GLOBAL SEARCH (admin-only): A "🔍" button pinned permanently in the topbar opens a unified search across clients, invoices, expenses, documents, and contracts at once — also reachable via Ctrl/Cmd+K.

UNSAVED CHANGES PROTECTION: If you (or a client) type into a form or field and then try to navigate away before saving, the app shows a "Discard changes?" confirmation first.

AI ASSISTANT: This chatbot itself (admin-only, via a floating "🤖" button) — free via Cloudflare Workers AI, for accounting/tax/admin guidance including "how do I record X in this app" questions.

PUSH NOTIFICATIONS: Real device push notifications can be enabled per device from a "Push Notifications" card. Once enabled, a daily server-side check sends: admins get notified about contracts expiring within 7 days, and a combined daily summary of what clients did the previous day across all clients at once (new invoices issued, new expenses logged, and bank statement files imported — counting only actions the client did themselves, not the admin's own work on their behalf); clients get notified about their own overdue invoices, and separately about any stale/unposted Cashier day that still needs a physical cash count to close out (this is a reminder only — it never posts anything on the client's behalf). If a browser/device clears its site data or cache, the underlying push subscription is wiped by the browser itself (not an app bug) and must be re-enabled manually.`;
var ADMIN_ASSISTANT_SYSTEM_PROMPT = `You are an internal assistant for ANB Financial Services, a Dutch bookkeeping and financial administration firm serving freelancers (ZZP) and small businesses. You help the firm's own admin staff think through accounting, tax (Dutch BTW/Belastingdienst rules), and general business-administration questions they run into during daily work — including questions about how to record something in their own ANB FinAdmin Pro application.

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
  if (auth.payload.at !== "admin") return json({ error: "Admin access required" }, 403, cors);
  const bucketKey = `assistant:${auth.payload.aid}`;
  if (await isRateLimited(env, bucketKey)) {
    return json({ error: "Too many requests, please wait a bit before asking again" }, 429, cors);
  }
  await registerAttempt(env, bucketKey);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { question } = body || {};
  if (!question || typeof question !== "string" || !question.trim()) {
    return json({ error: "question is required" }, 400, cors);
  }
  if (question.length > 2e3) {
    return json({ error: "Question is too long (max 2000 characters)" }, 400, cors);
  }
  try {
    const aiResponse = await env.AI.run(ADMIN_ASSISTANT_MODEL, {
      messages: [
        { role: "system", content: ADMIN_ASSISTANT_SYSTEM_PROMPT },
        { role: "user", content: question.trim() }
      ]
    });
    const answer = aiResponse && (aiResponse.response || aiResponse.result) || "";
    if (!answer) return json({ error: "assistant_error", message: "No response from the assistant — please try again." }, 502, cors);
    return json({ answer }, 200, cors);
  } catch (err) {
    return json({ error: "assistant_error", message: String(err && err.message || err) }, 502, cors);
  }
}

async function handleBackupNow(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== "admin") return json({ error: "Admin access required" }, 403, cors);
  const result = await performBackup(env, "manual");
  if (!result.ok) return json(result, 502, cors);
  return json(result, 200, cors);
}
async function handleListBackups(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== "admin") return json({ error: "Admin access required" }, 403, cors);
  const listed = await env.BACKUPS.list();
  const backups = listed.objects.map((o) => ({ key: o.key, size: o.size, uploaded: o.uploaded })).sort((a, b) => a.key < b.key ? 1 : -1);
  return json({ backups }, 200, cors);
}
async function handleRestoreBackup(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== "admin") return json({ error: "Admin access required" }, 403, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { backupKey } = body || {};
  if (!backupKey) return json({ error: "backupKey is required" }, 400, cors);
  const backupObj = await env.BACKUPS.get(backupKey);
  if (!backupObj) return json({ error: "Backup not found" }, 404, cors);
  const backupData = JSON.parse(await backupObj.text());
  await performBackup(env, "pre-restore-safety");
  await writeCloudPayload(env, backupData.payload);
  return json({ ok: true, restoredFrom: backupKey, restoredBackupTimestamp: backupData.backedUpAt }, 200, cors);
}
async function fetchCloudPayload(env) {
  try {
    const payload = {};
    let maxUpdatedAt = 0;
    for (const key of ALL_ARRAY_TABLE_KEYS) {
      const table = "tbl_" + key;
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
    const table = "tbl_" + key;
    const items = (payloadObj[key] || []).filter((it) => it && it.id);
    const currentIds = new Set(items.map((it) => it.id));
    const { results: existingRows } = await env.DB.prepare(`SELECT id FROM ${table}`).all();
    for (const row of existingRows) {
      if (!currentIds.has(row.id)) {
        statements.push(env.DB.prepare(`DELETE FROM ${table} WHERE id = ?`).bind(row.id));
      }
    }
    for (const item of items) {
      const jsonStr = JSON.stringify(item);
      if (ALL_SINGLE_TABLE_KEYS.includes(key)) {
        statements.push(env.DB.prepare(
          `INSERT INTO ${table} (id, payload, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at`
        ).bind(item.id, jsonStr, now));
      } else {
        const cid = item.cid || null;
        statements.push(env.DB.prepare(
          `INSERT INTO ${table} (id, cid, payload, updated_at) VALUES (?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET cid = excluded.cid, payload = excluded.payload, updated_at = excluded.updated_at`
        ).bind(item.id, cid, jsonStr, now));
      }
    }
  }
  statements.push(env.DB.prepare(
    `INSERT INTO tbl_settings (id, payload, updated_at) VALUES ('main', ?, ?)
     ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at`
  ).bind(JSON.stringify(payloadObj.settings || {}), now));
  if (statements.length > 0) await env.DB.batch(statements);
  return now;
}
function listFor(payload, role) {
  return role === "admin" ? payload.admins || [] : payload.clients || [];
}
var SENSITIVE_ACCOUNT_FIELDS = ["passwordHash", "passwordSalt", "totpSecret", "paymentApiKey"];
var CLIENT_SCOPED_ARRAY_KEYS = ["invoices", "expenses", "hours", "docs", "messages", "journal", "bankTx", "recurring", "yearClosings", "contracts", "assets", "serviceAgreements", "importBatches", "employees", "contacts", "cashPayments", "cashierLog", "cashierDayExceptions", "supplierOcrProfiles", "auditLog"];
var ALL_SINGLE_TABLE_KEYS = ["clients", "admins"];
var ALL_ARRAY_TABLE_KEYS = [...ALL_SINGLE_TABLE_KEYS, ...CLIENT_SCOPED_ARRAY_KEYS];
function stripSensitiveFields(account) {
  if (!account || typeof account !== "object") return account;
  const clean = { ...account };
  SENSITIVE_ACCOUNT_FIELDS.forEach((f) => { delete clean[f]; });
  return clean;
}
function filterPayloadForSync(payload, role, aid) {
  const filtered = { ...payload };
  filtered.clients = (payload.clients || []).map(stripSensitiveFields);
  filtered.admins = (payload.admins || []).map(stripSensitiveFields);
  if (role === "admin") return filtered;
  filtered.clients = filtered.clients.filter((c) => c && c.id === aid);
  filtered.admins = [];
  CLIENT_SCOPED_ARRAY_KEYS.forEach((key) => {
    filtered[key] = (payload[key] || []).filter((item) => item && item.cid === aid);
  });
  return filtered;
}
function mergeArrayByIdUpsert(existingArray, incomingArray) {
  const result = [...existingArray || []];
  const idxById = new Map();
  result.forEach((item, idx) => { if (item && item.id != null) idxById.set(item.id, idx); });
  (Array.isArray(incomingArray) ? incomingArray : []).forEach((incomingItem) => {
    if (!incomingItem || incomingItem.id == null) return;
    const idx = idxById.get(incomingItem.id);
    if (idx !== void 0) { result[idx] = incomingItem; }
    else { result.push(incomingItem); idxById.set(incomingItem.id, result.length - 1); }
  });
  return result;
}
function mergeClientScopedArray(existingArray, incomingArray, aid) {
  const others = (existingArray || []).filter((item) => !item || item.cid !== aid);
  const existingOwn = (existingArray || []).filter((item) => item && item.cid === aid);
  const incomingOwn = (Array.isArray(incomingArray) ? incomingArray : []).filter((item) => item && item.cid === aid);
  const mergedOwn = mergeArrayByIdUpsert(existingOwn, incomingOwn);
  return [...others, ...mergedOwn];
}
var PERIOD_LOCKED_ARRAY_KEYS = ["invoices", "expenses", "hours"];
function getClosingForDate(yearClosings, cid, dateStr) {
  if (!dateStr) return null;
  const closings = (yearClosings || []).filter((c) => c && c.cid === cid && !c.deleted);
  if (closings.length === 0) return null;
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return null;
  const year = date.getFullYear();
  const quarter = Math.floor(date.getMonth() / 3) + 1;
  return closings.find((c) => c.periodType === "year" && c.year === year) || closings.find((c) => c.periodType === "quarter" && c.year === year && c.quarter === quarter) || null;
}
function enforcePeriodLockOnClientArray(key, existingArray, incomingArray, aid, yearClosings) {
  if (!PERIOD_LOCKED_ARRAY_KEYS.includes(key)) return { allowed: incomingArray, blocked: [] };
  const existingById = new Map((existingArray || []).filter((x) => x).map((x) => [x.id, x]));
  const allowed = [];
  const blocked = [];
  (Array.isArray(incomingArray) ? incomingArray : []).forEach((item) => {
    if (!item || item.cid !== aid) return;
    const existingItem = existingById.get(item.id);
    const datesToCheck = [item.date, existingItem && existingItem.date].filter(Boolean);
    const isLocked = datesToCheck.some((d) => !!getClosingForDate(yearClosings, aid, d));
    if (isLocked) blocked.push(item);
    else allowed.push(item);
  });
  return { allowed, blocked };
}
var APPEND_ONLY_ARRAY_KEYS = ["auditLog"];
function mergeAppendOnlyArray(existingArray, incomingArray, aidFilter) {
  const existingIds = new Set((existingArray || []).filter((x) => x && x.id).map((x) => x.id));
  const merged = [...existingArray || []];
  (Array.isArray(incomingArray) ? incomingArray : []).forEach((item) => {
    if (!item || !item.id) return;
    if (aidFilter && item.cid !== aidFilter) return;
    if (existingIds.has(item.id)) return;
    existingIds.add(item.id);
    merged.push(item);
  });
  return merged;
}

async function handleResolveAccount(request, env, cors) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const bucketKey = `resolve-account:${ip}`;
  if (await isRateLimited(env, bucketKey)) return json({ error: "Too many attempts, slow down" }, 429, cors);
  await registerAttempt(env, bucketKey);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { role, identifier } = body || {};
  if (!role || !identifier) return json({ error: "role and identifier are required" }, 400, cors);
  if (role !== "admin" && role !== "client") return json({ error: 'role must be "admin" or "client"' }, 400, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const id = identifier.trim().toLowerCase();
  const list = listFor(cloud.payload, role);
  const account = list.find(
    (a) => a.email && a.email.toLowerCase() === id || a.phone && (a.phone === identifier.trim() || a.phone.replace(/\s/g, "") === identifier.trim().replace(/\s/g, ""))
  );
  if (!account) return json({ error: "Account not found" }, 404, cors);
  if (role === "admin" && account.status !== "active") return json({ error: "Account not found" }, 404, cors);
  if (role === "client" && account.accountStatus === "suspended") return json({ error: "account_suspended" }, 403, cors);
  if (role === "client" && account.accountStatus === "cancelled") return json({ error: "account_cancelled" }, 403, cors);
  if (isLockedOut(account)) return json({ error: "locked", minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);
  return json({
    accountId: account.id,
    name: account.name || "",
    email: account.email || "",
    type: account.type || "",
    totpEnabled: !!account.totpEnabled,
    isFirstTime: role === "client" ? !account.pwSet : !account.passwordHash
  }, 200, cors);
}
// ⭐ يتحقق من توكن Cloudflare Turnstile مع خادم Cloudflare نفسه قبل قبول أي
// محاولة تسجيل دخول - طبقة حماية من محاولات الدخول الآلية (bots)، إضافية فوق
// تحديد المعدل (rate limiting) الموجود أصلًا بلا استبدال له
async function verifyTurnstileToken(token, secretKey, ip) {
  if (!token) return { ok: false, reason: "missing_token" };
  if (!secretKey) return { ok: false, reason: "not_configured" }; // ⚠️ لو السرّ غير مُعرَّف بعد بالخادم، لا نمنع الدخول بالخطأ - نتجاهل التحقق مؤقتًا (انظر ملاحظة الاستخدام)
  try {
    const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: secretKey, response: token, remoteip: ip }),
    });
    const data = await resp.json();
    return { ok: !!data.success, reason: data.success ? null : (data["error-codes"] || []).join(",") };
  } catch (e) {
    return { ok: false, reason: "verify_request_failed" };
  }
}
async function handleLogin(request, env, cors) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const bucketKey = `login:${ip}`;
  if (await isRateLimited(env, bucketKey)) return json({ error: "Too many attempts, slow down" }, 429, cors);
  await registerAttempt(env, bucketKey);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { role, accountId, password, turnstileToken } = body || {};
  if (!role || !accountId || !password) return json({ error: "role, accountId and password are required" }, 400, cors);
  // ⚠️⚠️ إذا كان env.TURNSTILE_SECRET_KEY معرَّفًا فعليًا، التحقق إلزامي ويرفض
  // الطلب برسالة واضحة عند الفشل. لو السرّ غير معرَّف بعد (قبل إكمال الإعداد
  // بلوحة Cloudflare)، يُسمح بالدخول عاديًا بلا حجب - حتى لا يُغلَق الدخول
  // بالكامل بالخطأ لمجرد نسيان ضبط السرّ. أزل هذا الاستثناء بعد التأكد من ضبط
  // TURNSTILE_SECRET_KEY فعليًا كـ Worker secret.
  if (env.TURNSTILE_SECRET_KEY) {
    const tsResult = await verifyTurnstileToken(turnstileToken, env.TURNSTILE_SECRET_KEY, ip);
    if (!tsResult.ok) return json({ error: "Verification failed - please try again", detail: tsResult.reason }, 400, cors);
  }
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const list = listFor(cloud.payload, role);
  const idx = list.findIndex((a) => a && a.id === accountId);
  if (idx === -1) return json({ error: "Invalid credentials" }, 401, cors);
  const account = list[idx];
  if (isLockedOut(account)) return json({ error: "locked", minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);
  if (role === "admin" && account.status !== "active") return json({ error: "Account not active" }, 403, cors);
  if (role === "client" && account.accountStatus === "suspended") return json({ error: "account_suspended" }, 403, cors);
  if (role === "client" && account.accountStatus === "cancelled") return json({ error: "account_cancelled" }, 403, cors);
  const verdict = await verifyPasswordServerSide(password, account);
  if (!verdict.ok) {
    registerFailedAttempt(account);
    list[idx] = account;
    await writeCloudPayload(env, cloud.payload);
    if (isLockedOut(account)) return json({ error: "locked", minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);
    return json({ error: "Invalid credentials" }, 401, cors);
  }
  clearFailedAttempts(account);
  if (verdict.needsUpgrade) {
    const rec = await makePasswordRecord(password);
    account.passwordSalt = rec.passwordSalt;
    account.passwordHash = rec.passwordHash;
    account.passwordIterations = rec.passwordIterations;
    delete account.password; delete account.pwCustom; delete account.pw;
  }
  if (!account.pwv) account.pwv = generatePwv();
  if (role === "admin") account.lastLogin = (new Date()).toISOString().slice(0, 10);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);
  if (account.totpEnabled) return json({ step: "2fa", accountId: account.id }, 200, cors);
  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: role, aid: account.id, exp, pwv: account.pwv }, env.R2_HMAC_SECRET);
  return json({ step: "done", token, exp, mustChangePassword: !!account.mustChangePassword }, 200, cors);
}
async function handleVerify2FA(request, env, cors) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const bucketKey = `verify-2fa:${ip}`;
  if (await isRateLimited(env, bucketKey)) return json({ error: "Too many attempts, slow down" }, 429, cors);
  await registerAttempt(env, bucketKey);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { role, accountId, code } = body || {};
  if (!role || !accountId || !code) return json({ error: "role, accountId and code are required" }, 400, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const list = listFor(cloud.payload, role);
  const idx = list.findIndex((a) => a && a.id === accountId);
  if (idx === -1) return json({ error: "Invalid session" }, 401, cors);
  const account = list[idx];
  if (isLockedOut(account)) return json({ error: "locked", minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);
  if (role === "client" && account.accountStatus === "suspended") return json({ error: "account_suspended" }, 403, cors);
  if (role === "client" && account.accountStatus === "cancelled") return json({ error: "account_cancelled" }, 403, cors);
  const valid = await verifyTotpCode(account.totpSecret, code);
  if (!valid) {
    registerFailedAttempt(account);
    list[idx] = account;
    await writeCloudPayload(env, cloud.payload);
    if (isLockedOut(account)) return json({ error: "locked", minutesRemaining: lockoutRemainingMinutes(account) }, 423, cors);
    return json({ error: "Incorrect code" }, 401, cors);
  }
  clearFailedAttempts(account);
  if (!account.pwv) account.pwv = generatePwv();
  if (role === "admin") account.lastLogin = (new Date()).toISOString().slice(0, 10);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);
  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: role, aid: account.id, exp, pwv: account.pwv }, env.R2_HMAC_SECRET);
  return json({ token, exp, mustChangePassword: !!account.mustChangePassword }, 200, cors);
}
var PBKDF2_ITERATIONS = 1e5;
var PBKDF2_LEGACY_ITERATIONS = 1e5;
async function verifyPasswordServerSide(plainPassword, record) {
  if (record.passwordHash && record.passwordSalt) {
    const iterations = record.passwordIterations || PBKDF2_LEGACY_ITERATIONS;
    const hash = await hashPasswordPBKDF2(plainPassword, record.passwordSalt, iterations);
    const ok = timingSafeEqual(hash, record.passwordHash);
    return { ok, needsUpgrade: ok && iterations < PBKDF2_ITERATIONS };
  }
  const legacyPlain = record.password || record.pwCustom || record.pw;
  if (legacyPlain !== void 0 && legacyPlain === plainPassword) return { ok: true, needsUpgrade: true };
  return { ok: false, needsUpgrade: false };
}
async function makePasswordRecord(plainPassword) {
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const passwordSalt = bufToHex(saltBytes);
  const passwordHash = await hashPasswordPBKDF2(plainPassword, passwordSalt, PBKDF2_ITERATIONS);
  return { passwordSalt, passwordHash, passwordIterations: PBKDF2_ITERATIONS };
}
function generatePwv() {
  const bytes = new Uint8Array(9);
  crypto.getRandomValues(bytes);
  return bufToHex(bytes);
}
async function hashPasswordPBKDF2(password, saltHex, iterations) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(saltHex), iterations: iterations || PBKDF2_ITERATIONS, hash: "SHA-256" }, keyMaterial, 256);
  return bufToHex(bits);
}
function isLockedOut(account) { return !!(account && account.lockedUntil && Date.now() < account.lockedUntil); }
function lockoutRemainingMinutes(account) { return Math.max(1, Math.ceil((account.lockedUntil - Date.now()) / 6e4)); }
function registerFailedAttempt(account) {
  account.failedAttempts = (account.failedAttempts || 0) + 1;
  if (account.failedAttempts >= LOGIN_MAX_ATTEMPTS) {
    account.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
    account.failedAttempts = 0;
  }
}
function clearFailedAttempts(account) { account.failedAttempts = 0; account.lockedUntil = null; }
function base32Decode(base32) {
  const clean = (base32 || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const ch of clean) {
    const val = BASE32_ALPHABET.indexOf(ch);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return new Uint8Array(bytes);
}
function counterToBytes(num) {
  const bytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { bytes[i] = num & 255; num = Math.floor(num / 256); }
  return bytes;
}
async function hmacSha1(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}
async function generateTotpCode(secret, forTimeMs) {
  const counter = Math.floor((forTimeMs || Date.now()) / 1e3 / TOTP_STEP_SECONDS);
  const keyBytes = base32Decode(secret);
  const msgBytes = counterToBytes(counter);
  const hmac = await hmacSha1(keyBytes, msgBytes);
  const offset = hmac[hmac.length - 1] & 15;
  const binCode = (hmac[offset] & 127) << 24 | (hmac[offset + 1] & 255) << 16 | (hmac[offset + 2] & 255) << 8 | hmac[offset + 3] & 255;
  return (binCode % 10 ** TOTP_DIGITS).toString().padStart(TOTP_DIGITS, "0");
}
async function verifyTotpCode(secret, userCode) {
  if (!secret || !userCode) return false;
  const clean = userCode.toString().replace(/\s/g, "");
  if (!/^\d{6}$/.test(clean)) return false;
  const now = Date.now();
  for (const drift of [0, -1, 1, -2, 2]) {
    const code = await generateTotpCode(secret, now + drift * TOTP_STEP_SECONDS * 1e3);
    if (timingSafeEqual(code, clean)) return true;
  }
  return false;
}
async function handleSetPassword(request, env, cors) {
  return json({
    error: "self_service_disabled",
    message: "Self-service password setup has been disabled for security. Please contact your ANB administrator to receive your login credentials."
  }, 410, cors);
}
async function handleSetOwnPassword(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { newPassword, currentPassword } = body || {};
  if (!newPassword || newPassword.length < 6) return json({ error: "Password must be at least 6 characters" }, 400, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const list = listFor(cloud.payload, auth.payload.at);
  const idx = list.findIndex((a) => a && a.id === auth.payload.aid);
  if (idx === -1) return json({ error: "Account not found" }, 404, cors);
  const account = list[idx];
  if (currentPassword) {
    const verdict = await verifyPasswordServerSide(currentPassword, account);
    if (!verdict.ok) return json({ error: "Current password is incorrect" }, 401, cors);
  }
  const rec = await makePasswordRecord(newPassword);
  account.passwordSalt = rec.passwordSalt;
  account.passwordHash = rec.passwordHash;
  account.passwordIterations = rec.passwordIterations;
  delete account.password; delete account.pwCustom; delete account.pw;
  if (auth.payload.at === "client") account.pwSet = true;
  account.mustChangePassword = false;
  account.pwv = generatePwv();
  clearFailedAttempts(account);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);
  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: auth.payload.at, aid: auth.payload.aid, exp, pwv: account.pwv }, env.R2_HMAC_SECRET);
  return json({ ok: true, token, exp }, 200, cors);
}
async function handleAdminSetPassword(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== "admin") return json({ error: "Admin access required" }, 403, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { targetRole, targetAccountId, newPassword } = body || {};
  if (!targetRole || !targetAccountId) return json({ error: "targetRole and targetAccountId are required" }, 400, cors);
  if (targetRole !== "admin" && targetRole !== "client") return json({ error: 'targetRole must be "admin" or "client"' }, 400, cors);
  if (newPassword && newPassword.length < 6) return json({ error: "Password must be at least 6 characters" }, 400, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const list = listFor(cloud.payload, targetRole);
  const idx = list.findIndex((a) => a && a.id === targetAccountId);
  if (idx === -1) return json({ error: "Account not found" }, 404, cors);
  const account = list[idx];
  const isSelf = targetRole === "admin" && targetAccountId === auth.payload.aid;
  if (!isSelf && targetRole === "admin" && account.role === "super_admin") {
    return json({ error: "Cannot reset a Super Admin password this way" }, 403, cors);
  }
  const finalPassword = newPassword || generateTempPassword();
  const rec = await makePasswordRecord(finalPassword);
  account.passwordSalt = rec.passwordSalt;
  account.passwordHash = rec.passwordHash;
  account.passwordIterations = rec.passwordIterations;
  delete account.password; delete account.pwCustom; delete account.pw;
  if (targetRole === "client") account.pwSet = true;
  account.mustChangePassword = !newPassword;
  account.pwv = generatePwv();
  clearFailedAttempts(account);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);
  return json({ ok: true, tempPassword: newPassword ? void 0 : finalPassword }, 200, cors);
}
async function handleGenerateTempPassword(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== "admin") return json({ error: "Admin access required" }, 403, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { clientAccountId } = body || {};
  if (!clientAccountId) return json({ error: "clientAccountId is required" }, 400, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const list = listFor(cloud.payload, "client");
  const idx = list.findIndex((a) => a && a.id === clientAccountId);
  if (idx === -1) return json({ error: "Client not found" }, 404, cors);
  const tempPassword = generateTempPassword();
  const rec = await makePasswordRecord(tempPassword);
  const account = list[idx];
  account.passwordSalt = rec.passwordSalt;
  account.passwordHash = rec.passwordHash;
  account.passwordIterations = rec.passwordIterations;
  delete account.password; delete account.pwCustom; delete account.pw;
  account.pwSet = true;
  account.pwv = generatePwv();
  clearFailedAttempts(account);
  list[idx] = account;
  await writeCloudPayload(env, cloud.payload);
  return json({ tempPassword }, 200, cors);
}
function generateTempPassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  let out = "";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  for (let i = 0; i < 10; i++) out += chars[bytes[i] % chars.length];
  return out;
}
async function handleRefreshToken(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const exp = Date.now() + TOKEN_TTL_MS;
  const token = await signToken({ at: auth.payload.at, aid: auth.payload.aid, exp, pwv: auth.payload.pwv }, env.R2_HMAC_SECRET);
  return json({ token, exp }, 200, cors);
}

async function handleSyncGet(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "No data yet" }, 404, cors);
  const filteredPayload = filterPayloadForSync(cloud.payload, auth.payload.at, auth.payload.aid);
  return json({ payload: filteredPayload, updated_at: new Date(cloud.updated_at).toISOString() }, 200, cors);
}
async function handleSyncPost(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const { payload: incomingPayload } = body || {};
  if (!incomingPayload || typeof incomingPayload !== "object") return json({ error: "payload object is required" }, 400, cors);
  const cloud = await fetchCloudPayload(env);
  const existingPayload = cloud && cloud.payload || {};
  const merged = { ...existingPayload };
  const role = auth.payload.at;
  const aid = auth.payload.aid;
  function mergeAccount(existingAccount, incomingAccount) {
    if (!existingAccount) return incomingAccount;
    return { ...incomingAccount, passwordHash: existingAccount.passwordHash, passwordSalt: existingAccount.passwordSalt, pwv: existingAccount.pwv };
  }
  if (role === "admin") {
    Object.keys(incomingPayload).forEach((key) => {
      if (key === "clients" || key === "admins") {
        const existingList = existingPayload[key] || [];
        merged[key] = (incomingPayload[key] || []).map((incomingAccount) => {
          const existingAccount = existingList.find((a) => a && a.id === incomingAccount.id);
          return mergeAccount(existingAccount, incomingAccount);
        });
        const incomingIds = new Set((incomingPayload[key] || []).map((a) => a && a.id));
        existingList.forEach((existingAccount) => {
          if (existingAccount && !incomingIds.has(existingAccount.id)) merged[key].push(existingAccount);
        });
      } else if (APPEND_ONLY_ARRAY_KEYS.includes(key)) {
        merged[key] = mergeAppendOnlyArray(existingPayload[key], incomingPayload[key], null);
      } else if (key === "settings") {
        merged[key] = incomingPayload[key];
      } else {
        merged[key] = mergeArrayByIdUpsert(existingPayload[key], incomingPayload[key]);
      }
    });
  } else {
    const existingClients = existingPayload.clients || [];
    const incomingOwnClient = (incomingPayload.clients || []).find((c) => c && c.id === aid);
    if (incomingOwnClient) {
      const existingOwnClient = existingClients.find((c) => c && c.id === aid);
      const mergedOwnClient = mergeAccount(existingOwnClient, incomingOwnClient);
      merged.clients = existingClients.map((c) => c && c.id === aid ? mergedOwnClient : c);
    }
    merged.admins = existingPayload.admins || [];
    merged.yearClosings = existingPayload.yearClosings || [];
    const blockedByPeriodLock = [];
    CLIENT_SCOPED_ARRAY_KEYS.forEach((key) => {
      if (key === "yearClosings") return;
      if (APPEND_ONLY_ARRAY_KEYS.includes(key)) {
        merged[key] = mergeAppendOnlyArray(existingPayload[key], incomingPayload[key], aid);
        return;
      }
      const { allowed, blocked } = enforcePeriodLockOnClientArray(key, existingPayload[key], incomingPayload[key], aid, existingPayload.yearClosings);
      blocked.forEach((item) => blockedByPeriodLock.push({ key, id: item.id }));
      merged[key] = mergeClientScopedArray(existingPayload[key], allowed, aid);
    });
    if (blockedByPeriodLock.length > 0) {
      const savedAt2 = await writeCloudPayload(env, merged);
      return json({ ok: true, updated_at: new Date(savedAt2).toISOString(), warning: "period_locked", blocked: blockedByPeriodLock }, 200, cors);
    }
  }
  const savedAt = await writeCloudPayload(env, merged);
  return json({ ok: true, updated_at: new Date(savedAt).toISOString() }, 200, cors);
}
async function handleOcrVision(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const bucketKey = `ocr-vision:${auth.payload.aid || auth.payload.at}`;
  if (await isRateLimited(env, bucketKey)) return json({ error: "Too many OCR requests, please wait a moment" }, 429, cors);
  await registerAttempt(env, bucketKey);
  if (!env.GOOGLE_VISION_API_KEY) return json({ error: "OCR service not configured" }, 503, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid request body" }, 400, cors); }
  const base64Image = (body.image || "").replace(/^data:image\/\w+;base64,/, "");
  if (!base64Image) return json({ error: "No image provided" }, 400, cors);
  if (base64Image.length > 2e7) return json({ error: "Image too large" }, 413, cors);
  const visionRequestBody = {
    requests: [{ image: { content: base64Image }, features: [{ type: "DOCUMENT_TEXT_DETECTION" }], imageContext: { languageHints: ["en", "nl"] } }]
  };
  let visionResponse;
  try {
    visionResponse = await fetch(`https://vision.googleapis.com/v1/images:annotate?key=${env.GOOGLE_VISION_API_KEY}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(visionRequestBody)
    });
  } catch (err) { return json({ error: "Could not reach OCR service" }, 502, cors); }
  if (!visionResponse.ok) return json({ error: "OCR service error" }, 502, cors);
  const visionData = await visionResponse.json();
  const result = (visionData.responses || [])[0] || {};
  if (result.error) return json({ error: result.error.message || "OCR processing failed" }, 502, cors);
  const fullText = result.fullTextAnnotation?.text || "";
  let confidenceSum = 0, confidenceCount = 0;
  const words = [];
  (result.fullTextAnnotation?.pages || []).forEach((page) => {
    (page.blocks || []).forEach((block) => {
      (block.paragraphs || []).forEach((para) => {
        (para.words || []).forEach((word) => {
          if (typeof word.confidence === "number") { confidenceSum += word.confidence; confidenceCount++; }
          const text = (word.symbols || []).map((s) => s.text).join("");
          const vertices = word.boundingBox?.vertices || [];
          if (text && vertices.length === 4) {
            const xs = vertices.map((v) => v.x || 0), ys = vertices.map((v) => v.y || 0);
            words.push({ t: text, x: Math.min(...xs), y: Math.min(...ys), w: Math.max(...xs) - Math.min(...xs), h: Math.max(...ys) - Math.min(...ys) });
          }
        });
      });
    });
  });
  const avgConfidence = confidenceCount > 0 ? confidenceSum / confidenceCount * 100 : 75;
  return json({ text: fullText, confidence: avgConfidence, words }, 200, cors);
}
async function handleUpload(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const ALLOWED_UPLOAD_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif", "image/heic", "image/heif", "application/pdf"]);
  const contentType = (request.headers.get("Content-Type") || "application/octet-stream").split(";")[0].trim().toLowerCase();
  if (!ALLOWED_UPLOAD_TYPES.has(contentType)) return json({ error: "Unsupported file type. Only images and PDF files are allowed." }, 415, cors);
  const rawName = request.headers.get("X-File-Name") || "file";
  const safeName = sanitizeFileName(rawName);
  const requestedTargetCid = request.headers.get("X-Target-Client-Id");
  let ownerSegment = `${auth.payload.at}/${auth.payload.aid}`;
  if (requestedTargetCid) {
    if (auth.payload.at === "admin") ownerSegment = `client/${requestedTargetCid}`;
    else if (requestedTargetCid === auth.payload.aid) ownerSegment = `client/${auth.payload.aid}`;
  }
  const key = `${ownerSegment}/${Date.now()}-${safeName}`;
  const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
  const body = await request.arrayBuffer();
  if (body.byteLength > MAX_UPLOAD_BYTES) return json({ error: "File too large (max 25MB)" }, 413, cors);
  await env.ANB_FILES.put(key, body, { httpMetadata: { contentType } });
  const workerOrigin = new URL(request.url).origin;
  return json({ key, url: `${workerOrigin}/file/${key}` }, 200, cors);
}
function canAccessFileKey(key, auth) {
  if (auth.payload.at === "admin") return true;
  const ownPrefix = `${auth.payload.at}/${auth.payload.aid}/`;
  return key.startsWith(ownPrefix);
}
async function handleGetFile(request, env, cors, url) {
  let auth = await requireValidToken(request, env);
  if (!auth.ok) {
    const queryToken = url.searchParams.get("token");
    if (queryToken) {
      const fakeRequest = new Request(request.url, { headers: { Authorization: `Bearer ${queryToken}` } });
      auth = await requireValidToken(fakeRequest, env);
    }
  }
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const key = decodeURIComponent(url.pathname.replace("/file/", ""));
  if (!key) return json({ error: "Missing key" }, 400, cors);
  if (!canAccessFileKey(key, auth)) return json({ error: "Forbidden" }, 403, cors);
  const object = await env.ANB_FILES.get(key);
  if (!object) return json({ error: "Not found" }, 404, cors);
  const headers = new Headers(cors);
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("Cache-Control", "private, max-age=31536000, immutable");
  headers.set("X-Content-Type-Options", "nosniff");
  const SAFE_INLINE_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif", "application/pdf"]);
  const storedType = (object.httpMetadata?.contentType || "").split(";")[0].trim().toLowerCase();
  if (!SAFE_INLINE_TYPES.has(storedType)) headers.set("Content-Disposition", "attachment");
  return new Response(object.body, { headers });
}
async function handleDeleteFile(request, env, cors, url) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  const key = decodeURIComponent(url.pathname.replace("/file/", ""));
  if (!key) return json({ error: "Missing key" }, 400, cors);
  if (!canAccessFileKey(key, auth)) return json({ error: "Forbidden" }, 403, cors);
  await env.ANB_FILES.delete(key);
  return json({ ok: true }, 200, cors);
}

async function handlePushVapidKey(request, env, cors) {
  if (!env.VAPID_PUBLIC_KEY) return json({ error: "Push notifications are not configured on the server yet" }, 503, cors);
  return json({ publicKey: env.VAPID_PUBLIC_KEY }, 200, cors);
}
async function handlePushSubscribe(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const sub = body && body.subscription;
  if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return json({ error: "Invalid subscription" }, 400, cors);
  const id = await sha256Hex(sub.endpoint);
  await ensurePushTable(env);
  await env.DB.prepare(
    `INSERT INTO tbl_push_subscriptions (id, role, aid, endpoint, p256dh, auth, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET role = excluded.role, aid = excluded.aid, endpoint = excluded.endpoint,
       p256dh = excluded.p256dh, auth = excluded.auth`
  ).bind(id, auth.payload.at, auth.payload.aid, sub.endpoint, sub.keys.p256dh, sub.keys.auth, Date.now()).run();
  return json({ ok: true }, 200, cors);
}
async function handlePushUnsubscribe(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400, cors); }
  const endpoint = body && body.endpoint;
  if (!endpoint) return json({ error: "endpoint is required" }, 400, cors);
  const id = await sha256Hex(endpoint);
  await ensurePushTable(env);
  await env.DB.prepare(`DELETE FROM tbl_push_subscriptions WHERE id = ? AND aid = ?`).bind(id, auth.payload.aid).run();
  return json({ ok: true }, 200, cors);
}
var _pushTableEnsured = false;
async function ensurePushTable(env) {
  if (_pushTableEnsured) return;
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS tbl_push_subscriptions (
      id TEXT PRIMARY KEY, role TEXT NOT NULL, aid TEXT NOT NULL,
      endpoint TEXT NOT NULL, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL
    )`
  ).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_push_subs_aid ON tbl_push_subscriptions(role, aid)`).run();
  _pushTableEnsured = true;
}
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return bufToHex(buf);
}
function b64urlEncodeBytes(bytes) {
  let bin = "";
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecodeToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function concatBytes(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrs) { out.set(a, offset); offset += a.length; }
  return out;
}
async function hmacSha256Bytes(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
}
async function buildVapidAuthHeader(endpoint, env) {
  const endpointUrl = new URL(endpoint);
  const aud = `${endpointUrl.protocol}//${endpointUrl.host}`;
  const header = { typ: "JWT", alg: "ES256" };
  const claims = { aud, exp: Math.floor(Date.now() / 1e3) + 12 * 3600, sub: env.VAPID_SUBJECT || "mailto:admin@example.com" };
  const encHeader = b64urlEncodeBytes(new TextEncoder().encode(JSON.stringify(header)));
  const encClaims = b64urlEncodeBytes(new TextEncoder().encode(JSON.stringify(claims)));
  const signingInput = `${encHeader}.${encClaims}`;
  const privJwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const key = await crypto.subtle.importKey("jwk", privJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(signingInput));
  const sig = b64urlEncodeBytes(new Uint8Array(sigBuf));
  return `vapid t=${signingInput}.${sig}, k=${env.VAPID_PUBLIC_KEY}`;
}
async function sendWebPushToSubscription(sub, payloadObj, env) {
  const plaintext = new TextEncoder().encode(JSON.stringify(payloadObj));
  const uaPublicBytes = b64urlDecodeToBytes(sub.p256dh);
  const authSecret = b64urlDecodeToBytes(sub.auth);
  const serverKeyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", serverKeyPair.publicKey));
  const uaPublicKey = await crypto.subtle.importKey("raw", uaPublicBytes, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaPublicKey }, serverKeyPair.privateKey, 256));
  const prkKey = await hmacSha256Bytes(authSecret, ecdhSecret);
  const keyInfo = concatBytes(new TextEncoder().encode("WebPush: info\0"), uaPublicBytes, asPublicRaw);
  const ikm = (await hmacSha256Bytes(prkKey, concatBytes(keyInfo, new Uint8Array([1])))).slice(0, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmacSha256Bytes(salt, ikm);
  const cek = (await hmacSha256Bytes(prk, concatBytes(new TextEncoder().encode("Content-Encoding: aes128gcm\0"), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmacSha256Bytes(prk, concatBytes(new TextEncoder().encode("Content-Encoding: nonce\0"), new Uint8Array([1])))).slice(0, 12);
  const paddedPlaintext = concatBytes(plaintext, new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, paddedPlaintext));
  const recordSize = new Uint8Array(4);
  new DataView(recordSize.buffer).setUint32(0, 4096, false);
  const header = concatBytes(salt, recordSize, new Uint8Array([asPublicRaw.length]), asPublicRaw);
  const body = concatBytes(header, ciphertext);
  const authHeader = await buildVapidAuthHeader(sub.endpoint, env);
  return fetch(sub.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "Content-Encoding": "aes128gcm", "TTL": "86400", "Authorization": authHeader },
    body
  });
}
async function sendPushToAccount(env, role, aid, notification) {
  await ensurePushTable(env);
  const { results } = await env.DB.prepare(`SELECT * FROM tbl_push_subscriptions WHERE role = ? AND aid = ?`).bind(role, aid).all();
  for (const row of results) {
    try {
      const res = await sendWebPushToSubscription(row, notification, env);
      if (res.status === 404 || res.status === 410) {
        await env.DB.prepare(`DELETE FROM tbl_push_subscriptions WHERE id = ?`).bind(row.id).run();
      }
    } catch (err) {}
  }
}
async function sendDailyReminderPushes(env) {
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return;
  const payload = cloud.payload;
  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10);
  const admins = payload.admins || [];
  const contracts = payload.contracts || [];
  const soonContracts = contracts.filter((c) => {
    if (c.status !== "active" || !c.endDate) return false;
    const days = Math.floor((new Date(c.endDate) - today) / 864e5);
    return days >= 0 && days <= 7;
  });
  if (soonContracts.length > 0) {
    for (const admin of admins) {
      if (admin.status !== "active") continue;
      await sendPushToAccount(env, "admin", admin.id, {
        title: "ANB — عقود بحاجة تجديد",
        body: `${soonContracts.length} عقد سينتهي خلال 7 أيام أو أقل`
      });
    }
  }
  const invoices = payload.invoices || [];
  const overdueByClient = {};
  invoices.forEach((inv) => {
    if (!inv.deleted && inv.due && inv.due < todayStr && ["Openstaand", "Verzonden"].includes(inv.status)) {
      overdueByClient[inv.cid] = (overdueByClient[inv.cid] || 0) + 1;
    }
  });
  for (const cid of Object.keys(overdueByClient)) {
    await sendPushToAccount(env, "client", cid, {
      title: "ANB — فاتورة متأخرة السداد",
      body: `لديك ${overdueByClient[cid]} فاتورة متأخرة السداد`
    });
  }

  // ⭐⭐⭐ ملخَّص نشاط العملاء اليومي - حسب طلب صريح: خيار (ب) ملخَّص مجمَّع
  // يشمل كل عميل، لا إشعارًا منفصلًا لكل عملية. يُرسَل ضمن نفس الفحص الصباحي
  // اليومي الموجود أصلًا (٧ صباحًا) - لا حاجة لمُشغِّل cron جديد. يحسب نشاط
  // "الأمس" المكتمل فقط (لا اليوم الجاري غير المنتهي)، ويقتصر على ما فعله
  // العميل نفسه (actorRole==='client') - لا يُبلَّغ الأدمن عن أفعاله هو نفسه.
  const yesterday = new Date(today.getTime() - 864e5);
  const yesterdayStr = yesterday.toISOString().slice(0, 10);
  const auditLog = payload.auditLog || [];
  const clientActivity = {};
  auditLog.forEach((entry) => {
    if (!entry || entry.actorRole !== "client" || entry.action !== "create") return;
    if (!["invoice", "expense", "bank_import"].includes(entry.entityType)) return;
    const entryDateStr = (entry.ts || "").slice(0, 10);
    if (entryDateStr !== yesterdayStr) return;
    if (!entry.cid) return;
    if (!clientActivity[entry.cid]) clientActivity[entry.cid] = { invoices: 0, expenses: 0, bankImports: 0 };
    if (entry.entityType === "invoice") clientActivity[entry.cid].invoices++;
    else if (entry.entityType === "expense") clientActivity[entry.cid].expenses++;
    else if (entry.entityType === "bank_import") clientActivity[entry.cid].bankImports++;
  });
  const activeClientIds = Object.keys(clientActivity);
  if (activeClientIds.length > 0) {
    const clients = payload.clients || [];
    const summaryLines = activeClientIds.map((cid) => {
      const client = clients.find((c) => c && c.id === cid);
      const name = client ? client.name : "Unknown client";
      const a = clientActivity[cid];
      const parts = [];
      if (a.invoices) parts.push(a.invoices + " فاتورة");
      if (a.expenses) parts.push(a.expenses + " مصروف");
      if (a.bankImports) parts.push(a.bankImports + " استيراد كشف بنكي");
      return name + ": " + parts.join("، ");
    });
    const shown = summaryLines.slice(0, 6);
    const bodyText = shown.join(" · ") + (summaryLines.length > 6 ? " · +" + (summaryLines.length - 6) + " عميل آخر" : "");
    for (const admin of admins) {
      if (admin.status !== "active") continue;
      await sendPushToAccount(env, "admin", admin.id, {
        title: "ANB — ملخص نشاط العملاء (أمس)",
        body: bodyText
      });
    }
  }
}
async function signToken(claims, secret) {
  const payloadB64 = b64urlEncode(JSON.stringify(claims));
  const sig = await hmacSign(payloadB64, secret);
  return `${payloadB64}.${sig}`;
}
async function requireValidToken(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const m = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!m) return { ok: false, error: "Missing Authorization header" };
  const token = m[1];
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "Malformed token" };
  const [payloadB64, sig] = parts;
  const expectedSig = await hmacSign(payloadB64, env.R2_HMAC_SECRET);
  if (!timingSafeEqual(sig, expectedSig)) return { ok: false, error: "Invalid token signature" };
  let payload;
  try { payload = JSON.parse(b64urlDecode(payloadB64)); } catch { return { ok: false, error: "Malformed token payload" }; }
  if (!payload.exp || Date.now() > payload.exp) return { ok: false, error: "Token expired" };
  if (payload.pwv) {
    try {
      const table = payload.at === "admin" ? "tbl_admins" : "tbl_clients";
      const row = await env.DB.prepare(`SELECT payload FROM ${table} WHERE id = ?`).bind(payload.aid).first();
      if (row) {
        const currentAccount = JSON.parse(row.payload);
        if (currentAccount.pwv && currentAccount.pwv !== payload.pwv) {
          return { ok: false, error: "Session invalidated — password was changed, please sign in again" };
        }
      }
    } catch (e) {}
  }
  return { ok: true, payload };
}
async function hmacSign(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return bufToHex(sigBuf);
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function bufToHex(buf) { return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join(""); }
function b64urlEncode(str) { return btoa(unescape(encodeURIComponent(str))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return decodeURIComponent(escape(atob(str)));
}
function sanitizeFileName(name) { return name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(-120); }
async function isRateLimited(env, bucketKey) {
  if (!env.RATE_LIMIT_KV) return isRateLimitedLegacy(bucketKey);
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
  if (raw) { try { data = JSON.parse(raw); } catch {} }
  const now = Date.now();
  data.timestamps = (data.timestamps || []).filter((t) => now - t < MAX_ATTEMPTS_WINDOW_MS);
  data.timestamps.push(now);
  const ttlSeconds = Math.ceil(MAX_ATTEMPTS_WINDOW_MS / 1e3) + 60;
  await env.RATE_LIMIT_KV.put(bucketKey, JSON.stringify(data), { expirationTtl: ttlSeconds });
}
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
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-File-Name",
    "Access-Control-Max-Age": "86400",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store"
  };
}
function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...cors } });
}

/* ══════════════════════════════════════════════════════════════════════
   ANB AutoStack — Phase 1, Feature 1: Magic-Link Contract Signing
   Lets a client review and sign their service agreement from an emailed
   link, with no login required. Mirrors the existing in-app checkbox-based
   e-signature flow (signAgreementInApp on the frontend) exactly, just
   authenticated by a single-use token instead of a login session.
   ══════════════════════════════════════════════════════════════════════ */

// توليد توكن آمن تشفيريًا (32 بايت = 64 حرف hex) — أقوى بكثير من UID()+UID()
// المُولَّد بالواجهة الأمامية أصلًا (Math.random، غير آمن تشفيريًا)؛ يُستبدَل
// بهذا التوكن الجديد في كل مرة يُرسَل فيها رابط التوقيع، فتُلغى صلاحية أي
// رابط سابق تلقائيًا عند إعادة الإرسال
function generateSecureToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bufToHex(bytes);
}

function escapeHtmlServer(str) {
  return String(str == null ? "" : str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

async function sendResendEmail(env, { to, subject, html, text, from }) {
  if (!env.RESEND_API_KEY) return { ok: false, error: "email_not_configured" };
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + env.RESEND_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: from || "ANB Financial Services <info@anbfinancial.nl>",
        to: [to],
        subject,
        html,
        text
      })
    });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: (data && (data.message || data.name)) || "send_failed" };
    return { ok: true, id: data.id };
  } catch (err) {
    return { ok: false, error: String((err && err.message) || err) };
  }
}

// محتوى الإيميل بثلاث لغات - النص القانوني للعقد نفسه يبقى دائمًا بالهولندية
// (كما هو معتاد بعقود الخدمات الهولندية)، لكن نص الإيميل الحامل للرابط يُكتب
// بلغة العميل المفضَّلة المحفوظة على حسابه (client.preferredLang)، مع تنويه
// صريح بكل لغة أن نص العقد نفسه هولندي دائمًا بغض النظر عن هذا الإعداد
const SIGNING_EMAIL_CONTENT = {
  nl: {
    subject: "ANB Financial Services \u2014 Uw contract is klaar voor ondertekening",
    greeting: (name) => `Beste ${name},`,
    introHtml: "Uw dienstverleningsovereenkomst met <strong>ANB Financial Services</strong> is klaar voor beoordeling en ondertekening.",
    introText: "Uw dienstverleningsovereenkomst met ANB Financial Services is klaar voor beoordeling en ondertekening.",
    instruction: "Klik op onderstaande knop om het contract te bekijken en elektronisch te ondertekenen \u2014 geen inloggen nodig.",
    instructionText: "Open onderstaande link om het contract te bekijken en elektronisch te ondertekenen \u2014 geen inloggen nodig:",
    button: "Bekijk & Onderteken Overeenkomst",
    dutchNote: "Let op: de overeenkomst zelf is, zoals gebruikelijk bij Nederlandse dienstverleningscontracten, opgesteld in het Nederlands.",
    validity: "Deze link is 7 dagen geldig en kan slechts \u00E9\u00E9n keer worden gebruikt.",
    contact: "Als u deze e-mail niet verwachtte, neem dan contact met ons op via info@anbfinancial.nl.",
    regards: "Met vriendelijke groet,",
    dir: "ltr",
    align: "left"
  },
  en: {
    subject: "ANB Financial Services \u2014 Contract Ready for Your Signature",
    greeting: (name) => `Dear ${name},`,
    introHtml: "Your service agreement with <strong>ANB Financial Services</strong> is ready for review and signature.",
    introText: "Your service agreement with ANB Financial Services is ready for review and signature.",
    instruction: "Please click the button below to review the contract and sign electronically \u2014 no login required.",
    instructionText: "Open the link below to review the contract and sign electronically \u2014 no login required:",
    button: "Review & Sign Agreement",
    dutchNote: "Please note: the agreement itself is written in Dutch, as is standard for Dutch service contracts.",
    validity: "This link is valid for 7 days and can only be used once.",
    contact: "If you did not expect this email, please contact us at info@anbfinancial.nl.",
    regards: "Kind regards,",
    dir: "ltr",
    align: "left"
  },
  ar: {
    subject: "ANB Financial Services \u2014 \u0639\u0642\u062F\u0643 \u062C\u0627\u0647\u0632 \u0644\u0644\u062A\u0648\u0642\u064A\u0639",
    greeting: (name) => `\u0639\u0632\u064A\u0632\u064A/\u0639\u0632\u064A\u0632\u062A\u064A ${name}\u060C`,
    introHtml: "\u0627\u062A\u0641\u0627\u0642\u064A\u0629 \u0627\u0644\u062E\u062F\u0645\u0629 \u0627\u0644\u062E\u0627\u0635\u0629 \u0628\u0643 \u0645\u0639 <strong>ANB Financial Services</strong> \u062C\u0627\u0647\u0632\u0629 \u0644\u0644\u0645\u0631\u0627\u062C\u0639\u0629 \u0648\u0627\u0644\u062A\u0648\u0642\u064A\u0639.",
    introText: "\u0627\u062A\u0641\u0627\u0642\u064A\u0629 \u0627\u0644\u062E\u062F\u0645\u0629 \u0627\u0644\u062E\u0627\u0635\u0629 \u0628\u0643 \u0645\u0639 ANB Financial Services \u062C\u0627\u0647\u0632\u0629 \u0644\u0644\u0645\u0631\u0627\u062C\u0639\u0629 \u0648\u0627\u0644\u062A\u0648\u0642\u064A\u0639.",
    instruction: "\u064A\u0631\u062C\u0649 \u0627\u0644\u0636\u063A\u0637 \u0639\u0644\u0649 \u0627\u0644\u0632\u0631 \u0623\u062F\u0646\u0627\u0647 \u0644\u0645\u0631\u0627\u062C\u0639\u0629 \u0627\u0644\u0639\u0642\u062F \u0648\u062A\u0648\u0642\u064A\u0639\u0647 \u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A\u064B\u0627 \u2014 \u0628\u0644\u0627 \u062D\u0627\u062C\u0629 \u0644\u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644.",
    instructionText: "\u0627\u0641\u062A\u062D \u0627\u0644\u0631\u0627\u0628\u0637 \u0623\u062F\u0646\u0627\u0647 \u0644\u0645\u0631\u0627\u062C\u0639\u0629 \u0627\u0644\u0639\u0642\u062F \u0648\u062A\u0648\u0642\u064A\u0639\u0647 \u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A\u064B\u0627 \u2014 \u0628\u0644\u0627 \u062D\u0627\u062C\u0629 \u0644\u062A\u0633\u062C\u064A\u0644 \u0627\u0644\u062F\u062E\u0648\u0644:",
    button: "\u0645\u0631\u0627\u062C\u0639\u0629 \u0648\u062A\u0648\u0642\u064A\u0639 \u0627\u0644\u0627\u062A\u0641\u0627\u0642\u064A\u0629",
    dutchNote: "\u0645\u0644\u0627\u062D\u0638\u0629: \u0646\u0635 \u0627\u0644\u0639\u0642\u062F \u0646\u0641\u0633\u0647 \u0645\u0643\u062A\u0648\u0628 \u0628\u0627\u0644\u0644\u063A\u0629 \u0627\u0644\u0647\u0648\u0644\u0646\u062F\u064A\u0629\u060C \u0643\u0645\u0627 \u0647\u0648 \u0645\u0639\u062A\u0627\u062F \u0641\u064A \u0639\u0642\u0648\u062F \u0627\u0644\u062E\u062F\u0645\u0627\u062A \u0627\u0644\u0647\u0648\u0644\u0646\u062F\u064A\u0629.",
    validity: "\u0647\u0630\u0627 \u0627\u0644\u0631\u0627\u0628\u0637 \u0635\u0627\u0644\u062D \u0644\u0645\u062F\u0629 7 \u0623\u064A\u0627\u0645 \u0648\u064A\u0645\u0643\u0646 \u0627\u0633\u062A\u062E\u062F\u0627\u0645\u0647 \u0645\u0631\u0629 \u0648\u0627\u062D\u062F\u0629 \u0641\u0642\u0637.",
    contact: "\u0625\u0630\u0627 \u0644\u0645 \u062A\u0643\u0646 \u062A\u062A\u0648\u0642\u0639 \u0647\u0630\u0627 \u0627\u0644\u0628\u0631\u064A\u062F\u060C \u064A\u0631\u062C\u0649 \u0627\u0644\u062A\u0648\u0627\u0635\u0644 \u0645\u0639\u0646\u0627 \u0639\u0628\u0631 info@anbfinancial.nl.",
    regards: "\u0645\u0639 \u0623\u0637\u064A\u0628 \u0627\u0644\u062A\u062D\u064A\u0627\u062A\u060C",
    dir: "rtl",
    align: "right"
  }
};

function buildSigningEmailHtml(client, signUrl, lang) {
  const c = SIGNING_EMAIL_CONTENT[lang] || SIGNING_EMAIL_CONTENT.nl;
  const name = escapeHtmlServer(client.contactPerson || client.name || "");
  return `<!DOCTYPE html><html dir="${c.dir}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif" dir="${c.dir}">
<table width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f4f4f4"><tr><td align="center" style="padding:32px 16px">
<table width="600" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="border-radius:8px;overflow:hidden">
<tr><td bgcolor="#0A2218" style="padding:24px;text-align:center">
<span style="font-size:20px;font-weight:bold;color:#C89010;font-family:Arial,Helvetica,sans-serif">ANB Financial Services</span>
</td></tr>
<tr><td style="padding:32px 28px;font-size:14px;line-height:1.8;color:#222222;font-family:Arial,Helvetica,sans-serif;text-align:${c.align}" dir="${c.dir}">
<p>${c.greeting(name)}</p>
<p>${c.introHtml}</p>
<p>${c.instruction}</p>
<table cellpadding="0" cellspacing="0" border="0" style="margin:24px 0"><tr><td bgcolor="#C89010" style="border-radius:6px">
<a href="${signUrl}" style="display:inline-block;padding:14px 28px;font-size:14px;font-weight:bold;color:#0A2218;text-decoration:none;font-family:Arial,Helvetica,sans-serif">${c.button}</a>
</td></tr></table>
<p style="font-size:12.5px;color:#555555">${c.dutchNote}</p>
<p style="font-size:12px;color:#777777">${c.validity} ${c.contact}</p>
<p style="margin-top:24px">${c.regards}<br/>ANB Financial Services</p>
</td></tr>
<tr><td bgcolor="#f4f4f4" style="padding:16px;text-align:center;font-size:11px;color:#999999;font-family:Arial,Helvetica,sans-serif">ANB Financial Services &middot; anbfinancial.nl</td></tr>
</table></td></tr></table>
</body></html>`;
}

function buildSigningEmailText(client, signUrl, lang) {
  const c = SIGNING_EMAIL_CONTENT[lang] || SIGNING_EMAIL_CONTENT.nl;
  const name = client.contactPerson || client.name || "";
  return `${c.greeting(name)}

${c.introText}

${c.instructionText}
${signUrl}

${c.dutchNote}

${c.validity} ${c.contact}

${c.regards}
ANB Financial Services`;
}

// GET /agreement/by-token?token=... — عام بلا أي مصادقة (التوكن نفسه هو صك الدخول)
// يُعيد فقط لقطة بيانات العميل اللازمة لعرض نص العقد، لا شيء آخر من قاعدة البيانات
async function handleAgreementByToken(request, env, cors, url) {
  const token = url.searchParams.get("token");
  if (!token) return json({ error: "Missing token" }, 400, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const agreement = (cloud.payload.serviceAgreements || []).find((a) => a && a.token === token);
  if (!agreement) return json({ error: "invalid_token" }, 404, cors);
  if (["client_signed", "active", "rejected", "client_rejected"].includes(agreement.status)) {
    return json({ status: agreement.status, alreadyResolved: true }, 200, cors);
  }
  if (!agreement.tokenExpiresAt || Date.now() > agreement.tokenExpiresAt) {
    return json({ error: "expired" }, 410, cors);
  }
  return json({ status: agreement.status, clientData: agreement.clientData }, 200, cors);
}

// POST /agreement/sign-by-token — عام بلا أي مصادقة، نفس منطق signAgreementInApp
// بالضبط (checkbox-based e-signature) لكن عبر رابط بريد بدل الجلسة المسجَّلة
async function handleAgreementSignByToken(request, env, cors) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400, cors);
  }
  const { token, documentHash } = body || {};
  if (!token) return json({ error: "Missing token" }, 400, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const agreements = cloud.payload.serviceAgreements || [];
  const idx = agreements.findIndex((a) => a && a.token === token);
  if (idx === -1) return json({ error: "invalid_token" }, 404, cors);
  const agreement = agreements[idx];
  if (["client_signed", "active", "rejected", "client_rejected"].includes(agreement.status)) {
    return json({ error: "already_resolved", status: agreement.status }, 409, cors);
  }
  if (!agreement.tokenExpiresAt || Date.now() > agreement.tokenExpiresAt) {
    return json({ error: "expired" }, 410, cors);
  }
  const client = agreement.clientData || {};
  agreement.status = "client_signed";
  agreement.clientSignDate = (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
  agreement.clientSignature = (client.contactPerson || "") + " (" + (client.email || "") + ")";
  agreement.signatureAudit = {
    documentHash: documentHash || "",
    userAgent: request.headers.get("User-Agent") || "",
    ip: request.headers.get("CF-Connecting-IP") || "",
    signedAtIso: (/* @__PURE__ */ new Date()).toISOString(),
    agreedTerms: true,
    agreedPrivacy: true,
    viaMagicLink: true
  };
  // ⚠️ إبطال فوري للتوكن بعد الاستخدام — رابط لمرة واحدة، حتى لو أُعيد فتحه لاحقًا
  agreement.tokenExpiresAt = 0;
  agreements[idx] = agreement;
  const docs = cloud.payload.docs || [];
  const docIdx = docs.findIndex((d) => d && d.agreementId === agreement.id);
  if (docIdx !== -1) docs[docIdx].status = "client_signed";
  await writeCloudPayload(env, { ...cloud.payload, serviceAgreements: agreements, docs });
  // إشعار الأدمن بالبريد أن العميل وقّع — لإغلاق الحلقة دون تفقّد التطبيق يدويًا
  // (لا نُفشل عملية التوقيع نفسها لو تعذّر إرسال هذا الإشعار فقط)
  try {
    await sendResendEmail(env, {
      to: env.ADMIN_NOTIFY_EMAIL || "info@anbfinancial.nl",
      subject: "\u2713 " + (client.name || "Client") + " signed their agreement",
      html: `<p>${escapeHtmlServer(client.name || "")} has signed their service agreement via the emailed link.</p><p>Log in to ANB FinAdmin Pro to review and finalize.</p>`,
      text: (client.name || "") + " has signed their service agreement via the emailed link. Log in to ANB FinAdmin Pro to review and finalize."
    });
  } catch (e) {
  }
  return json({ ok: true }, 200, cors);
}

// POST /agreement/send-signing-link — أدمن فقط، يُولِّد توكن جديد آمن (يُبطل أي
// رابط سابق تلقائيًا) ويرسل إيميل التوقيع عبر Resend
async function handleSendSigningLink(request, env, cors) {
  const auth = await requireValidToken(request, env);
  if (!auth.ok) return json({ error: auth.error }, 401, cors);
  if (auth.payload.at !== "admin") return json({ error: "Admin access required" }, 403, cors);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400, cors);
  }
  const { agreementId } = body || {};
  if (!agreementId) return json({ error: "agreementId is required" }, 400, cors);
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return json({ error: "Could not reach database" }, 502, cors);
  const agreements = cloud.payload.serviceAgreements || [];
  const idx = agreements.findIndex((a) => a && a.id === agreementId);
  if (idx === -1) return json({ error: "Agreement not found" }, 404, cors);
  if (!env.RESEND_API_KEY) return json({ error: "email_not_configured", message: "RESEND_API_KEY is not set on the Worker yet." }, 503, cors);
  const agreement = agreements[idx];
  const client = agreement.clientData || {};
  if (!client.email) return json({ error: "no_client_email" }, 400, cors);
  agreement.token = generateSecureToken();
  agreement.tokenExpiresAt = Date.now() + 7 * 24 * 3600 * 1e3;
  agreements[idx] = agreement;
  await writeCloudPayload(env, { ...cloud.payload, serviceAgreements: agreements });
  const signUrl = (env.APP_BASE_URL || "https://app.anbfinancial.nl") + "/?sign=" + agreement.token;
  // ⭐ لغة الإيميل تتبع تفضيل العميل المحفوظ (preferredLang) - نص العقد نفسه
  // يبقى دائمًا بالهولندية بغض النظر عن هذا الإعداد (يُذكَر ذلك صراحة داخل
  // نص الإيميل بكل لغة أيضًا)
  const lang = (client.preferredLang === "en" || client.preferredLang === "ar") ? client.preferredLang : "nl";
  const emailContent = SIGNING_EMAIL_CONTENT[lang];
  const emailResult = await sendResendEmail(env, {
    to: client.email,
    subject: emailContent.subject,
    html: buildSigningEmailHtml(client, signUrl, lang),
    text: buildSigningEmailText(client, signUrl, lang)
  });
  if (!emailResult.ok) return json({ error: "email_send_failed", message: emailResult.error }, 502, cors);
  return json({ ok: true }, 200, cors);
}

/* ══════════════════════════════════════════════════════════════════════
   ANB AutoStack — Phase 1: Monthly Bank Statement & Receipts Reminder
   Runs on the 1st of every month (cron: "0 11 1 * *" — remember to add
   this exact cron expression to the Worker's Triggers in the Cloudflare
   dashboard, or to the "triggers.crons" array in wrangler config, same
   as the two existing daily crons). Emails every active client a
   reminder, in their preferred language, to (1) email last month's bank
   statement export and (2) upload last month's expense receipt photos
   directly in the app.
   ══════════════════════════════════════════════════════════════════════ */

const MONTH_NAMES = {
  nl: ["januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober", "november", "december"],
  en: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"],
  ar: ["\u064A\u0646\u0627\u064A\u0631", "\u0641\u0628\u0631\u0627\u064A\u0631", "\u0645\u0627\u0631\u0633", "\u0623\u0628\u0631\u064A\u0644", "\u0645\u0627\u064A\u0648", "\u064A\u0648\u0646\u064A\u0648", "\u064A\u0648\u0644\u064A\u0648", "\u0623\u063A\u0633\u0637\u0633", "\u0633\u0628\u062A\u0645\u0628\u0631", "\u0623\u0643\u062A\u0648\u0628\u0631", "\u0646\u0648\u0641\u0645\u0628\u0631", "\u062F\u064A\u0633\u0645\u0628\u0631"]
};

function formatPrevMonthName(lang) {
  const now = /* @__PURE__ */ new Date();
  const prevMonthDate = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const names = MONTH_NAMES[lang] || MONTH_NAMES.nl;
  return names[prevMonthDate.getMonth()] + " " + prevMonthDate.getFullYear();
}

const MONTHLY_REMINDER_CONTENT = {
  nl: {
    subjectPrefix: "ANB \u2014 Herinnering: bankafschriften & bonnetjes voor ",
    greeting: (name) => `Beste ${name},`,
    intro: (month) => `Het is weer zover! Zou u onderstaande gegevens voor <strong>${month}</strong> willen aanleveren, zodat wij uw administratie tijdig kunnen bijwerken?`,
    introText: (month) => `Het is weer zover! Zou u onderstaande gegevens voor ${month} willen aanleveren, zodat wij uw administratie tijdig kunnen bijwerken?`,
    item1Title: "1. Bankafschriften",
    item1Body: (month) => `Stuur het afschrift van ${month} per e-mail naar info@anbfinancial.nl.`,
    item2Title: "2. Bonnetjes / facturen",
    item2Body: (month) => `Upload foto's van uw uitgavenbonnetjes van ${month} rechtstreeks in de app, onder "Uitgaven".`,
    button: "Open ANB FinAdmin Pro",
    closing: "Alvast bedankt voor uw medewerking!",
    regards: "Met vriendelijke groet,",
    dir: "ltr",
    align: "left"
  },
  en: {
    subjectPrefix: "ANB \u2014 Reminder: bank statement & receipts for ",
    greeting: (name) => `Dear ${name},`,
    intro: (month) => `It's that time again! Could you please submit the following for <strong>${month}</strong> so we can keep your bookkeeping up to date?`,
    introText: (month) => `It's that time again! Could you please submit the following for ${month} so we can keep your bookkeeping up to date?`,
    item1Title: "1. Bank statement",
    item1Body: (month) => `Please email your ${month} bank statement export to info@anbfinancial.nl.`,
    item2Title: "2. Expense receipts",
    item2Body: (month) => `Please upload photos of your ${month} expense receipts directly in the app, under "Expenses".`,
    button: "Open ANB FinAdmin Pro",
    closing: "Thank you for your cooperation!",
    regards: "Kind regards,",
    dir: "ltr",
    align: "left"
  },
  ar: {
    subjectPrefix: "ANB \u2014 \u062A\u0630\u0643\u064A\u0631: \u0643\u0634\u0641 \u0627\u0644\u0628\u0646\u0643 \u0648\u0641\u0648\u0627\u062A\u064A\u0631 \u0627\u0644\u0645\u0635\u0627\u0631\u064A\u0641 \u0644\u0634\u0647\u0631 ",
    greeting: (name) => `\u0639\u0632\u064A\u0632\u064A/\u0639\u0632\u064A\u0632\u062A\u064A ${name}\u060C`,
    intro: (month) => `\u062D\u0627\u0646 \u0648\u0642\u062A \u0627\u0644\u062A\u062D\u062F\u064A\u062B \u0627\u0644\u0634\u0647\u0631\u064A! \u064A\u0631\u062C\u0649 \u062A\u0632\u0648\u064A\u062F\u0646\u0627 \u0628\u0627\u0644\u062A\u0627\u0644\u064A \u0639\u0646 \u0634\u0647\u0631 <strong>${month}</strong> \u062D\u062A\u0649 \u0646\u062A\u0645\u0643\u0646 \u0645\u0646 \u062A\u062D\u062F\u064A\u062B \u062D\u0633\u0627\u0628\u0627\u062A\u0643 \u0641\u064A \u0648\u0642\u062A\u0647\u0627:`,
    introText: (month) => `\u062D\u0627\u0646 \u0648\u0642\u062A \u0627\u0644\u062A\u062D\u062F\u064A\u062B \u0627\u0644\u0634\u0647\u0631\u064A! \u064A\u0631\u062C\u0649 \u062A\u0632\u0648\u064A\u062F\u0646\u0627 \u0628\u0627\u0644\u062A\u0627\u0644\u064A \u0639\u0646 \u0634\u0647\u0631 ${month} \u062D\u062A\u0649 \u0646\u062A\u0645\u0643\u0646 \u0645\u0646 \u062A\u062D\u062F\u064A\u062B \u062D\u0633\u0627\u0628\u0627\u062A\u0643 \u0641\u064A \u0648\u0642\u062A\u0647\u0627:`,
    item1Title: "1. \u0643\u0634\u0641 \u0627\u0644\u062D\u0633\u0627\u0628 \u0627\u0644\u0628\u0646\u0643\u064A",
    item1Body: (month) => `\u0623\u0631\u0633\u0644 \u0643\u0634\u0641 \u062D\u0633\u0627\u0628 \u0634\u0647\u0631 ${month} \u0639\u0628\u0631 \u0627\u0644\u0628\u0631\u064A\u062F \u0627\u0644\u0625\u0644\u0643\u062A\u0631\u0648\u0646\u064A \u0625\u0644\u0649 info@anbfinancial.nl.`,
    item2Title: "2. \u0641\u0648\u0627\u062A\u064A\u0631 \u0627\u0644\u0645\u0635\u0627\u0631\u064A\u0641",
    item2Body: (month) => `\u0627\u0631\u0641\u0639 \u0635\u0648\u0631 \u0641\u0648\u0627\u062A\u064A\u0631 \u0645\u0635\u0627\u0631\u064A\u0641\u0643 \u0644\u0634\u0647\u0631 ${month} \u0645\u0628\u0627\u0634\u0631\u0629 \u062F\u0627\u062E\u0644 \u0627\u0644\u062A\u0637\u0628\u064A\u0642\u060C \u062A\u062D\u062A \u0642\u0633\u0645 "\u0627\u0644\u0645\u0635\u0627\u0631\u064A\u0641".`,
    button: "\u0641\u062A\u062D ANB FinAdmin Pro",
    closing: "\u0634\u0627\u0643\u0631\u064A\u0646 \u0644\u0643 \u062A\u0639\u0627\u0648\u0646\u0643!",
    regards: "\u0645\u0639 \u0623\u0637\u064A\u0628 \u0627\u0644\u062A\u062D\u064A\u0627\u062A\u060C",
    dir: "rtl",
    align: "right"
  }
};

function buildMonthlyReminderHtml(client, monthLabel, lang) {
  const c = MONTHLY_REMINDER_CONTENT[lang] || MONTHLY_REMINDER_CONTENT.nl;
  const name = escapeHtmlServer(client.contactPerson || client.name || "");
  const appUrl = "https://app.anbfinancial.nl";
  return `<!DOCTYPE html><html dir="${c.dir}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif" dir="${c.dir}">
<table width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f4f4f4"><tr><td align="center" style="padding:32px 16px">
<table width="600" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="border-radius:8px;overflow:hidden">
<tr><td bgcolor="#0A2218" style="padding:24px;text-align:center">
<span style="font-size:20px;font-weight:bold;color:#C89010;font-family:Arial,Helvetica,sans-serif">ANB Financial Services</span>
</td></tr>
<tr><td style="padding:32px 28px;font-size:14px;line-height:1.8;color:#222222;font-family:Arial,Helvetica,sans-serif;text-align:${c.align}" dir="${c.dir}">
<p>${c.greeting(name)}</p>
<p>${c.intro(escapeHtmlServer(monthLabel))}</p>
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:20px 0"><tr><td style="background:#f7f7f5;border-radius:6px;padding:14px 16px;border-left:3px solid #C89010">
<div style="font-weight:bold;margin-bottom:4px">${c.item1Title}</div>
<div style="font-size:13px;color:#444444">${c.item1Body(escapeHtmlServer(monthLabel))}</div>
</td></tr></table>
<table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 20px"><tr><td style="background:#f7f7f5;border-radius:6px;padding:14px 16px;border-left:3px solid #C89010">
<div style="font-weight:bold;margin-bottom:4px">${c.item2Title}</div>
<div style="font-size:13px;color:#444444">${c.item2Body(escapeHtmlServer(monthLabel))}</div>
</td></tr></table>
<table cellpadding="0" cellspacing="0" border="0" style="margin:8px 0 24px"><tr><td bgcolor="#0A2218" style="border-radius:6px">
<a href="${appUrl}" style="display:inline-block;padding:12px 24px;font-size:13px;font-weight:bold;color:#C89010;text-decoration:none;font-family:Arial,Helvetica,sans-serif">${c.button}</a>
</td></tr></table>
<p>${c.closing}</p>
<p style="margin-top:16px">${c.regards}<br/>ANB Financial Services</p>
</td></tr>
<tr><td bgcolor="#f4f4f4" style="padding:16px;text-align:center;font-size:11px;color:#999999;font-family:Arial,Helvetica,sans-serif">ANB Financial Services &middot; anbfinancial.nl</td></tr>
</table></td></tr></table>
</body></html>`;
}

function buildMonthlyReminderText(client, monthLabel, lang) {
  const c = MONTHLY_REMINDER_CONTENT[lang] || MONTHLY_REMINDER_CONTENT.nl;
  const name = client.contactPerson || client.name || "";
  return `${c.greeting(name)}

${c.introText(monthLabel)}

${c.item1Title}
${c.item1Body(monthLabel)}

${c.item2Title}
${c.item2Body(monthLabel)}

https://app.anbfinancial.nl

${c.closing}

${c.regards}
ANB Financial Services`;
}

async function sendMonthlyDocumentReminders(env) {
  const cloud = await fetchCloudPayload(env);
  if (!cloud) return;
  const clients = cloud.payload.clients || [];
  for (const client of clients) {
    if (!client || client.id === "anb-self" || !client.email) continue;
    if (client.accountStatus === "suspended" || client.accountStatus === "cancelled") continue;
    const lang = (client.preferredLang === "en" || client.preferredLang === "ar") ? client.preferredLang : "nl";
    const monthLabel = formatPrevMonthName(lang);
    const content = MONTHLY_REMINDER_CONTENT[lang];
    try {
      await sendResendEmail(env, {
        to: client.email,
        subject: content.subjectPrefix + monthLabel,
        html: buildMonthlyReminderHtml(client, monthLabel, lang),
        text: buildMonthlyReminderText(client, monthLabel, lang)
      });
    } catch (e) {
    }
  }
}
