
require("dotenv").config();
require("express-async-errors");
const path = require("path");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const { PrismaClient, Prisma } = require("@prisma/client");
const cloudinary = require("cloudinary").v2;
const { Resend } = require("resend");
const bcrypt = require("bcryptjs");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const compression = require("compression");

// =============================================================================
// PRISMA CLIENT  (was config/db.js)
// =============================================================================

const prisma = global.__prisma || new PrismaClient();
if (process.env.NODE_ENV !== "production") {
  global.__prisma = prisma;
}

/** Reads the Director-editable platform name live, for every email. Falls
 * back sensibly if Settings hasn't been touched yet. */
async function getPlatformName() {
  const settings = await prisma.hotelSettings.findUnique({ where: { id: "main" } });
  return settings?.name || "Your Hotel";
}

// =============================================================================
// SETTINGS CACHE — the platform backbone. Same pattern as SystemSettings in
// the UYEH TECH marketplace codebase: an in-memory cache with a short TTL
// as a safety net, invalidated immediately on every save so changes are
// never stale for longer than one request.
// =============================================================================

let _settingsCache = null;   // cached settings object
let _settingsCacheTime = 0;  // epoch ms of last successful load
const SETTINGS_TTL_MS = 60_000; // 60 second safety-net TTL

/**
 * Canonical first-boot seed. Creates the ONE settings row with every field
 * at its schema default if it doesn't exist yet. Safe to call repeatedly —
 * upsert never duplicates, and never overwrites an existing row.
 */
async function ensureSettings() {
  return prisma.hotelSettings.upsert({
    where: { id: "main" },
    update: {}, // never touches an existing row — only fills in if missing
    create: { id: "main" }, // every other field uses its @default from the schema
  });
}

/**
 * Returns the current settings. First call (or after invalidation) hits
 * Postgres; subsequent calls within the TTL window return the in-memory
 * copy instantly. ALWAYS call this instead of prisma.hotelSettings.* directly.
 */
async function getSettings() {
  const now = Date.now();
  if (_settingsCache && now - _settingsCacheTime < SETTINGS_TTL_MS) {
    return _settingsCache;
  }

  let settings = await prisma.hotelSettings.findUnique({ where: { id: "main" } });
  if (!settings) settings = await ensureSettings();

  _settingsCache = settings;
  _settingsCacheTime = now;
  return settings;
}

/** Clears the in-memory cache. Must be called after every settings save —
 * already wired into the PATCH route in the next patch. */
function invalidateSettings() {
  _settingsCache = null;
  _settingsCacheTime = 0;
}

// =============================================================================
// UTIL: PAYSTACK  (was utils/paystack.js)
// =============================================================================

const PAYSTACK_BASE = "https://api.paystack.co";

function paystackSecretKey() {
  const key = process.env.PAYSTACK_SECRET_KEY;
  if (!key) throw Object.assign(new Error("Paystack is not configured (PAYSTACK_SECRET_KEY missing)"), { status: 500 });
  return key;
}

/** Naira amount -> kobo (Paystack's smallest unit), as an integer. */
function toKobo(amountNaira) {
  return Math.round(Number(amountNaira) * 100);
}

/**
 * Starts a Paystack transaction. Returns { authorization_url, access_code,
 * reference } — redirect the guest to authorization_url to complete payment.
 */
async function initializeTransaction({ email, amountNaira, reference, callbackUrl, metadata, subaccountCode }) {
  const res = await fetch(`${PAYSTACK_BASE}/transaction/initialize`, {
    method: "POST",
    headers: { Authorization: `Bearer ${paystackSecretKey()}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      email, amount: toKobo(amountNaira), reference,
      callback_url: callbackUrl, metadata,
      // Routes settlement straight to the branch's own bank account. If a
      // branch hasn't been set up with a subaccount yet, this is omitted
      // and the payment falls back to settling in the main account — see
      // the two call sites below for the warning this produces.
      ...(subaccountCode ? { subaccount: subaccountCode, bearer: "subaccount" } : {}),
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.status) {
    throw Object.assign(new Error(data.message || "Paystack initialization failed"), { status: 502 });
  }
  return data.data; // { authorization_url, access_code, reference }
}

/** Confirms a transaction directly with Paystack (used as a fallback to
 * the webhook, e.g. when the guest is redirected back to a success page). */
async function verifyTransaction(reference) {
  const res = await fetch(`${PAYSTACK_BASE}/transaction/verify/${encodeURIComponent(reference)}`, {
    headers: { Authorization: `Bearer ${paystackSecretKey()}` },
  });
  const data = await res.json();
  if (!res.ok || !data.status) {
    throw Object.assign(new Error(data.message || "Paystack verification failed"), { status: 502 });
  }
  return data.data; // { status: "success"|"failed"|..., amount, reference, ... }
}

/** Refunds a previously successful Paystack transaction, fully (omit
 * amountNaira) or partially. This is the piece that was missing entirely —
 * without this, "refund" only ever meant flipping a DB status. */
async function refundTransaction(reference, amountNaira, reason) {
  const res = await fetch(`${PAYSTACK_BASE}/refund`, {
    method: "POST",
    headers: { Authorization: `Bearer ${paystackSecretKey()}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      transaction: reference,
      ...(amountNaira ? { amount: toKobo(amountNaira) } : {}),
      ...(reason ? { customer_note: reason, merchant_note: reason } : {}),
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.status) {
    throw Object.assign(new Error(data.message || "Paystack refund failed"), { status: 502 });
  }
  return data.data; // { transaction_reference, status, amount, ... }
}

/** Paystack signs webhook payloads with HMAC-SHA512 of the raw body, using
 * your secret key. Must be checked against the RAW request body — not the
 * parsed JSON — so the webhook route is mounted with express.raw() before
 * the global express.json() middleware (see app wiring at the bottom). */
function isValidWebhookSignature(rawBody, signatureHeader) {
  if (!signatureHeader) return false;
  const hash = crypto.createHmac("sha512", paystackSecretKey()).update(rawBody).digest("hex");
  return hash === signatureHeader;
}

/** Nigerian bank list (code + name) for the Director's branch-payout setup UI. */
async function listPaystackBanks() {
  const res = await fetch(`${PAYSTACK_BASE}/bank?currency=NGN`, {
    headers: { Authorization: `Bearer ${paystackSecretKey()}` },
  });
  const data = await res.json();
  if (!res.ok || !data.status) {
    throw Object.assign(new Error(data.message || "Could not fetch bank list"), { status: 502 });
  }
  return data.data; // [{ name, code, ... }]
}

/** Confirms an account number actually belongs to the name on file, BEFORE
 * a subaccount is created — Paystack does not guarantee payouts if the
 * account details are wrong, so this check happens up front. */
async function resolvePaystackAccount(accountNumber, bankCode) {
  const res = await fetch(`${PAYSTACK_BASE}/bank/resolve?account_number=${encodeURIComponent(accountNumber)}&bank_code=${encodeURIComponent(bankCode)}`, {
    headers: { Authorization: `Bearer ${paystackSecretKey()}` },
  });
  const data = await res.json();
  if (!res.ok || !data.status) {
    throw Object.assign(new Error(data.message || "Could not verify this account number"), { status: 400 });
  }
  return data.data; // { account_number, account_name, bank_id }
}

/** Creates a Paystack Subaccount for a branch. percentage_charge: 0 means
 * 100% of every payment settles to the branch — the company keeps nothing
 * per-transaction, by design. */
async function createPaystackSubaccount({ businessName, bankCode, accountNumber }) {
  const res = await fetch(`${PAYSTACK_BASE}/subaccount`, {
    method: "POST",
    headers: { Authorization: `Bearer ${paystackSecretKey()}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      business_name: businessName,
      settlement_bank: bankCode,
      account_number: accountNumber,
      percentage_charge: 0,
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.status) {
    throw Object.assign(new Error(data.message || "Could not create Paystack subaccount"), { status: 502 });
  }
  return data.data; // { subaccount_code, account_name, ... }
}

/** Same as createPaystackSubaccount, but updates an existing one — used when
 * a branch needs to change its payout bank account later. */
async function updatePaystackSubaccount(subaccountCode, { businessName, bankCode, accountNumber }) {
  const res = await fetch(`${PAYSTACK_BASE}/subaccount/${encodeURIComponent(subaccountCode)}`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${paystackSecretKey()}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      business_name: businessName,
      settlement_bank: bankCode,
      account_number: accountNumber,
      percentage_charge: 0,
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.status) {
    throw Object.assign(new Error(data.message || "Could not update Paystack subaccount"), { status: 502 });
  }
  return data.data;
}

// =============================================================================
// UTIL: STRIPE  (utils/stripe.js) — secondary/international checkout.
// See note at top of patch.md: Stripe does not support direct merchant
// accounts for Nigerian-registered businesses, so Connect payouts to a
// branch only work if that branch's entity is registered somewhere Stripe
// supports. Until then every Stripe payment settles to the platform
// account, same fallback behavior as an unconfigured Paystack subaccount.
// =============================================================================

const StripeSDK = require("stripe");
let _stripe = null;

function stripeClient() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw Object.assign(new Error("Stripe is not configured (STRIPE_SECRET_KEY missing)"), { status: 500 });
  if (!_stripe) _stripe = new StripeSDK(key);
  return _stripe;
}

/** Smallest-unit conversion — Stripe wants the minor unit for whatever
 * currency is passed (kobo for NGN, cents for USD, etc). Naira/NGN follows
 * the same x100 rule as most Stripe-supported currencies. */
function toMinorUnit(amount) {
  return Math.round(Number(amount) * 100);
}

/**
 * Starts a Stripe Checkout Session. Returns { id, url } — redirect the
 * guest to `url` to complete payment. Mirrors initializeTransaction()'s
 * shape so the two providers can be called interchangeably by the
 * controllers below.
 */
async function createStripeCheckoutSession({ email, amount, currency, reference, successUrl, cancelUrl, metadata, connectedAccountId }) {
  const stripe = stripeClient();
  const session = await stripe.checkout.sessions.create(
    {
      mode: "payment",
      customer_email: email,
      client_reference_id: reference,
      line_items: [
        {
          price_data: {
            currency: (currency || "usd").toLowerCase(),
            product_data: { name: metadata?.description || "Payment" },
            unit_amount: toMinorUnit(amount),
          },
          quantity: 1,
        },
      ],
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: { reference, ...metadata },
      payment_intent_data: {
        metadata: { reference, ...metadata },
        // Destination charge — only applies once a branch has a real
        // Connect account. percentage 0 == 100% to the branch, same
        // no-platform-cut policy as the Paystack subaccounts.
        ...(connectedAccountId ? { transfer_data: { destination: connectedAccountId }, application_fee_amount: 0 } : {}),
      },
    },
  );
  return { id: session.id, url: session.url };
}

/** Fallback verification when the guest is redirected back to a success
 * page before the webhook has landed — mirrors verifyTransaction(). */
async function retrieveStripeSession(sessionId) {
  const stripe = stripeClient();
  const session = await stripe.checkout.sessions.retrieve(sessionId, { expand: ["payment_intent"] });
  return session; // session.payment_status: "paid" | "unpaid" | "no_payment_required"
}

/** Refunds a previously successful Stripe PaymentIntent, fully (omit
 * amount) or partially — mirrors refundTransaction(). */
async function refundStripePayment(paymentIntentId, amount, reason) {
  const stripe = stripeClient();
  const refund = await stripe.refunds.create({
    payment_intent: paymentIntentId,
    ...(amount ? { amount: toMinorUnit(amount) } : {}),
    ...(reason ? { reason: "requested_by_customer", metadata: { note: reason } } : {}),
  });
  return refund;
}

/** Stripe signs webhook payloads with its own scheme (t=…,v1=…) verified
 * via stripe.webhooks.constructEvent — NOT a plain HMAC compare like
 * Paystack's isValidWebhookSignature. Must be called with the RAW body,
 * same express.raw() requirement as the Paystack webhook route. */
function constructStripeEvent(rawBody, signatureHeader) {
  const stripe = stripeClient();
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) throw Object.assign(new Error("Stripe webhook secret not configured"), { status: 500 });
  return stripe.webhooks.constructEvent(rawBody, signatureHeader, secret); // throws on bad signature
}

/** Creates a Stripe Express connected account for a branch and returns an
 * onboarding link. Unlike Paystack's resolve-account-then-create-subaccount
 * flow, Stripe Connect onboarding is a hosted flow the Director completes
 * on Stripe's own site — there's no server-side bank-resolve equivalent. */
async function createStripeConnectedAccount({ branchName, email, country }) {
  const stripe = stripeClient();
  const account = await stripe.accounts.create({
    type: "express",
    country: country || "US", // Nigerian branches: see note at top of file
    email,
    business_type: "company",
    business_profile: { name: branchName },
    capabilities: { card_payments: { requested: true }, transfers: { requested: true } },
  });
  const link = await stripe.accountLinks.create({
    account: account.id,
    refresh_url: process.env.STRIPE_CONNECT_REFRESH_URL,
    return_url: process.env.STRIPE_CONNECT_RETURN_URL,
    type: "account_onboarding",
  });
  return { accountId: account.id, onboardingUrl: link.url };
}

async function getStripeAccountStatus(accountId) {
  const stripe = stripeClient();
  const account = await stripe.accounts.retrieve(accountId);
  return { chargesEnabled: account.charges_enabled, payoutsEnabled: account.payouts_enabled, detailsSubmitted: account.details_submitted };
}

// =============================================================================
// UTIL: CLOUDINARY  (was utils/cloudinary.js)
// =============================================================================

let cloudinaryConfigured = false;
function ensureCloudinaryConfigured() {
  if (cloudinaryConfigured) return;
  if (!process.env.CLOUDINARY_CLOUD_NAME) {
    throw Object.assign(new Error("Cloudinary is not configured (CLOUDINARY_CLOUD_NAME missing)"), { status: 500 });
  }
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
  cloudinaryConfigured = true;
}

/** Uploads a Buffer (e.g. from multer's memoryStorage) to Cloudinary and
 * resolves with the secure URL. `folder` keeps uploads organized, e.g.
 * "Uyeh-hotel/room-types" or "Uyeh-hotel/events". */
function uploadBuffer(buffer, folder) {
  ensureCloudinaryConfigured();
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream({ folder }, (err, result) => {
      if (err) return reject(err);
      resolve(result.secure_url);
    });
    stream.end(buffer);
  });
}

/** Cloudinary stores no public_id column on RoomType/Event — only the
 * secure_url. Pulls the public_id back out of a Cloudinary URL so we can
 * actually delete the asset (not just unlink it from the DB array). */
function extractCloudinaryPublicId(url) {
  const match = /\/upload\/(?:v\d+\/)?(.+)\.[a-zA-Z0-9]+(?:\?.*)?$/.exec(url || "");
  return match ? match[1] : null;
}

/** Deletes a Cloudinary asset by its stored secure_url and purges it from
 * the CDN edge cache (`invalidate: true`) — same pattern as the UYEH TECH
 * marketplace's deleteFromCloudinary helper. Never throws into the caller;
 * a failed cleanup shouldn't block the DB update, it just leaves the file
 * orphaned on Cloudinary, logged for later manual cleanup. */
async function deleteFromCloudinaryByUrl(url) {
  const publicId = extractCloudinaryPublicId(url);
  if (!publicId) return;
  try {
    ensureCloudinaryConfigured();
    await cloudinary.uploader.destroy(publicId, { invalidate: true });
  } catch (err) {
    console.error(`[cloudinary] failed to delete ${publicId}:`, err.message);
  }
}

// =============================================================================
// EXCHANGE RATES — live currency conversion for guest-facing prices.
// Same 1-hour in-memory cache pattern as getSettings() above. Falls back to
// 1:1 (no conversion) if EXCHANGE_RATE_API_KEY isn't set or the API call
// fails, so pricing never breaks — it just stops converting.
// =============================================================================

let _ratesCache = null;   // { USD: 1, NGN: 1600.5, GBP: 0.79, ... }
let _ratesCacheAt = 0;
const RATES_TTL_MS = 60 * 60 * 1000; // 1 hour

/** Fetch (or return cached) exchange rates from ExchangeRate-API. Base is
 * always USD; the flat map lets you convert between any two currencies it
 * returns via convertCurrency() below. */
async function getExchangeRates() {
  const now = Date.now();
  if (_ratesCache && now - _ratesCacheAt < RATES_TTL_MS) return _ratesCache;

  const apiKey = process.env.EXCHANGE_RATE_API_KEY;
  if (!apiKey) {
    console.warn("⚠️  EXCHANGE_RATE_API_KEY not set — currency conversion disabled, using 1:1 rates");
    return { USD: 1 };
  }

  try {
    const url = `https://v6.exchangerate-api.com/v6/${apiKey}/latest/USD`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
    const data = await res.json();

    if (data?.result !== "success") {
      throw new Error(`ExchangeRate-API error: ${data?.["error-type"] || "unknown"}`);
    }

    _ratesCache = data.conversion_rates; // { USD: 1, NGN: 1600, GBP: 0.79, ... }
    _ratesCacheAt = now;
    return _ratesCache;
  } catch (err) {
    console.error("❌ Exchange rate fetch failed:", err.message);
    return _ratesCache || { USD: 1 }; // stale cache if we have one, else 1:1
  }
}

/** Convert an amount between two ISO 4217 codes, via USD as the common
 * base. Returns a number rounded to 2 decimal places. */
async function convertCurrency(amount, fromCurrency = "USD", toCurrency = "USD") {
  if (!amount || isNaN(amount)) return 0;
  if (fromCurrency === toCurrency) return Math.round(Number(amount) * 100) / 100;

  const rates = await getExchangeRates();
  const fromRate = rates[fromCurrency] || 1;
  const toRate = rates[toCurrency] || 1;
  const converted = (Number(amount) / fromRate) * toRate;
  return Math.round(converted * 100) / 100;
}

// =============================================================================
// MIDDLEWARE: UPLOAD  (was middleware/upload.js)
// =============================================================================

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(Object.assign(new Error("Only image files are allowed"), { status: 400 }));
    }
    cb(null, true);
  },
});

// =============================================================================
// UTIL: EMAIL  (was utils/email.js)
// =============================================================================

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const EMAIL_FROM = process.env.EMAIL_FROM || "Uyeh Hotel <noreply@Uyehhotel.com>";

/**
 * Every email call is wrapped so a Resend outage or missing API key never
 * breaks the underlying operation (a booking still succeeds even if the
 * confirmation email fails to send) — it just gets logged.
 */
async function sendEmail({ to, subject, html }) {
  if (!resend) {
    console.warn(`[email] RESEND_API_KEY not set — skipped email "${subject}" to ${to}`);
    return { skipped: true };
  }
  try {
    const result = await resend.emails.send({ from: EMAIL_FROM, to, subject, html });
    return result;
  } catch (err) {
    console.error(`[email] Failed to send "${subject}" to ${to}:`, err.message);
    return { error: err.message };
  }
}

function emailLayout(bodyHtml, platformName = "Your Hotel") {
  return `
  <div style="font-family: -apple-system, Helvetica, Arial, sans-serif; background:#F6F1E7; padding:32px;">
    <div style="max-width:520px; margin:0 auto; background:#ffffff; border-radius:6px; overflow:hidden;">
      <div style="background:#14181F; padding:28px 32px;">
        <span style="font-family: Georgia, serif; font-size:20px; color:#F6F1E7;">Uyeh <span style="color:#D9B876;">Hotel</span></span>
      </div>
      <div style="padding:32px;">
        ${bodyHtml}
      </div>
      <div style="padding:20px 32px; background:#F6F1E7; color:#6B6355; font-size:12px;">
        This is an automated message from ${escapeHtml(platformName)}.
      </div>
    </div>
  </div>`;
}

function emailMoney(amount, currency) {
  return `${currency} ${Number(amount).toLocaleString()}`;
}
function emailDateStr(d) {
  return new Date(d).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
// ---- Guest-facing ----

async function sendBookingConfirmation({ guestEmail, guestName, branchName, roomTypeName, roomNumber, checkIn, checkOut, totalAmount, currency }) {
  const platformName = await getPlatformName();
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">Booking received</h2>
    <p style="color:#6B6355; margin:0 0 20px;">Hi ${guestName}, here's a summary of your reservation at ${branchName}.</p>
    <table style="width:100%; font-size:14px; color:#14181F;">
      <tr><td style="padding:6px 0; color:#6B6355;">Room</td><td style="text-align:right;">${roomTypeName} — ${roomNumber}</td></tr>
      <tr><td style="padding:6px 0; color:#6B6355;">Check in</td><td style="text-align:right;">${emailDateStr(checkIn)}</td></tr>
      <tr><td style="padding:6px 0; color:#6B6355;">Check out</td><td style="text-align:right;">${emailDateStr(checkOut)}</td></tr>
      <tr><td style="padding:6px 0; color:#6B6355;">Total</td><td style="text-align:right; font-weight:bold;">${emailMoney(totalAmount, currency)}</td></tr>
    </table>
    <p style="color:#6B6355; font-size:13px; margin-top:20px;">Payment is pending — you'll receive a separate confirmation once it clears.</p>
  `, platformName);
  return sendEmail({ to: guestEmail, subject: `Booking received — ${branchName}`, html });
}

async function sendBookingStatusUpdate({ guestEmail, guestName, branchName, status, roomTypeName, roomNumber }) {
  const STATUS_COPY = {
    CONFIRMED: "Your booking is confirmed.",
    CHECKED_IN: "You're checked in — welcome!",
    CHECKED_OUT: "Thanks for staying with us. You've been checked out.",
    CANCELLED: "Your booking has been cancelled.",
    NO_SHOW: "We've marked this reservation as a no-show. Per our policy, the prepaid amount is non-refundable.",
  };
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">${STATUS_COPY[status] || "Booking update"}</h2>
    <p style="color:#6B6355;">Hi ${guestName}, an update on your reservation at ${branchName} — ${roomTypeName} (${roomNumber}).</p>
  `);
  return sendEmail({ to: guestEmail, subject: `Booking update — ${branchName}`, html });
}

async function sendTicketReply({ guestEmail, guestName, branchName, subject, message, staffName }) {
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">Reply to: ${subject}</h2>
    <p style="color:#6B6355; margin-bottom:16px;">Hi ${escapeHtml(guestName)}, ${escapeHtml(staffName)} from ${escapeHtml(branchName)} replied to your message:</p>
    <div style="background:#F6F1E7; padding:16px; border-radius:4px; color:#14181F; font-size:14px;">${escapeHtml(message)}</div>
  `);
  return sendEmail({ to: guestEmail, subject: `Re: ${subject}`, html });
}

async function sendOrderConfirmation({ guestEmail, guestName, branchName, type, itemsSummary, totalAmount, currency }) {
  const TYPE_LABELS = {
    ROOM_SERVICE: "Room service", RESTAURANT: "Restaurant", BAR: "Bar",
    LAUNDRY: "Laundry", SPA: "Spa appointment", EVENT_TICKET: "Event ticket", OTHER: "Order",
  };
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">${TYPE_LABELS[type] || "Order"} received</h2>
    <p style="color:#6B6355; margin:0 0 16px;">Hi ${escapeHtml(guestName)}, here's what we've got for you at ${escapeHtml(branchName)}.</p>
    <div style="background:#F6F1E7; padding:16px; border-radius:4px; color:#14181F; font-size:14px; white-space:pre-line;">${escapeHtml(itemsSummary)}</div>
    ${totalAmount ? `<p style="margin-top:16px; font-weight:bold; color:#14181F;">Total: ${emailMoney(totalAmount, currency)}</p>` : ""}
  `);
  return sendEmail({ to: guestEmail, subject: `Order received — ${branchName}`, html });
}

// ---- Internal (Director/Manager/Staff) ----

async function sendManagerWelcome({ email, name, branchName, tempPassword }) {
  const platformName = await getPlatformName();
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">You've been appointed Manager</h2>
    <p style="color:#6B6355;">Hi ${name}, you now manage <strong>${branchName}</strong> on the ${escapeHtml(platformName)} platform.</p>
    <table style="width:100%; font-size:14px; margin-top:16px;">
      <tr><td style="padding:6px 0; color:#6B6355;">Login email</td><td style="text-align:right;">${email}</td></tr>
      <tr><td style="padding:6px 0; color:#6B6355;">Temporary password</td><td style="text-align:right; font-weight:bold;">${tempPassword}</td></tr>
    </table>
    <p style="color:#6B6355; font-size:13px; margin-top:16px;">Please log in and change this password as soon as possible.</p>
  `);
  return sendEmail({ to: email, subject: `You're the Manager of ${branchName}`, html });
}

async function sendStaffWelcome({ email, name, branchName, roleTitle, tempPassword }) {
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">Your staff account is ready</h2>
    <p style="color:#6B6355;">Hi ${name}, you've been added to <strong>${branchName}</strong> as <strong>${roleTitle}</strong>.</p>
    <table style="width:100%; font-size:14px; margin-top:16px;">
      <tr><td style="padding:6px 0; color:#6B6355;">Login email</td><td style="text-align:right;">${email}</td></tr>
      <tr><td style="padding:6px 0; color:#6B6355;">Temporary password</td><td style="text-align:right; font-weight:bold;">${tempPassword}</td></tr>
    </table>
    <p style="color:#6B6355; font-size:13px; margin-top:16px;">Please log in and change this password as soon as possible.</p>
  `);
  return sendEmail({ to: email, subject: `Welcome to ${branchName}`, html });
}

/** Sent to the branch's staff (those with handle_tickets) when a guest
 * raises a new ticket, so it doesn't sit unseen in the dashboard. */
async function sendNewTicketAlert({ staffEmails, branchName, subject, guestName }) {
  if (!staffEmails.length) return { skipped: true };
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">New guest ticket</h2>
    <p style="color:#6B6355;">${escapeHtml(guestName)} raised a ticket at ${escapeHtml(branchName)}: <strong>${escapeHtml(subject)}</strong></p>
  `);
  return sendEmail({ to: staffEmails, subject: `New ticket — ${branchName}`, html });
}

async function sendRefundConfirmation({ guestEmail, guestName, branchName, amount, currency, reference }) {
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">Refund processed</h2>
    <p style="color:#6B6355;">Hi ${escapeHtml(guestName)}, your payment at ${escapeHtml(branchName)} has been refunded.</p>
    <table style="width:100%; font-size:14px; margin-top:16px;">
      <tr><td style="padding:6px 0; color:#6B6355;">Amount</td><td style="text-align:right; font-weight:bold;">${emailMoney(amount, currency)}</td></tr>
      <tr><td style="padding:6px 0; color:#6B6355;">Reference</td><td style="text-align:right;">${reference}</td></tr>
    </table>
    <p style="color:#6B6355; font-size:13px; margin-top:16px;">Refunds typically take 5–10 business days to reflect, depending on your bank.</p>
  `);
  return sendEmail({ to: guestEmail, subject: `Refund processed — ${branchName}`, html });
}

async function sendPaymentReceipt({ guestEmail, guestName, branchName, amount, currency, reference }) {
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">Payment received</h2>
    <p style="color:#6B6355;">Hi ${guestName}, we've received your payment for ${branchName}.</p>
    <table style="width:100%; font-size:14px; margin-top:16px;">
      <tr><td style="padding:6px 0; color:#6B6355;">Amount</td><td style="text-align:right; font-weight:bold;">${emailMoney(amount, currency)}</td></tr>
      <tr><td style="padding:6px 0; color:#6B6355;">Reference</td><td style="text-align:right;">${reference}</td></tr>
    </table>
  `);
  return sendEmail({ to: guestEmail, subject: `Payment received — ${branchName}`, html });
}

/** Sent to a branch's managers when an order pushes a linked stock item at
 * or below its lowStockThreshold — so nothing quietly runs out mid-service. */
async function sendLowStockAlert({ managerEmails, branchName, items }) {
  if (!managerEmails.length) return { skipped: true };
  const rows = items.map((i) =>
    `<tr><td style="padding:6px 0; color:#6B6355;">${escapeHtml(i.name)}</td><td style="text-align:right;">${i.quantity} ${escapeHtml(i.unit || "")} left</td></tr>`
  ).join("");
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">Low stock alert</h2>
    <p style="color:#6B6355; margin-bottom:16px;">${escapeHtml(branchName)} is running low on:</p>
    <table style="width:100%; font-size:14px;">${rows}</table>
  `);
  return sendEmail({ to: managerEmails, subject: `Low stock — ${branchName}`, html });
}

// =============================================================================
// SOCKET.IO STATE + HANDLERS  (was config/socket.js + sockets/handlers.js)
// =============================================================================

let io = null;
function setIO(instance) {
  io = instance;
}
/** Controllers call this AFTER a successful DB write, to push a live
 * update. Never throws if sockets aren't running (e.g. in tests) — it
 * just no-ops, same fire-and-forget spirit as the email sends. */
function getIO() {
  return io;
}

function branchSupportRoom(branchId) {
  return `branch:${branchId}:support`;
}
function ticketRoom(ticketId) {
  return `ticket:${ticketId}`;
}

function authenticateSocket(socket, next) {
  const token = socket.handshake.auth?.token;
  if (!token) return next(); // anonymous guest — allowed, just can't auto-join a branch room

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (payload.type === "ticket_guest") {
      // Scoped anonymous-guest credential — NOT a full user identity.
      socket.data.ticketAccess = { ticketId: payload.ticketId, email: payload.email };
    } else {
      socket.data.user = payload; // staff or registered-guest login token, as before
    }
  } catch (err) {
    // Bad/expired token on a socket that might just be an anonymous guest
    // who happened to send garbage — don't hard-fail the connection.
    socket.data.user = null;
  }
  next();
}

// In-memory presence/rate-limit state. Deliberately not persisted — online
// status is inherently ephemeral and resets correctly on every server
// restart; only the resulting last-seen TIMESTAMP is durable (in the DB).
const onlineStaffByBranch = new Map();   // branchId -> Set<staffId>
const onlineGuestsByTicket = new Map();  // ticketId -> Set<socketId>
const socketRateBuckets = new Map();     // socketId -> { count, windowStart }

function addToSetMap(map, key, value) {
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(value);
}
/** Returns true if removing this value emptied the set (i.e. now fully offline). */
function removeFromSetMap(map, key, value) {
  const set = map.get(key);
  if (!set) return false;
  set.delete(value);
  if (set.size === 0) { map.delete(key); return true; }
  return false;
}
function isRateLimited(socket, max = 20, windowMs = 10000) {
  const now = Date.now();
  const bucket = socketRateBuckets.get(socket.id) || { count: 0, windowStart: now };
  if (now - bucket.windowStart > windowMs) { bucket.count = 0; bucket.windowStart = now; }
  bucket.count += 1;
  socketRateBuckets.set(socket.id, bucket);
  return bucket.count > max;
}

/**
 * Connection model:
 *  - Staff/Director connect WITH a JWT (same token as REST). If the staff
 *    member holds "handle_tickets", they're auto-joined to their branch's
 *    support room, so new tickets and messages appear live on their
 *    dashboard without polling.
 *  - Registered guests connect with their guest JWT.
 *  - Anonymous guest checkout connects with a ticket-scoped access token
 *    (see signTicketAccessToken) — issued at ticket creation, or re-issued
 *    via POST /branches/:branchId/tickets/:id/access-token. Replaces the
 *    old "just tell me the email" check, which had no real proof behind it.
 *
 * REST remains the system of record — every message is still written to
 * the database by the controller. Socket events here only (a) broadcast
 * what REST already saved, and (b) let a guest send a follow-up chat
 * message directly over the socket for a snappier feel; that handler still
 * writes to the DB itself, same as the REST path, before broadcasting.
 */
function initSocketHandlers(ioInstance) {
  ioInstance.use(authenticateSocket);

  ioInstance.on("connection", (socket) => {
    const user = socket.data.user;

    // Director is company-wide (no branchId) so isn't auto-joined to one
    // branch's room, but can still explicitly join any ticket via
    // join_ticket below. Manager/Staff auto-join their own branch's room.
    if ((user?.type === "manager" || user?.type === "staff") && (user.permissions || []).includes("handle_tickets") && user.branchId) {
      socket.join(branchSupportRoom(user.branchId));
      addToSetMap(onlineStaffByBranch, user.branchId, user.id);
      ioInstance.to(branchSupportRoom(user.branchId)).emit("staff_online", { staffId: user.id, staffType: user.type });
    }

    /** Staff, a registered guest, or an anonymous guest holding a
     * ticket-scoped access token joins one ticket's room. */
    socket.on("join_ticket", async ({ ticketId }, ack) => {
      try {
        const ticket = await prisma.ticket.findUnique({ where: { id: ticketId }, include: { guest: true } });
        if (!ticket) return ack?.({ ok: false, error: "Ticket not found" });

        let viewerType = null;
        if (user?.type === "director") {
          viewerType = "staff"; // company-wide — always allowed into any ticket
        } else if (user?.type === "manager" || user?.type === "staff") {
          if (user.branchId !== ticket.branchId) return ack?.({ ok: false, error: "Not your branch" });
          viewerType = "staff";
        } else if (user?.type === "guest") {
          if (user.id !== ticket.guestId) return ack?.({ ok: false, error: "Not your ticket" });
          viewerType = "guest";
        } else if (socket.data.ticketAccess?.ticketId === ticketId && socket.data.ticketAccess.email === ticket.guest.email.toLowerCase()) {
          viewerType = "guest";
        } else {
          return ack?.({ ok: false, error: "Not authorized — log in or provide a valid ticket access token" });
        }

        socket.join(ticketRoom(ticketId));
        socket.data.viewerType = viewerType;
        socket.data.currentTicketId = ticketId;

        if (viewerType === "guest") {
          addToSetMap(onlineGuestsByTicket, ticketId, socket.id);
          ioInstance.to(ticketRoom(ticketId)).emit("guest_online", { ticketId });
        }

        ack?.({ ok: true });
      } catch (err) {
        ack?.({ ok: false, error: "Could not join ticket" });
      }
    });

    /** Typing indicators — broadcast to everyone else in the room, never
     * back to the sender (socket.to, not ioInstance.to). */
    socket.on("typing_start", ({ ticketId }) => {
      if (!ticketId || socket.data.currentTicketId !== ticketId) return;
      const event = socket.data.viewerType === "staff" ? "staff_typing" : "guest_typing";
      socket.to(ticketRoom(ticketId)).emit(event, { ticketId, typing: true });
    });
    socket.on("typing_stop", ({ ticketId }) => {
      if (!ticketId || socket.data.currentTicketId !== ticketId) return;
      const event = socket.data.viewerType === "staff" ? "staff_typing" : "guest_typing";
      socket.to(ticketRoom(ticketId)).emit(event, { ticketId, typing: false });
    });

    /** Read receipts. Call this when the client actually views the chat
     * (on open/focus), not just on join — that distinction is what makes
     * "delivered" vs "read" meaningful, same as grey vs blue ticks. */
    socket.on("mark_read", async ({ ticketId }, ack) => {
      try {
        if (socket.data.currentTicketId !== ticketId) return ack?.({ ok: false, error: "Join the ticket first" });
        const viewerType = socket.data.viewerType;
        // "staff side" collapses DIRECTOR/MANAGER/STAFF into one read cursor
        // (see the schema comment on Ticket.staffLastReadAt) — a guest's
        // unread count is "any staff-type sender", not just literal STAFF.
        const opposingSenderTypes = viewerType === "staff" ? ["GUEST"] : ["DIRECTOR", "MANAGER", "STAFF"];
        const now = new Date();

        await prisma.ticketMessage.updateMany({
          where: { ticketId, senderType: { in: opposingSenderTypes }, readAt: null },
          data: { readAt: now },
        });
        await prisma.ticket.update({
          where: { id: ticketId },
          data: viewerType === "staff" ? { staffLastReadAt: now } : { guestLastReadAt: now },
        });

        ioInstance.to(ticketRoom(ticketId)).emit("messages_read", { ticketId, readAt: now, by: viewerType });
        ack?.({ ok: true });
      } catch (err) {
        ack?.({ ok: false, error: "Could not mark as read" });
      }
    });

    /** A guest sends a chat message directly over the socket. Still
     * persisted to the DB here, same as the REST reply path, before
     * broadcasting. Supports an optional attachment (upload it first via
     * POST /branches/:branchId/tickets/:id/attachment, send the returned
     * URL here), auto-marks "delivered" if staff are online for this
     * branch right now, and is rate-limited per socket. */
    socket.on("guest_message", async ({ ticketId, message, attachmentUrl, attachmentType }, ack) => {
      if ((!message || !message.trim()) && !attachmentUrl) return ack?.({ ok: false, error: "Empty message" });
      if (isRateLimited(socket)) return ack?.({ ok: false, error: "You're sending messages too fast — slow down a moment" });

      try {
        const ticket = await prisma.ticket.findUnique({ where: { id: ticketId }, include: { guest: true } });
        if (!ticket) return ack?.({ ok: false, error: "Ticket not found" });

        const isOwner = user?.type === "guest"
          ? user.id === ticket.guestId
          : socket.data.ticketAccess?.ticketId === ticketId && socket.data.ticketAccess.email === ticket.guest.email.toLowerCase();
        if (!isOwner) return ack?.({ ok: false, error: "Not authorized for this ticket" });

        const deliveredNow = (onlineStaffByBranch.get(ticket.branchId)?.size || 0) > 0;
        const now = new Date();

        const saved = await prisma.$transaction(async (tx) => {
          const created = await tx.ticketMessage.create({
            data: {
              ticketId, senderType: "GUEST", guestName: ticket.guest.name, message: message || "",
              attachmentUrl: attachmentUrl || null, attachmentType: attachmentType || null,
              deliveredAt: deliveredNow ? now : null,
            },
          });
          await tx.ticket.update({
            where: { id: ticketId },
            data: {
              guestLastReadAt: now, // sending implies you've seen everything up to now
              ...(ticket.status === "RESOLVED" || ticket.status === "CLOSED" ? { status: "IN_PROGRESS" } : {}),
            },
          });
          return created;
        });

        ioInstance.to(ticketRoom(ticketId)).emit("new_message", saved);
        ioInstance.to(branchSupportRoom(ticket.branchId)).emit("ticket_activity", { ticketId, from: "guest" });
        ack?.({ ok: true, message: saved });
      } catch (err) {
        ack?.({ ok: false, error: "Could not send message" });
      }
    });

    /** Presence cleanup — marks last-seen in the DB (fire-and-forget, same
     * spirit as the email sends) and tells anyone still in the room. */
    socket.on("disconnect", () => {
      socketRateBuckets.delete(socket.id);

      if ((user?.type === "manager" || user?.type === "staff") && user.branchId) {
        const nowFullyOffline = removeFromSetMap(onlineStaffByBranch, user.branchId, user.id);
        if (nowFullyOffline) {
          const seenAt = new Date();
          prisma[user.type].update({ where: { id: user.id }, data: { lastSeenAt: seenAt } }).catch(() => {});
          ioInstance.to(branchSupportRoom(user.branchId)).emit("staff_offline", { staffId: user.id, staffType: user.type, lastSeenAt: seenAt });
        }
      }

      const ticketId = socket.data.currentTicketId;
      if (ticketId && socket.data.viewerType === "guest") {
        const nowFullyOffline = removeFromSetMap(onlineGuestsByTicket, ticketId, socket.id);
        if (nowFullyOffline) {
          const seenAt = new Date();
          if (user?.type === "guest") {
            prisma.guest.update({ where: { id: user.id }, data: { lastSeenAt: seenAt } }).catch(() => {});
          }
          ioInstance.to(ticketRoom(ticketId)).emit("guest_offline", { ticketId, lastSeenAt: seenAt });
        }
      }
    });
  });
}

// =============================================================================
// AUTH  (was middleware/auth.js — kept inline, this project stays one file)
// =============================================================================


function jwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw Object.assign(new Error("JWT_SECRET is not configured"), { status: 500 });
  return secret;
}
/** expiresIn now matters: access tokens are short-lived (default 15m) since
 * a RefreshToken row is what actually keeps someone logged in — see
 * issueTokenPair() below. The old 7-day single-token approach meant a
 * leaked token stayed valid for a week with no way to revoke it. */
function signToken(payload, expiresIn = "60m") {
  return jwt.sign(payload, jwtSecret(), { expiresIn });
}

/** Scoped, stateless credential for anonymous guest-checkout chat — replaces
 * the old "just tell me the email and I'll believe you" check. Carries no
 * broad identity, only "this token can act as the owner of ticket X". 30-day
 * expiry: long enough to return to an old thread without an account, short
 * enough not to be a permanent credential. */
function signTicketAccessToken(ticketId, guestEmail) {
  return signToken({ type: "ticket_guest", ticketId, email: guestEmail.toLowerCase() }, "30d");
}

// ── Login lockout ───────────────────────────────────────────────────────
const LOGIN_LOCK_THRESHOLD = 5;          // failed attempts before locking
const LOGIN_LOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes

/** Shared by Staff and Guest login. Returns { locked: true, retryAfterMs }
 * if currently locked, otherwise null. */
function checkLockout(account) {
  if (account.lockUntil && account.lockUntil > new Date()) {
    return { locked: true, retryAfterMs: account.lockUntil.getTime() - Date.now() };
  }
  return null;
}

// ── Opaque token helpers (refresh tokens, reset tokens, verification tokens) ─
// These are high-entropy random strings, not JWTs — hashed before storage so
// a database leak alone doesn't hand out working credentials.
function generateRawToken() {
  return crypto.randomBytes(32).toString("hex");
}
function hashRawToken(raw) {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// Central registry for the four login-able account types. Add a new type
// here (and to the Prisma schema) and every route below picks it up —
// login, 2FA verify, refresh, and logout don't need type-specific code.
const REFRESH_FK_BY_TYPE = { director: "directorId", manager: "managerId", staff: "staffId", guest: "guestId" };

function accountModel(type) {
  const models = { director: prisma.director, manager: prisma.manager, staff: prisma.staff, guest: prisma.guest };
  const model = models[type];
  if (!model) throw Object.assign(new Error(`Unknown account type: ${type}`), { status: 500 });
  return model;
}

/** Shapes what's safe to return to the client for each account type. */
function serializeAccount(type, account) {
  if (type === "director") {
    return { id: account.id, type, name: account.name, email: account.email };
  }
  if (type === "manager") {
    return {
      id: account.id, type, name: account.name, email: account.email,
      roleTitle: account.roleTitle, department: account.department, permissions: account.permissions,
      branchId: account.branchId, branchName: account.branch?.name || null,
    };
  }
  if (type === "staff") {
    return {
      id: account.id, type, name: account.name, email: account.email, role: account.role,
      roleTitle: account.roleTitle, department: account.department, permissions: account.permissions,
      branchId: account.branchId, branchName: account.branch?.name || null,
    };
  }
  // guest
  return { id: account.id, type, name: account.name, email: account.email, phone: account.phone, emailVerified: account.emailVerified };
}

/** Issues an access token + a refresh token for a director, manager, staff
 * member, or guest. The refresh token is stored hashed in RefreshToken; the
 * raw value is only ever returned to the client once, here. */
async function issueTokenPair({ subjectType, subject, req }) {
  const fk = REFRESH_FK_BY_TYPE[subjectType];
  if (!fk) throw Object.assign(new Error(`Unknown subjectType: ${subjectType}`), { status: 500 });

  const payload = { id: subject.id, type: subjectType, name: subject.name };
  if (subjectType === "manager" || subjectType === "staff") {
    payload.branchId = subject.branchId;
    payload.permissions = subject.permissions;
  }
  const accessToken = signToken(payload);

  const rawRefreshToken = generateRawToken();
  await prisma.refreshToken.create({
    data: {
      tokenHash: hashRawToken(rawRefreshToken),
      [fk]: subject.id,
      userAgent: req?.headers["user-agent"]?.slice(0, 255),
      ip: req?.ip,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
    },
  });

  return { accessToken, refreshToken: rawRefreshToken };
}

// ── Password reset / verification email ──────────────────────────────────
async function sendPasswordResetEmail({ email, name, resetUrl }) {
  const platformName = await getPlatformName();
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">Reset your password</h2>
    <p style="color:#6B6355;">Hi ${escapeHtml(name)}, click below to reset your password. This link expires in 1 hour.</p>
    <p style="margin:20px 0;"><a href="${resetUrl}" style="background:#B98D45; color:#14181F; padding:12px 24px; border-radius:4px; text-decoration:none; font-weight:600;">Reset password</a></p>
    <p style="color:#6B6355; font-size:13px;">If you didn't request this, you can safely ignore this email.</p>
  `, platformName);
  return sendEmail({ to: email, subject: "Reset your password", html });
}
async function sendVerificationEmail({ email, name, verifyUrl }) {
  const platformName = await getPlatformName();
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">Verify your email</h2>
    <p style="color:#6B6355;">Hi ${escapeHtml(name)}, please confirm your email address. This link expires in 24 hours.</p>
    <p style="margin:20px 0;"><a href="${verifyUrl}" style="background:#B98D45; color:#14181F; padding:12px 24px; border-radius:4px; text-decoration:none; font-weight:600;">Verify email</a></p>
  `, platformName);
  return sendEmail({ to: email, subject: "Verify your email", html });
}


function notImplemented(label) {
  return (req, res) => res.status(501).json({ error: `${label} not implemented yet — pending file` });
}

/** Verifies the JWT and attaches the decoded payload to req.user. Used by
 * every staff-facing route (Director, Manager, Staff alike). */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function requireBranchAccess(permission) {
  return (req, res, next) => {
    if (!req.user || !["director", "manager", "staff"].includes(req.user.type)) {
      return res.status(403).json({ error: "Staff access required" });
    }
    // Director: full authority, company-wide. Manager: full authority within
    // their own branch — branch scope is already enforced separately via
    // resolveBranchScope() reading their JWT, so there's nothing extra to
    // gate here. The `permissions` array is a Staff-only concept: it's how
    // a Manager delegates specific capabilities to individual Staff members,
    // not a checklist Director has to fill out for every Manager they create.
    if (req.user.type === "director" || req.user.type === "manager") return next();
    if (permission && !(req.user.permissions || []).includes(permission)) {
      return res.status(403).json({ error: `Missing permission: ${permission}` });
    }
    next();
  };
}

/** Director-only routes (branch CRUD, company overview, manager management). */
function requireDirector(req, res, next) {
  if (!req.user || req.user.type !== "director") {
    return res.status(403).json({ error: "Director access required" });
  }
  next();
}

/** Manager-only routes — specifically, creating Staff on their own branch. */
function requireManager(req, res, next) {
  if (!req.user || req.user.type !== "manager") {
    return res.status(403).json({ error: "Manager access required" });
  }
  next();
}

/** Upcoming Events are Director-and-Manager only, full stop. Unlike
 * requireBranchAccess("manage_events") — which a Director CAN delegate to
 * Staff for venue-booking Events — no permission unlocks this for Staff. */
function requireDirectorOrManager(req, res, next) {
  if (!req.user || !["director", "manager"].includes(req.user.type)) {
    return res.status(403).json({ error: "Director or Manager access required" });
  }
  next();
}

/** The actual branch-scoping boundary. Director: ?branchId= to filter to one
 * branch, or null (company-wide, no filter) if omitted. Manager/Staff: always
 * their own branchId from their verified DB record — a client can send
 * anything in the request and it's ignored. */
function resolveBranchScope(req) {
  if (req.user.type === "director") {
    return req.query.branchId || req.body.branchId || null;
  }
  return req.user.branchId;
}

/** Fire-and-forget audit trail write. Never throws into the caller — a
 * logging failure shouldn't fail the underlying action. Call this from
 * inside route handlers after a mutation succeeds:
 *   logAudit(req, "branch.create", { targetType: "branch", targetId: branch.id });
 */
function logAudit(req, action, { targetType, targetId, branchId, metadata } = {}) {
  prisma.auditLog
    .create({
      data: {
        actorType: req.user.type,
        actorId: req.user.id,
        actorName: req.user.name || req.user.email || req.user.id,
        action,
        targetType: targetType || null,
        targetId: targetId || null,
        branchId: branchId || null,
        metadata: metadata || undefined,
      },
    })
    .catch((err) => console.error("[audit log] failed to write:", err.message));
}

/** Never blocks. Sets req.user if a valid guest token is present. */
async function optionalGuestAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return next();
  try {
    const payload = jwt.verify(token, jwtSecret());
    if (payload.type === "guest") {
      const guest = await prisma.guest.findUnique({ where: { id: payload.id } });
      if (guest) req.user = { id: guest.id, type: "guest" };
    }
  } catch {
    // expired/invalid on an optional route — proceed anonymous, don't block
  }
  next();
}

/** Gates a guest-facing branch route behind that branch actually offering
 * the service. 404s rather than 403s — an unsupported service on a branch
 * should look the same as a route that doesn't exist, not reveal that it's
 * merely turned off. Attaches the branch to req.branch so handlers that
 * already need it (createOrder) don't have to fetch it twice. */
function requireBranchService(serviceKey) {
  return async (req, res, next) => {
    const branch = await prisma.branch.findFirst({ where: { id: req.params.branchId, isActive: true } });
    if (!branch) return res.status(404).json({ error: "Branch not found" });
    if (!branch.services.includes(serviceKey)) {
      return res.status(404).json({ error: `This branch does not offer "${serviceKey}"` });
    }
    req.branch = branch;
    next();
  };
}

// ── 2FA verification (shared) ─────────────────────────────────────────────
const TWO_FA_LOCK_THRESHOLD = 5;
const TWO_FA_LOCK_DURATION_MS = 15 * 60 * 1000;

/** Verifies a 6-digit TOTP code, or a backup code as a fallback. Mutates and
 * persists the account's lockout/attempt counters either way. Returns true/false. */
async function verifyTwoFactorCode({ model, account, code }) {
  if (account.twoFactorLockedUntil && account.twoFactorLockedUntil > new Date()) {
    return { ok: false, locked: true };
  }

  const totpValid = speakeasy.totp.verify({
    secret: account.twoFactorSecret, encoding: "base32", token: code, window: 1,
  });

  let backupUsed = false;
  let validBackupCodes = account.twoFactorBackupCodes;
  if (!totpValid && Array.isArray(account.twoFactorBackupCodes)) {
    for (const entry of account.twoFactorBackupCodes) {
      if (!entry.usedAt && (await bcrypt.compare(code, entry.codeHash))) {
        backupUsed = true;
        validBackupCodes = account.twoFactorBackupCodes.map((c) =>
          c.codeHash === entry.codeHash ? { ...c, usedAt: new Date().toISOString() } : c
        );
        break;
      }
    }
  }

  if (totpValid || backupUsed) {
    await model.update({ where: { id: account.id }, data: { twoFactorAttempts: 0, twoFactorLockedUntil: null, ...(backupUsed ? { twoFactorBackupCodes: validBackupCodes } : {}) } });
    return { ok: true, backupUsed };
  }

  const attempts = account.twoFactorAttempts + 1;
  const data = attempts >= TWO_FA_LOCK_THRESHOLD
    ? { twoFactorAttempts: 0, twoFactorLockedUntil: new Date(Date.now() + TWO_FA_LOCK_DURATION_MS) }
    : { twoFactorAttempts: attempts };
  await model.update({ where: { id: account.id }, data });
  return { ok: false, locked: attempts >= TWO_FA_LOCK_THRESHOLD };
}

function generateBackupCodes(count = 8) {
  return Array.from({ length: count }, () => crypto.randomBytes(5).toString("hex"));
}

// =============================================================================
// CONTROLLERS: BOOKINGS  (was controllers/bookingController.js)
// =============================================================================

const ACTIVE_BOOKING_STATUSES = ["PENDING", "CONFIRMED", "CHECKED_IN"];

async function checkAvailability(req, res) {
  const { branchId } = req.params;
  const { checkIn, checkOut, currency } = req.query;
  if (!checkIn || !checkOut) return res.status(400).json({ error: "checkIn and checkOut are required (YYYY-MM-DD)" });

  const start = new Date(checkIn);
  const end = new Date(checkOut);
  if (!(start < end)) return res.status(400).json({ error: "checkOut must be after checkIn" });

  // A room fresh off a same-day checkout hasn't been cleaned yet — don't
  // offer it for an immediate check-in. Future-dated check-ins are fine
  // regardless of today's housekeeping state; there's time to clean before
  // the guest arrives. OUT_OF_ORDER is excluded regardless of date.
  const isImmediateCheckIn = start <= new Date();
  const excludedHousekeeping = isImmediateCheckIn
    ? ["OUT_OF_ORDER", "DIRTY", "CLEANING"]
    : ["OUT_OF_ORDER"];

  const rooms = await prisma.room.findMany({
    where: {
      branchId, status: "ACTIVE",
      housekeepingStatus: { notIn: excludedHousekeeping },
      bookings: { none: { status: { in: ACTIVE_BOOKING_STATUSES }, AND: [{ checkIn: { lt: end } }, { checkOut: { gt: start } }] } },
    },
  });

  // Optional display-currency conversion — the stored basePrice/currency
  // on the room is untouched; this only adds a converted figure alongside.
  let availableRooms = rooms;
  if (currency) {
    availableRooms = await Promise.all(
      rooms.map(async (r) => ({
        ...r,
        displayPrice: await convertCurrency(r.basePrice, r.currency, currency),
        displayCurrency: currency,
      }))
    );
  }

  res.json({ checkIn, checkOut, availableRooms });
}

/** Works whether or not the guest is logged in. If `req.user` (from
 * optionalGuestAuth) is set, that account is used directly. Otherwise the
 * guest is matched/created by email, same as before — preferences and
 * history still attach correctly either way. */
async function createBooking(req, res) {
  const { branchId } = req.params;
  const { roomId, checkIn, checkOut, guestsCount, specialRequests, guest, promoCode } = req.body;

  if (!req.user && (!guest?.name || !guest?.email)) {
    return res.status(400).json({ error: "guest.name and guest.email are required for guest checkout" });
  }
  if (!roomId || !checkIn || !checkOut) {
    return res.status(400).json({ error: "roomId, checkIn, checkOut are required" });
  }

  const start = new Date(checkIn);
  const end = new Date(checkOut);
  if (!(start < end)) return res.status(400).json({ error: "checkOut must be after checkIn" });

  const room = await prisma.room.findFirst({ where: { id: roomId, branchId } });
  if (!room) return res.status(404).json({ error: "Room not found at this branch" });

  // Same guard as checkAvailability — a client could otherwise skip the
  // availability search and POST straight to a room that isn't clean yet.
  const isImmediateCheckIn = start <= new Date();
  if (room.housekeepingStatus === "OUT_OF_ORDER" || (isImmediateCheckIn && ["DIRTY", "CLEANING"].includes(room.housekeepingStatus))) {
    return res.status(409).json({ error: "This room isn't ready for immediate check-in yet — housekeeping hasn't cleared it." });
  }

  const conflict = await prisma.booking.findFirst({
    where: { roomId, status: { in: ACTIVE_BOOKING_STATUSES }, checkIn: { lt: end }, checkOut: { gt: start } },
  });
  if (conflict) return res.status(409).json({ error: "This room is already booked for the selected dates." });

  const nights = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
  let totalAmount = Number(room.basePrice) * nights;

  // Resolve the guest first (outside the transaction is fine — upsert is
  // idempotent) so the promo helper has a guestId to check per-guest limits.
  let guestIdForPromo = req.user?.id;
  if (!guestIdForPromo) {
    const existing = await prisma.guest.findUnique({ where: { email: guest.email } });
    guestIdForPromo = existing?.id;
  }

  let promoResult = null;
  if (promoCode) {
    try {
      promoResult = await resolveAndPreviewPromo(promoCode, { guestId: guestIdForPromo, branchId, context: "BOOKING", subtotal: totalAmount });
      totalAmount = Math.max(0, totalAmount - promoResult.discountAmount);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  }

  const result = await prisma.$transaction(async (tx) => {
    let guestRecord;
    if (req.user) {
      guestRecord = await tx.guest.findUnique({ where: { id: req.user.id } });
    } else {
      guestRecord = await tx.guest.upsert({
        where: { email: guest.email },
        update: { name: guest.name, phone: guest.phone },
        create: { name: guest.name, email: guest.email, phone: guest.phone },
      });
    }

    const booking = await tx.booking.create({
      data: {
        branchId, roomId, guestId: guestRecord.id, checkIn: start, checkOut: end,
        guestsCount: guestsCount || 1, specialRequests,
        status: "PENDING", totalAmount, currency: room.currency,
      },
    });

    if (promoResult) {
      await tx.promoRedemption.create({
        data: { promoCodeId: promoResult.promoCodeId, guestId: guestRecord.id, bookingId: booking.id, discountAmount: promoResult.discountAmount },
      });
      await tx.promoCode.update({ where: { id: promoResult.promoCodeId }, data: { usedCount: { increment: 1 } } });
    }

    return { booking, guestRecord };
  });

  // Booking is created PENDING. Payment is a separate step — see
  // initiateBookingPayment() below — so the guest can review the booking
  // before being sent to Paystack.

  if (!req.user && guest?.subscribeNewsletter) {
    upsertConfirmedSubscriber({ email: result.guestRecord.email, name: result.guestRecord.name, source: "guest_checkout" });
  }

  const branch = await prisma.branch.findUnique({ where: { id: branchId } });
  sendBookingConfirmation({
    guestEmail: result.guestRecord.email,
    guestName: result.guestRecord.name,
    branchName: branch.name,
    roomTypeName: room.name,
    roomNumber: room.roomNumber,
    checkIn: start,
    checkOut: end,
    totalAmount,
    currency: room.currency,
  }).catch((err) => console.error("[email] booking confirmation failed:", err.message));

  res.status(201).json({ message: "Booking created, pending payment.", booking: result.booking });
}

/** Starts a Paystack transaction for a PENDING booking. Returns the
 * authorization_url the guest should be redirected/linked to. A
 * BookingPayment row is created up front with status PENDING so the
 * webhook has something to match against by reference.
 * Renamed from `initiatePayment` -> `initiateBookingPayment` (collided with
 * orderController's `initiatePayment` once merged into one file). */
async function initiateBookingPayment(req, res) {
  const { branchId, id } = req.params;
  const { callbackUrl } = req.body;

  const booking = await prisma.booking.findFirst({
    where: { id, branchId },
    include: { guest: true, payment: true, branch: true },
  });
  if (!booking) return res.status(404).json({ error: "Booking not found at this branch" });
  if (booking.status !== "PENDING") {
    return res.status(409).json({ error: `Booking is already ${booking.status}` });
  }
  if (booking.payment && booking.payment.status === "SUCCESSFUL") {
    return res.status(409).json({ error: "This booking has already been paid for" });
  }
  if (!booking.branch.paystackSubaccountCode) {
    console.error(`[paystack] Branch ${branchId} has no payout account configured — this payment will settle to the main account instead of the branch.`);
  }

  const reference = `booking_${booking.id}_${Date.now()}`;

  const transaction = await initializeTransaction({
    email: booking.guest.email,
    amountNaira: booking.totalAmount,
    reference,
    callbackUrl,
    metadata: { bookingId: booking.id, branchId },
    subaccountCode: booking.branch.paystackSubaccountCode || undefined,
  });

  await prisma.bookingPayment.upsert({
    where: { bookingId: booking.id },
    update: { providerRef: reference, amount: booking.totalAmount, currency: booking.currency, status: "PENDING" },
    create: {
      bookingId: booking.id, provider: "PAYSTACK", providerRef: reference,
      amount: booking.totalAmount, currency: booking.currency, status: "PENDING",
    },
  });

  res.json({ authorizationUrl: transaction.authorization_url, reference });
}

/** Stripe equivalent of initiateBookingPayment — separate endpoint rather
 * than branching the existing one, so the Paystack path is untouched. */
async function initiateBookingPaymentStripe(req, res) {
  const { branchId, id } = req.params;
  const { successUrl, cancelUrl } = req.body;

  const booking = await prisma.booking.findFirst({
    where: { id, branchId },
    include: { guest: true, payment: true, branch: true },
  });
  if (!booking) return res.status(404).json({ error: "Booking not found at this branch" });
  if (booking.status !== "PENDING") {
    return res.status(409).json({ error: `Booking is already ${booking.status}` });
  }
  if (booking.payment && booking.payment.status === "SUCCESSFUL") {
    return res.status(409).json({ error: "This booking has already been paid for" });
  }

  const reference = `booking_${booking.id}_${Date.now()}`;

  const session = await createStripeCheckoutSession({
    email: booking.guest.email,
    amount: booking.totalAmount,
    currency: booking.currency,
    reference,
    successUrl,
    cancelUrl,
    metadata: { bookingId: booking.id, branchId, description: `Booking at ${booking.branch.name}` },
    connectedAccountId: booking.branch.stripeConnectedAccountId || undefined,
  });

  await prisma.bookingPayment.upsert({
    where: { bookingId: booking.id },
    update: { providerRef: reference, amount: booking.totalAmount, currency: booking.currency, status: "PENDING", provider: "STRIPE" },
    create: {
      bookingId: booking.id, provider: "STRIPE", providerRef: reference,
      amount: booking.totalAmount, currency: booking.currency, status: "PENDING",
    },
  });

  res.json({ checkoutUrl: session.url, sessionId: session.id, reference });
}

async function listBranchBookings(req, res) {
  const branchId = resolveBranchScope(req);
  const { status } = req.query;
  const bookings = await prisma.booking.findMany({
    where: { ...(branchId ? { branchId } : {}), ...(status ? { status } : {}) },
    include: { room: true, guest: true, payment: true, branch: true },
    orderBy: { checkIn: "asc" },
  });
  // Surfaces loyalty tier alongside each booking so front-desk sees who
  // they're serving without a separate lookup.
  res.json({ bookings: bookings.map((b) => ({ ...b, guestTier: loyaltyTierForLifetimePoints(b.guest.lifetimePoints) })) });
}

const VALID_BOOKING_STATUSES = ["PENDING", "CONFIRMED", "CHECKED_IN", "CHECKED_OUT", "CANCELLED", "NO_SHOW"];

async function updateBookingStatus(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const { status } = req.body;
  if (!status || !VALID_BOOKING_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${VALID_BOOKING_STATUSES.join(", ")}` });
  }

  const existing = await prisma.booking.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Booking not found at this branch" });

  const booking = await prisma.booking.update({
    where: { id },
    data: { status },
    include: { guest: true, branch: true, room: true },
  });

  // A room that's just been vacated always needs housekeeping before it can
  // be sold again — flip it out of "ready" the moment checkout (or a
  // no-show release) happens. Staff clear it via the /housekeeping routes.
  if (status === "CHECKED_OUT" || status === "NO_SHOW") {
    prisma.room.update({
      where: { id: booking.roomId },
      data: { housekeepingStatus: "DIRTY", housekeepingUpdatedAt: new Date() },
    }).catch((err) => console.error("[housekeeping] failed to flag room dirty:", err.message));
  }

  if (["CONFIRMED", "CHECKED_IN", "CHECKED_OUT", "CANCELLED", "NO_SHOW"].includes(status)) {
    sendBookingStatusUpdate({
      guestEmail: booking.guest.email,
      guestName: booking.guest.name,
      branchName: booking.branch.name,
      status,
      roomTypeName: booking.room.name,
      roomNumber: booking.room.roomNumber,
    }).catch((err) => console.error("[email] booking status update failed:", err.message));
  }

  res.json({ booking });
}

const VALID_ORDER_STATUSES = ["PENDING", "IN_PROGRESS", "COMPLETED", "CANCELLED"];

async function updateOrderStatus(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const { status } = req.body;
  if (!status || !VALID_ORDER_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${VALID_ORDER_STATUSES.join(", ")}` });
  }
  const existing = await prisma.order.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Order not found at this branch" });

  const order = await prisma.order.update({ where: { id }, data: { status } });
  res.json({ order });
}


// =============================================================================
// CONTROLLERS: SERVICE CATALOGS  (menu items, laundry items, spa treatments)
// =============================================================================

// ---- Menu (Restaurant = FOOD, Bar = DRINK, both also power Room Service) ----

async function createMenuItem(req, res) {
  const branchId = resolveBranchScope(req) || req.body.branchId;
  if (!branchId) return res.status(400).json({ error: "branchId is required" });
  const { category, name, description, price, currency, dietaryTags, availableForRoomService } = req.body;
  if (!category || !["FOOD", "DRINK"].includes(category)) return res.status(400).json({ error: "category must be FOOD or DRINK" });
  if (!name || price === undefined) return res.status(400).json({ error: "name and price are required" });

  const item = await prisma.menuItem.create({
    data: {
      branchId, category, name, description, price, currency: currency || "NGN",
      dietaryTags: dietaryTags || [], availableForRoomService: !!availableForRoomService,
    },
  });
  res.status(201).json({ menuItem: item });
}

async function listMenuItems(req, res) {
  const branchId = req.params.branchId || resolveBranchScope(req);
  const { category } = req.query;
  const isAdminCaller = !!req.user && req.user.type !== "guest"; // manager/staff/director route — see inactive items too
  const items = await prisma.menuItem.findMany({
    where: { branchId, ...(isAdminCaller ? {} : { isAvailable: true }), ...(category ? { category } : {}) },
    orderBy: { name: "asc" },
  });
  res.json({ menuItems: items });
}

async function updateMenuItem(req, res) {
  const { id } = req.params;
  const { name, description, price, currency, dietaryTags, availableForRoomService, isAvailable } = req.body;
  const item = await prisma.menuItem.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(description !== undefined ? { description } : {}),
      ...(price !== undefined ? { price } : {}),
      ...(currency !== undefined ? { currency } : {}),
      ...(dietaryTags !== undefined ? { dietaryTags } : {}),
      ...(availableForRoomService !== undefined ? { availableForRoomService } : {}),
      ...(isAvailable !== undefined ? { isAvailable } : {}),
    },
  });
  res.json({ menuItem: item });
}

async function deleteMenuItem(req, res) {
  const { id } = req.params;
  // Soft-delete: an item with past order lines can't be hard-deleted without
  // breaking receipt history, so this just hides it from new orders.
  const item = await prisma.menuItem.update({ where: { id }, data: { isAvailable: false } });
  res.json({ menuItem: item });
}

// ---- Laundry price list ----

async function createLaundryItem(req, res) {
  const branchId = resolveBranchScope(req) || req.body.branchId;
  if (!branchId) return res.status(400).json({ error: "branchId is required" });
  const { name, description, price, currency, turnaroundHours } = req.body;
  if (!name || price === undefined) return res.status(400).json({ error: "name and price are required" });

  const item = await prisma.laundryItem.create({
    data: { branchId, name, description, price, currency: currency || "NGN", turnaroundHours: turnaroundHours || 24 },
  });
  res.status(201).json({ laundryItem: item });
}

async function listLaundryItems(req, res) {
  const branchId = req.params.branchId || resolveBranchScope(req);
  const isAdminCaller = !!req.user && req.user.type !== "guest";
  const items = await prisma.laundryItem.findMany({
    where: { branchId, ...(isAdminCaller ? {} : { isAvailable: true }) },
    orderBy: { name: "asc" },
  });
  res.json({ laundryItems: items });
}

async function updateLaundryItem(req, res) {
  const { id } = req.params;
  const { name, description, price, currency, turnaroundHours, isAvailable } = req.body;
  const item = await prisma.laundryItem.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(description !== undefined ? { description } : {}),
      ...(price !== undefined ? { price } : {}),
      ...(currency !== undefined ? { currency } : {}),
      ...(turnaroundHours !== undefined ? { turnaroundHours } : {}),
      ...(isAvailable !== undefined ? { isAvailable } : {}),
    },
  });
  res.json({ laundryItem: item });
}

async function deleteLaundryItem(req, res) {
  const { id } = req.params;
  const item = await prisma.laundryItem.update({ where: { id }, data: { isAvailable: false } });
  res.json({ laundryItem: item });
}

// ---- Spa treatments ----

async function createSpaTreatment(req, res) {
  const branchId = resolveBranchScope(req) || req.body.branchId;
  if (!branchId) return res.status(400).json({ error: "branchId is required" });
  const { name, description, durationMinutes, price, currency } = req.body;
  if (!name || !durationMinutes || price === undefined) {
    return res.status(400).json({ error: "name, durationMinutes, and price are required" });
  }

  const treatment = await prisma.spaTreatment.create({
    data: { branchId, name, description, durationMinutes, price, currency: currency || "NGN" },
  });
  res.status(201).json({ spaTreatment: treatment });
}

async function listSpaTreatments(req, res) {
  const branchId = req.params.branchId || resolveBranchScope(req);
  const isAdminCaller = !!req.user && req.user.type !== "guest";
  const treatments = await prisma.spaTreatment.findMany({
    where: { branchId, ...(isAdminCaller ? {} : { isAvailable: true }) },
    orderBy: { name: "asc" },
  });
  res.json({ spaTreatments: treatments });
}

async function updateSpaTreatment(req, res) {
  const { id } = req.params;
  const { name, description, durationMinutes, price, currency, isAvailable } = req.body;
  const treatment = await prisma.spaTreatment.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(description !== undefined ? { description } : {}),
      ...(durationMinutes !== undefined ? { durationMinutes } : {}),
      ...(price !== undefined ? { price } : {}),
      ...(currency !== undefined ? { currency } : {}),
      ...(isAvailable !== undefined ? { isAvailable } : {}),
    },
  });
  res.json({ spaTreatment: treatment });
}

async function deleteSpaTreatment(req, res) {
  const { id } = req.params;
  const treatment = await prisma.spaTreatment.update({ where: { id }, data: { isAvailable: false } });
  res.json({ spaTreatment: treatment });
}


// =============================================================================
// CONTROLLERS: ORDERS  (was controllers/orderController.js)
// =============================================================================

const VALID_ORDER_TYPES = ["ROOM_SERVICE", "RESTAURANT", "BAR", "EVENT_TICKET", "UPCOMING_EVENT_TICKET", "SPA", "LAUNDRY", "OTHER"];

// Which Branch.services entry each order type requires. OTHER has no
// mapping — it's the deliberate catch-all and stays ungated.
const ORDER_TYPE_SERVICE = {
  ROOM_SERVICE: "room_service",
  RESTAURANT: "restaurant",
  BAR: "bar",
  EVENT_TICKET: "events",
  UPCOMING_EVENT_TICKET: "upcoming_events",
  SPA: "spa",
  LAUNDRY: "laundry",
  OTHER: null,
};

/** Validates a promo code against a guest/branch/context/subtotal and
 * returns the discount to apply — does NOT record the redemption or
 * increment usedCount, since the caller needs to do that inside the same
 * transaction as the actual booking/order creation (so a failed booking
 * never burns a use of the code). */
async function resolveAndPreviewPromo(code, { guestId, branchId, context, subtotal }) {
  const promo = await prisma.promoCode.findUnique({ where: { code: code.trim().toUpperCase() } });
  if (!promo || !promo.isActive) throw new Error("Invalid or inactive promo code");
  if (promo.branchId && promo.branchId !== branchId) throw new Error("This code isn't valid at this branch");
  if (promo.restrictToGuestId && promo.restrictToGuestId !== guestId) throw new Error("This code isn't valid on this account");
  const now = new Date();
  if (promo.startsAt && now < promo.startsAt) throw new Error("This code isn't active yet");
  if (promo.expiresAt && now > promo.expiresAt) throw new Error("This code has expired");
  if (promo.maxUses != null && promo.usedCount >= promo.maxUses) throw new Error("This code has reached its usage limit");
  if (promo.appliesTo.length && !promo.appliesTo.includes(context)) throw new Error(`This code doesn't apply to ${context}`);

  if (promo.perGuestLimit != null) {
    const guestUses = await prisma.promoRedemption.count({ where: { promoCodeId: promo.id, guestId } });
    if (guestUses >= promo.perGuestLimit) throw new Error("You've already used this code");
  }

  const discountAmount = promo.discountType === "PERCENT"
    ? Math.round(subtotal * (Number(promo.discountValue) / 100) * 100) / 100
    : Math.min(Number(promo.discountValue), subtotal);

  return { promoCodeId: promo.id, discountAmount };
}

/** Guest places an order — works logged in or as guest checkout. Every
 * catalog-backed type (ROOM_SERVICE, RESTAURANT, BAR, LAUNDRY, SPA,
 * EVENT_TICKET) has its price computed HERE from the DB, never trusted from
 * the request body. Only OTHER (staff-priced/complimentary, no catalog)
 * still accepts a client-supplied totalAmount, same as before. */
async function createOrder(req, res) {
  const { branchId } = req.params;
  const { type, guest, roomId, bookingId, promoCode } = req.body;

  if (!req.user && (!guest?.name || !guest?.email)) {
    return res.status(400).json({ error: "guest.name and guest.email are required for guest checkout" });
  }
  if (!type || !VALID_ORDER_TYPES.includes(type)) {
    return res.status(400).json({ error: `type must be one of: ${VALID_ORDER_TYPES.join(", ")}` });
  }

  const branch = await prisma.branch.findFirst({ where: { id: branchId, isActive: true } });
  if (!branch) return res.status(404).json({ error: "Branch not found" });
  const requiredService = ORDER_TYPE_SERVICE[type];
  if (requiredService && !branch.services.includes(requiredService)) {
    return res.status(404).json({ error: `This branch does not offer "${requiredService}"` });
  }

  let guestId;
  if (req.user) {
    guestId = req.user.id;
  } else {
    const guestRecord = await prisma.guest.upsert({
      where: { email: guest.email },
      update: { name: guest.name, phone: guest.phone },
      create: { name: guest.name, email: guest.email, phone: guest.phone },
    });
    guestId = guestRecord.id;
  }

  // If a room/booking is given, verify it's actually this guest's active
  // stay at this branch — so kitchen/spa/front-desk always know exactly
  // where an order belongs, and a guest can't order "to" someone else's room.
  if (roomId || bookingId) {
    const activeBooking = await prisma.booking.findFirst({
      where: {
        branchId, guestId,
        ...(bookingId ? { id: bookingId } : {}),
        ...(roomId ? { roomId } : {}),
        status: { in: ["CONFIRMED", "CHECKED_IN"] },
      },
    });
    if (!activeBooking) return res.status(400).json({ error: "No matching active booking found for this room" });
  }

  let totalAmount = 0;
  let currency = "NGN";
  let items = null;
  let orderLines = [];
  let spaAppointmentData = null;
  let eventId = null;
  let upcomingEventId = null;
  let stockDeductions = []; // [{ stockItemId, qty }] — only populated for lines linked to inventory

  if (type === "ROOM_SERVICE" || type === "RESTAURANT" || type === "BAR") {
    const category = type === "BAR" ? "DRINK" : "FOOD";
    const lines = req.body.lines;
    if (!Array.isArray(lines) || !lines.length) return res.status(400).json({ error: "lines is required (array of { menuItemId, quantity })" });

    const menuItemIds = [...new Set(lines.map((l) => l.menuItemId))];
    const menuItems = await prisma.menuItem.findMany({ where: { id: { in: menuItemIds }, branchId, category, isAvailable: true } });
    if (menuItems.length !== menuItemIds.length) {
      return res.status(400).json({ error: "One or more menu items are unavailable or don't belong to this branch/category" });
    }
    if (type === "ROOM_SERVICE" && menuItems.some((m) => !m.availableForRoomService)) {
      return res.status(400).json({ error: "One or more items aren't available for room service" });
    }
    const byId = Object.fromEntries(menuItems.map((m) => [m.id, m]));
    for (const line of lines) {
      const item = byId[line.menuItemId];
      const qty = Math.max(1, Number(line.quantity) || 1);
      totalAmount += Number(item.price) * qty;
      orderLines.push({ menuItemId: item.id, itemName: item.name, quantity: qty, unitPrice: item.price, notes: line.notes || null });
      if (item.stockItemId) stockDeductions.push({ stockItemId: item.stockItemId, qty: qty * (item.stockQtyPerUnit || 1) });
    }
    currency = menuItems[0].currency;
  } else if (type === "LAUNDRY") {
    const lines = req.body.lines;
    if (!Array.isArray(lines) || !lines.length) return res.status(400).json({ error: "lines is required (array of { laundryItemId, quantity })" });

    const ids = [...new Set(lines.map((l) => l.laundryItemId))];
    const laundryItems = await prisma.laundryItem.findMany({ where: { id: { in: ids }, branchId, isAvailable: true } });
    if (laundryItems.length !== ids.length) {
      return res.status(400).json({ error: "One or more laundry items are unavailable or don't belong to this branch" });
    }
    const byId = Object.fromEntries(laundryItems.map((m) => [m.id, m]));
    for (const line of lines) {
      const item = byId[line.laundryItemId];
      const qty = Math.max(1, Number(line.quantity) || 1);
      totalAmount += Number(item.price) * qty;
      orderLines.push({ laundryItemId: item.id, itemName: item.name, quantity: qty, unitPrice: item.price });
      // Laundry never touches StockItem — capacity-unlimited by design.
    }
    currency = laundryItems[0].currency;
  } else if (type === "SPA") {
    const { treatmentId, scheduledAt } = req.body;
    if (!treatmentId || !scheduledAt) return res.status(400).json({ error: "treatmentId and scheduledAt are required" });

    const treatment = await prisma.spaTreatment.findFirst({ where: { id: treatmentId, branchId, isAvailable: true } });
    if (!treatment) return res.status(404).json({ error: "Spa treatment not found" });

    const start = new Date(scheduledAt);
    if (Number.isNaN(start.getTime())) return res.status(400).json({ error: "scheduledAt is not a valid date" });
    const end = new Date(start.getTime() + treatment.durationMinutes * 60000);

    // App-level overlap check (same pattern as room booking conflicts) —
    // widened window to catch any appointment that could plausibly overlap.
    const nearby = await prisma.spaAppointment.findMany({
      where: { treatment: { branchId }, scheduledAt: { gte: new Date(start.getTime() - 4 * 60 * 60000), lt: end } },
    });
    const hasConflict = nearby.some((a) => {
      const aEnd = new Date(a.scheduledAt.getTime() + a.durationMinutes * 60000);
      return start < aEnd && end > a.scheduledAt;
    });
    if (hasConflict) return res.status(409).json({ error: "This time slot is already booked" });

    totalAmount = Number(treatment.price);
    currency = treatment.currency;
    spaAppointmentData = { treatmentId, scheduledAt: start, durationMinutes: treatment.durationMinutes };
    items = { treatmentId, treatmentName: treatment.name, scheduledAt: start.toISOString() };
  } else if (type === "EVENT_TICKET") {
    eventId = req.body.eventId;
    const quantity = Math.max(1, Number(req.body.quantity) || 1);
    if (!eventId) return res.status(400).json({ error: "eventId is required" });

    const event = await prisma.event.findFirst({ where: { id: eventId, branchId } });
    if (!event) return res.status(404).json({ error: "Event not found" });

    if (event.capacity != null) {
      const soldOrders = await prisma.order.findMany({
        where: { eventId, type: "EVENT_TICKET", status: { not: "CANCELLED" } },
        select: { items: true },
      });
      const sold = soldOrders.reduce((sum, o) => sum + (o.items?.quantity || 0), 0);
      if (sold + quantity > event.capacity) {
        return res.status(409).json({ error: `Only ${Math.max(0, event.capacity - sold)} ticket(s) remaining for this event` });
      }
    }

    totalAmount = event.price ? Number(event.price) * quantity : 0;
    currency = event.currency;
    items = { quantity };
  } else if (type === "UPCOMING_EVENT_TICKET") {
    upcomingEventId = req.body.upcomingEventId;
    const quantity = Math.max(1, Number(req.body.quantity) || 1);
    if (!upcomingEventId) return res.status(400).json({ error: "upcomingEventId is required" });

    const upcomingEvent = await prisma.upcomingEvent.findFirst({ where: { id: upcomingEventId, branchId } });
    if (!upcomingEvent) return res.status(404).json({ error: "Upcoming event not found" });
    if (upcomingEvent.status !== "PUBLISHED") {
      return res.status(404).json({ error: "This event isn't open for ticket sales" });
    }

    if (upcomingEvent.capacity != null) {
      const soldOrders = await prisma.order.findMany({
        where: { upcomingEventId, type: "UPCOMING_EVENT_TICKET", status: { not: "CANCELLED" } },
        select: { items: true },
      });
      const sold = soldOrders.reduce((sum, o) => sum + (o.items?.quantity || 0), 0);
      if (sold + quantity > upcomingEvent.capacity) {
        return res.status(409).json({ error: `Only ${Math.max(0, upcomingEvent.capacity - sold)} ticket(s) remaining for this event` });
      }
    }

    totalAmount = upcomingEvent.ticketPrice ? Number(upcomingEvent.ticketPrice) * quantity : 0;
    currency = upcomingEvent.currency;
    items = { quantity };
  } else {
    // OTHER — no catalog to price against; staff-priced or complimentary,
    // same trust model as before (this is the one deliberate exception).
    if (!req.body.items) return res.status(400).json({ error: "items is required" });
    items = req.body.items;
    totalAmount = req.body.totalAmount || null;
  }

  // Optional promo code — validated and applied against the computed subtotal.
  let promoResult = null;
  if (promoCode && totalAmount) {
    try {
      promoResult = await resolveAndPreviewPromo(promoCode, { guestId, branchId, context: type, subtotal: totalAmount });
      totalAmount = Math.max(0, totalAmount - promoResult.discountAmount);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  }

  const order = await prisma.$transaction(async (tx) => {
    const created = await tx.order.create({
      data: {
        branchId, guestId, type, items, totalAmount, currency,
        roomId: roomId || null, bookingId: bookingId || null, eventId: eventId || null,
        upcomingEventId: upcomingEventId || null,
        ...(orderLines.length ? { lines: { create: orderLines } } : {}),
        ...(spaAppointmentData ? { spaAppointment: { create: spaAppointmentData } } : {}),
      },
      include: { lines: true, spaAppointment: true },
    });
    if (promoResult) {
      await tx.promoRedemption.create({
        data: { promoCodeId: promoResult.promoCodeId, guestId, orderId: created.id, discountAmount: promoResult.discountAmount },
      });
      await tx.promoCode.update({ where: { id: promoResult.promoCodeId }, data: { usedCount: { increment: 1 } } });
    }
    return created;
  });

  
  const guestRecord = await prisma.guest.findUnique({ where: { id: guestId } });
  const ORDER_SUMMARY_BUILDERS = {
    ROOM_SERVICE: () => orderLines.map((l) => `${l.quantity}x ${l.itemName}`).join("\n"),
    RESTAURANT: () => orderLines.map((l) => `${l.quantity}x ${l.itemName}`).join("\n"),
    BAR: () => orderLines.map((l) => `${l.quantity}x ${l.itemName}`).join("\n"),
    LAUNDRY: () => orderLines.map((l) => `${l.quantity}x ${l.itemName}`).join("\n"),
    SPA: () => items ? `${items.treatmentName} — ${new Date(items.scheduledAt).toLocaleString()}` : "Spa appointment",
    EVENT_TICKET: () => `${items?.quantity || 1} ticket(s)`,
    UPCOMING_EVENT_TICKET: () => `${items?.quantity || 1} ticket(s)`,
    OTHER: () => (typeof items === "string" ? items : JSON.stringify(items || {})),
  };
  sendOrderConfirmation({
    guestEmail: guestRecord.email,
    guestName: guestRecord.name,
    branchName: branch.name,
    type,
    itemsSummary: (ORDER_SUMMARY_BUILDERS[type] || (() => "Order"))(),
    totalAmount: order.totalAmount,
    currency: order.currency,
  }).catch((err) => console.error("[email] order confirmation failed:", err.message));

  
  res.status(201).json({ order });
}

/** Starts a Paystack transaction for an order that has a totalAmount (e.g.
 * a restaurant order or event ticket). Free/complimentary orders (no
 * totalAmount) skip payment entirely and just get processed by branch staff.
 * Renamed from `initiatePayment` -> `initiateOrderPayment` (collided with
 * bookingController's `initiatePayment` once merged into one file). */
async function initiateOrderPayment(req, res) {
  const { branchId, id } = req.params;
  const { callbackUrl } = req.body;

  const order = await prisma.order.findFirst({ where: { id, branchId }, include: { guest: true, branch: true } });
  if (!order) return res.status(404).json({ error: "Order not found at this branch" });
  if (!order.totalAmount) return res.status(400).json({ error: "This order has no charge to pay" });
  if (order.paymentStatus === "SUCCESSFUL") return res.status(409).json({ error: "This order has already been paid for" });
  if (!order.branch.paystackSubaccountCode) {
    console.error(`[paystack] Branch ${branchId} has no payout account configured — this payment will settle to the main account instead of the branch.`);
  }

  const reference = `order_${order.id}_${Date.now()}`;

  const transaction = await initializeTransaction({
    email: order.guest.email,
    amountNaira: order.totalAmount,
    reference,
    callbackUrl,
    metadata: { orderId: order.id, branchId },
    subaccountCode: order.branch.paystackSubaccountCode || undefined,
  });

  await prisma.order.update({ where: { id: order.id }, data: { paymentRef: reference, paymentStatus: "PENDING" } });

  res.json({ authorizationUrl: transaction.authorization_url, reference });
}

/** Stripe equivalent of initiateOrderPayment — separate endpoint, same
 * reasoning as initiateBookingPaymentStripe above. */
async function initiateOrderPaymentStripe(req, res) {
  const { branchId, id } = req.params;
  const { successUrl, cancelUrl } = req.body;

  const order = await prisma.order.findFirst({ where: { id, branchId }, include: { guest: true, branch: true } });
  if (!order) return res.status(404).json({ error: "Order not found at this branch" });
  if (!order.totalAmount) return res.status(400).json({ error: "This order has no charge to pay" });
  if (order.paymentStatus === "SUCCESSFUL") return res.status(409).json({ error: "This order has already been paid for" });

  const reference = `order_${order.id}_${Date.now()}`;

  const session = await createStripeCheckoutSession({
    email: order.guest.email,
    amount: order.totalAmount,
    currency: order.currency,
    reference,
    successUrl,
    cancelUrl,
    metadata: { orderId: order.id, branchId, description: `Order at ${order.branch.name}` },
    connectedAccountId: order.branch.stripeConnectedAccountId || undefined,
  });

  await prisma.order.update({ where: { id: order.id }, data: { paymentRef: reference, paymentStatus: "PENDING" } });

  res.json({ checkoutUrl: session.url, sessionId: session.id, reference });
}

async function listBranchOrders(req, res) {
  const branchId = resolveBranchScope(req);
  const { status, type } = req.query;
  const orders = await prisma.order.findMany({
    where: { ...(branchId ? { branchId } : {}), ...(status ? { status } : {}), ...(type ? { type } : {}) },
    include: { guest: true, event: true, branch: true },
    orderBy: { createdAt: "desc" },
  });
  res.json({ orders });
}


// =============================================================================
// CONTROLLERS: TICKETS  (was controllers/ticketController.js)
// =============================================================================

async function createTicket(req, res) {
  const { branchId } = req.params;
  const { subject, message, priority, guest } = req.body;

  if (!req.user && (!guest?.name || !guest?.email)) {
    return res.status(400).json({ error: "guest.name and guest.email are required for guest checkout" });
  }
  if (!subject || !message) return res.status(400).json({ error: "subject and message are required" });

  let guestRecord;
  if (req.user) {
    guestRecord = await prisma.guest.findUnique({ where: { id: req.user.id } });
  } else {
    guestRecord = await prisma.guest.upsert({
      where: { email: guest.email },
      update: { name: guest.name, phone: guest.phone },
      create: { name: guest.name, email: guest.email, phone: guest.phone },
    });
  }

  const ticket = await prisma.ticket.create({
    data: {
      branchId, guestId: guestRecord.id, subject, priority: priority || "NORMAL",
      messages: { create: { senderType: "GUEST", guestName: guestRecord.name, message } },
    },
    include: { messages: true },
  });

  const branch = await prisma.branch.findUnique({ where: { id: branchId } });
  const [ticketManagers, ticketStaff] = await Promise.all([
    prisma.manager.findMany({ where: { branchId, isActive: true, permissions: { has: "handle_tickets" } }, select: { email: true } }),
    prisma.staff.findMany({ where: { branchId, isActive: true, permissions: { has: "handle_tickets" } }, select: { email: true } }),
  ]);
  sendNewTicketAlert({
    staffEmails: [...ticketManagers, ...ticketStaff].map((s) => s.email),
    branchName: branch.name,
    subject,
    guestName: guestRecord.name,
  }).catch((err) => console.error("[email] new ticket alert failed:", err.message));

  getIO()?.to(branchSupportRoom(branchId)).emit("new_ticket", ticket);

  // Anonymous guest checkout gets a scoped token to authenticate chat for
  // THIS ticket only — nothing broader. A registered guest already has a
  // full login token and doesn't need this.
  const accessToken = req.user ? null : signTicketAccessToken(ticket.id, guestRecord.email);

  res.status(201).json({ ticket, accessToken });
}

/** Re-issues a ticket access token for a guest returning without their
 * original one (new device, cleared storage) — proven by email match
 * against the ticket's own guest record. */
async function issueTicketAccessToken(req, res) {
  const { branchId, id } = req.params;
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "email is required" });

  const ticket = await prisma.ticket.findFirst({ where: { id, branchId }, include: { guest: true } });
  if (!ticket) return res.status(404).json({ error: "Ticket not found at this branch" });
  if (ticket.guest.email.toLowerCase() !== email.toLowerCase()) {
    return res.status(403).json({ error: "Email does not match this ticket" });
  }

  res.json({ accessToken: signTicketAccessToken(ticket.id, ticket.guest.email) });
}

/** Shared by the attachment-upload route: resolves whether the requester
 * (director, manager, staff, registered guest, or anonymous guest bearing a
 * ticket access token) may act on this ticket at all. */
async function resolveTicketParticipant(req) {
  const { id } = req.params;
  const ticket = await prisma.ticket.findUnique({ where: { id }, include: { guest: true } });
  if (!ticket) return { ticket: null, viewerType: null };

  if (req.user?.type === "director") return { ticket, viewerType: "staff" };
  if ((req.user?.type === "manager" || req.user?.type === "staff") && req.user.branchId === ticket.branchId) {
    return { ticket, viewerType: "staff" };
  }
  if (req.user?.type === "guest" && req.user.id === ticket.guestId) {
    return { ticket, viewerType: "guest" };
  }
  const accessToken = req.headers["x-ticket-access-token"];
  if (accessToken) {
    try {
      const payload = jwt.verify(accessToken, jwtSecret());
      if (payload.type === "ticket_guest" && payload.ticketId === id && payload.email === ticket.guest.email.toLowerCase()) {
        return { ticket, viewerType: "guest" };
      }
    } catch (err) { /* falls through to unauthorized below */ }
  }
  return { ticket, viewerType: null };
}

/** Uploads a chat attachment (image or file) to Cloudinary and returns the
 * URL — the client sends that URL in the actual message (guest_message
 * over the socket, or the `attachmentUrl` field on a staff REST reply). */
async function uploadTicketAttachment(req, res) {
  const { ticket, viewerType } = await resolveTicketParticipant(req);
  if (!ticket) return res.status(404).json({ error: "Ticket not found" });
  if (!viewerType) return res.status(403).json({ error: "Not authorized for this ticket" });
  if (!req.file) return res.status(400).json({ error: "No file provided (field name: file)" });

  const url = await uploadBuffer(req.file.buffer, "uyeh-hotel/tickets");
  const attachmentType = req.file.mimetype.startsWith("image/") ? "image" : "file";
  res.status(201).json({ attachmentUrl: url, attachmentType });
}

async function listBranchTickets(req, res) {
  const branchId = resolveBranchScope(req);
  const { status } = req.query;
  const tickets = await prisma.ticket.findMany({
    where: { ...(branchId ? { branchId } : {}), ...(status ? { status } : {}) },
    include: {
      guest: true,
      assignedManager: { select: { id: true, name: true, roleTitle: true } },
      assignedStaffMember: { select: { id: true, name: true, roleTitle: true } },
    },
    orderBy: { createdAt: "desc" },
  });
  const withUnread = await Promise.all(tickets.map(async (t) => ({
    ...t,
    unreadCount: await prisma.ticketMessage.count({
      where: { ticketId: t.id, senderType: "GUEST", ...(t.staffLastReadAt ? { createdAt: { gt: t.staffLastReadAt } } : {}) },
    }),
    online: (onlineGuestsByTicket.get(t.id)?.size || 0) > 0,
  })));
  res.json({ tickets: withUnread });
}

async function getTicket(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const ticket = await prisma.ticket.findFirst({
    where: { id, ...(branchId ? { branchId } : {}) },
    include: { guest: true, assignedStaff: true, messages: { orderBy: { createdAt: "asc" } } },
  });
  if (!ticket) return res.status(404).json({ error: "Ticket not found at this branch" });
  res.json({ ticket });
}

/** The staff member being assigned must belong to the ticket's own branch —
 * the rule that keeps staff scoped to their own branch's guests. A Director
 * assigning across branches still has to name someone from that ticket's
 * actual branch. */
async function assignTicket(req, res) {
  const { id } = req.params;
  const { staffId } = req.body;

  const ticket = await prisma.ticket.findUnique({ where: { id } });
  if (!ticket) return res.status(404).json({ error: "Ticket not found" });

  const scope = resolveBranchScope(req);
  if (scope && ticket.branchId !== scope) return res.status(404).json({ error: "Ticket not found at this branch" });

  const targetStaffId = staffId || (["manager", "staff"].includes(req.user.type) ? req.user.id : null);
  if (!targetStaffId) return res.status(400).json({ error: "staffId is required" });

  const [manager, staffMember] = await Promise.all([
    prisma.manager.findFirst({ where: { id: targetStaffId, branchId: ticket.branchId } }),
    prisma.staff.findFirst({ where: { id: targetStaffId, branchId: ticket.branchId } }),
  ]);
  if (!manager && !staffMember) return res.status(400).json({ error: "That person does not belong to this ticket's branch" });

  const updated = await prisma.ticket.update({
    where: { id },
    data: manager
      ? { assignedManagerId: manager.id, assignedStaffId: null, status: "IN_PROGRESS" }
      : { assignedStaffId: staffMember.id, assignedManagerId: null, status: "IN_PROGRESS" },
  });

  getIO()?.to(branchSupportRoom(ticket.branchId)).emit("ticket_updated", updated);

  res.json({ ticket: updated });
}

async function replyToTicket(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const { message, attachmentUrl, attachmentType } = req.body;
  if (!message && !attachmentUrl) return res.status(400).json({ error: "message or attachmentUrl is required" });

  const ticket = await prisma.ticket.findFirst({ where: { id, ...(branchId ? { branchId } : {}) }, include: { guest: true, branch: true } });
  if (!ticket) return res.status(404).json({ error: "Ticket not found at this branch" });

  const senderType = req.user.type.toUpperCase(); // "DIRECTOR" | "MANAGER" | "STAFF"
  const senderFkField = { DIRECTOR: "directorId", MANAGER: "managerId", STAFF: "staffId" }[senderType];
  const senderModel = { DIRECTOR: "director", MANAGER: "manager", STAFF: "staff" }[senderType];
  const sender = await prisma[senderModel].findUnique({ where: { id: req.user.id } });

  // Best-effort "delivered": true if the guest currently has an active
  // socket in this ticket's room (onlineGuestsByTicket, module-scope,
  // populated in initSocketHandlers).
  const deliveredNow = (onlineGuestsByTicket.get(id)?.size || 0) > 0;
  const now = new Date();

  const ticketMessage = await prisma.$transaction(async (tx) => {
    const created = await tx.ticketMessage.create({
      data: {
        ticketId: id, senderType, [senderFkField]: req.user.id, message: message || "",
        attachmentUrl: attachmentUrl || null, attachmentType: attachmentType || null,
        deliveredAt: deliveredNow ? now : null,
      },
    });
    await tx.ticket.update({ where: { id }, data: { staffLastReadAt: now } }); // replying implies you've read up to now
    return created;
  });

  sendTicketReply({
    guestEmail: ticket.guest.email,
    guestName: ticket.guest.name,
    branchName: ticket.branch.name,
    subject: ticket.subject,
    message: message || "(sent an attachment)",
    staffName: sender.name,
  }).catch((err) => console.error("[email] ticket reply failed:", err.message));

  getIO()?.to(ticketRoom(id)).emit("new_message", ticketMessage);
  getIO()?.to(branchSupportRoom(ticket.branchId)).emit("ticket_activity", { ticketId: id, from: "staff" });

  res.status(201).json({ ticketMessage });
}

async function resolveTicket(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const ticket = await prisma.ticket.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!ticket) return res.status(404).json({ error: "Ticket not found at this branch" });

  const updated = await prisma.ticket.update({ where: { id }, data: { status: "RESOLVED", resolvedAt: new Date() } });

  getIO()?.to(ticketRoom(id)).emit("ticket_resolved", updated);
  getIO()?.to(branchSupportRoom(ticket.branchId)).emit("ticket_updated", updated);

  res.json({ ticket: updated });
}

// =============================================================================
// CONTROLLERS: EVENTS  (was controllers/eventController.js)
// =============================================================================

/** Both Event (venue rental) and UpcomingEvent (hotel-hosted, ticketed)
 * compete for the same physical space — only one hosted per branch per
 * overlapping day. Checked on Event creation, and on UpcomingEvent submit
 * + approve (a draft/rejected UpcomingEvent doesn't block anything —
 * same reasoning as why a PENDING_APPROVAL newsletter campaign doesn't
 * send). Follows the same fetch-candidates-then-filter-in-JS pattern as
 * the spa appointment overlap check above, rather than a raw SQL overlap
 * query, to stay consistent with the rest of this file. */
async function assertNoEventSameDay({ branchId, startsAt, endsAt, excludeEventId, excludeUpcomingEventId }) {
  const dayStart = new Date(startsAt);
  const dayEnd = endsAt ? new Date(endsAt) : new Date(new Date(dayStart).setHours(23, 59, 59, 999));

  const [venueEvents, upcomingEvents] = await Promise.all([
    prisma.event.findMany({ where: { branchId, ...(excludeEventId ? { id: { not: excludeEventId } } : {}) } }),
    prisma.upcomingEvent.findMany({
      where: {
        branchId,
        status: { in: ["PENDING_APPROVAL", "PUBLISHED"] },
        ...(excludeUpcomingEventId ? { id: { not: excludeUpcomingEventId } } : {}),
      },
    }),
  ]);

  const overlaps = (ev) => {
    const evStart = new Date(ev.startsAt);
    const evEnd = ev.endsAt ? new Date(ev.endsAt) : new Date(new Date(evStart).setHours(23, 59, 59, 999));
    return dayStart < evEnd && evStart < dayEnd;
  };

  if (venueEvents.some(overlaps) || upcomingEvents.some(overlaps)) {
    throw Object.assign(new Error("Another event is already scheduled at this branch on an overlapping day"), { status: 409 });
  }
}

async function createEvent(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "branchId is required (Director must pass ?branchId=)" });
  const { name, description, startsAt, endsAt, capacity, price, currency, images } = req.body;
  if (!name || !startsAt) return res.status(400).json({ error: "name and startsAt are required" });

  try {
    await assertNoEventSameDay({ branchId, startsAt, endsAt });
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }

  const event = await prisma.event.create({
    data: {
      branchId, name, description, startsAt: new Date(startsAt),
      endsAt: endsAt ? new Date(endsAt) : null, capacity, price,
      currency: currency || "NGN", images: images || [],
    },
  });
  res.status(201).json({ event });
}

/** Shared by the public site (branchId in the URL) and the admin panel
 * (branchId from the token) — same dual-source pattern as listRoomTypes. */
async function listEvents(req, res) {
  const branchId = req.params.branchId || resolveBranchScope(req);
  const { upcoming } = req.query;
  const events = await prisma.event.findMany({
    where: { ...(branchId ? { branchId } : {}), ...(upcoming === "true" ? { startsAt: { gte: new Date() } } : {}) },
    orderBy: { startsAt: "asc" },
  });
  res.json({ events });
}

async function updateEvent(req, res) {
  const { id } = req.params;
  const { name, description, startsAt, endsAt, capacity, price, images } = req.body;
  const event = await prisma.event.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(description !== undefined ? { description } : {}),
      ...(startsAt !== undefined ? { startsAt: new Date(startsAt) } : {}),
      ...(endsAt !== undefined ? { endsAt: endsAt ? new Date(endsAt) : null } : {}),
      ...(capacity !== undefined ? { capacity } : {}),
      ...(price !== undefined ? { price } : {}),
      ...(images !== undefined ? { images } : {}),
    },
  });
  res.json({ event });
}

async function deleteEvent(req, res) {
  const { id } = req.params;
  await prisma.event.delete({ where: { id } });
  res.json({ message: "Event deleted" });
}

async function uploadEventImage(req, res) {
  const { id } = req.params;
  if (!req.file) return res.status(400).json({ error: "No image file provided (field name: image)" });

  const event = await prisma.event.findUnique({ where: { id } });
  if (!event) return res.status(404).json({ error: "Event not found" });

  const url = await uploadBuffer(req.file.buffer, "Uyeh-hotel/events");
  const updated = await prisma.event.update({ where: { id }, data: { images: [...event.images, url] } });
  res.status(201).json({ event: updated, uploadedUrl: url });
}

async function deleteEventImage(req, res) {
  const { id } = req.params;
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "url is required" });

  const event = await prisma.event.findUnique({ where: { id } });
  if (!event) return res.status(404).json({ error: "Event not found" });

  const updated = await prisma.event.update({ where: { id }, data: { images: event.images.filter((img) => img !== url) } });
  await deleteFromCloudinaryByUrl(url);
  res.json({ event: updated });
}

// =============================================================================
// CONTROLLERS: UPCOMING EVENTS (hotel-hosted, ticketed — distinct from
// Event, which is a guest renting the hall for their OWN function)
// =============================================================================

const UPCOMING_EVENT_EDITABLE_STATUSES = ["DRAFT", "REJECTED"];

/** Manager drafts. Invisible everywhere else until submitted + approved. */
async function createUpcomingEvent(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "branchId is required" });
  if (req.user.type !== "manager") return res.status(403).json({ error: "Only a Manager can draft an Upcoming Event — a Director approves it" });

  const { title, description, startsAt, endsAt, capacity, ticketPrice, currency, images } = req.body;
  if (!title || !startsAt) return res.status(400).json({ error: "title and startsAt are required" });

  const upcomingEvent = await prisma.upcomingEvent.create({
    data: {
      branchId, title, description, startsAt: new Date(startsAt),
      endsAt: endsAt ? new Date(endsAt) : null, capacity, ticketPrice,
      currency: currency || "NGN", images: images || [],
      status: "DRAFT", createdByManagerId: req.user.id,
    },
  });
  res.status(201).json({ upcomingEvent });
}

/** Manager can only edit while DRAFT or REJECTED — once submitted or
 * published it's locked pending Director action. */
async function updateUpcomingEvent(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.upcomingEvent.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Upcoming event not found at this branch" });
  if (req.user.type === "manager" && !UPCOMING_EVENT_EDITABLE_STATUSES.includes(existing.status)) {
    return res.status(409).json({ error: `Can't edit an event that's ${existing.status.toLowerCase().replace("_", " ")} — only draft or rejected events can be revised` });
  }

  const { title, description, startsAt, endsAt, capacity, ticketPrice, currency, images } = req.body;
  const upcomingEvent = await prisma.upcomingEvent.update({
    where: { id },
    data: {
      ...(title !== undefined ? { title } : {}),
      ...(description !== undefined ? { description } : {}),
      ...(startsAt !== undefined ? { startsAt: new Date(startsAt) } : {}),
      ...(endsAt !== undefined ? { endsAt: endsAt ? new Date(endsAt) : null } : {}),
      ...(capacity !== undefined ? { capacity } : {}),
      ...(ticketPrice !== undefined ? { ticketPrice } : {}),
      ...(currency !== undefined ? { currency } : {}),
      ...(images !== undefined ? { images } : {}),
      // Re-editing a rejected draft clears the rejection so it doesn't
      // linger stale once resubmitted.
      ...(existing.status === "REJECTED" ? { status: "DRAFT", rejectionReason: null } : {}),
    },
  });
  res.json({ upcomingEvent });
}

async function deleteUpcomingEvent(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.upcomingEvent.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Upcoming event not found at this branch" });
  if (existing.status === "PUBLISHED") {
    const soldOrders = await prisma.order.count({ where: { upcomingEventId: id, status: { not: "CANCELLED" } } });
    if (soldOrders > 0) return res.status(409).json({ error: "This event has tickets sold — cancel it instead of deleting" });
  }
  await prisma.upcomingEvent.delete({ where: { id } });
  res.json({ message: "Upcoming event deleted" });
}

async function submitUpcomingEventForApproval(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.upcomingEvent.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Upcoming event not found at this branch" });
  if (!UPCOMING_EVENT_EDITABLE_STATUSES.includes(existing.status)) {
    return res.status(409).json({ error: `Only a draft or rejected event can be submitted — this one is ${existing.status.toLowerCase().replace("_", " ")}` });
  }

  try {
    await assertNoEventSameDay({ branchId, startsAt: existing.startsAt, endsAt: existing.endsAt, excludeUpcomingEventId: id });
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }

  const upcomingEvent = await prisma.upcomingEvent.update({ where: { id }, data: { status: "PENDING_APPROVAL" } });
  res.json({ upcomingEvent, message: "Submitted — waiting on Director approval." });
}

async function listUpcomingEvents(req, res) {
  const branchId = resolveBranchScope(req);
  const { status } = req.query;
  const upcomingEvents = await prisma.upcomingEvent.findMany({
    where: { ...(branchId ? { branchId } : {}), ...(status ? { status: status.toUpperCase() } : {}) },
    orderBy: { startsAt: "asc" },
    include: { branch: { select: { id: true, name: true } } },
  });
  res.json({ upcomingEvents });
}

async function approveUpcomingEvent(req, res) {
  const { id } = req.params;
  const existing = await prisma.upcomingEvent.findUnique({ where: { id } });
  if (!existing) return res.status(404).json({ error: "Upcoming event not found" });
  if (existing.status !== "PENDING_APPROVAL") {
    return res.status(409).json({ error: `Only a pending event can be approved — this one is ${existing.status.toLowerCase().replace("_", " ")}` });
  }

  try {
    await assertNoEventSameDay({ branchId: existing.branchId, startsAt: existing.startsAt, endsAt: existing.endsAt, excludeUpcomingEventId: id });
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }

  const upcomingEvent = await prisma.upcomingEvent.update({
    where: { id },
    data: { status: "PUBLISHED", approvedByDirectorId: req.user.id, approvedAt: new Date() },
  });
  logAudit(req, "upcomingEvent.approve", { targetType: "upcomingEvent", targetId: id, branchId: existing.branchId });
  res.json({ upcomingEvent, message: "Published — guests can now see it and buy tickets." });
}

async function rejectUpcomingEvent(req, res) {
  const { id } = req.params;
  const { reason } = req.body;
  const existing = await prisma.upcomingEvent.findUnique({ where: { id } });
  if (!existing) return res.status(404).json({ error: "Upcoming event not found" });
  if (existing.status !== "PENDING_APPROVAL") {
    return res.status(409).json({ error: `Only a pending event can be rejected — this one is ${existing.status.toLowerCase().replace("_", " ")}` });
  }

  const upcomingEvent = await prisma.upcomingEvent.update({
    where: { id },
    data: { status: "REJECTED", rejectionReason: reason || null },
  });
  logAudit(req, "upcomingEvent.reject", { targetType: "upcomingEvent", targetId: id, branchId: existing.branchId });
  res.json({ upcomingEvent, message: "Sent back to the Manager for revision." });
}

/** Public — guests only ever see PUBLISHED, still-upcoming events. */
async function listPublicUpcomingEvents(req, res) {
  const { branchId } = req.params;
  const upcomingEvents = await prisma.upcomingEvent.findMany({
    where: { branchId, status: "PUBLISHED", startsAt: { gte: new Date() } },
    orderBy: { startsAt: "asc" },
  });
  res.json({ upcomingEvents });
}

async function getPublicUpcomingEvent(req, res) {
  const { branchId, id } = req.params;
  const upcomingEvent = await prisma.upcomingEvent.findFirst({ where: { id, branchId, status: "PUBLISHED" } });
  if (!upcomingEvent) return res.status(404).json({ error: "Event not found" });
  res.json({ upcomingEvent });
}

// =============================================================================
// CONTROLLERS: REVIEWS
// =============================================================================

async function createReview(req, res) {
  const { bookingId, ratingValue, title, body } = req.body;
  if (!bookingId || !ratingValue) return res.status(400).json({ error: "bookingId and ratingValue are required" });
  if (ratingValue < 1 || ratingValue > 5) return res.status(400).json({ error: "ratingValue must be 1-5" });

  const booking = await prisma.booking.findFirst({ where: { id: bookingId, guestId: req.user.id } });
  if (!booking) return res.status(404).json({ error: "Booking not found on your account" });
  if (booking.status !== "CHECKED_OUT") return res.status(400).json({ error: "You can only review a completed stay" });

  const existing = await prisma.review.findUnique({ where: { bookingId } });
  if (existing) return res.status(409).json({ error: "You've already reviewed this stay" });

  const review = await prisma.review.create({
    data: { branchId: booking.branchId, guestId: req.user.id, bookingId, ratingValue, title, body, status: "PENDING" },
  });
  res.status(201).json({ review, message: "Thanks — your review is awaiting approval before it appears publicly." });
}

async function listPublishedReviews(req, res) {
  const { branchId } = req.params;
  const reviews = await prisma.review.findMany({
    where: { branchId, status: "PUBLISHED" },
    include: { guest: { select: { name: true } } },
    orderBy: { createdAt: "desc" },
  });
  res.json({ reviews });
}

async function listBranchReviews(req, res) {
  const branchId = resolveBranchScope(req);
  const { status } = req.query;
  const reviews = await prisma.review.findMany({
    where: { ...(branchId ? { branchId } : {}), ...(status ? { status } : {}) },
    include: { guest: { select: { name: true, email: true } } },
    orderBy: { createdAt: "desc" },
  });
  res.json({ reviews });
}

async function moderateReview(req, res) {
  const { id } = req.params;
  const { status } = req.body;
  if (!["PUBLISHED", "REJECTED"].includes(status)) return res.status(400).json({ error: "status must be PUBLISHED or REJECTED" });
  const review = await prisma.review.update({ where: { id }, data: { status } });
  res.json({ review });
}

async function replyToReview(req, res) {
  const { id } = req.params;
  const { reply } = req.body;
  if (!reply) return res.status(400).json({ error: "reply is required" });
  const review = await prisma.review.update({ where: { id }, data: { staffReplyBody: reply, staffReplyAt: new Date() } });
  res.json({ review });
}

// =============================================================================
// CONTROLLERS: PROMO CODES
// =============================================================================

async function createPromoCode(req, res) {
  const isDirector = req.user.type === "director";

  const { code, description, discountType, discountValue, appliesTo, maxUses, perGuestLimit, startsAt, expiresAt } = req.body;
  if (!code || !discountType || discountValue === undefined) {
    return res.status(400).json({ error: "code, discountType, and discountValue are required" });
  }
  if (!["PERCENT", "FIXED"].includes(discountType)) return res.status(400).json({ error: "discountType must be PERCENT or FIXED" });

  // Director may go company-wide (branchId: null) or scope to one branch.
  // Manager is always locked to their own branch, regardless of what's sent.
  const branchId = isDirector ? (req.body.branchId || null) : req.user.branchId;

  const existing = await prisma.promoCode.findUnique({ where: { code: code.trim().toUpperCase() } });
  if (existing) return res.status(409).json({ error: "This code already exists" });

  const promo = await prisma.promoCode.create({
    data: {
      branchId, code: code.trim().toUpperCase(), description, discountType, discountValue,
      appliesTo: appliesTo || [], maxUses: maxUses || null, perGuestLimit: perGuestLimit ?? 1,
      startsAt: startsAt ? new Date(startsAt) : null, expiresAt: expiresAt ? new Date(expiresAt) : null,
      createdById: req.user.id,
    },
  });
  res.status(201).json({ promoCode: promo });
}

async function listPromoCodes(req, res) {
  const branchId = resolveBranchScope(req);
  const promos = await prisma.promoCode.findMany({
    where: branchId ? { OR: [{ branchId }, { branchId: null }] } : {},
    orderBy: { createdAt: "desc" },
  });
  res.json({ promoCodes: promos });
}

async function updatePromoCode(req, res) {
  const isDirector = req.user.type === "director";
  const { id } = req.params;
  const target = await prisma.promoCode.findUnique({ where: { id } });
  if (!target) return res.status(404).json({ error: "Promo code not found" });
  if (!isDirector && target.branchId !== req.user.branchId) {
    return res.status(403).json({ error: "You do not have access to this promo code" });
  }

  const { description, discountValue, appliesTo, maxUses, perGuestLimit, startsAt, expiresAt, isActive } = req.body;
  const promo = await prisma.promoCode.update({
    where: { id },
    data: {
      ...(description !== undefined ? { description } : {}),
      ...(discountValue !== undefined ? { discountValue } : {}),
      ...(appliesTo !== undefined ? { appliesTo } : {}),
      ...(maxUses !== undefined ? { maxUses } : {}),
      ...(perGuestLimit !== undefined ? { perGuestLimit } : {}),
      ...(startsAt !== undefined ? { startsAt: startsAt ? new Date(startsAt) : null } : {}),
      ...(expiresAt !== undefined ? { expiresAt: expiresAt ? new Date(expiresAt) : null } : {}),
      ...(isActive !== undefined ? { isActive } : {}),
    },
  });
  res.json({ promoCode: promo });
}

// =============================================================================
// CONTROLLERS: CORPORATE ACCOUNTS + GROUP BOOKINGS
// =============================================================================

async function createCorporateAccount(req, res) {
  const { companyName, contactName, contactEmail, contactPhone, negotiatedDiscountPercent, billingNotes } = req.body;
  if (!companyName || !contactName || !contactEmail) {
    return res.status(400).json({ error: "companyName, contactName, and contactEmail are required" });
  }
  const account = await prisma.corporateAccount.create({
    data: { companyName, contactName, contactEmail, contactPhone, negotiatedDiscountPercent, billingNotes },
  });
  res.status(201).json({ corporateAccount: account });
}

async function listCorporateAccounts(req, res) {
  const accounts = await prisma.corporateAccount.findMany({ where: { isActive: true }, orderBy: { companyName: "asc" } });
  res.json({ corporateAccounts: accounts });
}

async function updateCorporateAccount(req, res) {
  const { id } = req.params;
  const { companyName, contactName, contactEmail, contactPhone, negotiatedDiscountPercent, billingNotes, isActive } = req.body;
  const account = await prisma.corporateAccount.update({
    where: { id },
    data: {
      ...(companyName !== undefined ? { companyName } : {}),
      ...(contactName !== undefined ? { contactName } : {}),
      ...(contactEmail !== undefined ? { contactEmail } : {}),
      ...(contactPhone !== undefined ? { contactPhone } : {}),
      ...(negotiatedDiscountPercent !== undefined ? { negotiatedDiscountPercent } : {}),
      ...(billingNotes !== undefined ? { billingNotes } : {}),
      ...(isActive !== undefined ? { isActive } : {}),
    },
  });
  res.json({ corporateAccount: account });
}

/** Shared by both the guest-facing and staff-facing routes below. Creates
 * one GroupBooking wrapper plus a real Booking per room, in a single
 * transaction, applying the corporate discount (if any) to every room. */
async function createGroupBookingCore({ branchId, corporateAccountId, groupName, checkIn, checkOut, rooms, guestInfo, existingGuestId }) {
  const start = new Date(checkIn);
  const end = new Date(checkOut);
  if (!(start < end)) throw Object.assign(new Error("checkOut must be after checkIn"), { status: 400 });
  if (!Array.isArray(rooms) || !rooms.length) throw Object.assign(new Error("rooms is required (array of { roomId, guestsCount })"), { status: 400 });

  let discountPercent = 0;
  if (corporateAccountId) {
    const account = await prisma.corporateAccount.findFirst({ where: { id: corporateAccountId, isActive: true } });
    if (!account) throw Object.assign(new Error("Corporate account not found or inactive"), { status: 404 });
    discountPercent = Number(account.negotiatedDiscountPercent || 0);
  }

  const roomIds = rooms.map((r) => r.roomId);
  const roomRecords = await prisma.room.findMany({ where: { id: { in: roomIds }, branchId, status: "ACTIVE" } });
  if (roomRecords.length !== new Set(roomIds).size) throw Object.assign(new Error("One or more rooms are unavailable at this branch"), { status: 400 });

  const conflicts = await prisma.booking.findMany({
    where: { roomId: { in: roomIds }, status: { in: ["PENDING", "CONFIRMED", "CHECKED_IN"] }, checkIn: { lt: end }, checkOut: { gt: start } },
  });
  if (conflicts.length) throw Object.assign(new Error("One or more rooms are already booked for these dates"), { status: 409 });

  const nights = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
  const byId = Object.fromEntries(roomRecords.map((r) => [r.id, r]));

  return prisma.$transaction(async (tx) => {
    let guestId = existingGuestId;
    if (!guestId) {
      const guestRecord = await tx.guest.upsert({
        where: { email: guestInfo.email },
        update: { name: guestInfo.name, phone: guestInfo.phone },
        create: { name: guestInfo.name, email: guestInfo.email, phone: guestInfo.phone },
      });
      guestId = guestRecord.id;
    }

    const group = await tx.groupBooking.create({
      data: { branchId, corporateAccountId: corporateAccountId || null, groupName, contactGuestId: guestId, checkIn: start, checkOut: end, status: "PENDING" },
    });

    const bookings = [];
    for (const r of rooms) {
      const room = byId[r.roomId];
      const rawTotal = Number(room.basePrice) * nights;
      const totalAmount = discountPercent ? Math.round(rawTotal * (1 - discountPercent / 100) * 100) / 100 : rawTotal;
      const booking = await tx.booking.create({
        data: {
          branchId, roomId: r.roomId, guestId, checkIn: start, checkOut: end,
          guestsCount: r.guestsCount || 1, status: "PENDING", totalAmount, currency: room.currency,
          groupBookingId: group.id,
        },
      });
      bookings.push(booking);
    }

    return { group, bookings };
  });
}

async function createGroupBookingPublic(req, res) {
  const { branchId } = req.params;
  const { corporateAccountId, groupName, checkIn, checkOut, rooms, guest } = req.body;
  if (!req.user && (!guest?.name || !guest?.email)) {
    return res.status(400).json({ error: "guest.name and guest.email are required" });
  }
  if (!groupName) return res.status(400).json({ error: "groupName is required" });

  try {
    const result = await createGroupBookingCore({
      branchId, corporateAccountId, groupName, checkIn, checkOut, rooms,
      guestInfo: guest, existingGuestId: req.user?.id,
    });
    res.status(201).json({ message: "Group booking created, pending payment per room.", ...result });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
}

async function createGroupBookingStaff(req, res) {
  const branchId = resolveBranchScope(req) || req.body.branchId;
  const { corporateAccountId, groupName, checkIn, checkOut, rooms, guest } = req.body;
  if (!branchId) return res.status(400).json({ error: "branchId is required" });
  if (!groupName || !guest?.name || !guest?.email) return res.status(400).json({ error: "groupName and guest.name/email are required" });

  try {
    const result = await createGroupBookingCore({ branchId, corporateAccountId, groupName, checkIn, checkOut, rooms, guestInfo: guest });
    res.status(201).json({ message: "Group booking created.", ...result });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
}

async function listGroupBookings(req, res) {
  const branchId = resolveBranchScope(req);
  const groups = await prisma.groupBooking.findMany({
    where: branchId ? { branchId } : {},
    include: { bookings: { include: { room: true } }, corporateAccount: true, contactGuest: true },
    orderBy: { checkIn: "asc" },
  });
  res.json({ groupBookings: groups });
}

// =============================================================================
// CONTROLLERS: WISHLIST
// =============================================================================

async function listWishlist(req, res) {
  const items = await prisma.wishlistItem.findMany({
    where: { guestId: req.user.id },
    include: { branch: { select: { name: true, slug: true } }, room: true, event: true },
    orderBy: { createdAt: "desc" },
  });
  res.json({ wishlist: items });
}

async function addWishlistItem(req, res) {
  const { branchId, roomId, eventId } = req.body;
  if (!branchId || (!roomId && !eventId)) {
    return res.status(400).json({ error: "branchId and exactly one of roomId/eventId are required" });
  }
  const item = await prisma.wishlistItem.create({
    data: { guestId: req.user.id, branchId, roomId: roomId || null, eventId: eventId || null },
  });
  res.status(201).json({ wishlistItem: item });
}

async function removeWishlistItem(req, res) {
  const { id } = req.params;
  const item = await prisma.wishlistItem.findFirst({ where: { id, guestId: req.user.id } });
  if (!item) return res.status(404).json({ error: "Wishlist item not found" });
  await prisma.wishlistItem.delete({ where: { id } });
  res.json({ message: "Removed from wishlist" });
}

// =============================================================================
// CONTROLLERS: LOYALTY (guest-facing)
// =============================================================================

async function getLoyalty(req, res) {
  const guest = await prisma.guest.findUnique({ where: { id: req.user.id }, select: { loyaltyPoints: true, lifetimePoints: true } });
  const history = await prisma.loyaltyTransaction.findMany({ where: { guestId: req.user.id }, orderBy: { createdAt: "desc" }, take: 25 });
  res.json({ points: guest.loyaltyPoints, tier: loyaltyTierForLifetimePoints(guest.lifetimePoints), history });
}

/** Converts N points into a one-time, one-guest-only fixed-discount promo
 * code the guest can apply at their next checkout. Points are deducted
 * immediately (not on redemption of the resulting code), so a guest can't
 * generate ten codes with the same point balance. */
async function redeemLoyaltyPoints(req, res) {
  const { points } = req.body;
  const amount = Number(points);
  if (!amount || amount < 100 || amount % 100 !== 0) {
    return res.status(400).json({ error: "points must be a positive multiple of 100" });
  }

  const guest = await prisma.guest.findUnique({ where: { id: req.user.id } });
  if (guest.loyaltyPoints < amount) return res.status(400).json({ error: "Not enough points" });

  const discountValue = (amount / 100) * LOYALTY_NAIRA_PER_POINT_REDEEMED * 100 / 100; // ₦5 per point in 100-point blocks, see constant above
  const code = `LOYALTY-${guest.id.slice(0, 6).toUpperCase()}-${Date.now().toString(36).toUpperCase()}`;

  const promo = await prisma.$transaction(async (tx) => {
    const created = await tx.promoCode.create({
      data: {
        code, discountType: "FIXED", discountValue: amount * LOYALTY_NAIRA_PER_POINT_REDEEMED / 100,
        restrictToGuestId: guest.id, maxUses: 1, perGuestLimit: 1,
        description: `Redeemed ${amount} loyalty points`,
      },
    });
    await tx.guest.update({ where: { id: guest.id }, data: { loyaltyPoints: { decrement: amount } } });
    await tx.loyaltyTransaction.create({ data: { guestId: guest.id, points: -amount, reason: `Redeemed for code ${code}` } });
    return created;
  });

  res.status(201).json({ promoCode: promo.code, discountValue: promo.discountValue, message: "Apply this code at checkout on your next booking or order." });
}
// =============================================================================
// CONTROLLERS: PAYMENTS (Paystack webhook)  (was controllers/paymentController.js)
// =============================================================================

/**
 * Mounted with express.raw() in the app wiring below (not express.json()) so
 * `req.body` here is the raw Buffer needed for signature verification. We
 * JSON.parse it ourselves after the signature check passes.
 */
async function paystackWebhook(req, res) {
  const signature = req.headers["x-paystack-signature"];
  const rawBody = req.body; // Buffer, thanks to express.raw()

  if (!isValidWebhookSignature(rawBody, signature)) {
    return res.status(401).json({ error: "Invalid webhook signature" });
  }

  const event = JSON.parse(rawBody.toString("utf8"));

  // Acknowledge immediately-ish; Paystack retries on non-2xx or timeout.
  if (event.event !== "charge.success") {
    return res.status(200).json({ received: true });
  }

  const reference = event.data?.reference;
  if (!reference) return res.status(200).json({ received: true });

  if (reference.startsWith("booking_")) {
    await handleBookingPayment(reference, event.data);
  } else if (reference.startsWith("order_")) {
    await handleOrderPayment(reference, event.data);
  }

  res.status(200).json({ received: true });
}

/**
 * Mounted with express.raw() — same requirement as paystackWebhook, for the
 * same reason (signature verification needs the raw bytes).
 */
async function stripeWebhook(req, res) {
  let event;
  try {
    event = constructStripeEvent(req.body, req.headers["stripe-signature"]);
  } catch (err) {
    return res.status(400).json({ error: `Webhook signature verification failed: ${err.message}` });
  }

  if (event.type !== "checkout.session.completed") {
    return res.status(200).json({ received: true });
  }

  const reference = event.data.object.client_reference_id || event.data.object.metadata?.reference;
  if (!reference) return res.status(200).json({ received: true });

  if (reference.startsWith("booking_")) {
    await handleBookingPayment(reference, event.data.object);
  } else if (reference.startsWith("order_")) {
    await handleOrderPayment(reference, event.data.object);
  }

  res.status(200).json({ received: true });
}

const LOYALTY_POINTS_PER_NAIRA_SPENT = 0.01; // 1 point per ₦100 spent
const LOYALTY_NAIRA_PER_POINT_REDEEMED = 5;  // 100 points redeem for ₦500

function loyaltyTierForLifetimePoints(points) {
  if (points >= 150000) return "PLATINUM";
  if (points >= 50000) return "GOLD";
  if (points >= 10000) return "SILVER";
  return "BRONZE";
}

/** Fire-and-forget, same spirit as email sends — a loyalty-award failure
 * should never block a payment webhook from completing. */
async function awardLoyaltyPoints(guestId, amountSpent, reason, refs = {}) {
  try {
    const points = Math.floor(Number(amountSpent) * LOYALTY_POINTS_PER_NAIRA_SPENT);
    if (points <= 0) return;
    await prisma.$transaction([
      prisma.guest.update({ where: { id: guestId }, data: { loyaltyPoints: { increment: points }, lifetimePoints: { increment: points } } }),
      prisma.loyaltyTransaction.create({ data: { guestId, points, reason, bookingId: refs.bookingId || null, orderId: refs.orderId || null } }),
    ]);
  } catch (err) {
    console.error("[loyalty] award failed:", err.message);
  }
}

async function handleBookingPayment(reference, paystackData) {
  const payment = await prisma.bookingPayment.findUnique({ where: { providerRef: reference } });
  if (!payment || payment.status === "SUCCESSFUL") return; // already processed or unknown — idempotent

  const result = await prisma.$transaction(async (tx) => {
    const updatedPayment = await tx.bookingPayment.update({ where: { id: payment.id }, data: { status: "SUCCESSFUL" } });
    const booking = await tx.booking.update({
      where: { id: payment.bookingId },
      data: { status: "CONFIRMED" },
      include: { guest: true, branch: true, room: true },
    });
    return { updatedPayment, booking };
  });

  sendPaymentReceipt({
    guestEmail: result.booking.guest.email,
    guestName: result.booking.guest.name,
    branchName: result.booking.branch.name,
    amount: result.updatedPayment.amount,
    currency: result.updatedPayment.currency,
    reference,
  }).catch((err) => console.error("[email] payment receipt failed:", err.message));

  sendBookingStatusUpdate({
    guestEmail: result.booking.guest.email,
    guestName: result.booking.guest.name,
    branchName: result.booking.branch.name,
    status: "CONFIRMED",
    roomTypeName: result.booking.room.name,
    roomNumber: result.booking.room.roomNumber,
  }).catch((err) => console.error("[email] booking status update failed:", err.message));

  awardLoyaltyPoints(result.booking.guestId, result.updatedPayment.amount, `Stay at ${result.booking.branch.name} — booking #${result.booking.id.slice(0, 8)}`, { bookingId: result.booking.id });
}

async function handleOrderPayment(reference, paystackData) {
  const order = await prisma.order.findUnique({ where: { paymentRef: reference }, include: { guest: true, branch: true } });
  if (!order || order.paymentStatus === "SUCCESSFUL") return;

  const updated = await prisma.order.update({
    where: { id: order.id },
    data: { paymentStatus: "SUCCESSFUL", status: "IN_PROGRESS" },
  });

 sendPaymentReceipt({
    guestEmail: order.guest.email,
    guestName: order.guest.name,
    branchName: order.branch.name,
    amount: updated.totalAmount,
    currency: updated.currency,
    reference,
  }).catch((err) => console.error("[email] payment receipt failed:", err.message));

  awardLoyaltyPoints(order.guestId, updated.totalAmount, `Order #${order.id.slice(0, 8)} at ${order.branch.name}`, { orderId: order.id });
}


// =============================================================================
// CONTROLLERS: ROOMS  (was controllers/roomController.js)
// =============================================================================
/** Director-only (see directorRoutes). Every field here is structural —
 * name, price, photos, room number, floor — the stuff a Director "builds"
 * into a branch. Manager's only room-touching route is updateRoomStatus. */
async function createRoom(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "branchId is required (Director must pass ?branchId=)" });
  const { name, description, basePrice, currency, maxOccupancy, amenities, roomNumber, floor, status } = req.body;
  if (!name || basePrice === undefined || !roomNumber) {
    return res.status(400).json({ error: "name, basePrice and roomNumber are required" });
  }
  if (status && !["ACTIVE", "MAINTENANCE", "INACTIVE"].includes(status)) {
    return res.status(400).json({ error: "status must be one of: ACTIVE, MAINTENANCE, INACTIVE" });
  }

  const room = await prisma.room.create({
    data: {
      branchId, name, description, basePrice, currency: currency || "NGN",
      maxOccupancy: maxOccupancy || 2, amenities: amenities || [],
      roomNumber, floor, ...(status ? { status } : {}),
    },
  });
  res.status(201).json({ room });
}

/** Director-only. Full structural edit — name/price/photos/amenities/
 * roomNumber/floor. Manager never reaches this route. */
async function updateRoom(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.room.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Room not found at this branch" });

  const { name, description, basePrice, currency, maxOccupancy, amenities, roomNumber, floor } = req.body;
  const room = await prisma.room.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(description !== undefined ? { description } : {}),
      ...(basePrice !== undefined ? { basePrice } : {}),
      ...(currency !== undefined ? { currency } : {}),
      ...(maxOccupancy !== undefined ? { maxOccupancy } : {}),
      ...(amenities !== undefined ? { amenities } : {}),
      ...(roomNumber !== undefined ? { roomNumber } : {}),
      ...(floor !== undefined ? { floor } : {}),
    },
  });
  res.json({ room });
}

/** Director-only. Refuses to delete a room with an active/upcoming
 * booking rather than silently orphaning it. */
async function deleteRoom(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.room.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Room not found at this branch" });

  const activeBooking = await prisma.booking.findFirst({ where: { roomId: id, status: { in: ACTIVE_BOOKING_STATUSES } } });
  if (activeBooking) return res.status(409).json({ error: "This room has an active or upcoming booking — resolve it before deleting the room" });

  await prisma.room.delete({ where: { id } });
  res.json({ message: "Room deleted" });
}

async function uploadRoomImage(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  if (!req.file) return res.status(400).json({ error: "No image file provided (field name: image)" });

  const room = await prisma.room.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!room) return res.status(404).json({ error: "Room not found at this branch" });

  const url = await uploadBuffer(req.file.buffer, "Uyeh-hotel/rooms");
  const updated = await prisma.room.update({ where: { id }, data: { images: [...room.images, url] } });
  res.status(201).json({ room: updated, uploadedUrl: url });
}

async function deleteRoomImage(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "url is required" });

  const room = await prisma.room.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!room) return res.status(404).json({ error: "Room not found at this branch" });

  const updated = await prisma.room.update({ where: { id }, data: { images: room.images.filter((img) => img !== url) } });
  await deleteFromCloudinaryByUrl(url);
  res.json({ room: updated });
}

/** Shared by the public site (branchId in the URL) and staff panels
 * (branchId from the token/query) — same dual-source pattern used by
 * listEvents. Read-only for everyone; who can WRITE is gated at the route
 * level (Director-only for create/update/delete, see directorRoutes). */
async function listRooms(req, res) {
  const branchId = req.params.branchId || resolveBranchScope(req);
  const rooms = await prisma.room.findMany({
    where: branchId ? { branchId } : {},
    orderBy: { roomNumber: "asc" },
  });

  const { currency } = req.query;
  if (!currency) return res.json({ rooms });

  const withDisplayPrice = await Promise.all(
    rooms.map(async (r) => ({
      ...r,
      displayPrice: await convertCurrency(r.basePrice, r.currency, currency),
      displayCurrency: currency,
    }))
  );
  res.json({ rooms: withDisplayPrice });
}

/** The ONLY room-editing action available to Manager/Staff. Everything
 * structural (name, price, photos, room number, floor) is Director-only. */
async function updateRoomStatus(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const { status } = req.body;
  if (!status || !["ACTIVE", "MAINTENANCE", "INACTIVE"].includes(status)) {
    return res.status(400).json({ error: "status must be one of: ACTIVE, MAINTENANCE, INACTIVE" });
  }
  const existing = await prisma.room.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Room not found at this branch" });

  const room = await prisma.room.update({ where: { id }, data: { status } });
  res.json({ room });
}

const VALID_HOUSEKEEPING_STATUSES = ["CLEAN", "DIRTY", "CLEANING", "INSPECTED", "OUT_OF_ORDER"];

async function listHousekeeping(req, res) {
  const branchId = resolveBranchScope(req);
  const { status } = req.query;
  const rooms = await prisma.room.findMany({
    where: { ...(branchId ? { branchId } : {}), ...(status ? { housekeepingStatus: status } : {}) },
    orderBy: [{ housekeepingStatus: "asc" }, { roomNumber: "asc" }],
  });
  res.json({ rooms });
}

async function updateHousekeepingStatus(req, res) {
  const branchId = resolveBranchScope(req);
  const { roomId } = req.params;
  const { housekeepingStatus } = req.body;
  if (!housekeepingStatus || !VALID_HOUSEKEEPING_STATUSES.includes(housekeepingStatus)) {
    return res.status(400).json({ error: `housekeepingStatus must be one of: ${VALID_HOUSEKEEPING_STATUSES.join(", ")}` });
  }
  const existing = await prisma.room.findFirst({ where: { id: roomId, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Room not found at this branch" });

  const room = await prisma.room.update({
    where: { id: roomId },
    data: { housekeepingStatus, housekeepingUpdatedAt: new Date() },
  });
  res.json({ room });
}

// =============================================================================
// CONTROLLERS: STOCK  (was controllers/stockController.js)
// =============================================================================

async function listStockItems(req, res) {
  const branchId = resolveBranchScope(req);
  const items = await prisma.stockItem.findMany({
    where: branchId ? { branchId } : {},
    orderBy: { name: "asc" },
  });
  res.json({ stockItems: items });
}

async function createStockItem(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "branchId is required (Director must pass ?branchId=)" });
  const { name, quantity, unit, lowStockThreshold } = req.body;
  if (!name) return res.status(400).json({ error: "name is required" });

  const item = await prisma.stockItem.create({
    data: { branchId, name, quantity: quantity ?? 0, unit, lowStockThreshold: lowStockThreshold ?? 5 },
  });
  res.status(201).json({ stockItem: item });
}

async function updateStockItem(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.stockItem.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Stock item not found at this branch" });

  const { name, quantity, unit, lowStockThreshold } = req.body;
  const item = await prisma.stockItem.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(quantity !== undefined ? { quantity } : {}),
      ...(unit !== undefined ? { unit } : {}),
      ...(lowStockThreshold !== undefined ? { lowStockThreshold } : {}),
    },
  });
  res.json({ stockItem: item });
}

async function deleteStockItem(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.stockItem.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Stock item not found at this branch" });

  await prisma.stockItem.delete({ where: { id } });
  res.json({ message: "Stock item deleted" });
}

// =============================================================================
// CONTROLLERS: MANAGERS (Director only)  (was controllers/staffController.js)
// =============================================================================

async function createManager(req, res) {
  const { name, email, password, branchId, roleTitle, department } = req.body;
  if (!name || !email || !password || !branchId) {
    return res.status(400).json({ error: "name, email, password, and branchId are required" });
  }
  if (department !== undefined && department !== null && !DEPARTMENT_CATALOG[department]) {
    return res.status(400).json({ error: `Unknown department. Choose one of: ${Object.keys(DEPARTMENT_CATALOG).join(", ")}` });
  }

  const existing = await prisma.manager.findUnique({ where: { email } });
  if (existing) return res.status(409).json({ error: "A manager account with this email already exists" });

  const branchExists = await prisma.branch.findUnique({ where: { id: branchId } });
  if (!branchExists) return res.status(404).json({ error: "Branch not found" });

  const passwordHash = await bcrypt.hash(password, 10);
  const manager = await prisma.manager.create({
    data: { name, email, passwordHash, roleTitle, department, permissions: ALL_PERMISSIONS, branchId, createdByDirectorId: req.user.id },
  });

  sendManagerWelcome({ email, name, branchName: branchExists.name, tempPassword: password })
    .catch((err) => console.error("[email] manager welcome failed:", err.message));

  res.status(201).json({ manager: { id: manager.id, name: manager.name, email: manager.email, roleTitle: manager.roleTitle, department: manager.department, permissions: manager.permissions, branchId: manager.branchId, isActive: manager.isActive } });
}

async function listManagers(req, res) {
  const { branchId } = req.query;
  const managers = await prisma.manager.findMany({
    where: { ...(branchId ? { branchId } : {}) },
    select: { id: true, name: true, email: true, roleTitle: true, department: true, permissions: true, branchId: true, isActive: true, createdAt: true, branch: { select: { name: true } } },
    orderBy: { name: "asc" },
  });
  res.json({ managers });
}

async function updateManager(req, res) {
  const { id } = req.params;
  const target = await prisma.manager.findUnique({ where: { id } });
  if (!target) return res.status(404).json({ error: "Manager not found" });

  const { name, roleTitle, department, permissions, isActive } = req.body;
  if (department !== undefined && department !== null && !DEPARTMENT_CATALOG[department]) {
    return res.status(400).json({ error: `Unknown department. Choose one of: ${Object.keys(DEPARTMENT_CATALOG).join(", ")}` });
  }
  const manager = await prisma.manager.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(roleTitle !== undefined ? { roleTitle } : {}),
      ...(department !== undefined ? { department } : {}),
      ...(permissions !== undefined ? { permissions } : {}),
      ...(isActive !== undefined ? { isActive } : {}),
    },
  });
  res.json({ manager: { id: manager.id, name: manager.name, email: manager.email, roleTitle: manager.roleTitle, department: manager.department, permissions: manager.permissions, branchId: manager.branchId, isActive: manager.isActive } });
}

// =============================================================================
// CONTROLLERS: DIRECTORS (Director only — appointing a co-owner/co-director)
// Note: this cannot create the FIRST Director, since nothing can
// authenticate as Director until one already exists. The first Director is
// still a one-time DB seed, by design — this route is for adding more.
// =============================================================================

async function createDirector(req, res) {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "name, email, and password are required" });
  }

  const existing = await prisma.director.findUnique({ where: { email } });
  if (existing) return res.status(409).json({ error: "A director account with this email already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const director = await prisma.director.create({ data: { name, email, passwordHash } });

  res.status(201).json({ director: { id: director.id, name: director.name, email: director.email, isActive: director.isActive } });
}

async function listDirectors(req, res) {
  const directors = await prisma.director.findMany({
    select: { id: true, name: true, email: true, isActive: true, createdAt: true },
    orderBy: { name: "asc" },
  });
  res.json({ directors });
}

// =============================================================================
// CONTROLLERS: BRANCH PAYOUTS (Director only) — Paystack Subaccount setup
// =============================================================================

async function getPaystackBankList(req, res) {
  const banks = await listPaystackBanks();
  res.json({ banks: banks.map((b) => ({ name: b.name, code: b.code })) });
}

/** Step 1: verify the account number/name match BEFORE committing to it. */
async function verifyBranchPayoutAccount(req, res) {
  const { accountNumber, bankCode } = req.body;
  if (!accountNumber || !bankCode) {
    return res.status(400).json({ error: "accountNumber and bankCode are required" });
  }
  const resolved = await resolvePaystackAccount(accountNumber, bankCode);
  res.json({ accountName: resolved.account_name, accountNumber: resolved.account_number });
}

/** Step 2: create (or replace) the branch's payout subaccount. Call
 * verifyBranchPayoutAccount first so the Director sees the account name
 * before this runs — Paystack does not guarantee refunds for payouts to a
 * mistyped account number. */
async function setBranchPayoutAccount(req, res) {
  const { id: branchId } = req.params;
  const { accountNumber, bankCode, bankName } = req.body;
  if (!accountNumber || !bankCode || !bankName) {
    return res.status(400).json({ error: "accountNumber, bankCode, and bankName are required" });
  }

  const branch = await prisma.branch.findUnique({ where: { id: branchId } });
  if (!branch) return res.status(404).json({ error: "Branch not found" });

  const resolved = await resolvePaystackAccount(accountNumber, bankCode);

  const subaccount = branch.paystackSubaccountCode
    ? await updatePaystackSubaccount(branch.paystackSubaccountCode, { businessName: branch.name, bankCode, accountNumber })
    : await createPaystackSubaccount({ businessName: branch.name, bankCode, accountNumber });

  const updated = await prisma.branch.update({
    where: { id: branchId },
    data: {
      paystackSubaccountCode: subaccount.subaccount_code,
      settlementBankCode: bankCode,
      settlementBankName: bankName,
      settlementAccountNumber: accountNumber,
      settlementAccountName: resolved.account_name,
    },
  });

  res.json({
    branch: {
      id: updated.id, name: updated.name,
      paystackSubaccountCode: updated.paystackSubaccountCode,
      settlementBankName: updated.settlementBankName,
      settlementAccountNumber: updated.settlementAccountNumber,
      settlementAccountName: updated.settlementAccountName,
    },
  });
}

/** Starts (or restarts) Stripe Connect onboarding for a branch. Returns a
 * one-time onboarding URL — Director completes it on Stripe's site, then
 * lands back on STRIPE_CONNECT_RETURN_URL. See the Nigeria/Stripe note at
 * the top of patch.md before expecting this to work for an NGN branch. */
async function connectBranchStripeAccount(req, res) {
  const { id: branchId } = req.params;
  const { email, country } = req.body;
  if (!email) return res.status(400).json({ error: "email is required (used for the Stripe account)" });

  const branch = await prisma.branch.findUnique({ where: { id: branchId } });
  if (!branch) return res.status(404).json({ error: "Branch not found" });

  const { accountId, onboardingUrl } = await createStripeConnectedAccount({ branchName: branch.name, email, country });

  await prisma.branch.update({ where: { id: branchId }, data: { stripeConnectedAccountId: accountId, stripeOnboardingComplete: false } });

  res.json({ onboardingUrl });
}

async function getBranchStripeStatus(req, res) {
  const { id: branchId } = req.params;
  const branch = await prisma.branch.findUnique({ where: { id: branchId } });
  if (!branch) return res.status(404).json({ error: "Branch not found" });
  if (!branch.stripeConnectedAccountId) return res.json({ connected: false });

  const status = await getStripeAccountStatus(branch.stripeConnectedAccountId);
  if (status.chargesEnabled !== branch.stripeOnboardingComplete) {
    await prisma.branch.update({ where: { id: branchId }, data: { stripeOnboardingComplete: status.chargesEnabled } });
  }
  res.json({ connected: true, ...status });
}

// =============================================================================
// CONTROLLERS: STAFF (Manager creates; Director + permitted Manager manage)
// =============================================================================

// Single source of truth for what a department "means" in permission terms.
const DEPARTMENT_CATALOG = {
  "Front Desk": ["manage_bookings", "manage_rooms", "handle_tickets", "manage_payments"],
  "Housekeeping": ["manage_rooms"],
  "Stock & Inventory": ["manage_stock"],
  "Restaurant & Bar": ["manage_menu", "manage_bookings"],
  "Events": ["manage_events"],
  "Spa": ["manage_spa"],
  "Laundry": ["manage_laundry"],
  "Guest Support": ["handle_tickets"],
  "Reviews & Marketing": ["manage_reviews", "manage_promos"],
  "Content": ["manage_blog", "manage_newsletter"], // was gating live routes with no way to grant it — fixed
  "Security": ["manage_security"],
  "Branch Administration": ["manage_staff", "manage_settings", "view_reports", "manage_bookings", "manage_rooms", "manage_stock", "manage_events", "manage_payments"],
};

const ALL_PERMISSIONS = Array.from(new Set(Object.values(DEPARTMENT_CATALOG).flat()));
const STAFF_ASSIGNABLE_PERMISSIONS = ALL_PERMISSIONS.filter((p) => !["manage_staff", "manage_newsletter"].includes(p));

function listDepartmentCatalog(req, res) {
  res.json({ departments: DEPARTMENT_CATALOG });
}

async function createStaffMember(req, res) {
  const { name, email, password, roleTitle, department, permissions } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "name, email, and password are required" });
  if (!permissions || !Array.isArray(permissions) || !permissions.length) {
    return res.status(400).json({ error: "permissions is required — assign at least one duty for this staff member" });
  }
  if (permissions.includes("manage_staff")) {
    return res.status(403).json({ error: "manage_staff cannot be assigned to a Staff account — Manager or Director level only" });
  }
  const invalidPermissions = permissions.filter((p) => !STAFF_ASSIGNABLE_PERMISSIONS.includes(p));
  if (invalidPermissions.length) {
    return res.status(400).json({ error: `Unknown or non-assignable permission(s): ${invalidPermissions.join(", ")}` });
  }
  if (department !== undefined && department !== null && !DEPARTMENT_CATALOG[department]) {
    return res.status(400).json({ error: `Unknown department. Choose one of: ${Object.keys(DEPARTMENT_CATALOG).join(", ")}` });
  }

  let branchId;
  if (req.user.type === "director") {
    branchId = req.body.branchId;
    if (!branchId) return res.status(400).json({ error: "branchId is required when a Director creates staff" });
    const branchExists = await prisma.branch.findUnique({ where: { id: branchId } });
    if (!branchExists) return res.status(404).json({ error: "Branch not found" });
  } else {
    branchId = req.user.branchId;
  }

  const existing = await prisma.staff.findUnique({ where: { email } });
  if (existing) return res.status(409).json({ error: "A staff account with this email already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const staff = await prisma.staff.create({
    data: { name, email, passwordHash, roleTitle, department, permissions, branchId, createdByManagerId: req.user.id },
  });

  const branch = await prisma.branch.findUnique({ where: { id: branchId } });
  sendStaffWelcome({ email, name, branchName: branch?.name, roleTitle, tempPassword: password })
    .catch((err) => console.error("[email] staff welcome failed:", err.message));

  res.status(201).json({ staff: { id: staff.id, name: staff.name, email: staff.email, roleTitle: staff.roleTitle, department: staff.department, permissions: staff.permissions, branchId: staff.branchId, isActive: staff.isActive } });
}

async function listBranchStaff(req, res) {
  const branchId = resolveBranchScope(req);
  const staff = await prisma.staff.findMany({
    where: { ...(branchId ? { branchId } : {}) },
    select: { id: true, name: true, email: true, roleTitle: true, department: true, permissions: true, branchId: true, isActive: true, createdAt: true },
    orderBy: { name: "asc" },
  });
  res.json({ staff });
}

async function updateStaffMember(req, res) {
  const { id } = req.params;
  const target = await prisma.staff.findUnique({ where: { id } });
  if (!target) return res.status(404).json({ error: "Staff member not found" });
  // Director: company-wide. Manager: only their own branch's staff.
  if (req.user.type !== "director" && target.branchId !== req.user.branchId) {
    return res.status(403).json({ error: "You do not have access to this staff member" });
  }

  const { name, roleTitle, department, permissions, isActive } = req.body;

  if (isActive !== undefined && req.user.type !== "director") {
    return res.status(403).json({ error: "Deactivating a staff account requires Director approval" });
  }

  if (permissions !== undefined) {
    if (!Array.isArray(permissions)) {
      return res.status(400).json({ error: "permissions must be an array" });
    }
    if (req.user.type !== "director") {
      if (permissions.includes("manage_staff")) {
        return res.status(403).json({ error: "manage_staff cannot be assigned to a Staff account — Manager or Director level only" });
      }
      const invalidPermissions = permissions.filter((p) => !STAFF_ASSIGNABLE_PERMISSIONS.includes(p));
      if (invalidPermissions.length) {
        return res.status(400).json({ error: `Unknown or non-assignable permission(s): ${invalidPermissions.join(", ")}` });
      }
    }
  }

  if (department !== undefined && department !== null && !DEPARTMENT_CATALOG[department]) {
    return res.status(400).json({ error: `Unknown department. Choose one of: ${Object.keys(DEPARTMENT_CATALOG).join(", ")}` });
  }
  const staff = await prisma.staff.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(roleTitle !== undefined ? { roleTitle } : {}),
      ...(department !== undefined ? { department } : {}),
      ...(permissions !== undefined ? { permissions } : {}),
      ...(isActive !== undefined ? { isActive } : {}),
    },
  });
  res.json({ staff: { id: staff.id, name: staff.name, email: staff.email, roleTitle: staff.roleTitle, department: staff.department, permissions: staff.permissions, branchId: staff.branchId, isActive: staff.isActive } });
}

// =============================================================================
// CONTROLLERS: BRANCH SETTINGS (manage_settings) — branch-level counterpart
// to the Director's company-wide /api/director/settings. Only the fields a
// branch actually owns on itself are editable here.
// =============================================================================

async function getBranchSettings(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "Director must specify ?branchId=" });
  const branch = await prisma.branch.findUnique({ where: { id: branchId } });
  if (!branch) return res.status(404).json({ error: "Branch not found" });
  res.json({
    branch: {
      id: branch.id, name: branch.name, slug: branch.slug,
      address: branch.address, city: branch.city, state: branch.state,
      phone: branch.phone, email: branch.email, services: branch.services,
    },
  });
}

async function updateBranchSettings(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "Director must specify ?branchId=" });

  // Sensitive/company-wide fields a Manager must never be able to set
  // through this route. Director-only equivalents live in directorRoutes
  // (/director/settings, /director/branches/:id/payout-account).
  const BLOCKED_FIELDS = [
    "paystackSubaccountCode", "settlementBankCode", "settlementBankName",
    "settlementAccountNumber", "settlementAccountName",
    "primaryColor", "secondaryColor", "accentColor", "customCSS", "customHead",
    "checkInTime", "checkOutTime", "cancellationPolicy", "maintenanceMode",
    "maintenanceBypassToken", "isActive",
  ];
  const attemptedBlocked = BLOCKED_FIELDS.filter((f) => req.body[f] !== undefined);
  if (attemptedBlocked.length && req.user.type !== "director") {
    console.warn(`⚠️  Manager ${req.user.id} attempted to set restricted branch field(s): ${attemptedBlocked.join(", ")}`);
    return res.status(403).json({ error: `You don't have permission to change: ${attemptedBlocked.join(", ")}. Contact your Director.` });
  }

  const { address, city, state, phone, email, services } = req.body;
  const branch = await prisma.branch.update({
    where: { id: branchId },
    data: {
      ...(address !== undefined ? { address } : {}),
      ...(city !== undefined ? { city } : {}),
      ...(state !== undefined ? { state } : {}),
      ...(phone !== undefined ? { phone } : {}),
      ...(email !== undefined ? { email } : {}),
      ...(services !== undefined ? { services } : {}),
    },
  });
  res.json({
    branch: {
      id: branch.id, name: branch.name, slug: branch.slug,
      address: branch.address, city: branch.city, state: branch.state,
      phone: branch.phone, email: branch.email, services: branch.services,
    },
  });
}

// =============================================================================
// CONTROLLERS: BRANCH REPORTS (view_reports) — read-only snapshot. Director
// already has a company-wide overview at GET /api/director/overview; this is
// the same idea scoped to one branch for a Manager/permitted Staff member.
// =============================================================================

async function getBranchReports(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "Director must specify ?branchId=" });

  const startOfMonth = new Date();
  startOfMonth.setDate(1);
  startOfMonth.setHours(0, 0, 0, 0);

  const [roomCount, activeBookings, bookingsThisMonth, ordersThisMonth, openTickets] = await Promise.all([
    prisma.room.count({ where: { branchId } }),
    prisma.booking.count({ where: { branchId, status: { in: ["CONFIRMED", "CHECKED_IN"] } } }),
    prisma.booking.findMany({ where: { branchId, createdAt: { gte: startOfMonth } }, select: { totalAmount: true } }),
    prisma.order.findMany({ where: { branchId, createdAt: { gte: startOfMonth } }, select: { totalAmount: true } }),
    prisma.ticket.count({ where: { branchId, status: { in: ["OPEN", "IN_PROGRESS"] } } }),
  ]);

  const revenueThisMonth =
    bookingsThisMonth.reduce((sum, b) => sum + Number(b.totalAmount || 0), 0) +
    ordersThisMonth.reduce((sum, o) => sum + Number(o.totalAmount || 0), 0);

  res.json({
    report: {
      roomCount,
      activeBookings,
      bookingsThisMonth: bookingsThisMonth.length,
      revenueThisMonth,
      openTickets,
    },
  });
}

// =============================================================================
// CONTROLLERS: SECURITY (manage_security) — read-only guest/stay
// verification. Deliberately narrow: confirms who's checked in and where,
// without exposing full guest records or granting booking-management rights.
// =============================================================================

async function guestLookup(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "Director must specify ?branchId=" });

  const { query } = req.query;
  if (!query || query.trim().length < 2) {
    return res.status(400).json({ error: "query must be at least 2 characters" });
  }

  const bookings = await prisma.booking.findMany({
    where: {
      branchId,
      status: { in: ["CONFIRMED", "CHECKED_IN"] },
      OR: [
        { guest: { name: { contains: query, mode: "insensitive" } } },
        { guest: { phone: { contains: query } } },
        { room: { roomNumber: { contains: query, mode: "insensitive" } } },
      ],
    },
    select: {
      id: true, checkIn: true, checkOut: true, status: true, specialRequests: true,
      guest: {
        select: {
          id: true, name: true, phone: true, email: true,
          lifetimePoints: true, loyaltyPoints: true,
          preferences: true, dietaryNotes: true, specialRequests: true,
        },
      },
      room: { select: { roomNumber: true } },
    },
    take: 20,
    orderBy: { checkIn: "desc" },
  });

  res.json({
    results: bookings.map((b) => ({
      bookingId: b.id,
      guestId: b.guest.id,
      guestName: b.guest.name,
      guestPhone: b.guest.phone,
      guestEmail: b.guest.email,
      guestTier: loyaltyTierForLifetimePoints(b.guest.lifetimePoints),
      loyaltyPoints: b.guest.loyaltyPoints,
      preferences: b.guest.preferences || null,
      dietaryNotes: b.guest.dietaryNotes || null,
      standingSpecialRequests: b.guest.specialRequests || null,
      thisStayRequests: b.specialRequests || null,
      roomNumber: b.room.roomNumber,
      checkIn: b.checkIn,
      checkOut: b.checkOut,
      status: b.status,
    })),
  });
}

// =============================================================================
// CONTROLLERS: CONCIERGE (manage_concierge) — structured guest requests
// (dinner reservations, transport, in-room setup) beyond the free-text
// Guest.specialRequests field.
// =============================================================================

const VALID_CONCIERGE_STATUSES = ["PENDING", "IN_PROGRESS", "COMPLETED", "CANCELLED"];

async function createConciergeRequest(req, res) {
  const { branchId, bookingId, type, details } = req.body;
  if (!branchId || !type || !details) return res.status(400).json({ error: "branchId, type, and details are required" });

  const request = await prisma.conciergeRequest.create({
    data: { branchId, guestId: req.user.id, bookingId: bookingId || null, type, details, status: "PENDING" },
  });
  res.status(201).json({ request });
}

async function listConciergeRequests(req, res) {
  const branchId = resolveBranchScope(req);
  const { status } = req.query;
  const requests = await prisma.conciergeRequest.findMany({
    where: { ...(branchId ? { branchId } : {}), ...(status ? { status } : {}) },
    orderBy: { createdAt: "desc" },
  });
  const guestIds = [...new Set(requests.map((r) => r.guestId))];
  const guests = await prisma.guest.findMany({ where: { id: { in: guestIds } }, select: { id: true, name: true, phone: true } });
  const guestById = Object.fromEntries(guests.map((g) => [g.id, g]));
  res.json({ requests: requests.map((r) => ({ ...r, guest: guestById[r.guestId] || null })) });
}

async function updateConciergeRequest(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const { status, assignedToStaffId } = req.body;
  if (status && !VALID_CONCIERGE_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${VALID_CONCIERGE_STATUSES.join(", ")}` });
  }
  const existing = await prisma.conciergeRequest.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Concierge request not found at this branch" });

  const request = await prisma.conciergeRequest.update({
    where: { id },
    data: { ...(status !== undefined ? { status } : {}), ...(assignedToStaffId !== undefined ? { assignedToStaffId } : {}) },
  });
  res.json({ request });
}

// =============================================================================
// ROUTES: PAYMENTS  (was routes/paymentRoutes.js)
// =============================================================================

const paymentRoutes = express.Router();

// Paystack signs the RAW body, so this route uses express.raw() instead of
// the global express.json() — must be mounted BEFORE express.json() below.
paymentRoutes.post("/paystack/webhook", express.raw({ type: "application/json" }), paystackWebhook);

// Same requirement for Stripe — raw body needed for stripe.webhooks.constructEvent.
paymentRoutes.post("/stripe/webhook", express.raw({ type: "application/json" }), stripeWebhook);

// =============================================================================
// ROUTES: PUBLIC  (was routes/publicRoutes.js)
// =============================================================================

const publicRoutes = express.Router();

publicRoutes.use(optionalGuestAuth); // sets req.user if a valid guest token is present, never blocks

// Resolves the :branchId param on EVERY route below
publicRoutes.param("branchId", async (req, res, next, value) => {
  const branch = await prisma.branch.findFirst({
    where: { isActive: true, OR: [{ id: value }, { slug: value }] },
    select: { id: true },
  });
  if (!branch) return res.status(404).json({ error: "Branch not found" });
  req.params.branchId = branch.id;
  next();
});

// Public settings — every page on the public site reads the platform
// name, brand colors, and feature flags from here instead of anything
// being hardcoded. Explicitly field-by-field, never the raw DB row — this
// is what keeps write-only fields (maintenanceBypassToken) and internal
// fields (updatedById) from ever leaking into a public response.
publicRoutes.get("/settings", async (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=60");
  const settings = await getSettings();

  const bypassToken = req.query.bypass || req.headers["x-bypass-token"];
  const bypassGranted =
    bypassToken && settings.maintenanceBypassToken && bypassToken === settings.maintenanceBypassToken;

  res.json({
    settings: {
      // Identity
      platformName: settings.name,
      tagline: settings.tagline,
      description: settings.description || "",
      email: settings.email || "",
      phone: settings.phone || "",
      address: settings.address || "",
      logoUrl: settings.logoUrl || "",
      faviconUrl: settings.faviconUrl || "",
      heroImageUrl: settings.heroImageUrl || "",
      socialLinks: settings.socialLinks || {},

      // Homepage copy — index.html renders these into [data-content] slots
      headline: settings.headline || "",
      subheadline: settings.subheadline || "",
      ctaTitle: settings.ctaTitle || "",
      ctaSubtitle: settings.ctaSubtitle || "",
      footerAbout: settings.footerAbout || "",
      footerEmail: settings.footerEmail || "",
      footerPhone: settings.footerPhone || "",

      // Brand colors — the public site's CSS custom properties read these
      brand: {
        primaryColor: settings.primaryColor,
        secondaryColor: settings.secondaryColor,
        accentColor: settings.accentColor,
      },

      // Business hours
      checkInTime: settings.checkInTime,
      checkOutTime: settings.checkOutTime,
      baseCurrency: settings.baseCurrency,

      // Feature flags — the frontend hides/shows nav items and sections
      // based on these instead of assuming everything is always on
      features: {
        bookingsEnabled: settings.bookingsEnabled,
        ordersEnabled: settings.ordersEnabled,
        eventsEnabled: settings.eventsEnabled,
        ticketsEnabled: settings.ticketsEnabled,
        guestAccountsEnabled: settings.guestAccountsEnabled,
      },

      // Maintenance — bypassGranted suppresses maintenanceMode for that
      // caller specifically (used by the maintenance middleware too)
      maintenanceMode: bypassGranted ? false : settings.maintenanceMode,
      maintenanceTitle: settings.maintenanceTitle,
      maintenanceMessage: settings.maintenanceMessage,
      maintenanceETA: settings.maintenanceETA || "",
      // maintenanceBypassToken is NEVER returned — write-only, checked above

      // Announcement banner
      banner: {
        enabled: settings.bannerEnabled,
        text: settings.bannerText || "",
        type: settings.bannerType,
        link: settings.bannerLink || "",
        linkText: settings.bannerLinkText || "",
        dismissible: settings.bannerDismissible,
      },

      // SEO
      seo: {
        metaTitle: settings.metaTitle || settings.name,
        metaDescription: settings.metaDescription || settings.tagline,
        metaKeywords: settings.metaKeywords || "",
        ogImageUrl: settings.ogImageUrl || settings.heroImageUrl || "",
        googleAnalyticsId: settings.googleAnalyticsId || "",
        facebookPixelId: settings.facebookPixelId || "",
      },

      // Custom code — the frontend injects these into <style>/<head> if present
      customCSS: settings.customCSS || "",
      customHead: settings.customHead || "",
    },
  });
});

// Current exchange rates, base USD — lets the frontend build a currency
// switcher without proxying every price through the backend. Cached for
// 1 hour server-side (see getExchangeRates above), so this is cheap to
// call on every page load.
publicRoutes.get("/exchange-rates", async (req, res) => {
  const rates = await getExchangeRates();
  res.json({ base: "USD", rates });
});

// ── Newsletter — public ──────────────────────────────────────────────────
publicRoutes.post("/newsletter/subscribe", async (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ error: "email is required" });

  const existing = await prisma.newsletterSubscriber.findUnique({ where: { email } });
  if (existing?.status === "CONFIRMED") {
    return res.json({ message: "You're already subscribed." });
  }

  const rawToken = generateRawToken();
  const sub = await prisma.newsletterSubscriber.upsert({
    where: { email },
    update: {
      name: name || undefined, status: "PENDING",
      confirmTokenHash: hashRawToken(rawToken), confirmExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    },
    create: {
      email, name, status: "PENDING", source: "public_signup",
      confirmTokenHash: hashRawToken(rawToken), confirmExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    },
  });

  const confirmUrl = `${process.env.FRONTEND_URL || ""}/newsletter/confirm?token=${rawToken}`;
  sendNewsletterConfirmation({ email: sub.email, name: sub.name, confirmUrl }).catch((err) => console.error("[email] newsletter confirmation failed:", err.message));

  res.json({ message: "Check your email to confirm your subscription." });
});

publicRoutes.get("/newsletter/confirm", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: "token is required" });

  const tokenHash = hashRawToken(token);
  const sub = await prisma.newsletterSubscriber.findFirst({
    where: { confirmTokenHash: tokenHash, confirmExpires: { gt: new Date() } },
  });
  if (!sub) return res.status(400).json({ error: "This confirmation link is invalid or has expired." });

  await prisma.newsletterSubscriber.update({
    where: { id: sub.id },
    data: { status: "CONFIRMED", confirmedAt: new Date(), confirmTokenHash: null, confirmExpires: null },
  });
  res.json({ message: "Subscription confirmed — welcome aboard!" });
});

publicRoutes.get("/newsletter/unsubscribe", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: "token is required" });

  const sub = await prisma.newsletterSubscriber.findUnique({ where: { unsubscribeToken: token } });
  if (!sub) return res.status(404).json({ error: "Subscriber not found" });

  await prisma.newsletterSubscriber.update({
    where: { id: sub.id },
    data: { status: "UNSUBSCRIBED", unsubscribedAt: new Date() },
  });
  res.json({ message: "You've been unsubscribed." });
});

// ── Blog — public ────────────────────────────────────────────────────────
publicRoutes.get("/blog", async (req, res) => {
  const { branchId, tag } = req.query;
  const posts = await prisma.blogPost.findMany({
    where: {
      status: "PUBLISHED",
      ...(branchId ? { branchId } : {}),
      ...(tag ? { tags: { has: tag } } : {}),
    },
    orderBy: { publishedAt: "desc" },
    select: {
      id: true, title: true, slug: true, excerpt: true, coverImageUrl: true, tags: true, publishedAt: true,
      branch: { select: { id: true, name: true, slug: true } },
    },
  });
  res.json({ posts });
});

publicRoutes.get("/blog/:slug", async (req, res) => {
  const post = await prisma.blogPost.findFirst({
    where: { slug: req.params.slug, status: "PUBLISHED" },
    include: { branch: { select: { id: true, name: true, slug: true } } },
  });
  if (!post) return res.status(404).json({ error: "Post not found" });
  res.json({ post });
});

// Company-wide: list active branches (for a "choose your branch" picker)
publicRoutes.get("/branches", async (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=60");
  const branches = await prisma.branch.findMany({
    where: { isActive: true },
    select: { id: true, name: true, slug: true, city: true, state: true, address: true, phone: true, services: true },
    orderBy: { name: "asc" },
  });
  res.json({ branches });
});

publicRoutes.get("/branches/:branchId", async (req, res) => {
  const branch = await prisma.branch.findFirst({ where: { id: req.params.branchId, isActive: true } });
  if (!branch) return res.status(404).json({ error: "Branch not found" });
  res.json({ branch });
});

// Branch-scoped, guest-facing
publicRoutes.get("/branches/:branchId/rooms", requireBranchService("rooms"), listRooms);
publicRoutes.get("/branches/:branchId/upcoming-events", requireBranchService("upcoming_events"), listPublicUpcomingEvents);
publicRoutes.get("/branches/:branchId/upcoming-events/:id", requireBranchService("upcoming_events"), getPublicUpcomingEvent);
publicRoutes.get("/branches/:branchId/availability", requireBranchService("rooms"), checkAvailability);
publicRoutes.post("/branches/:branchId/bookings", requireBranchService("rooms"), createBooking);
publicRoutes.post("/branches/:branchId/bookings/:id/initiate-payment", initiateBookingPayment);
publicRoutes.post("/branches/:branchId/bookings/:id/initiate-stripe-payment", initiateBookingPaymentStripe);
publicRoutes.get("/branches/:branchId/events", requireBranchService("events"), listEvents);
publicRoutes.get("/branches/:branchId/events/:id", requireBranchService("events"), async (req, res) => {
  const { branchId, id } = req.params;
  const event = await prisma.event.findFirst({ where: { id, branchId } });
  if (!event) return res.status(404).json({ error: "Event not found" });
  res.json({ event });
});
publicRoutes.post("/branches/:branchId/orders", createOrder); // type-dependent — checked inside the controller
publicRoutes.post("/branches/:branchId/orders/:id/initiate-payment", initiateOrderPayment);
publicRoutes.post("/branches/:branchId/tickets", createTicket); // support ticketing isn't a toggleable service — always available
publicRoutes.post("/branches/:branchId/tickets/:id/access-token", issueTicketAccessToken);
publicRoutes.post("/branches/:branchId/tickets/:id/attachment", upload.single("file"), uploadTicketAttachment);

publicRoutes.get("/branches/:branchId/tickets/:id", async (req, res) => {
  const { branchId, id } = req.params;
  const { email } = req.query;

  const ticket = await prisma.ticket.findFirst({
    where: { id, branchId },
    include: { guest: true, messages: { orderBy: { createdAt: "asc" } }, assignedStaff: { select: { name: true, roleTitle: true } } },
  });
  if (!ticket) return res.status(404).json({ error: "Ticket not found" });

  const isOwner = req.user?.type === "guest"
    ? req.user.id === ticket.guestId
    : email && email.toLowerCase() === ticket.guest.email.toLowerCase();
  if (!isOwner) return res.status(403).json({ error: "Provide the email used to raise this ticket (?email=)" });

  res.json({ ticket });
});

publicRoutes.post("/branches/:branchId/tickets/:id/messages", async (req, res) => {
  const { branchId, id } = req.params;
  const { message, email } = req.body;
  if (!message) return res.status(400).json({ error: "message is required" });

  const ticket = await prisma.ticket.findFirst({ where: { id, branchId }, include: { guest: true } });
  if (!ticket) return res.status(404).json({ error: "Ticket not found" });

  const isOwner = req.user?.type === "guest"
    ? req.user.id === ticket.guestId
    : email && email.toLowerCase() === ticket.guest.email.toLowerCase();
  if (!isOwner) return res.status(403).json({ error: "Provide the email used to raise this ticket (email in the request body)" });

  const ticketMessage = await prisma.ticketMessage.create({
    data: { ticketId: id, senderType: "GUEST", guestName: ticket.guest.name, message },
  });

  // A guest reply should reopen a ticket that staff already marked
  // resolved/closed — otherwise it silently sits unseen.
  if (["RESOLVED", "CLOSED"].includes(ticket.status)) {
    await prisma.ticket.update({ where: { id }, data: { status: "OPEN" } });
  }

  res.status(201).json({ ticketMessage });
});

// Cancel 24h+ before check-in: full refund. Inside that window: no refund
// (retained as a late-cancellation fee — the same policy a no-show relies
// on, just guest-initiated instead of staff-initiated).
const FREE_CANCELLATION_HOURS = 24;

publicRoutes.patch("/branches/:branchId/bookings/:id/cancel", async (req, res) => {
  const { branchId, id } = req.params;
  const { email } = req.body;

  const booking = await prisma.booking.findFirst({ where: { id, branchId }, include: { guest: true, payment: true } });
  if (!booking) return res.status(404).json({ error: "Booking not found" });

  const isOwner = req.user?.type === "guest"
    ? req.user.id === booking.guestId
    : email && email.toLowerCase() === booking.guest.email.toLowerCase();
  if (!isOwner) return res.status(403).json({ error: "Provide the email used to make this booking" });

  if (["CHECKED_IN", "CHECKED_OUT", "CANCELLED"].includes(booking.status)) {
    return res.status(409).json({ error: `Booking is already ${booking.status} and cannot be cancelled` });
  }

  const hoursUntilCheckIn = (new Date(booking.checkIn).getTime() - Date.now()) / (60 * 60 * 1000);
  const eligibleForRefund = hoursUntilCheckIn >= FREE_CANCELLATION_HOURS;

  const updated = await prisma.booking.update({ where: { id }, data: { status: "CANCELLED" } });

  let refunded = false;
  let refundError = null;
  if (eligibleForRefund && booking.payment && booking.payment.status === "SUCCESSFUL") {
    try {
      if (booking.payment.provider === "STRIPE") {
        await refundStripePayment(booking.payment.providerRef, booking.payment.amount, "Booking cancelled by guest");
      } else {
        await refundTransaction(booking.payment.providerRef, booking.payment.amount, "Booking cancelled by guest");
      }
      await prisma.bookingPayment.update({ where: { bookingId: booking.id }, data: { status: "REFUNDED" } });
      refunded = true;
    } catch (err) {
      refundError = err.message;
      console.error(`[refund] booking ${booking.id} cancellation refund failed:`, err.message);
    }
  }

  res.json({
    booking: updated,
    refunded,
    ...(refundError ? { refundError: "Automatic refund failed — contact the branch to process this manually." } : {}),
    ...(!eligibleForRefund && booking.payment?.status === "SUCCESSFUL"
      ? { message: `Cancelled within ${FREE_CANCELLATION_HOURS}h of check-in — this booking's payment is non-refundable per policy.` }
      : {}),
  });
});

// Catalogs — public browsing
publicRoutes.get("/branches/:branchId/menu", requireBranchService("restaurant"), listMenuItems);
publicRoutes.get("/branches/:branchId/bar-menu", requireBranchService("bar"), (req, res) => { req.query.category = "DRINK"; return listMenuItems(req, res); });
publicRoutes.get("/branches/:branchId/spa-treatments", requireBranchService("spa"), listSpaTreatments);
publicRoutes.get("/branches/:branchId/laundry-items", requireBranchService("laundry"), listLaundryItems);

// Reviews — public, published only
publicRoutes.get("/branches/:branchId/reviews", listPublishedReviews);
publicRoutes.get("/branches/:branchId/promo-codes/:code/validate", async (req, res) => {
  const { branchId, code } = req.params;
  const { context, subtotal } = req.query;
  try {
    const preview = await resolveAndPreviewPromo(code, {
      guestId: req.user?.id,
      branchId,
      context: context || "BOOKING",
      subtotal: Number(subtotal) || 0,
    });
    res.json({ valid: true, discountAmount: preview.discountAmount });
  } catch (err) {
    res.status(400).json({ valid: false, error: err.message });
  }
});

// Group / corporate bookings
publicRoutes.post("/branches/:branchId/group-bookings", requireBranchService("rooms"), createGroupBookingPublic);

// =============================================================================
// ROUTES: AUTH  (was routes/authRoutes.js)
// =============================================================================

// =============================================================================
// routes/authRoutes.js — real implementation (staff login only; guest
// register/login is still routes/guestRoutes.js, not yet provided)
// =============================================================================

// Stricter per-IP limit specifically for auth routes — login/register/2fa/
// password-reset shouldn't get the same 300-per-15-min budget as browsing.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts — please try again in 15 minutes." },
});

// Per-EMAIL limit — catches distributed brute force (many IPs, one target
// account) that an IP-based limiter alone can't see.
const authEmailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.body?.email || "").toLowerCase().trim() || req.ip,
  skip: (req) => !req.body?.email,
  message: { error: "Too many attempts for this account — please try again in 15 minutes." },
});

const authRoutes = express.Router();
authRoutes.use(authLimiter);

// ── Login: Director / Manager / Staff — one route per type, same shape ────
// Each type gets its own path so a client always knows which portal it's
// hitting, but the underlying logic (lockout → password check → 2FA gate
// → token issue) is identical, so it lives in one factory instead of being
// copy-pasted three times.
function makeStaffLikeLoginHandler({ type, include }) {
  return async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email and password are required" });

    const model = accountModel(type);
    const account = await model.findUnique({ where: { email }, ...(include ? { include } : {}) });
    if (!account || !account.isActive) return res.status(401).json({ error: "Invalid email or password" });

    const lockout = checkLockout(account);
    if (lockout) return res.status(423).json({ error: "Account temporarily locked due to failed login attempts", retryAfterMs: lockout.retryAfterMs });

    const valid = await bcrypt.compare(password, account.passwordHash);
    if (!valid) {
      const attempts = account.loginAttempts + 1;
      const data = attempts >= LOGIN_LOCK_THRESHOLD
        ? { loginAttempts: 0, lockUntil: new Date(Date.now() + LOGIN_LOCK_DURATION_MS) }
        : { loginAttempts: attempts };
      await model.update({ where: { id: account.id }, data });
      return res.status(401).json({ error: "Invalid email or password" });
    }

    await model.update({ where: { id: account.id }, data: { loginAttempts: 0, lockUntil: null } });

    if (account.twoFactorEnabled) {
      const tempToken = signToken({ id: account.id, type, purpose: "2fa_pending" }, "5m");
      return res.json({ requires2FA: true, tempToken });
    }

    const { accessToken, refreshToken } = await issueTokenPair({ subjectType: type, subject: account, req });
    await model.update({ where: { id: account.id }, data: { lastLogin: new Date() } });

    res.json({ token: accessToken, refreshToken, [type]: serializeAccount(type, account) });
  };
}

const adminRoutes = express.Router();
adminRoutes.use(requireAuth);

// --- My own account (Director or Staff — whichever is logged in) ---
adminRoutes.get("/me", async (req, res) => {
  if (req.user.type === "director") {
    const director = await prisma.director.findUnique({ where: { id: req.user.id }, select: { id: true, name: true, email: true } });
    return res.json({ account: { ...director, type: "director" } });
  }
  if (req.user.type === "manager") {
    const manager = await prisma.manager.findUnique({
      where: { id: req.user.id },
      select: { id: true, name: true, email: true, roleTitle: true, department: true, branchId: true, permissions: true },
    });
    return res.json({ account: { ...manager, type: "manager" } });
  }
  const staff = await prisma.staff.findUnique({
    where: { id: req.user.id },
    select: { id: true, name: true, email: true, role: true, roleTitle: true, branchId: true, permissions: true },
  });
  res.json({ account: { ...staff, type: "staff" } });
});

adminRoutes.patch("/me", async (req, res) => {
  const { name, email } = req.body;
  if (req.user.type === "director") {
    const director = await prisma.director.update({
      where: { id: req.user.id },
      data: { ...(name !== undefined ? { name } : {}), ...(email !== undefined ? { email } : {}) },
      select: { id: true, name: true, email: true },
    });
    return res.json({ account: { ...director, type: "director" } });
  }
  if (req.user.type === "manager") {
    const manager = await prisma.manager.update({
      where: { id: req.user.id },
      data: { ...(name !== undefined ? { name } : {}), ...(email !== undefined ? { email } : {}) },
      select: { id: true, name: true, email: true, roleTitle: true, department: true, branchId: true, permissions: true },
    });
    return res.json({ account: { ...manager, type: "manager" } });
  }
  const staff = await prisma.staff.update({
    where: { id: req.user.id },
    data: { ...(name !== undefined ? { name } : {}), ...(email !== undefined ? { email } : {}) },
    select: { id: true, name: true, email: true, role: true, roleTitle: true, branchId: true, permissions: true },
  });
  res.json({ account: { ...staff, type: "staff" } });
});

// No permission required beyond being logged in — anyone can change their OWN password.
adminRoutes.patch("/me/password", async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "currentPassword and newPassword are required" });
  if (newPassword.length < 8) return res.status(400).json({ error: "New password must be at least 8 characters" });

  const model = req.user.type === "director" ? prisma.director : prisma.staff;
  const account = await model.findUnique({ where: { id: req.user.id } });
  if (!account || !(await bcrypt.compare(currentPassword, account.passwordHash))) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }
  const passwordHash = await bcrypt.hash(newPassword, 10);
  await model.update({ where: { id: req.user.id }, data: { passwordHash } });
  res.json({ message: "Password updated" });
});

// ── One-time Director bootstrap — creates the FIRST Director account only.
// Works only while the Director table is empty AND the caller knows
// DIRECTOR_BOOTSTRAP_SECRET (set on Render). Once a Director exists, this
// route refuses permanently — use POST /api/director/directors
// (logged-in-Director-only) to add more after that.
authRoutes.post("/director/bootstrap", async (req, res) => {
  const { name, email, password, secret } = req.body;
  if (!name || !email || !password || !secret) {
    return res.status(400).json({ error: "name, email, password, and secret are required" });
  }

  const expectedSecret = process.env.DIRECTOR_BOOTSTRAP_SECRET;
  if (!expectedSecret) {
    return res.status(500).json({ error: "Bootstrap is not configured (DIRECTOR_BOOTSTRAP_SECRET missing)" });
  }
  if (secret !== expectedSecret) {
    return res.status(403).json({ error: "Invalid bootstrap secret" });
  }

  const existingCount = await prisma.director.count();
  if (existingCount > 0) {
    return res.status(403).json({ error: "A Director already exists — use the Director dashboard to add more" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const director = await prisma.director.create({ data: { name, email, passwordHash } });

  res.status(201).json({ director: { id: director.id, name: director.name, email: director.email } });
});

// Settings (branch-level; kept generic so a Director hitting it without
authRoutes.post("/director/login", authEmailLimiter, makeStaffLikeLoginHandler({ type: "director" }));
authRoutes.post("/manager/login", authEmailLimiter, makeStaffLikeLoginHandler({ type: "manager", include: { branch: true } }));
authRoutes.post("/staff/login", authEmailLimiter, makeStaffLikeLoginHandler({ type: "staff", include: { branch: true } }));

// ── Login 2FA verify — shared by all four account types. The tempToken's
// `type` claim (set above) tells this route which model to check against,
// so Director, Manager, Staff, and Guest all finish their login here. ──
async function loginTwoFactorHandler(req, res) {
  const { tempToken, code } = req.body;
  if (!tempToken || !code) return res.status(400).json({ error: "tempToken and code are required" });

  let payload;
  try { payload = jwt.verify(tempToken, jwtSecret()); } catch { return res.status(401).json({ error: "2FA session expired — log in again" }); }
  if (payload.purpose !== "2fa_pending" || !REFRESH_FK_BY_TYPE[payload.type]) {
    return res.status(401).json({ error: "Invalid session" });
  }

  const type = payload.type;
  const model = accountModel(type);
  const include = type === "manager" || type === "staff" ? { branch: true } : undefined;
  const account = await model.findUnique({ where: { id: payload.id }, ...(include ? { include } : {}) });
  if (!account || (type !== "guest" && !account.isActive)) {
    return res.status(401).json({ error: "Account not found or deactivated" });
  }

  const result = await verifyTwoFactorCode({ model, account, code });
  if (!result.ok) {
    return res.status(result.locked ? 423 : 401).json({ error: result.locked ? "Too many failed codes — try again in 15 minutes" : "Invalid code" });
  }

  const { accessToken, refreshToken } = await issueTokenPair({ subjectType: type, subject: account, req });
  await model.update({ where: { id: account.id }, data: { lastLogin: new Date() } });

  res.json({ token: accessToken, refreshToken, [type]: serializeAccount(type, account) });
}

// Canonical shared route:
authRoutes.post("/login/2fa", loginTwoFactorHandler);
// Old per-type paths kept as aliases so existing frontend calls don't break
// — point your clients at POST /api/auth/login/2fa going forward.
authRoutes.post("/director/login/2fa", loginTwoFactorHandler);
authRoutes.post("/manager/login/2fa", loginTwoFactorHandler);
authRoutes.post("/staff/login/2fa", loginTwoFactorHandler);
authRoutes.post("/guest/login/2fa", loginTwoFactorHandler);

authRoutes.post("/guest/register", async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "name, email, and password are required" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

  const existing = await prisma.guest.findUnique({ where: { email } });
  if (existing && existing.passwordHash) return res.status(409).json({ error: "An account with this email already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const rawVerifyToken = generateRawToken();
  const verificationData = {
    emailVerificationTokenHash: hashRawToken(rawVerifyToken),
    emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
  };

  const guest = existing
    ? await prisma.guest.update({ where: { id: existing.id }, data: { name, phone, passwordHash, ...verificationData } })
    : await prisma.guest.create({ data: { name, email, phone, passwordHash, ...verificationData } });

  const verifyUrl = `${process.env.FRONTEND_URL || ""}/verify-email?token=${rawVerifyToken}`;
  sendVerificationEmail({ email, name, verifyUrl }).catch((err) => console.error("[email] verification send failed:", err.message));

  if (req.body.subscribeNewsletter) {
    upsertConfirmedSubscriber({ email, name, source: "guest_registration" });
  }

  const { accessToken, refreshToken } = await issueTokenPair({ subjectType: "guest", subject: guest, req });
  res.status(201).json({ token: accessToken, refreshToken, guest: { id: guest.id, name: guest.name, email: guest.email, phone: guest.phone, emailVerified: guest.emailVerified } });
});

authRoutes.post("/guest/verify-email", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "token is required" });

  const tokenHash = hashRawToken(token);
  const guest = await prisma.guest.findFirst({ where: { emailVerificationTokenHash: tokenHash } });
  if (!guest || !guest.emailVerificationExpires || guest.emailVerificationExpires < new Date()) {
    return res.status(400).json({ error: "Invalid or expired verification link" });
  }

  await prisma.guest.update({
    where: { id: guest.id },
    data: { emailVerified: true, emailVerifiedAt: new Date(), emailVerificationTokenHash: null, emailVerificationExpires: null },
  });
  res.json({ message: "Email verified" });
});

authRoutes.post("/guest/resend-verification", requireAuth, async (req, res) => {
  if (req.user.type !== "guest") return res.status(403).json({ error: "Guest access required" });
  const guest = await prisma.guest.findUnique({ where: { id: req.user.id } });
  if (guest.emailVerified) return res.status(400).json({ error: "Email already verified" });

  const rawVerifyToken = generateRawToken();
  await prisma.guest.update({
    where: { id: guest.id },
    data: { emailVerificationTokenHash: hashRawToken(rawVerifyToken), emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000) },
  });
  const verifyUrl = `${process.env.FRONTEND_URL || ""}/verify-email?token=${rawVerifyToken}`;
  sendVerificationEmail({ email: guest.email, name: guest.name, verifyUrl })
    .catch((err) => console.error("[email] verification resend failed:", err.message));
  res.json({ message: "Verification email sent" });
});

authRoutes.post("/guest/login", authEmailLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email and password are required" });

  const guest = await prisma.guest.findUnique({ where: { email } });
  if (!guest || !guest.passwordHash) return res.status(401).json({ error: "Invalid email or password" });

  const lockout = checkLockout(guest);
  if (lockout) return res.status(423).json({ error: "Account temporarily locked due to failed login attempts", retryAfterMs: lockout.retryAfterMs });

  const valid = await bcrypt.compare(password, guest.passwordHash);
  if (!valid) {
    const attempts = guest.loginAttempts + 1;
    const data = attempts >= LOGIN_LOCK_THRESHOLD
      ? { loginAttempts: 0, lockUntil: new Date(Date.now() + LOGIN_LOCK_DURATION_MS) }
      : { loginAttempts: attempts };
    await prisma.guest.update({ where: { id: guest.id }, data });
    return res.status(401).json({ error: "Invalid email or password" });
  }

  await prisma.guest.update({ where: { id: guest.id }, data: { loginAttempts: 0, lockUntil: null } });

  if (guest.twoFactorEnabled) {
    const tempToken = signToken({ id: guest.id, type: "guest", purpose: "2fa_pending" }, "5m");
    return res.json({ requires2FA: true, tempToken });
  }

  const { accessToken, refreshToken } = await issueTokenPair({ subjectType: "guest", subject: guest, req });
  await prisma.guest.update({ where: { id: guest.id }, data: { lastLogin: new Date() } });

  res.json({ token: accessToken, refreshToken, guest: { id: guest.id, name: guest.name, email: guest.email, phone: guest.phone, emailVerified: guest.emailVerified } });
});


// ── Refresh (Director + Manager + Staff + Guest, disambiguated by which FK on the RefreshToken row is set) ──
authRoutes.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: "refreshToken is required" });

  const tokenHash = hashRawToken(refreshToken);
  const record = await prisma.refreshToken.findUnique({ where: { tokenHash } });
  if (!record || record.revokedAt || record.expiresAt < new Date()) {
    return res.status(401).json({ error: "Invalid or expired refresh token" });
  }

  // Rotation: this token is single-use — revoke it, issue a new pair.
  await prisma.refreshToken.update({ where: { id: record.id }, data: { revokedAt: new Date() } });

  const fk = ["directorId", "managerId", "staffId", "guestId"].find((f) => record[f]);
  const subjectType = Object.keys(REFRESH_FK_BY_TYPE).find((t) => REFRESH_FK_BY_TYPE[t] === fk);
  const subject = await accountModel(subjectType).findUnique({ where: { id: record[fk] } });
  if (!subject || (subjectType !== "guest" && !subject.isActive)) {
    return res.status(401).json({ error: "Account not found or deactivated" });
  }

  const { accessToken, refreshToken: newRefreshToken } = await issueTokenPair({ subjectType, subject, req });
  res.json({ token: accessToken, refreshToken: newRefreshToken });
});

// ── Logout: revoke one refresh token, or all of the caller's (?all=true) ──
authRoutes.post("/logout", requireAuth, async (req, res) => {
  const { refreshToken, all } = req.body;
  if (all) {
    const fk = REFRESH_FK_BY_TYPE[req.user.type];
    await prisma.refreshToken.updateMany({
      where: { revokedAt: null, [fk]: req.user.id },
      data: { revokedAt: new Date() },
    });
    return res.json({ message: "Logged out on all devices" });
  }
  if (refreshToken) {
    await prisma.refreshToken.updateMany({ where: { tokenHash: hashRawToken(refreshToken), revokedAt: null }, data: { revokedAt: new Date() } });
  }
  res.json({ message: "Logged out" });
});

// ── Password reset — Director / Manager / Staff / Guest, one factory ─────
// isEligible lets each type express its own "does this account count"
// check without the factory needing to know about it: Staff/Director/Manager
// gate on isActive, Guest gates on having a password set at all (an
// existing Guest row can be checkout-only, with no passwordHash yet).
function makeForgotPasswordHandler(type, { isEligible = (a) => a.isActive } = {}) {
  return async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "email is required" });

    const model = accountModel(type);
    const account = await model.findUnique({ where: { email } });
    // Same response whether or not the account exists — don't leak which
    // emails have accounts.
    if (account && isEligible(account)) {
      const rawToken = generateRawToken();
      await model.update({
        where: { id: account.id },
        data: { passwordResetTokenHash: hashRawToken(rawToken), passwordResetExpires: new Date(Date.now() + 60 * 60 * 1000) },
      });
      const resetUrl = `${process.env.FRONTEND_URL || ""}/reset-password?token=${rawToken}&type=${type}`;
      sendPasswordResetEmail({ email, name: account.name, resetUrl }).catch((err) => console.error("[email] reset send failed:", err.message));
    }
    res.json({ message: "If an account exists for that email, a reset link has been sent." });
  };
}

function makeResetPasswordHandler(type) {
  return async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: "token and newPassword are required" });
    if (newPassword.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

    const model = accountModel(type);
    const account = await model.findFirst({ where: { passwordResetTokenHash: hashRawToken(token) } });
    if (!account || !account.passwordResetExpires || account.passwordResetExpires < new Date()) {
      return res.status(400).json({ error: "Invalid or expired reset link" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await model.update({
      where: { id: account.id },
      data: { passwordHash, passwordResetTokenHash: null, passwordResetExpires: null, loginAttempts: 0, lockUntil: null },
    });
    // Resetting the password invalidates every existing session — a stolen
    // token shouldn't survive the owner taking back control of the account.
    const fk = REFRESH_FK_BY_TYPE[type];
    await prisma.refreshToken.updateMany({ where: { [fk]: account.id, revokedAt: null }, data: { revokedAt: new Date() } });

    res.json({ message: "Password updated. Please log in again." });
  };
}

authRoutes.post("/director/forgot-password", authEmailLimiter, makeForgotPasswordHandler("director"));
authRoutes.post("/director/reset-password", makeResetPasswordHandler("director"));
authRoutes.post("/manager/forgot-password", authEmailLimiter, makeForgotPasswordHandler("manager"));
authRoutes.post("/manager/reset-password", makeResetPasswordHandler("manager"));
authRoutes.post("/staff/forgot-password", authEmailLimiter, makeForgotPasswordHandler("staff"));
authRoutes.post("/staff/reset-password", makeResetPasswordHandler("staff"));
authRoutes.post("/guest/forgot-password", authEmailLimiter, makeForgotPasswordHandler("guest", { isEligible: (a) => !!a.passwordHash }));
authRoutes.post("/guest/reset-password", makeResetPasswordHandler("guest"));

// ── 2FA setup/enable/disable — works for whoever requireAuth resolves,
// Director/Manager/Staff and Guest alike, since it just reads req.user.type ──
const TWO_FA_LABEL_BY_TYPE = { director: "Director", manager: "Manager", staff: "Staff", guest: "Guest" };

authRoutes.post("/2fa/setup", requireAuth, async (req, res) => {
  const secret = speakeasy.generateSecret({ name: `Oxygen Hotel (${TWO_FA_LABEL_BY_TYPE[req.user.type] || req.user.type})` });
  const model = accountModel(req.user.type);
  await model.update({ where: { id: req.user.id }, data: { twoFactorPending: secret.base32 } });

  const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);
  res.json({ secret: secret.base32, qrCodeDataUrl: qrDataUrl });
});

authRoutes.post("/2fa/enable", requireAuth, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "code is required" });

  const model = accountModel(req.user.type);
  const account = await model.findUnique({ where: { id: req.user.id } });
  if (!account.twoFactorPending) return res.status(400).json({ error: "Call /2fa/setup first" });

  const valid = speakeasy.totp.verify({ secret: account.twoFactorPending, encoding: "base32", token: code, window: 1 });
  if (!valid) return res.status(400).json({ error: "Invalid code" });

  const backupCodes = generateBackupCodes();
  const hashedBackupCodes = await Promise.all(backupCodes.map(async (c) => ({ codeHash: await bcrypt.hash(c, 10), usedAt: null })));

  await model.update({
    where: { id: req.user.id },
    data: {
      twoFactorEnabled: true, twoFactorSecret: account.twoFactorPending, twoFactorPending: null,
      twoFactorEnabledAt: new Date(), twoFactorBackupCodes: hashedBackupCodes,
    },
  });

  // Backup codes are shown exactly once — store only their hashes, same as a password.
  res.json({ message: "2FA enabled", backupCodes });
});

authRoutes.post("/2fa/disable", requireAuth, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "password is required to disable 2FA" });

  const model = accountModel(req.user.type);
  const account = await model.findUnique({ where: { id: req.user.id } });
  const valid = await bcrypt.compare(password, account.passwordHash);
  if (!valid) return res.status(401).json({ error: "Incorrect password" });

  await model.update({
    where: { id: req.user.id },
    data: { twoFactorEnabled: false, twoFactorSecret: null, twoFactorPending: null, twoFactorBackupCodes: null, twoFactorEnabledAt: null },
  });
  res.json({ message: "2FA disabled" });
});

// =============================================================================
// ROUTES: GUEST (logged-in guest profile)  (was routes/guestRoutes.js)
// =============================================================================

async function requireGuest(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  try {
    const payload = jwt.verify(token, jwtSecret());
    if (payload.type !== "guest") return res.status(401).json({ error: "Guest access required" });
    const guest = await prisma.guest.findUnique({ where: { id: payload.id } });
    if (!guest) return res.status(401).json({ error: "Account not found" });
    req.user = { id: guest.id, type: "guest" };
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

const guestRoutes = express.Router();
guestRoutes.use(requireGuest);

guestRoutes.get("/profile", async (req, res) => {
  const guest = await prisma.guest.findUnique({ where: { id: req.user.id }, select: { id: true, name: true, email: true, phone: true } });
  res.json({ profile: guest });
});

guestRoutes.patch("/profile", async (req, res) => {
  const { name, email, phone } = req.body;
  const guest = await prisma.guest.update({
    where: { id: req.user.id },
    data: { ...(name !== undefined ? { name } : {}), ...(email !== undefined ? { email } : {}), ...(phone !== undefined ? { phone } : {}) },
    select: { id: true, name: true, email: true, phone: true },
  });
  res.json({ profile: guest });
});

guestRoutes.patch("/profile/password", async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "currentPassword and newPassword are required" });
  if (newPassword.length < 8) return res.status(400).json({ error: "New password must be at least 8 characters" });

  const guest = await prisma.guest.findUnique({ where: { id: req.user.id } });
  if (!guest.passwordHash || !(await bcrypt.compare(currentPassword, guest.passwordHash))) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }
  const passwordHash = await bcrypt.hash(newPassword, 10);
  await prisma.guest.update({ where: { id: guest.id }, data: { passwordHash } });
  res.json({ message: "Password updated" });
});

guestRoutes.get("/bookings", async (req, res) => {
  const bookings = await prisma.booking.findMany({
    where: { guestId: req.user.id },
    include: { room: true, branch: true, payment: true },
    orderBy: { checkIn: "desc" },
  });
  res.json({ bookings: bookings.map((b) => ({ ...b, branchName: b.branch.name })) });
});

guestRoutes.get("/tickets", async (req, res) => {
  const tickets = await prisma.ticket.findMany({
    where: { guestId: req.user.id },
    include: {
      branch: { select: { name: true } },
      assignedManager: { select: { name: true, roleTitle: true } },
      assignedStaffMember: { select: { name: true, roleTitle: true } },
    },
    orderBy: { createdAt: "desc" },
  });
  const withUnread = await Promise.all(tickets.map(async (t) => ({
    ...t,
    unreadCount: await prisma.ticketMessage.count({
      where: { ticketId: t.id, senderType: { in: ["DIRECTOR", "MANAGER", "STAFF"] }, ...(t.guestLastReadAt ? { createdAt: { gt: t.guestLastReadAt } } : {}) },
    }),
  })));
  res.json({ tickets: withUnread });
});

guestRoutes.patch("/preferences", async (req, res) => {
  const { preferences, dietaryNotes, specialRequests } = req.body;
  const guest = await prisma.guest.update({
    where: { id: req.user.id },
    data: {
      ...(preferences !== undefined ? { preferences } : {}),
      ...(dietaryNotes !== undefined ? { dietaryNotes } : {}),
      ...(specialRequests !== undefined ? { specialRequests } : {}),
    },
    select: { id: true, preferences: true, dietaryNotes: true, specialRequests: true },
  });
  res.json({ profile: guest });
});

guestRoutes.patch("/orders/:id/cancel", async (req, res) => {
  const { id } = req.params;
  const order = await prisma.order.findFirst({ where: { id, guestId: req.user.id } });
  if (!order) return res.status(404).json({ error: "Order not found on your account" });
  if (!["PENDING", "CONFIRMED"].includes(order.status)) {
    return res.status(409).json({ error: `Order is already ${order.status} and cannot be cancelled` });
  }
  const updated = await prisma.order.update({ where: { id }, data: { status: "CANCELLED" } });
  res.json({ order: updated });
});

guestRoutes.get("/orders", async (req, res) => {
  const orders = await prisma.order.findMany({
    where: { guestId: req.user.id },
    include: { branch: true, event: true, upcomingEvent: true },
    orderBy: { createdAt: "desc" },
  });
  res.json({ orders: orders.map((o) => ({ ...o, branchName: o.branch.name })) });
});

guestRoutes.post("/tickets/:id/messages", async (req, res) => {
  const { id } = req.params;
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "message is required" });

  const ticket = await prisma.ticket.findFirst({ where: { id, guestId: req.user.id } });
  if (!ticket) return res.status(404).json({ error: "Ticket not found on your account" });

  const guest = await prisma.guest.findUnique({ where: { id: req.user.id } });
  const created = await prisma.ticketMessage.create({
    data: { ticketId: id, senderType: "GUEST", guestName: guest.name, message },
  });

  // A guest replying to a ticket that had been marked resolved almost
  // always means it isn't actually resolved — reopen it.
  if (ticket.status === "RESOLVED") {
    await prisma.ticket.update({ where: { id }, data: { status: "OPEN", resolvedAt: null } });
  }

  res.status(201).json({ message: created });
});

guestRoutes.get("/tickets", async (req, res) => {
  const tickets = await prisma.ticket.findMany({
    where: { guestId: req.user.id },
    include: { branch: true, messages: { orderBy: { createdAt: "asc" } } },
    orderBy: { createdAt: "desc" },
  });
  res.json({ tickets: tickets.map((t) => ({ ...t, branchName: t.branch.name })) });
});

guestRoutes.get("/loyalty", getLoyalty);
guestRoutes.post("/loyalty/redeem", redeemLoyaltyPoints);

guestRoutes.get("/wishlist", listWishlist);
guestRoutes.post("/wishlist", addWishlistItem);
guestRoutes.delete("/wishlist/:id", removeWishlistItem);

guestRoutes.post("/reviews", createReview);

guestRoutes.post("/concierge-requests", createConciergeRequest);

guestRoutes.get("/reviews", async (req, res) => {
  const reviews = await prisma.review.findMany({
    where: { guestId: req.user.id },
    include: { branch: { select: { name: true } } },
    orderBy: { createdAt: "desc" },
  });
  res.json({ reviews });
});

guestRoutes.patch("/reviews/:id", async (req, res) => {
  const { id } = req.params;
  const { ratingValue, title, body } = req.body;
  const existing = await prisma.review.findFirst({ where: { id, guestId: req.user.id } });
  if (!existing) return res.status(404).json({ error: "Review not found on your account" });
  // Once published, the review is the public record — edits go back through
  // moderation rather than silently changing what's already live.
  if (existing.status === "PUBLISHED") {
    return res.status(409).json({ error: "This review is already published. Delete it and submit a new one instead." });
  }
  const review = await prisma.review.update({
    where: { id },
    data: {
      ...(ratingValue !== undefined ? { ratingValue } : {}),
      ...(title !== undefined ? { title } : {}),
      ...(body !== undefined ? { body } : {}),
      status: "PENDING",
    },
  });
  res.json({ review });
});

guestRoutes.delete("/reviews/:id", async (req, res) => {
  const { id } = req.params;
  const existing = await prisma.review.findFirst({ where: { id, guestId: req.user.id } });
  if (!existing) return res.status(404).json({ error: "Review not found on your account" });
  await prisma.review.delete({ where: { id } });
  res.json({ message: "Review removed" });
});

// =============================================================================
// ROUTES: DIRECTOR  (company-wide, Director-only — settings, branches,
// company rollup, corporate accounts)
// =============================================================================

const directorRoutes = express.Router();
directorRoutes.use(requireAuth);

// Settings — the platform backbone. Company-wide, Director-only. A
// Manager/Staff member's manage_settings permission is meant for
// branch-level things (their own rooms/services), not this singleton.
directorRoutes.get("/settings", requireDirector, async (req, res) => {
  const settings = await getSettings();
  res.json({ settings: shapeSettingsForAdmin(settings) });
});

directorRoutes.patch("/settings", requireDirector, async (req, res) => {
  // Explicit allowlist — never spread req.body directly into the update.
  // Grouped exactly like the schema, so adding a field later means adding
  // it in exactly two places (schema + this list), nowhere else.
  const ALLOWED_FIELDS = [
    // Identity
    "name", "tagline", "description", "email", "phone", "address", "city", "country",
    "logoUrl", "faviconUrl", "heroImageUrl", "socialLinks",
    // Homepage copy (public site reads these from GET /api/settings)
    "headline", "subheadline", "ctaTitle", "ctaSubtitle",
    "footerAbout", "footerEmail", "footerPhone",
    // Brand colors
    "primaryColor", "secondaryColor", "accentColor",
    // Business hours
    "checkInTime", "checkOutTime", "cancellationPolicy",
    // Currency
    "baseCurrency", "taxRatePercent",
    // Feature flags
    "bookingsEnabled", "ordersEnabled", "eventsEnabled", "ticketsEnabled", "guestAccountsEnabled",
    // Maintenance mode
    "maintenanceMode", "maintenanceTitle", "maintenanceMessage", "maintenanceETA", "maintenanceBypassToken",
    // Announcement banner
    "bannerEnabled", "bannerText", "bannerType", "bannerLink", "bannerLinkText", "bannerDismissible",
    // SEO
    "metaTitle", "metaDescription", "metaKeywords", "ogImageUrl", "googleAnalyticsId", "facebookPixelId",
    // Custom code
    "customCSS", "customHead",
  ];

  const data = {};
  for (const field of ALLOWED_FIELDS) {
    if (req.body[field] !== undefined) data[field] = req.body[field];
  }

  // Light validation on the fields worth validating server-side.
  const HEX_COLOR = /^#[0-9a-fA-F]{6}$/;
  for (const colorField of ["primaryColor", "secondaryColor", "accentColor"]) {
    if (data[colorField] !== undefined && !HEX_COLOR.test(data[colorField])) {
      return res.status(400).json({ error: `${colorField} must be a hex color like #14181f` });
    }
  }
  if (data.bannerType !== undefined && !["info", "success", "warning", "urgent"].includes(data.bannerType)) {
    return res.status(400).json({ error: "bannerType must be one of: info, success, warning, urgent" });
  }

  data.updatedById = req.user.id;

  const settings = await prisma.hotelSettings.upsert({
    where: { id: "main" },
    update: data,
    create: { id: "main", ...data },
  });

  invalidateSettings(); // next getSettings() call re-reads from Postgres

  // Flag sensitive changes in the server log — same pattern as the
  // marketplace's audit log for customCSS/customJS/customHead.
  const sensitiveTouched = ["customCSS", "customHead", "maintenanceBypassToken"].some(
    (f) => req.body[f] !== undefined
  );
  if (sensitiveTouched) {
    console.warn(`⚠️  Director ${req.user.id} modified sensitive settings fields at ${new Date().toISOString()}`);
  }

  res.json({ settings: shapeSettingsForAdmin(settings) });
});

// One-call maintenance toggle — flips the boolean without needing the
// caller to know the current value first.
directorRoutes.post("/settings/maintenance/toggle", requireDirector, async (req, res) => {
  const current = await getSettings();
  const settings = await prisma.hotelSettings.update({
    where: { id: "main" },
    data: { maintenanceMode: !current.maintenanceMode, updatedById: req.user.id },
  });
  invalidateSettings();
  res.json({ settings: shapeSettingsForAdmin(settings) });
});

/** Strips write-only fields before sending settings back to the admin
 * panel — maintenanceBypassToken is set-only, never read back, same as
 * the marketplace pattern. `hasMaintenanceBypassToken` lets the UI show
 * "a bypass token is set" without ever exposing the value itself. */
function shapeSettingsForAdmin(settings) {
  const safe = { ...settings };
  const hasBypassToken = !!safe.maintenanceBypassToken;
  delete safe.maintenanceBypassToken;
  return { ...safe, hasMaintenanceBypassToken: hasBypassToken };
}

// Branches — Director only
// Rooms — full structural CRUD (create, edit, delete, photos) is
// Director-only. Manager/Staff only get status + housekeeping updates,
// on /api/manager/rooms.
directorRoutes.get("/rooms", requireDirector, listRooms);
directorRoutes.post("/rooms", requireDirector, createRoom);
directorRoutes.patch("/rooms/:id", requireDirector, updateRoom);
directorRoutes.delete("/rooms/:id", requireDirector, deleteRoom);
directorRoutes.post("/rooms/:id/images", requireDirector, upload.single("image"), uploadRoomImage);
directorRoutes.delete("/rooms/:id/images", requireDirector, deleteRoomImage);

// Upcoming Events — approval side. Manager drafts/submits via
// /api/manager/upcoming-events; Director approves or rejects here.
directorRoutes.get("/upcoming-events", requireDirector, listUpcomingEvents);
directorRoutes.patch("/upcoming-events/:id/approve", requireDirector, approveUpcomingEvent);
directorRoutes.patch("/upcoming-events/:id/reject", requireDirector, rejectUpcomingEvent);

directorRoutes.get("/branches", requireDirector, async (req, res) => {
  const branches = await prisma.branch.findMany({ orderBy: { name: "asc" } });

  const withCounts = await Promise.all(
    branches.map(async (b) => {
      const [roomCount, staffCount, manager] = await Promise.all([
        prisma.room.count({ where: { branchId: b.id } }),
        prisma.staff.count({ where: { branchId: b.id, isActive: true } }),
        prisma.manager.findFirst({ where: { branchId: b.id, isActive: true }, orderBy: { createdAt: "asc" } }),
      ]);
      return {
        ...b,
        roomCount,
        staffCount,
        manager: manager ? { id: manager.id, name: manager.name } : null,
      };
    })
  );

  res.json({ branches: withCounts });
});

directorRoutes.post("/branches", requireDirector, async (req, res) => {
  const { name, slug, address, city, state, phone, email, services } = req.body;
  if (!name || !slug) return res.status(400).json({ error: "name and slug are required" });
  const branch = await prisma.branch.create({ data: { name, slug, address, city, state, phone, email, services: services || [] } });
  res.status(201).json({ branch });
});
directorRoutes.patch("/branches/:id", requireDirector, async (req, res) => {
  const { id } = req.params;
  const { name, address, city, state, phone, email, services, isActive } = req.body;
  const branch = await prisma.branch.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}), ...(address !== undefined ? { address } : {}),
      ...(city !== undefined ? { city } : {}), ...(state !== undefined ? { state } : {}),
      ...(phone !== undefined ? { phone } : {}), ...(email !== undefined ? { email } : {}),
      ...(services !== undefined ? { services } : {}), ...(isActive !== undefined ? { isActive } : {}),
    },
  });
  res.json({ branch });
});

// Company-wide rollup — Director only. Shape matches what the admin panel's
// Director dashboard renders directly: { totals, branches }.
directorRoutes.get("/company/overview", requireDirector, async (req, res) => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const monthStart = new Date(today.getFullYear(), today.getMonth(), 1);

  const [branches, totalRooms, activeStaff, openTicketsCompanyWide, bookingsThisMonth] = await Promise.all([
    prisma.branch.findMany({ orderBy: { name: "asc" } }),
    prisma.room.count(),
    prisma.staff.count({ where: { isActive: true } }),
    prisma.ticket.count({ where: { status: { in: ["OPEN", "IN_PROGRESS"] } } }),
    prisma.booking.findMany({
      where: { createdAt: { gte: monthStart }, status: { not: "CANCELLED" } },
      select: { totalAmount: true },
    }),
  ]);
  const revenueThisMonth = bookingsThisMonth.reduce((sum, b) => sum + Number(b.totalAmount), 0);

  const branchDetails = await Promise.all(
    branches.map(async (b) => {
      const [roomCount, occupiedToday, openTickets, manager] = await Promise.all([
        prisma.room.count({ where: { branchId: b.id } }),
        prisma.booking.count({
          where: {
            branchId: b.id,
            status: { in: ["CONFIRMED", "CHECKED_IN"] },
            checkIn: { lt: tomorrow },
            checkOut: { gt: today },
          },
        }),
        prisma.ticket.count({ where: { branchId: b.id, status: { in: ["OPEN", "IN_PROGRESS"] } } }),
        prisma.manager.findFirst({ where: { branchId: b.id, isActive: true }, orderBy: { createdAt: "asc" } }),
      ]);
      return {
        id: b.id,
        name: b.name,
        city: b.city,
        manager: manager ? { id: manager.id, name: manager.name } : null,
        occupancyRatePercent: roomCount ? Math.round((occupiedToday / roomCount) * 100) : 0,
        openTickets,
        isActive: b.isActive,
      };
    })
  );

  const companyOccupancyRatePercent = totalRooms
    ? Math.round((branchDetails.reduce((sum, b) => sum + Math.round((b.occupancyRatePercent / 100) * (branches.length ? totalRooms / branches.length : 0)), 0) / totalRooms) * 100) || 0
    : 0;

  res.json({
    totals: {
      branchCount: branches.length,
      totalRooms,
      occupancyRatePercent: companyOccupancyRatePercent,
      openTickets: openTicketsCompanyWide,
      activeStaff,
      revenueThisMonth,
    },
    branches: branchDetails,
  });
});

// Corporate accounts — Director only (company-wide resource)
directorRoutes.get("/corporate-accounts", requireDirector, listCorporateAccounts);
directorRoutes.post("/corporate-accounts", requireDirector, createCorporateAccount);
directorRoutes.patch("/corporate-accounts/:id", requireDirector, updateCorporateAccount);

// Managers — Director only (this was previously dead code: written, never routed)
directorRoutes.get("/managers", requireDirector, listManagers);
directorRoutes.post("/managers", requireDirector, createManager);
directorRoutes.patch("/managers/:id", requireDirector, updateManager);

// Directors — Director only, for appointing additional Directors/co-owners
directorRoutes.get("/directors", requireDirector, listDirectors);
directorRoutes.post("/directors", requireDirector, createDirector);

// Newsletter — Director only, matches "director does settings + sends"
directorRoutes.get("/newsletter/subscribers", requireDirector, async (req, res) => {
  const { status } = req.query;
  const [subscribers, counts] = await Promise.all([
    prisma.newsletterSubscriber.findMany({
      where: status ? { status: status.toUpperCase() } : {},
      orderBy: { createdAt: "desc" },
      take: 500,
    }),
    prisma.newsletterSubscriber.groupBy({ by: ["status"], _count: true }),
  ]);
  res.json({
    subscribers,
    counts: Object.fromEntries(counts.map((c) => [c.status, c._count])),
  });
});

directorRoutes.get("/newsletter/campaigns", requireDirector, async (req, res) => {
  const { status } = req.query;
  const campaigns = await prisma.newsletterCampaign.findMany({
    where: status ? { status: status.toUpperCase() } : {},
    orderBy: { createdAt: "desc" },
    include: { blogPost: { select: { id: true, title: true, slug: true } }, branch: { select: { id: true, name: true } } },
  });
  res.json({ campaigns });
});

// A Director writing and sending their own campaign, unchanged behavior —
// still immediate, no approval step (they ARE the approval step).
directorRoutes.post("/newsletter/campaigns", requireDirector, async (req, res) => {
  const { subject, html } = req.body;
  if (!subject || !html) return res.status(400).json({ error: "subject and html are required" });

  const campaign = await prisma.newsletterCampaign.create({
    data: { subject, html, createdByType: "director", createdById: req.user.id, status: "SENDING" },
  });
  dispatchNewsletterCampaign(campaign.id).catch((err) => console.error("[newsletter] manual dispatch failed:", err.message));

  logAudit(req, "newsletter.campaign.send", { targetType: "newsletterCampaign", targetId: campaign.id });
  res.status(201).json({ campaign, message: "Sending — check back in a moment for delivery counts." });
});

// Review queue — Manager-submitted campaigns waiting on a Director.
directorRoutes.get("/newsletter/campaigns/pending", requireDirector, async (req, res) => {
  const campaigns = await prisma.newsletterCampaign.findMany({
    where: { status: "PENDING_APPROVAL" },
    orderBy: { submittedForApprovalAt: "asc" },
    include: { branch: { select: { id: true, name: true } } },
  });
  res.json({ campaigns });
});

directorRoutes.patch("/newsletter/campaigns/:id/approve", requireDirector, async (req, res) => {
  const { id } = req.params;
  const existing = await prisma.newsletterCampaign.findUnique({ where: { id } });
  if (!existing) return res.status(404).json({ error: "Campaign not found" });
  if (existing.status !== "PENDING_APPROVAL") {
    return res.status(409).json({ error: `Only a pending campaign can be approved — this one is ${existing.status.toLowerCase().replace("_", " ")}` });
  }

  await prisma.newsletterCampaign.update({
    where: { id },
    data: { approvedByDirectorId: req.user.id, approvedAt: new Date() },
  });
  dispatchNewsletterCampaign(id).catch((err) => console.error("[newsletter] approved dispatch failed:", err.message));

  logAudit(req, "newsletter.campaign.approve", { targetType: "newsletterCampaign", targetId: id, branchId: existing.branchId });
  res.json({ message: "Approved — sending now, check back in a moment for delivery counts." });
});

directorRoutes.patch("/newsletter/campaigns/:id/reject", requireDirector, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  const existing = await prisma.newsletterCampaign.findUnique({ where: { id } });
  if (!existing) return res.status(404).json({ error: "Campaign not found" });
  if (existing.status !== "PENDING_APPROVAL") {
    return res.status(409).json({ error: `Only a pending campaign can be rejected — this one is ${existing.status.toLowerCase().replace("_", " ")}` });
  }

  const campaign = await prisma.newsletterCampaign.update({
    where: { id },
    data: { status: "DRAFT", rejectedReason: reason || null, rejectedAt: new Date() },
  });
  logAudit(req, "newsletter.campaign.reject", { targetType: "newsletterCampaign", targetId: id, branchId: existing.branchId });
  res.json({ campaign, message: "Sent back to draft — the Manager can revise and resubmit." });
});

directorRoutes.get("/paystack/banks", requireDirector, getPaystackBankList);
directorRoutes.post("/paystack/verify-account", requireDirector, verifyBranchPayoutAccount);
directorRoutes.post("/branches/:id/payout-account", requireDirector, setBranchPayoutAccount);
directorRoutes.post("/branches/:id/stripe-account", requireDirector, connectBranchStripeAccount);
directorRoutes.get("/branches/:id/stripe-account/status", requireDirector, getBranchStripeStatus);

// Audit log — Director only. Pattern for adding more call sites: see
// logAudit() near resolveBranchScope() above.
directorRoutes.get("/audit-log", requireDirector, async (req, res) => {
  const { actorType, action, from, to } = req.query;
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = 50;

  const where = {
    ...(actorType ? { actorType } : {}),
    ...(action ? { action } : {}),
    ...((from || to) ? { createdAt: { ...(from ? { gte: new Date(from) } : {}), ...(to ? { lte: new Date(to) } : {}) } } : {}),
  };

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({ where, orderBy: { createdAt: "desc" }, skip: (page - 1) * pageSize, take: pageSize }),
    prisma.auditLog.count({ where }),
  ]);

  res.json({ logs, total, page, pageSize });
});
// =============================================================================
// ROUTES: MANAGER  (branch-scoped — open to Manager + Staff per permission;
// Director still passes every check here too, via requireBranchAccess's
// built-in Director bypass, for company-wide oversight)
// =============================================================================

const managerRoutes = express.Router();
managerRoutes.use(requireAuth);
// Rooms — Manager/Staff can only view and operate (status, housekeeping).
// Creating, editing, deleting a room, or touching its photos, is
// Director-only — see directorRoutes below. Nothing here can create or
// rename a room, on purpose.
managerRoutes.get("/rooms", requireBranchAccess("manage_rooms"), listRooms);
managerRoutes.patch("/rooms/:id/status", requireBranchAccess("manage_rooms"), updateRoomStatus);

// Upcoming Events — Director-and-Manager only, never Staff (see
// requireDirectorOrManager). Manager drafts and submits here; Director
// approves/rejects via /api/director/upcoming-events.
managerRoutes.get("/upcoming-events", requireDirectorOrManager, listUpcomingEvents);
managerRoutes.post("/upcoming-events", requireDirectorOrManager, createUpcomingEvent);
managerRoutes.patch("/upcoming-events/:id", requireDirectorOrManager, updateUpcomingEvent);
managerRoutes.post("/upcoming-events/:id/submit", requireDirectorOrManager, submitUpcomingEventForApproval);
managerRoutes.delete("/upcoming-events/:id", requireDirectorOrManager, deleteUpcomingEvent);

// Housekeeping — same "manage_rooms" permission as room CRUD (the existing
// "Housekeeping" department in DEPARTMENT_CATALOG already maps to it).
managerRoutes.get("/housekeeping", requireBranchAccess("manage_rooms"), listHousekeeping);
managerRoutes.patch("/housekeeping/:roomId", requireBranchAccess("manage_rooms"), updateHousekeepingStatus);

// Bookings
managerRoutes.get("/bookings", requireBranchAccess("manage_bookings"), listBranchBookings);
managerRoutes.patch("/bookings/:id/status", requireBranchAccess("manage_bookings"), updateBookingStatus);

// Stock
managerRoutes.get("/stock", requireBranchAccess("manage_stock"), listStockItems);
managerRoutes.post("/stock", requireBranchAccess("manage_stock"), createStockItem);
managerRoutes.patch("/stock/:id", requireBranchAccess("manage_stock"), updateStockItem);
managerRoutes.delete("/stock/:id", requireBranchAccess("manage_stock"), deleteStockItem);

// Events
managerRoutes.get("/events", requireBranchAccess("manage_events"), listEvents);
managerRoutes.post("/events", requireBranchAccess("manage_events"), createEvent);
managerRoutes.patch("/events/:id", requireBranchAccess("manage_events"), updateEvent);
managerRoutes.post("/events/:id/images", requireBranchAccess("manage_events"), upload.single("image"), uploadEventImage);
managerRoutes.delete("/events/:id/images", requireBranchAccess("manage_events"), deleteEventImage);
managerRoutes.delete("/events/:id", requireBranchAccess("manage_events"), deleteEvent);

// Blog (Director: company-wide by default, or scope to one branch via
// ?branchId=. Manager: always their own branch — enforced the same way
// resolveBranchScope() enforces it everywhere else in this file.)
managerRoutes.get("/blog", requireBranchAccess("manage_blog"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const posts = await prisma.blogPost.findMany({
    where: branchId ? { branchId } : {},
    orderBy: { createdAt: "desc" },
    include: { branch: { select: { id: true, name: true } }, campaign: { select: { id: true, status: true, sentCount: true } } },
  });
  res.json({ posts });
});

managerRoutes.post("/blog", requireBranchAccess("manage_blog"), async (req, res) => {
  const branchId = resolveBranchScope(req); // null for a Director posting company-wide — that's valid here, unlike most other resources
  const { title, excerpt, content, coverImageUrl, tags, status, autoNewsletter } = req.body;
  if (!title || !content) return res.status(400).json({ error: "title and content are required" });

  let slug = title.toString().trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  const slugTaken = await prisma.blogPost.findUnique({ where: { slug } });
  if (slugTaken) slug = `${slug}-${Date.now().toString(36)}`;

  const isPublishing = status === "PUBLISHED";
  const post = await prisma.blogPost.create({
    data: {
      branchId, authorType: req.user.type, authorId: req.user.id,
      title, slug, excerpt, content, coverImageUrl,
      tags: tags || [], status: isPublishing ? "PUBLISHED" : "DRAFT",
      publishedAt: isPublishing ? new Date() : null,
      autoNewsletter: autoNewsletter !== false,
    },
  });

  if (isPublishing && post.autoNewsletter) triggerBlogNewsletterDispatch(post).catch((err) => console.error("[newsletter] auto-dispatch failed:", err.message));

  logAudit(req, "blog.create", { targetType: "blogPost", targetId: post.id, branchId });
  res.status(201).json({ post });
});

managerRoutes.patch("/blog/:id", requireBranchAccess("manage_blog"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.blogPost.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Post not found" });

  const { title, excerpt, content, coverImageUrl, tags, status, autoNewsletter } = req.body;
  const willPublishNow = status === "PUBLISHED" && existing.status !== "PUBLISHED";

  const post = await prisma.blogPost.update({
    where: { id },
    data: {
      ...(title !== undefined ? { title } : {}),
      ...(excerpt !== undefined ? { excerpt } : {}),
      ...(content !== undefined ? { content } : {}),
      ...(coverImageUrl !== undefined ? { coverImageUrl } : {}),
      ...(tags !== undefined ? { tags } : {}),
      ...(autoNewsletter !== undefined ? { autoNewsletter } : {}),
      ...(status !== undefined ? { status, ...(willPublishNow ? { publishedAt: new Date() } : {}) } : {}),
    },
  });

  if (willPublishNow && post.autoNewsletter) triggerBlogNewsletterDispatch(post).catch((err) => console.error("[newsletter] auto-dispatch failed:", err.message));

  logAudit(req, "blog.update", { targetType: "blogPost", targetId: post.id, branchId: existing.branchId });
  res.json({ post });
});

managerRoutes.post("/blog/:id/image", requireBranchAccess("manage_blog"), upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No image file provided (field name: image)" });
  const { id } = req.params;
  const existing = await prisma.blogPost.findUnique({ where: { id } });
  if (!existing) return res.status(404).json({ error: "Post not found" });

  const url = await uploadBuffer(req.file.buffer, "Uyeh-hotel/blog");
  const post = await prisma.blogPost.update({ where: { id }, data: { coverImageUrl: url } });
  res.status(201).json({ post, uploadedUrl: url });
});

managerRoutes.delete("/blog/:id", requireBranchAccess("manage_blog"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.blogPost.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Post not found" });
  await prisma.blogPost.delete({ where: { id } });
  res.json({ message: "Post deleted" });
});

/** Actually sends a campaign: pulls every CONFIRMED subscriber, sends one
 * email each (with that subscriber's personal unsubscribe link appended),
 * and records the outcome. This was previously called from two places but
 * never defined — every newsletter send has been failing silently. */
async function dispatchNewsletterCampaign(campaignId) {
  const campaign = await prisma.newsletterCampaign.findUnique({ where: { id: campaignId } });
  if (!campaign) throw new Error(`Newsletter campaign ${campaignId} not found`);

  await prisma.newsletterCampaign.update({ where: { id: campaignId }, data: { status: "SENDING" } });

  const subscribers = await prisma.newsletterSubscriber.findMany({ where: { status: "CONFIRMED" } });

  let sentCount = 0;
  let failedCount = 0;

  for (const subscriber of subscribers) {
    const unsubscribeUrl = `${process.env.FRONTEND_URL || ""}/newsletter/unsubscribe?token=${subscriber.unsubscribeToken}`;
    const html = `${campaign.html}<p style="font-size:11px; color:#9a9384; margin-top:32px; text-align:center;"><a href="${unsubscribeUrl}" style="color:#9a9384;">Unsubscribe</a></p>`;
    const result = await sendEmail({ to: subscriber.email, subject: campaign.subject, html });
    if (result?.error) failedCount++; else sentCount++;
  }

  const finalStatus = failedCount > 0 && sentCount === 0 ? "FAILED" : "SENT";
  await prisma.newsletterCampaign.update({
    where: { id: campaignId },
    data: { status: finalStatus, sentCount, failedCount, sentAt: new Date() },
  });

  return { sentCount, failedCount };
}

/** Publish → auto-dispatch: builds one NewsletterCampaign row from the
 * post (skipped if one already exists for this post — the @unique on
 * blogPostId also guards this at the DB level) and sends it. */
async function triggerBlogNewsletterDispatch(post) {
  if (post.newsletterSentAt) return; // already dispatched — editing a published post never re-sends
  const platformName = await getPlatformName();
  const postUrl = `${process.env.FRONTEND_URL || ""}/blog/${post.slug}`;
  const html = emailLayout(`
    <h2 style="font-family:Georgia,serif; color:#14181F; margin:0 0 12px;">${escapeHtml(post.title)}</h2>
    ${post.coverImageUrl ? `<img src="${post.coverImageUrl}" alt="" style="width:100%; border-radius:4px; margin-bottom:16px;">` : ""}
    <p style="color:#6B6355;">${escapeHtml(post.excerpt || post.content.slice(0, 200))}</p>
    <p style="margin:20px 0;"><a href="${postUrl}" style="background:#B98D45; color:#14181F; padding:12px 24px; border-radius:4px; text-decoration:none; font-weight:600;">Read the full post</a></p>
  `, platformName);

  const authoredByManager = post.authorType === "manager";
  const campaign = await prisma.newsletterCampaign.create({
    data: {
      blogPostId: post.id, subject: post.title, html,
      branchId: post.branchId,
      createdByType: post.authorType, createdById: post.authorId,
      status: authoredByManager ? "PENDING_APPROVAL" : "DRAFT",
      ...(authoredByManager ? { submittedForApprovalAt: new Date() } : {}),
    },
  });

  if (authoredByManager) {
    // Queued for a Director to approve — don't mark newsletterSentAt yet,
    // don't dispatch. A Director-authored post still sends immediately,
    // same as before.
    return;
  }

  await prisma.blogPost.update({ where: { id: post.id }, data: { newsletterSentAt: new Date() } });
  await dispatchNewsletterCampaign(campaign.id);
}

// Newsletter — Manager drafts/submits for their branch, Director approves
// & sends (see directorRoutes below). Recipients are always the full
// company subscriber list — there's no per-branch subscriber segmentation,
// this only controls who authored/requested the send.
managerRoutes.get("/newsletter/campaigns", requireBranchAccess("manage_newsletter"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const campaigns = await prisma.newsletterCampaign.findMany({
    where: branchId ? { branchId } : { createdById: req.user.id },
    orderBy: { createdAt: "desc" },
  });
  res.json({ campaigns });
});

managerRoutes.post("/newsletter/campaigns", requireBranchAccess("manage_newsletter"), async (req, res) => {
  const { subject, html } = req.body;
  if (!subject || !html) return res.status(400).json({ error: "subject and html are required" });

  const campaign = await prisma.newsletterCampaign.create({
    data: { subject, html, branchId: req.user.branchId || null, createdByType: req.user.type, createdById: req.user.id, status: "DRAFT" },
  });
  logAudit(req, "newsletter.campaign.draft", { targetType: "newsletterCampaign", targetId: campaign.id, branchId: req.user.branchId });
  res.status(201).json({ campaign });
});

managerRoutes.patch("/newsletter/campaigns/:id", requireBranchAccess("manage_newsletter"), async (req, res) => {
  const { id } = req.params;
  const existing = await prisma.newsletterCampaign.findFirst({
    where: { id, ...(req.user.type !== "director" ? { branchId: req.user.branchId } : {}) },
  });
  if (!existing) return res.status(404).json({ error: "Campaign not found" });
  if (!["DRAFT"].includes(existing.status)) {
    return res.status(409).json({ error: `Cannot edit a campaign that's already ${existing.status.toLowerCase().replace("_", " ")}` });
  }

  const { subject, html } = req.body;
  const campaign = await prisma.newsletterCampaign.update({
    where: { id },
    data: { ...(subject !== undefined ? { subject } : {}), ...(html !== undefined ? { html } : {}) },
  });
  res.json({ campaign });
});

managerRoutes.post("/newsletter/campaigns/:id/submit", requireBranchAccess("manage_newsletter"), async (req, res) => {
  const { id } = req.params;
  const existing = await prisma.newsletterCampaign.findFirst({
    where: { id, ...(req.user.type !== "director" ? { branchId: req.user.branchId } : {}) },
  });
  if (!existing) return res.status(404).json({ error: "Campaign not found" });
  if (existing.status !== "DRAFT") {
    return res.status(409).json({ error: `Only a draft can be submitted — this campaign is ${existing.status.toLowerCase().replace("_", " ")}` });
  }

  const campaign = await prisma.newsletterCampaign.update({
    where: { id },
    data: { status: "PENDING_APPROVAL", submittedForApprovalAt: new Date(), rejectedReason: null, rejectedAt: null },
  });
  logAudit(req, "newsletter.campaign.submit", { targetType: "newsletterCampaign", targetId: campaign.id, branchId: existing.branchId });
  res.json({ campaign, message: "Submitted — a Director will review before it sends." });
});

// Staff (Director: any branch via ?branchId=. Manager: own branch, Staff-role accounts only.)
managerRoutes.get("/departments", requireBranchAccess("manage_staff"), listDepartmentCatalog);
managerRoutes.get("/staff", requireBranchAccess("manage_staff"), listBranchStaff);
managerRoutes.post("/staff", requireBranchAccess("manage_staff"), createStaffMember);
managerRoutes.patch("/staff/:id", requireBranchAccess("manage_staff"), updateStaffMember);

// Guest tickets
managerRoutes.get("/tickets", requireBranchAccess("handle_tickets"), listBranchTickets);
managerRoutes.get("/tickets/:id", requireBranchAccess("handle_tickets"), getTicket);
managerRoutes.patch("/tickets/:id/assign", requireBranchAccess("handle_tickets"), assignTicket);
managerRoutes.post("/tickets/:id/messages", requireBranchAccess("handle_tickets"), replyToTicket);
managerRoutes.patch("/tickets/:id/resolve", requireBranchAccess("handle_tickets"), resolveTicket);

// Orders (room service, restaurant, bar, events, spa, laundry...)
managerRoutes.get("/orders", requireBranchAccess("manage_bookings"), listBranchOrders);
managerRoutes.get("/orders/:id", requireBranchAccess("manage_bookings"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const order = await prisma.order.findFirst({
    where: { id: req.params.id, ...(branchId ? { branchId } : {}) },
    include: { guest: true, lines: true, event: true, spaAppointment: true, room: true },
  });
  if (!order) return res.status(404).json({ error: "Order not found at this branch" });
  res.json({ order });
});
managerRoutes.patch("/orders/:id/status", requireBranchAccess("manage_bookings"), updateOrderStatus);

// Menu (restaurant + bar catalog)
managerRoutes.get("/menu", requireBranchAccess("manage_menu"), listMenuItems);
managerRoutes.post("/menu", requireBranchAccess("manage_menu"), createMenuItem);
managerRoutes.patch("/menu/:id", requireBranchAccess("manage_menu"), updateMenuItem);
managerRoutes.delete("/menu/:id", requireBranchAccess("manage_menu"), deleteMenuItem);
managerRoutes.post("/menu/:id/images", requireBranchAccess("manage_menu"), upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No image file provided (field name: image)" });
  const item = await prisma.menuItem.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: "Menu item not found" });
  const url = await uploadBuffer(req.file.buffer, "Uyeh-hotel/menu");
  const updated = await prisma.menuItem.update({ where: { id: item.id }, data: { image: url } });
  res.status(201).json({ menuItem: updated, uploadedUrl: url });
});
managerRoutes.delete("/menu/:id/images", requireBranchAccess("manage_menu"), async (req, res) => {
  const item = await prisma.menuItem.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: "Menu item not found" });
  const updated = await prisma.menuItem.update({ where: { id: item.id }, data: { image: null } });
  res.json({ menuItem: updated });
});

// Laundry price list
managerRoutes.get("/laundry-items", requireBranchAccess("manage_laundry"), listLaundryItems);
managerRoutes.post("/laundry-items", requireBranchAccess("manage_laundry"), createLaundryItem);
managerRoutes.patch("/laundry-items/:id", requireBranchAccess("manage_laundry"), updateLaundryItem);
managerRoutes.delete("/laundry-items/:id", requireBranchAccess("manage_laundry"), deleteLaundryItem);
managerRoutes.post("/laundry-items/:id/images", requireBranchAccess("manage_laundry"), upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No image file provided (field name: image)" });
  const item = await prisma.laundryItem.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: "Laundry item not found" });
  const url = await uploadBuffer(req.file.buffer, "Uyeh-hotel/laundry");
  const updated = await prisma.laundryItem.update({ where: { id: item.id }, data: { image: url } });
  res.status(201).json({ laundryItem: updated, uploadedUrl: url });
});
managerRoutes.delete("/laundry-items/:id/images", requireBranchAccess("manage_laundry"), async (req, res) => {
  const item = await prisma.laundryItem.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: "Laundry item not found" });
  const updated = await prisma.laundryItem.update({ where: { id: item.id }, data: { image: null } });
  res.json({ laundryItem: updated });
});

// Spa treatments
managerRoutes.get("/spa-treatments", requireBranchAccess("manage_spa"), listSpaTreatments);
managerRoutes.post("/spa-treatments", requireBranchAccess("manage_spa"), createSpaTreatment);
managerRoutes.patch("/spa-treatments/:id", requireBranchAccess("manage_spa"), updateSpaTreatment);
managerRoutes.delete("/spa-treatments/:id", requireBranchAccess("manage_spa"), deleteSpaTreatment);
managerRoutes.post("/spa-treatments/:id/images", requireBranchAccess("manage_spa"), upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No image file provided (field name: image)" });
  const item = await prisma.spaTreatment.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: "Spa treatment not found" });
  const url = await uploadBuffer(req.file.buffer, "Uyeh-hotel/spa");
  const updated = await prisma.spaTreatment.update({ where: { id: item.id }, data: { image: url } });
  res.status(201).json({ spaTreatment: updated, uploadedUrl: url });
});
managerRoutes.delete("/spa-treatments/:id/images", requireBranchAccess("manage_spa"), async (req, res) => {
  const item = await prisma.spaTreatment.findUnique({ where: { id: req.params.id } });
  if (!item) return res.status(404).json({ error: "Spa treatment not found" });
  const updated = await prisma.spaTreatment.update({ where: { id: item.id }, data: { image: null } });
  res.json({ spaTreatment: updated });
});

// Transactions — manual payment ledger (see Transaction model note in schema.prisma)
managerRoutes.get("/transactions", requireBranchAccess("manage_payments"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const { source, status } = req.query;

  const where = {
    ...(branchId ? { branchId } : {}),
    ...(source ? { source: source.toUpperCase() } : {}),
    ...(status ? { status: status.toUpperCase() } : {}),
  };

  const [transactions, branchMap] = await Promise.all([
    prisma.transaction.findMany({ where, orderBy: { createdAt: "desc" }, take: 200 }),
    req.user.type === "director"
      ? prisma.branch.findMany({ select: { id: true, name: true } }).then((rows) => Object.fromEntries(rows.map((b) => [b.id, b.name])))
      : Promise.resolve({}),
  ]);

  const paidAgg = await prisma.transaction.aggregate({ where: { ...where, status: "PAID" }, _sum: { amount: true } });
  const pendingAgg = await prisma.transaction.aggregate({ where: { ...where, status: "PENDING" }, _sum: { amount: true } });
  const refundedAgg = await prisma.transaction.aggregate({ where: { ...where, status: "REFUNDED" }, _sum: { amount: true } });

  res.json({
    transactions: transactions.map((t) => ({
      id: t.id,
      createdAt: t.createdAt,
      guestName: t.guestName,
      branchName: branchMap[t.branchId] || null,
      source: t.source.toLowerCase(),
      method: t.method,
      amount: t.amount,
      status: t.status,
    })),
    totals: {
      paid: Number(paidAgg._sum.amount || 0),
      pending: Number(pendingAgg._sum.amount || 0),
      refunded: Number(refundedAgg._sum.amount || 0),
    },
  });
});

managerRoutes.get("/transactions/:id", requireBranchAccess("manage_payments"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const txn = await prisma.transaction.findFirst({ where: { id: req.params.id, ...(branchId ? { branchId } : {}) } });
  if (!txn) return res.status(404).json({ error: "Transaction not found" });
  res.json({ transaction: txn });
});

managerRoutes.post("/transactions", requireBranchAccess("manage_payments"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "branchId is required (Director must pass ?branchId=)" });

  const { bookingId, guestName, source, amount, method, providerRef } = req.body;
  if (!guestName || !source || amount === undefined || !method) {
    return res.status(400).json({ error: "guestName, source, amount, and method are required" });
  }
  const VALID_SOURCES = ["BOOKING", "FOOD", "DRINK", "SERVICE", "EVENT"];
  const VALID_METHODS = ["CASH", "CARD", "TRANSFER", "PAYSTACK", "STRIPE"];
  if (!VALID_SOURCES.includes(source.toUpperCase())) return res.status(400).json({ error: `source must be one of: ${VALID_SOURCES.join(", ")}` });
  if (!VALID_METHODS.includes(method.toUpperCase())) return res.status(400).json({ error: `method must be one of: ${VALID_METHODS.join(", ")}` });

  const transaction = await prisma.transaction.create({
    data: {
      branchId, bookingId: bookingId || null, guestName,
      source: source.toUpperCase(), method: method.toUpperCase(),
      amount, status: "PAID",
      // Without this, a PAYSTACK-method transaction can still be marked
      // REFUNDED later but can't trigger an actual refund — see B16.
      providerRef: method.toUpperCase() === "PAYSTACK" ? (providerRef || null) : null,
      recordedByType: req.user.type, recordedById: req.user.id,
    },
  });
  logAudit(req, "transaction.record", { targetType: "transaction", targetId: transaction.id, branchId, metadata: { amount, source, method } });
  res.status(201).json({ transaction });
});

// Refunding is Director-only — Manager/Staff with manage_payments can still
// view transactions and take payments, just not reverse money out.
managerRoutes.patch("/transactions/:id/refund", requireDirector, async (req, res) => {
  const branchId = resolveBranchScope(req);
  const existing = await prisma.transaction.findFirst({
    where: { id: req.params.id, ...(branchId ? { branchId } : {}) },
    include: { branch: true },
  });
  if (!existing) return res.status(404).json({ error: "Transaction not found" });
  if (existing.status === "REFUNDED") return res.status(409).json({ error: "Already refunded" });

   // Only a PAYSTACK-method transaction with a stored reference can actually
  // be refunded through Paystack — cash/transfer/terminal transactions were
  // never processed by us, so those stay a manual record-keeping flip and
  // the response says so explicitly rather than implying money moved.
  let paystackResult = null;
  if (existing.method === "PAYSTACK" && existing.providerRef) {
    try {
      paystackResult = await refundTransaction(existing.providerRef, existing.amount, req.body?.reason);
    } catch (err) {
      return res.status(err.status || 502).json({ error: `Paystack refund failed: ${err.message}` });
    }
  }

  const transaction = await prisma.transaction.update({
    where: { id: existing.id },
    data: {
      status: "REFUNDED",
      refundedAt: new Date(),
      refundedByType: req.user.type,
      refundedById: req.user.id,
      refundReason: req.body?.reason || null,
    },
  });
  logAudit(req, "transaction.refund", { targetType: "transaction", targetId: transaction.id, branchId: existing.branchId, metadata: { amount: existing.amount, reason: req.body?.reason } });

  // Transaction.guestName is a free-text snapshot, not a Guest relation, so
  // there's no guaranteed email address on this record — only send if the
  // guest can actually be resolved (e.g. via the linked booking).
  if (existing.bookingId) {
    const booking = await prisma.booking.findUnique({ where: { id: existing.bookingId }, include: { guest: true } });
    if (booking?.guest?.email) {
      sendRefundConfirmation({
        guestEmail: booking.guest.email,
        guestName: booking.guest.name,
        branchName: existing.branch.name,
        amount: existing.amount,
        currency: existing.currency || "NGN",
        reference: existing.id,
      }).catch((err) => console.error("[email] refund confirmation failed:", err.message));
    }
  }

  res.json({ transaction });
});

// Printable invoice — plain HTML (opens in a new tab, prints via browser).
// Not a generated PDF file; if you need a downloadable PDF later, the pdf
// skill/library route is the place to add that, this keeps it simple for now.
// Only for this route: allow ?token= as a fallback to the Authorization
// header, since it's opened by direct navigation (target="_blank"), not
// fetched with JS. Every other route in this file stays header-only.
function authFromQueryOrHeader(req, res, next) {
  if (!req.headers.authorization && req.query.token) {
    req.headers.authorization = `Bearer ${req.query.token}`;
  }
  requireAuth(req, res, next);
}

managerRoutes.get("/transactions/:id/invoice", authFromQueryOrHeader, requireBranchAccess("manage_payments"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const txn = await prisma.transaction.findFirst({ where: { id: req.params.id, ...(branchId ? { branchId } : {}) } });
  if (!txn) return res.status(404).send("Transaction not found");

  const branch = await prisma.branch.findUnique({ where: { id: txn.branchId } });
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Invoice — ${txn.id}</title>
    <style>
      body { font-family: -apple-system, sans-serif; max-width: 560px; margin: 40px auto; color: #1a1a1a; }
      h1 { font-size: 1.3rem; margin-bottom: 0; }
      .muted { color: #777; font-size: 0.85rem; }
      table { width: 100%; border-collapse: collapse; margin-top: 24px; }
      td { padding: 8px 0; border-bottom: 1px solid #eee; }
      .total { font-weight: 700; font-size: 1.1rem; }
      @media print { button { display: none; } }
    </style></head><body>
    <h1>${branch?.name || "Receipt"}</h1>
    <p class="muted">Transaction ${txn.id}</p>
    <table>
      <tr><td>Date</td><td>${new Date(txn.createdAt).toLocaleString()}</td></tr>
      <tr><td>Guest</td><td>${txn.guestName}</td></tr>
      <tr><td>Source</td><td>${txn.source}</td></tr>
      <tr><td>Method</td><td>${txn.method}</td></tr>
      <tr><td>Status</td><td>${txn.status}</td></tr>
      <tr><td class="total">Amount</td><td class="total">&#8358;${Number(txn.amount).toLocaleString()}</td></tr>
    </table>
    <button onclick="window.print()" style="margin-top:24px;">Print</button>
  </body></html>`;
  res.status(200).send(html);
});

// Reviews — moderation
managerRoutes.get("/reviews", requireBranchAccess("manage_reviews"), listBranchReviews);
managerRoutes.patch("/reviews/:id/moderate", requireBranchAccess("manage_reviews"), moderateReview);
managerRoutes.post("/reviews/:id/reply", requireBranchAccess("manage_reviews"), replyToReview);

// Promo codes — Director (company-wide or scoped) or Manager (own branch only)
managerRoutes.get("/promo-codes", requireBranchAccess("manage_promos"), listPromoCodes);
managerRoutes.post("/promo-codes", requireBranchAccess("manage_promos"), createPromoCode);
managerRoutes.patch("/promo-codes/:id", requireBranchAccess("manage_promos"), updatePromoCode);

// Group bookings — staff-initiated (phone/walk-in), on top of the public guest-initiated route
managerRoutes.get("/group-bookings", requireBranchAccess("manage_bookings"), listGroupBookings);
managerRoutes.post("/group-bookings", requireBranchAccess("manage_bookings"), createGroupBookingStaff);

managerRoutes.get("/concierge-requests", requireBranchAccess("manage_concierge"), listConciergeRequests);
managerRoutes.patch("/concierge-requests/:id", requireBranchAccess("manage_concierge"), updateConciergeRequest);
managerRoutes.get("/group-bookings/:id", requireBranchAccess("manage_bookings"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const group = await prisma.groupBooking.findFirst({
    where: { id: req.params.id, ...(branchId ? { branchId } : {}) },
    include: { bookings: { include: { room: true, guest: true } }, corporateAccount: true, contactGuest: true },
  });
  if (!group) return res.status(404).json({ error: "Group booking not found at this branch" });
  res.json({ groupBooking: group });
});
managerRoutes.patch("/group-bookings/:id/status", requireBranchAccess("manage_bookings"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  const { status } = req.body;
  const VALID = ["PENDING", "CONFIRMED", "CHECKED_IN", "CHECKED_OUT", "CANCELLED"];
  if (!status || !VALID.includes(status)) return res.status(400).json({ error: `status must be one of: ${VALID.join(", ")}` });
  const existing = await prisma.groupBooking.findFirst({ where: { id: req.params.id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Group booking not found at this branch" });
  const group = await prisma.groupBooking.update({ where: { id: existing.id }, data: { status } });
  res.json({ groupBooking: group });
});

// Branch settings

managerRoutes.get("/branch-settings", requireBranchAccess("manage_settings"), getBranchSettings);
managerRoutes.patch("/branch-settings", requireBranchAccess("manage_settings"), updateBranchSettings);

// Branch Profile — READ-ONLY. Lets a Manager see the platform-wide
// policies, brand, and their branch's payout connection status, without
// exposing anything a Manager shouldn't touch (bank details, Paystack
// subaccount code, customCSS/Head, maintenance controls all stay
// Director-only). Deliberately has no matching PATCH route.
managerRoutes.get("/branch-profile", requireBranchAccess("manage_settings"), async (req, res) => {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "Director must specify ?branchId=" });

  const [branch, settings] = await Promise.all([
    prisma.branch.findUnique({ where: { id: branchId } }),
    getSettings(),
  ]);
  if (!branch) return res.status(404).json({ error: "Branch not found" });

  res.json({
    branch: {
      id: branch.id,
      name: branch.name,
      city: branch.city,
      state: branch.state,
      address: branch.address,
      services: branch.services,
      // Masked — a Manager can see THAT a payout account is connected,
      // never the account number or Paystack subaccount code itself.
      payoutConnected: !!branch.paystackSubaccountCode,
      payoutBankName: branch.settlementBankName || null,
    },
    companyPolicies: {
      checkInTime: settings.checkInTime,
      checkOutTime: settings.checkOutTime,
      cancellationPolicy: settings.cancellationPolicy,
      baseCurrency: settings.baseCurrency,
      taxRatePercent: settings.taxRatePercent,
    },
    brand: {
      primaryColor: settings.primaryColor,
      secondaryColor: settings.secondaryColor,
      accentColor: settings.accentColor,
      logoUrl: settings.logoUrl,
    },
  });
});
// Reports
managerRoutes.get("/reports", requireBranchAccess("view_reports"), getBranchReports);

// Security — guest/stay verification
managerRoutes.get("/guest-lookup", requireBranchAccess("manage_security"), guestLookup);

// Manual loyalty adjustment — goodwill awards or corrections, always
// reason-logged. Positive amount = award, negative = deduct.
managerRoutes.post("/loyalty/adjust", requireBranchAccess("manage_security"), async (req, res) => {
  const { guestId, points, reason } = req.body;
  const amount = Number(points);
  if (!guestId || !amount || !Number.isInteger(amount)) {
    return res.status(400).json({ error: "guestId and a whole-number points value are required" });
  }
  if (!reason || !reason.trim()) {
    return res.status(400).json({ error: "A reason is required for every manual loyalty adjustment" });
  }

  const guest = await prisma.guest.findUnique({ where: { id: guestId } });
  if (!guest) return res.status(404).json({ error: "Guest not found" });
  if (amount < 0 && guest.loyaltyPoints + amount < 0) {
    return res.status(400).json({ error: "This would take the guest below zero points" });
  }

  const [updated] = await prisma.$transaction([
    prisma.guest.update({
      where: { id: guestId },
      data: {
        loyaltyPoints: { increment: amount },
        // Only a positive award raises lifetime total (and therefore
        // tier) — a correction/deduction should never demote a guest.
        ...(amount > 0 ? { lifetimePoints: { increment: amount } } : {}),
      },
    }),
    prisma.loyaltyTransaction.create({
      data: { guestId, points: amount, reason: `${reason.trim()} (manual, by ${req.user.type} ${req.user.id})` },
    }),
  ]);

  await logAudit({ req, action: "loyalty.manual_adjust", targetType: "Guest", targetId: guestId, metadata: { points: amount, reason } });

  res.json({ guest: { id: updated.id, loyaltyPoints: updated.loyaltyPoints, lifetimePoints: updated.lifetimePoints, tier: loyaltyTierForLifetimePoints(updated.lifetimePoints) } });
});

// =============================================================================
// ERROR HANDLER  (was middleware/errorHandler.js — Batch 1 version, includes
// the Multer check that the event/room-type image upload routes need)
// =============================================================================

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  console.error(err);

  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }

  // ── DB connection / init failures — previously fell through silently
  // to a generic 500. Surface them distinctly so a bad DATABASE_URL,
  // Neon cold-start timeout, or network block doesn't look like an app bug. ──
  if (
    err instanceof Prisma.PrismaClientInitializationError ||
    err instanceof Prisma.PrismaClientUnknownRequestError ||
    err.code === "P1001" ||
    err.code === "P1002" ||
    err.code === "P1017"
  ) {
    console.error("[DB CONNECTION FAILURE]", { code: err.code, message: err.message });
    return res.status(503).json({
      error: "Database is unreachable right now — please retry shortly.",
      ...(process.env.NODE_ENV !== "production" ? { detail: err.message, code: err.code } : {}),
    });
  }

  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    if (err.code === "P2010" || err.message.includes("no_overlapping_bookings")) {
      return res.status(409).json({ error: "This room is already booked for the selected dates." });
    }
    if (err.code === "P2002") {
      return res.status(409).json({ error: `Duplicate value for: ${err.meta?.target?.join(", ") || "unique field"}` });
    }
    if (err.code === "P2025") {
      return res.status(404).json({ error: "Record not found" });
    }
  }

  const status = err.status || 500;
  res.status(status).json({ error: err.publicMessage || "Something went wrong on our end." });
}

// =============================================================================
// APP WIRING  (was app.js)
// =============================================================================

const app = express();

// allowedOrigins is shared with the Socket.IO server further down, so both
// layers agree on who's allowed in. Comma-separated env var, e.g.
// "https://oxygenhotel.com,https://admin.oxygenhotel.com". Falls back to
// "*" only if unset, so nothing breaks before you set it — set it before
// production.
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",").map((o) => o.trim()) : "*";

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }, // needed for Cloudinary-hosted images
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      // Every public page (index.html, location.html, blog.html, etc.) is
      // deliberately self-contained — inline <style> and <script>, no
      // external .css/.js files. Helmet's default CSP blocks inline
      // script/style entirely, which would silently break every page the
      // moment static serving goes live below. This directive is what
      // lets that self-contained-file convention actually work in prod.
      "script-src": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      "font-src": ["'self'", "https://fonts.gstatic.com", "data:"],
      "img-src": ["'self'", "data:", "https:"], // Cloudinary-hosted branch/room photos
    },
  },
}));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // Postman, curl, server-to-server, mobile apps
    if (allowedOrigins === "*" || allowedOrigins.includes(origin)) return callback(null, true);
    if (/^https?:\/\/localhost(:\d+)?$/.test(origin)) return callback(null, true); // local dev
    if (/^https:\/\/[a-z0-9-]+\.netlify\.app$/.test(origin)) return callback(null, true); // Netlify deploy previews
    callback(new Error(`CORS: origin not allowed: ${origin}`));
  },
  credentials: true,
}));
app.use(compression());
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 })); // general fallback for everything

app.use("/api/payments", paymentRoutes);

app.use(express.json());

// =============================================================================
// PUBLIC SITE — static HTML (index.html, about.html, blog.html, contact.html,
// location.html) + their inline CSS/JS. Adjust "public" below to match
// wherever these files actually live relative to server.js.
// =============================================================================
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// =============================================================================
// MAINTENANCE MODE — checked on every request after this point. Admin
// routes and a short allowlist stay reachable so the Director can turn
// maintenance mode back OFF without needing direct database access.
// =============================================================================

// /api/director and /api/manager are back-office tooling, not the public
// site — they belong in the bypass for the same reason /api/admin does.
// Missing this previously meant flipping maintenanceMode ON locked every
// Director/Manager out of the ENTIRE admin/manager API, including the one
// route (/api/director/settings/maintenance/toggle) that turns it back
// off — a full self-lockout recoverable only via direct DB access.
const MAINTENANCE_BYPASS_PREFIXES = ["/api/admin", "/api/auth", "/api/director", "/api/manager", "/health"];

app.use(async (req, res, next) => {
  if (MAINTENANCE_BYPASS_PREFIXES.some((prefix) => req.path.startsWith(prefix))) {
    return next();
  }

  let settings;
  try {
    settings = await getSettings();
  } catch (err) {
    // Fail OPEN, not silently hung. A settings-read hiccup (e.g. a DB cold
    // start) should not take down every public/guest route on the site —
    // that's a worse outcome than briefly skipping the maintenance check.
    console.error("[maintenance check] getSettings() failed, allowing request through:", err.message);
    return next();
  }

  if (!settings.maintenanceMode) return next();

  // A Director can still browse the live site during maintenance with
  // ?bypass=<token> or an X-Bypass-Token header, matching the token they
  // set via PATCH /api/admin/settings.
  const bypassToken = req.query.bypass || req.headers["x-bypass-token"];
  const bypassGranted =
    bypassToken && settings.maintenanceBypassToken && bypassToken === settings.maintenanceBypassToken;
  if (bypassGranted) return next();

  res.status(503).json({
    maintenance: true,
    title: settings.maintenanceTitle,
    message: settings.maintenanceMessage,
    eta: settings.maintenanceETA || "",
  });
});

app.get("/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));

app.get("/health/detailed", async (req, res) => {
  const checks = { database: "unknown" };
  let healthy = true;

  try {
    await prisma.$queryRaw`SELECT 1`;
    checks.database = "ok";
  } catch (err) {
    checks.database = "unreachable";
    healthy = false;
  }

  res.status(healthy ? 200 : 503).json({
    status: healthy ? "ok" : "degraded",
    time: new Date().toISOString(),
    uptime: process.uptime(),
    checks,
  });
});

app.use("/api/auth", authRoutes);      // director/login, manager/login, staff/login, guest/register, guest/login, shared login/2fa
app.use("/api/admin", adminRoutes);
app.use("/api/guest", guestRoutes);    // logged-in guest: profile, preferences, bookings
app.use("/api", publicRoutes);         // /api/branches, room-types, availability, bookings, events, orders, tickets
app.use("/api/director", directorRoutes); // director-only: settings, branches, company overview, corporate accounts
app.use("/api/manager", managerRoutes);   // branch-scoped: rooms, bookings, stock, events, staff, tickets, orders, etc. — Director still passes every check here too

app.use((req, res) => res.status(404).json({ error: "Route not found" }));
app.use(errorHandler);

// =============================================================================
// SERVER BOOTSTRAP  (was server.js)
// =============================================================================

const PORT = process.env.PORT || 4000;

const server = http.createServer(app);

const ioServer = new Server(server, { cors: { origin: allowedOrigins } });

setIO(ioServer);
initSocketHandlers(ioServer);

server.listen(PORT, () => console.log(`Uyeh Hotel backend (HTTP + WebSocket) running on port ${PORT}`));

// =============================================================================
// GRACEFUL SHUTDOWN + CRASH HANDLING
// =============================================================================

let _shuttingDown = false;

async function shutdown(signal) {
  if (_shuttingDown) return;
  _shuttingDown = true;
  console.log(`\n${signal} received — shutting down gracefully...`);

  const forceExit = setTimeout(() => {
    console.error("⚠️  Shutdown timed out after 15s — forcing exit");
    process.exit(1);
  }, 15_000);

  try {
    await new Promise((resolve) => server.close(resolve)); // stop accepting new connections, finish in-flight ones
    ioServer.close();
    await prisma.$disconnect();
    clearTimeout(forceExit);
    console.log("✅ Shutdown complete");
    process.exit(0);
  } catch (err) {
    console.error("❌ Error during shutdown:", err.message);
    clearTimeout(forceExit);
    process.exit(1);
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM")); // sent by Render on redeploy/restart
process.on("SIGINT", () => shutdown("SIGINT"));   // Ctrl+C locally

process.on("uncaughtException", (err) => {
  console.error("❌ Uncaught exception:", err);
  shutdown("uncaughtException");
});
process.on("unhandledRejection", (reason) => {
  // express-async-errors already routes rejected route handlers to
  // errorHandler — this only catches rejections outside the request cycle
  // (e.g. a stray unawaited promise), so log rather than crash.
  console.error("❌ Unhandled promise rejection:", reason);
});

module.exports = app;