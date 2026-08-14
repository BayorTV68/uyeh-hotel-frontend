
require("dotenv").config();

require("express-async-errors");
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

// ---- Internal (Director/Manager/Staff) ----

async function sendManagerWelcome({ email, name, branchName, tempPassword }) {
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
    socket.data.user = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    // Bad/expired token on a socket that might just be an anonymous guest
    // who happened to send garbage — don't hard-fail the connection.
    socket.data.user = null;
  }
  next();
}

/**
 * Connection model:
 *  - Staff/Director connect WITH a JWT (same token as REST). If the staff
 *    member holds "handle_tickets", they're auto-joined to their branch's
 *    support room, so new tickets and messages appear live on their
 *    dashboard without polling.
 *  - Guests connect WITHOUT a token most of the time (guest checkout has
 *    no account). They explicitly join one ticket's room via `join_ticket`,
 *    proving ownership either with a guest JWT (if they have an account)
 *    or by matching the email they used when the ticket was created.
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

    if (user?.type === "staff" && (user.permissions || []).includes("handle_tickets")) {
      socket.join(branchSupportRoom(user.branchId));
    }

    /** Staff or a logged-in/anonymous guest joins one ticket's room.
     * payload: { ticketId, guestEmail? } — guestEmail required only for
     * anonymous guest checkout, to prove they own that ticket. */
    socket.on("join_ticket", async ({ ticketId, guestEmail }, ack) => {
      try {
        const ticket = await prisma.ticket.findUnique({ where: { id: ticketId }, include: { guest: true } });
        if (!ticket) return ack?.({ ok: false, error: "Ticket not found" });

        if (user?.type === "staff") {
          if (user.branchId !== ticket.branchId) return ack?.({ ok: false, error: "Not your branch" });
        } else if (user?.type === "guest") {
          if (user.id !== ticket.guestId) return ack?.({ ok: false, error: "Not your ticket" });
        } else {
          // Anonymous guest checkout — verify by email match.
          if (!guestEmail || guestEmail.toLowerCase() !== ticket.guest.email.toLowerCase()) {
            return ack?.({ ok: false, error: "Email does not match this ticket" });
          }
        }

        socket.join(ticketRoom(ticketId));
        ack?.({ ok: true });
      } catch (err) {
        ack?.({ ok: false, error: "Could not join ticket" });
      }
    });

    /** A guest sends a chat message directly over the socket (faster than
     * a REST round trip for an open chat window). Still persisted to the
     * DB here, same as the REST reply path, before broadcasting. */
    socket.on("guest_message", async ({ ticketId, message, guestEmail }, ack) => {
      if (!message || !message.trim()) return ack?.({ ok: false, error: "Empty message" });

      try {
        const ticket = await prisma.ticket.findUnique({ where: { id: ticketId }, include: { guest: true } });
        if (!ticket) return ack?.({ ok: false, error: "Ticket not found" });

        const isOwner = user?.type === "guest"
          ? user.id === ticket.guestId
          : guestEmail && guestEmail.toLowerCase() === ticket.guest.email.toLowerCase();
        if (!isOwner) return ack?.({ ok: false, error: "Not authorized for this ticket" });

        const saved = await prisma.ticketMessage.create({
          data: { ticketId, senderType: "GUEST", guestName: ticket.guest.name, message },
        });
        if (ticket.status === "RESOLVED" || ticket.status === "CLOSED") {
          await prisma.ticket.update({ where: { id: ticketId }, data: { status: "IN_PROGRESS" } });
        }

        ioInstance.to(ticketRoom(ticketId)).emit("new_message", saved);
        ioInstance.to(branchSupportRoom(ticket.branchId)).emit("ticket_activity", { ticketId, from: "guest" });
        ack?.({ ok: true, message: saved });
      } catch (err) {
        ack?.({ ok: false, error: "Could not send message" });
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
    return { id: account.id, name: account.name, email: account.email };
  }
  if (type === "manager") {
    return {
      id: account.id, name: account.name, email: account.email,
      roleTitle: account.roleTitle, department: account.department, permissions: account.permissions,
      branchId: account.branchId, branchName: account.branch?.name || null,
    };
  }
  if (type === "staff") {
    return {
      id: account.id, name: account.name, email: account.email, role: account.role,
      roleTitle: account.roleTitle, department: account.department, permissions: account.permissions,
      branchId: account.branchId, branchName: account.branch?.name || null,
    };
  }
  // guest
  return { id: account.id, name: account.name, email: account.email, phone: account.phone, emailVerified: account.emailVerified };
}

/** Issues an access token + a refresh token for a director, manager, staff
 * member, or guest. The refresh token is stored hashed in RefreshToken; the
 * raw value is only ever returned to the client once, here. */
async function issueTokenPair({ subjectType, subject, req }) {
  const fk = REFRESH_FK_BY_TYPE[subjectType];
  if (!fk) throw Object.assign(new Error(`Unknown subjectType: ${subjectType}`), { status: 500 });

  const payload = { id: subject.id, type: subjectType };
  if (subjectType === "manager" || subjectType === "staff") payload.branchId = subject.branchId;
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
  await resend.emails.send({
    from: process.env.EMAIL_FROM || "Oxygen Hotel <no-reply@oxygenhotel.com>",
    to: email,
    subject: "Reset your password",
    html: `<p>Hi ${name},</p><p>Click below to reset your password. This link expires in 1 hour.</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>If you didn't request this, you can ignore this email.</p>`,
  });
}
async function sendVerificationEmail({ email, name, verifyUrl }) {
  await resend.emails.send({
    from: process.env.EMAIL_FROM || "Oxygen Hotel <no-reply@oxygenhotel.com>",
    to: email,
    subject: "Verify your email",
    html: `<p>Hi ${name},</p><p>Please confirm your email address:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p><p>This link expires in 24 hours.</p>`,
  });
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
    if (req.user.type === "director") return next();
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
  const { checkIn, checkOut, roomTypeId } = req.query;
  if (!checkIn || !checkOut) return res.status(400).json({ error: "checkIn and checkOut are required (YYYY-MM-DD)" });

  const start = new Date(checkIn);
  const end = new Date(checkOut);
  if (!(start < end)) return res.status(400).json({ error: "checkOut must be after checkIn" });

  const rooms = await prisma.room.findMany({
    where: {
      branchId, status: "ACTIVE",
      ...(roomTypeId ? { roomTypeId } : {}),
      bookings: { none: { status: { in: ACTIVE_BOOKING_STATUSES }, AND: [{ checkIn: { lt: end } }, { checkOut: { gt: start } }] } },
    },
    include: { roomType: true },
  });

  res.json({ checkIn, checkOut, availableRooms: rooms });
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

  const room = await prisma.room.findFirst({ where: { id: roomId, branchId }, include: { roomType: true } });
  if (!room) return res.status(404).json({ error: "Room not found at this branch" });

  const conflict = await prisma.booking.findFirst({
    where: { roomId, status: { in: ACTIVE_BOOKING_STATUSES }, checkIn: { lt: end }, checkOut: { gt: start } },
  });
  if (conflict) return res.status(409).json({ error: "This room is already booked for the selected dates." });

  const nights = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
  let totalAmount = Number(room.roomType.basePrice) * nights;

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
        status: "PENDING", totalAmount, currency: room.roomType.currency,
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

  const branch = await prisma.branch.findUnique({ where: { id: branchId } });
  sendBookingConfirmation({
    guestEmail: result.guestRecord.email,
    guestName: result.guestRecord.name,
    branchName: branch.name,
    roomTypeName: room.roomType.name,
    roomNumber: room.roomNumber,
    checkIn: start,
    checkOut: end,
    totalAmount,
    currency: room.roomType.currency,
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

async function listBranchBookings(req, res) {
  const branchId = resolveBranchScope(req);
  const { status } = req.query;
  const bookings = await prisma.booking.findMany({
    where: { ...(branchId ? { branchId } : {}), ...(status ? { status } : {}) },
    include: { room: { include: { roomType: true } }, guest: true, payment: true, branch: true },
    orderBy: { checkIn: "asc" },
  });
  res.json({ bookings });
}

const VALID_BOOKING_STATUSES = ["PENDING", "CONFIRMED", "CHECKED_IN", "CHECKED_OUT", "CANCELLED"];

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
    include: { guest: true, branch: true, room: { include: { roomType: true } } },
  });

  if (["CONFIRMED", "CHECKED_IN", "CHECKED_OUT", "CANCELLED"].includes(status)) {
    sendBookingStatusUpdate({
      guestEmail: booking.guest.email,
      guestName: booking.guest.name,
      branchName: booking.branch.name,
      status,
      roomTypeName: booking.room.roomType.name,
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
  const items = await prisma.menuItem.findMany({
    where: { branchId, isAvailable: true, ...(category ? { category } : {}) },
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
  const { name, price, currency, turnaroundHours } = req.body;
  if (!name || price === undefined) return res.status(400).json({ error: "name and price are required" });

  const item = await prisma.laundryItem.create({
    data: { branchId, name, price, currency: currency || "NGN", turnaroundHours: turnaroundHours || 24 },
  });
  res.status(201).json({ laundryItem: item });
}

async function listLaundryItems(req, res) {
  const branchId = req.params.branchId || resolveBranchScope(req);
  const items = await prisma.laundryItem.findMany({ where: { branchId, isAvailable: true }, orderBy: { name: "asc" } });
  res.json({ laundryItems: items });
}

async function updateLaundryItem(req, res) {
  const { id } = req.params;
  const { name, price, currency, turnaroundHours, isAvailable } = req.body;
  const item = await prisma.laundryItem.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
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
  const treatments = await prisma.spaTreatment.findMany({ where: { branchId, isAvailable: true }, orderBy: { name: "asc" } });
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

const VALID_ORDER_TYPES = ["ROOM_SERVICE", "RESTAURANT", "EVENT_TICKET", "SPA", "LAUNDRY", "OTHER"];

// Which Branch.services entry each order type requires. OTHER has no
// mapping — it's the deliberate catch-all and stays ungated.
const ORDER_TYPE_SERVICE = {
  ROOM_SERVICE: "room_service",
  RESTAURANT: "restaurant",
  BAR: "bar",
  EVENT_TICKET: "events",
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

    totalAmount = event.price ? Number(event.price) * quantity : 0;
    currency = event.currency;
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

  res.status(201).json({ ticket });
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
  res.json({ tickets });
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
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "message is required" });

  const ticket = await prisma.ticket.findFirst({ where: { id, ...(branchId ? { branchId } : {}) }, include: { guest: true, branch: true } });
  if (!ticket) return res.status(404).json({ error: "Ticket not found at this branch" });

  const senderType = req.user.type.toUpperCase(); // "DIRECTOR" | "MANAGER" | "STAFF"
  const senderFkField = { DIRECTOR: "directorId", MANAGER: "managerId", STAFF: "staffId" }[senderType];
  const senderModel = { DIRECTOR: "director", MANAGER: "manager", STAFF: "staff" }[senderType];
  const sender = await prisma[senderModel].findUnique({ where: { id: req.user.id } });

  const ticketMessage = await prisma.ticketMessage.create({
    data: { ticketId: id, senderType, [senderFkField]: req.user.id, message },
  });

  sendTicketReply({
    guestEmail: ticket.guest.email,
    guestName: ticket.guest.name,
    branchName: ticket.branch.name,
    subject: ticket.subject,
    message,
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

async function createEvent(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "branchId is required (Director must pass ?branchId=)" });
  const { name, description, startsAt, endsAt, capacity, price, currency, images } = req.body;
  if (!name || !startsAt) return res.status(400).json({ error: "name and startsAt are required" });

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
  res.json({ event: updated });
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
  const isDirector = req.user.role === "DIRECTOR";
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
  const isDirector = req.user.role === "DIRECTOR";
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
  const roomRecords = await prisma.room.findMany({ where: { id: { in: roomIds }, branchId, status: "ACTIVE" }, include: { roomType: true } });
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
      const rawTotal = Number(room.roomType.basePrice) * nights;
      const totalAmount = discountPercent ? Math.round(rawTotal * (1 - discountPercent / 100) * 100) / 100 : rawTotal;
      const booking = await tx.booking.create({
        data: {
          branchId, roomId: r.roomId, guestId, checkIn: start, checkOut: end,
          guestsCount: r.guestsCount || 1, status: "PENDING", totalAmount, currency: room.roomType.currency,
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
    include: { bookings: { include: { room: { include: { roomType: true } } } }, corporateAccount: true, contactGuest: true },
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
    include: { branch: { select: { name: true, slug: true } }, roomType: true, event: true },
    orderBy: { createdAt: "desc" },
  });
  res.json({ wishlist: items });
}

async function addWishlistItem(req, res) {
  const { branchId, roomTypeId, eventId } = req.body;
  if (!branchId || (!roomTypeId && !eventId)) {
    return res.status(400).json({ error: "branchId and exactly one of roomTypeId/eventId are required" });
  }
  const item = await prisma.wishlistItem.create({
    data: { guestId: req.user.id, branchId, roomTypeId: roomTypeId || null, eventId: eventId || null },
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
      include: { guest: true, branch: true, room: { include: { roomType: true } } },
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
    roomTypeName: result.booking.room.roomType.name,
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

/** Shared by the public site (branchId in the URL) and the admin panel
 * (branchId from the logged-in staff member's token) — whichever is present
 * wins, public callers never have req.user so it falls through to params. */
async function listRoomTypes(req, res) {
  const branchId = req.params.branchId || resolveBranchScope(req);
  const roomTypes = await prisma.roomType.findMany({
    where: branchId ? { branchId } : {},
    include: { rooms: { select: { id: true, roomNumber: true, status: true } } },
    orderBy: { name: "asc" },
  });
  res.json({ roomTypes });
}

async function createRoomType(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "branchId is required (Director must pass ?branchId=)" });
  const { name, description, basePrice, currency, maxOccupancy, amenities } = req.body;
  if (!name || basePrice === undefined) return res.status(400).json({ error: "name and basePrice are required" });

  const roomType = await prisma.roomType.create({
    data: { branchId, name, description, basePrice, currency: currency || "NGN", maxOccupancy: maxOccupancy || 2, amenities: amenities || [] },
  });
  res.status(201).json({ roomType });
}

async function updateRoomType(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const existing = await prisma.roomType.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!existing) return res.status(404).json({ error: "Room type not found at this branch" });

  const { name, description, basePrice, currency, maxOccupancy, amenities } = req.body;
  const roomType = await prisma.roomType.update({
    where: { id },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(description !== undefined ? { description } : {}),
      ...(basePrice !== undefined ? { basePrice } : {}),
      ...(currency !== undefined ? { currency } : {}),
      ...(maxOccupancy !== undefined ? { maxOccupancy } : {}),
      ...(amenities !== undefined ? { amenities } : {}),
    },
  });
  res.json({ roomType });
}

async function uploadRoomTypeImage(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  if (!req.file) return res.status(400).json({ error: "No image file provided (field name: image)" });

  const roomType = await prisma.roomType.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!roomType) return res.status(404).json({ error: "Room type not found at this branch" });

  const url = await uploadBuffer(req.file.buffer, "Uyeh-hotel/room-types");
  const updated = await prisma.roomType.update({ where: { id }, data: { images: [...roomType.images, url] } });
  res.status(201).json({ roomType: updated, uploadedUrl: url });
}

async function deleteRoomTypeImage(req, res) {
  const branchId = resolveBranchScope(req);
  const { id } = req.params;
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "url is required" });

  const roomType = await prisma.roomType.findFirst({ where: { id, ...(branchId ? { branchId } : {}) } });
  if (!roomType) return res.status(404).json({ error: "Room type not found at this branch" });

  const updated = await prisma.roomType.update({ where: { id }, data: { images: roomType.images.filter((img) => img !== url) } });
  res.json({ roomType: updated });
}

async function createRoom(req, res) {
  const branchId = resolveBranchScope(req);
  if (!branchId) return res.status(400).json({ error: "branchId is required (Director must pass ?branchId=)" });
  const { roomTypeId, roomNumber, floor } = req.body;
  if (!roomTypeId || !roomNumber) return res.status(400).json({ error: "roomTypeId and roomNumber are required" });

  const roomType = await prisma.roomType.findFirst({ where: { id: roomTypeId, branchId } });
  if (!roomType) return res.status(400).json({ error: "That room type does not belong to this branch" });

  const room = await prisma.room.create({ data: { branchId, roomTypeId, roomNumber, floor } });
  res.status(201).json({ room });
}

async function listRooms(req, res) {
  const branchId = resolveBranchScope(req);
  const rooms = await prisma.room.findMany({
    where: branchId ? { branchId } : {},
    include: { roomType: true },
    orderBy: { roomNumber: "asc" },
  });
  res.json({ rooms });
}

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
  const { name, email, password, branchId, roleTitle, department, permissions } = req.body;
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
    data: { name, email, passwordHash, roleTitle, department, permissions: permissions || [], branchId, createdByDirectorId: req.user.id },
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

// =============================================================================
// CONTROLLERS: STAFF (Manager creates; Director + permitted Manager manage)
// =============================================================================

// Single source of truth for what a department "means" in permission terms.
// Purely organizational — a department suggests which permissions a role
// typically needs so the create-staff UI can group checkboxes sensibly, but
// it never restricts what a Manager actually grants. Add a new department
// here and it's immediately available everywhere — no other file to touch.
const DEPARTMENT_CATALOG = {
  "Front Desk": ["manage_bookings", "manage_rooms", "handle_tickets"],
  "Housekeeping": ["manage_rooms"],
  "Stock & Inventory": ["manage_stock"],
  "Restaurant & Bar": ["manage_menu", "manage_bookings"],
  "Events": ["manage_events"],
  "Spa": ["manage_spa"],
  "Laundry": ["manage_laundry"],
  "Guest Support": ["handle_tickets"],
  "Reviews & Marketing": ["manage_reviews", "manage_promos"],
  "Security": ["manage_security"],
  "Branch Administration": ["manage_staff", "manage_settings", "view_reports", "manage_bookings", "manage_rooms", "manage_stock", "manage_events"],
};

/** Lets the Manager/Director "create staff" screen render permission
 * checkboxes grouped by department instead of a flat undocumented list. */
function listDepartmentCatalog(req, res) {
  res.json({ departments: DEPARTMENT_CATALOG });
}

async function createStaffMember(req, res) {
  const { name, email, password, roleTitle, department, permissions } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "name, email, and password are required" });
  if (!permissions || !Array.isArray(permissions) || !permissions.length) {
    return res.status(400).json({ error: "permissions is required — assign at least one duty for this staff member" });
  }
  if (department !== undefined && department !== null && !DEPARTMENT_CATALOG[department]) {
    return res.status(400).json({ error: `Unknown department. Choose one of: ${Object.keys(DEPARTMENT_CATALOG).join(", ")}` });
  }

  // Always the creating manager's own branch — never taken from the request body.
  const branchId = req.user.branchId;

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
      id: true, checkIn: true, checkOut: true, status: true,
      guest: { select: { name: true, phone: true } },
      room: { select: { roomNumber: true } },
    },
    take: 20,
    orderBy: { checkIn: "desc" },
  });

  res.json({
    results: bookings.map((b) => ({
      bookingId: b.id,
      guestName: b.guest.name,
      guestPhone: b.guest.phone,
      roomNumber: b.room.roomNumber,
      checkIn: b.checkIn,
      checkOut: b.checkOut,
      status: b.status,
    })),
  });
}

// =============================================================================
// ROUTES: PAYMENTS  (was routes/paymentRoutes.js)
// =============================================================================

const paymentRoutes = express.Router();

// Paystack signs the RAW body, so this route uses express.raw() instead of
// the global express.json() — must be mounted BEFORE express.json() below.
paymentRoutes.post("/paystack/webhook", express.raw({ type: "application/json" }), paystackWebhook);

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

// Company-wide: list active branches (for a "choose your branch" picker)
publicRoutes.get("/branches", async (req, res) => {
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
publicRoutes.get("/branches/:branchId/room-types", requireBranchService("rooms"), listRoomTypes);
publicRoutes.get("/branches/:branchId/availability", requireBranchService("rooms"), checkAvailability);
publicRoutes.post("/branches/:branchId/bookings", requireBranchService("rooms"), createBooking);
publicRoutes.post("/branches/:branchId/bookings/:id/initiate-payment", initiateBookingPayment);
publicRoutes.get("/branches/:branchId/events", requireBranchService("events"), listEvents);
publicRoutes.post("/branches/:branchId/orders", createOrder); // type-dependent — checked inside the controller
publicRoutes.post("/branches/:branchId/orders/:id/initiate-payment", initiateOrderPayment);
publicRoutes.post("/branches/:branchId/tickets", createTicket); // support ticketing isn't a toggleable service — always available

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

publicRoutes.patch("/branches/:branchId/bookings/:id/cancel", async (req, res) => {
  const { branchId, id } = req.params;
  const { email } = req.body;

  const booking = await prisma.booking.findFirst({ where: { id, branchId }, include: { guest: true } });
  if (!booking) return res.status(404).json({ error: "Booking not found" });

  const isOwner = req.user?.type === "guest"
    ? req.user.id === booking.guestId
    : email && email.toLowerCase() === booking.guest.email.toLowerCase();
  if (!isOwner) return res.status(403).json({ error: "Provide the email used to make this booking" });

  if (["CHECKED_IN", "CHECKED_OUT", "CANCELLED"].includes(booking.status)) {
    return res.status(409).json({ error: `Booking is already ${booking.status} and cannot be cancelled` });
  }

  const updated = await prisma.booking.update({ where: { id }, data: { status: "CANCELLED" } });
  res.json({ booking: updated });
});

// Catalogs — public browsing
publicRoutes.get("/branches/:branchId/menu", requireBranchService("restaurant"), listMenuItems);
publicRoutes.get("/branches/:branchId/bar-menu", requireBranchService("bar"), (req, res) => { req.query.category = "DRINK"; return listMenuItems(req, res); });
publicRoutes.get("/branches/:branchId/spa-treatments", requireBranchService("spa"), listSpaTreatments);
publicRoutes.get("/branches/:branchId/laundry-items", requireBranchService("laundry"), listLaundryItems);

// Reviews — public, published only
publicRoutes.get("/branches/:branchId/reviews", listPublishedReviews);

// Group / corporate bookings
publicRoutes.post("/branches/:branchId/group-bookings", requireBranchService("rooms"), createGroupBookingPublic);

// =============================================================================
// ROUTES: AUTH  (was routes/authRoutes.js)
// =============================================================================

// =============================================================================
// routes/authRoutes.js — real implementation (staff login only; guest
// register/login is still routes/guestRoutes.js, not yet provided)
// =============================================================================

const authRoutes = express.Router();

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
authRoutes.post("/director/login", makeStaffLikeLoginHandler({ type: "director" }));
authRoutes.post("/manager/login", makeStaffLikeLoginHandler({ type: "manager", include: { branch: true } }));
authRoutes.post("/staff/login", makeStaffLikeLoginHandler({ type: "staff", include: { branch: true } }));

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
  await sendVerificationEmail({ email: guest.email, name: guest.name, verifyUrl });
  res.json({ message: "Verification email sent" });
});

authRoutes.post("/guest/login", async (req, res) => {
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

authRoutes.post("/guest/login/2fa", async (req, res) => {
  const { tempToken, code } = req.body;
  if (!tempToken || !code) return res.status(400).json({ error: "tempToken and code are required" });

  let payload;
  try { payload = jwt.verify(tempToken, jwtSecret()); } catch { return res.status(401).json({ error: "2FA session expired — log in again" }); }
  if (payload.type !== "guest" || payload.purpose !== "2fa_pending") return res.status(401).json({ error: "Invalid session" });

  const guest = await prisma.guest.findUnique({ where: { id: payload.id } });
  if (!guest) return res.status(401).json({ error: "Account not found" });

  const result = await verifyTwoFactorCode({ model: prisma.guest, account: guest, code });
  if (!result.ok) {
    return res.status(result.locked ? 423 : 401).json({ error: result.locked ? "Too many failed codes — try again in 15 minutes" : "Invalid code" });
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

authRoutes.post("/director/forgot-password", makeForgotPasswordHandler("director"));
authRoutes.post("/director/reset-password", makeResetPasswordHandler("director"));
authRoutes.post("/manager/forgot-password", makeForgotPasswordHandler("manager"));
authRoutes.post("/manager/reset-password", makeResetPasswordHandler("manager"));
authRoutes.post("/staff/forgot-password", makeForgotPasswordHandler("staff"));
authRoutes.post("/staff/reset-password", makeResetPasswordHandler("staff"));
authRoutes.post("/guest/forgot-password", makeForgotPasswordHandler("guest", { isEligible: (a) => !!a.passwordHash }));
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
    include: { room: { include: { roomType: true } }, branch: true, payment: true },
    orderBy: { checkIn: "desc" },
  });
  res.json({ bookings: bookings.map((b) => ({ ...b, branchName: b.branch.name })) });
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

guestRoutes.get("/orders", async (req, res) => {
  const orders = await prisma.order.findMany({
    where: { guestId: req.user.id },
    include: { branch: true, event: true },
    orderBy: { createdAt: "desc" },
  });
  res.json({ orders: orders.map((o) => ({ ...o, branchName: o.branch.name })) });
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
    // Brand colors
    "primaryColor", "secondaryColor", "accentColor",
    // Business hours
    "checkInTime", "checkOutTime",
    // Currency
    "baseCurrency",
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
directorRoutes.get("/branches", requireDirector, async (req, res) => {
  const branches = await prisma.branch.findMany({ orderBy: { name: "asc" } });
  res.json({ branches });
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

// Company-wide rollup — Director only
directorRoutes.get("/company/overview", requireDirector, async (req, res) => {
  const [branchCount, managerCount, staffCount, openTickets, bookingsThisMonth] = await Promise.all([
    prisma.branch.count({ where: { isActive: true } }),
    prisma.manager.count({ where: { isActive: true } }),
    prisma.staff.count({ where: { isActive: true } }),
    prisma.ticket.count({ where: { status: { in: ["OPEN", "IN_PROGRESS"] } } }),
    prisma.booking.findMany({
      where: { createdAt: { gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1) }, status: { not: "CANCELLED" } },
      select: { totalAmount: true },
    }),
  ]);
  const revenueThisMonth = bookingsThisMonth.reduce((sum, b) => sum + Number(b.totalAmount), 0);
res.json({ overview: { branchCount, managerCount, staffCount, openTickets, revenueThisMonth, bookingsThisMonth: bookingsThisMonth.length } });
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

directorRoutes.get("/paystack/banks", requireDirector, getPaystackBankList);
directorRoutes.post("/paystack/verify-account", requireDirector, verifyBranchPayoutAccount);
directorRoutes.post("/branches/:id/payout-account", requireDirector, setBranchPayoutAccount);
// =============================================================================
// ROUTES: MANAGER  (branch-scoped — open to Manager + Staff per permission;
// Director still passes every check here too, via requireBranchAccess's
// built-in Director bypass, for company-wide oversight)
// =============================================================================

const managerRoutes = express.Router();
// Rooms
managerRoutes.get("/room-types", requireBranchAccess("manage_rooms"), listRoomTypes);
managerRoutes.post("/room-types", requireBranchAccess("manage_rooms"), createRoomType);
managerRoutes.patch("/room-types/:id", requireBranchAccess("manage_rooms"), updateRoomType);
managerRoutes.post("/room-types/:id/images", requireBranchAccess("manage_rooms"), upload.single("image"), uploadRoomTypeImage);
managerRoutes.delete("/room-types/:id/images", requireBranchAccess("manage_rooms"), deleteRoomTypeImage);
managerRoutes.get("/rooms", requireBranchAccess("manage_rooms"), listRooms);
managerRoutes.post("/rooms", requireBranchAccess("manage_rooms"), createRoom);
managerRoutes.patch("/rooms/:id/status", requireBranchAccess("manage_rooms"), updateRoomStatus);

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
managerRoutes.patch("/orders/:id/status", requireBranchAccess("manage_bookings"), updateOrderStatus);

// Menu (restaurant + bar catalog)
managerRoutes.get("/menu", requireBranchAccess("manage_menu"), listMenuItems);
managerRoutes.post("/menu", requireBranchAccess("manage_menu"), createMenuItem);
managerRoutes.patch("/menu/:id", requireBranchAccess("manage_menu"), updateMenuItem);
managerRoutes.delete("/menu/:id", requireBranchAccess("manage_menu"), deleteMenuItem);

// Laundry price list
managerRoutes.get("/laundry-items", requireBranchAccess("manage_laundry"), listLaundryItems);
managerRoutes.post("/laundry-items", requireBranchAccess("manage_laundry"), createLaundryItem);
managerRoutes.patch("/laundry-items/:id", requireBranchAccess("manage_laundry"), updateLaundryItem);
managerRoutes.delete("/laundry-items/:id", requireBranchAccess("manage_laundry"), deleteLaundryItem);

// Spa treatments
managerRoutes.get("/spa-treatments", requireBranchAccess("manage_spa"), listSpaTreatments);
managerRoutes.post("/spa-treatments", requireBranchAccess("manage_spa"), createSpaTreatment);
managerRoutes.patch("/spa-treatments/:id", requireBranchAccess("manage_spa"), updateSpaTreatment);
managerRoutes.delete("/spa-treatments/:id", requireBranchAccess("manage_spa"), deleteSpaTreatment);

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

// Branch settings
managerRoutes.get("/branch-settings", requireBranchAccess("manage_settings"), getBranchSettings);
managerRoutes.patch("/branch-settings", requireBranchAccess("manage_settings"), updateBranchSettings);

// Reports
managerRoutes.get("/reports", requireBranchAccess("view_reports"), getBranchReports);

// Security — guest/stay verification
managerRoutes.get("/guest-lookup", requireBranchAccess("manage_security"), guestLookup);

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

app.use(helmet());
app.use(cors());
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));

app.use("/api/payments", paymentRoutes);

app.use(express.json());

// =============================================================================
// MAINTENANCE MODE — checked on every request after this point. Admin
// routes and a short allowlist stay reachable so the Director can turn
// maintenance mode back OFF without needing direct database access.
// =============================================================================

const MAINTENANCE_BYPASS_PREFIXES = ["/api/admin", "/api/auth", "/health"];

app.use(async (req, res, next) => {
  if (MAINTENANCE_BYPASS_PREFIXES.some((prefix) => req.path.startsWith(prefix))) {
    return next();
  }

  const settings = await getSettings();
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
const ioServer = new Server(server, { cors: { origin: "*" } }); // tighten to your frontend domain(s) before production

setIO(ioServer);
initSocketHandlers(ioServer);

server.listen(PORT, () => console.log(`Uyeh Hotel backend (HTTP + WebSocket) running on port ${PORT}`));

module.exports = app;