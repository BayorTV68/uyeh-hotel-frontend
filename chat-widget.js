/**
 * UYEH HOTEL — Site-wide Live Chat Widget
 *
 * Drop this file on your static host (Netlify, etc.) and add ONE line
 * before </body> on every page you want the widget on:
 *
 *   <script src="/chat-widget.js"></script>
 *
 * Optional per-page branch scoping (a ticket always belongs to one
 * branch on this backend, so tell the widget which one when you know it):
 *
 *   <script src="/chat-widget.js" data-branch-id="THE_BRANCH_ID"></script>
 *
 * If you don't set data-branch-id (e.g. on the homepage), the widget asks
 * the guest to pick a branch in the pre-chat form.
 *
 * Wired to the REAL hotel backend: Socket.IO (not raw WebSocket), ticket
 * access tokens for anonymous guests, and the exact events built in the
 * WebSocket upgrade patch — join_ticket, guest_message, typing_start/stop,
 * mark_read, new_message, messages_read, staff_typing, staff_online/offline.
 * Does NOT invent features the backend can't back (no message edit/delete,
 * no reactions, no threading) — everything here maps to a real endpoint.
 */
(function () {
  "use strict";

  /* ============================================================
     CONFIG — the only block you should need to touch
     ============================================================ */
  const CW_API = "https://YOUR-UYEH-HOTEL-BACKEND.onrender.com"; // same value as index.html's API_BASE
  const CW_EXCLUDE = ["/manager", "/director", "/staff", "/admin", "/login"]; // no guest widget on internal dashboards
  // If your site stores a logged-in GUEST's login token in localStorage under
  // a different key, change this so the widget can auto-skip the pre-chat
  // form for returning logged-in guests. Leave as-is if you don't have this yet.
  const CW_GUEST_TOKEN_KEY = "uyeh_guest_token";

  /* ---- Guards ---- */
  if (CW_EXCLUDE.some((p) => location.pathname.startsWith(p))) return;
  if (document.getElementById("ucw-root")) return; // already injected on this page

  const scriptTag = document.currentScript;
  const configuredBranchId = scriptTag ? scriptTag.getAttribute("data-branch-id") : null;

  /* ============================================================
     STYLES — fully self-contained, prefixed vars/selectors so this
     never collides with the host page's own CSS, even on a page
     that never loaded the main design system.
     ============================================================ */
  const css = `
#ucw-root{--ucw-lagoon:#0E1A18;--ucw-lagoon2:#142622;--ucw-sand:#F1E9D8;--ucw-ink:#1B2422;--ucw-brass:#C9A24B;--ucw-brass2:#E4C77C;--ucw-tide:#2F6E62;--ucw-danger:#B5603F;--ucw-line:rgba(201,162,75,.28);--ucw-line-soft:rgba(27,36,34,.14);font-family:'Sora',-apple-system,Helvetica,Arial,sans-serif;position:fixed;inset:auto 0 0 auto;z-index:99990}
#ucw-fab{position:fixed;right:24px;bottom:24px;z-index:99991;width:58px;height:58px;border-radius:50%;background:var(--ucw-brass);color:var(--ucw-lagoon);border:none;font-size:23px;box-shadow:0 12px 28px rgba(0,0,0,.28);display:flex;align-items:center;justify-content:center;cursor:pointer;transition:transform .15s ease}
#ucw-fab:hover{transform:scale(1.06)}
#ucw-fab .ucw-badge{position:absolute;top:-3px;right:-3px;min-width:18px;height:18px;padding:0 4px;border-radius:9px;background:var(--ucw-danger);color:#fff;font-size:10.5px;font-weight:700;display:none;align-items:center;justify-content:center;border:2px solid var(--ucw-sand)}
#ucw-fab .ucw-badge.show{display:flex}
#ucw-panel{position:fixed;right:24px;bottom:94px;z-index:99991;width:min(368px,calc(100vw - 48px));max-height:min(600px,72vh);background:var(--ucw-sand);color:var(--ucw-ink);border:1px solid var(--ucw-line-soft);box-shadow:0 24px 60px rgba(0,0,0,.32);display:none;flex-direction:column;overflow:hidden;border-radius:3px}
#ucw-panel.ucw-open{display:flex}
#ucw-head{background:var(--ucw-lagoon);color:var(--ucw-sand);padding:14px 16px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
#ucw-head .ucw-title{font-family:'Fraunces',Georgia,serif;font-size:16px}
#ucw-head .ucw-sub{display:flex;align-items:center;gap:6px;font-family:ui-monospace,monospace;font-size:11px;opacity:.65;margin-top:3px}
#ucw-head .ucw-dot{width:6px;height:6px;border-radius:50%;background:#7a7a7a}
#ucw-head .ucw-dot.online{background:#4CAF80}
#ucw-head .ucw-close{background:none;border:none;color:var(--ucw-sand);font-size:18px;opacity:.7;cursor:pointer;padding:4px}
#ucw-head .ucw-close:hover{opacity:1}
#ucw-banner{background:rgba(201,162,75,.14);border-bottom:1px solid var(--ucw-line);padding:7px 14px;font-family:ui-monospace,monospace;font-size:11.5px;color:#8a6c22;text-align:center;display:none}
#ucw-banner.show{display:block}
#ucw-banner.ucw-err{background:rgba(181,96,63,.12);color:var(--ucw-danger)}
#ucw-pre{padding:18px;display:flex;flex-direction:column;gap:11px;overflow-y:auto}
#ucw-pre p{font-size:13px;opacity:.72;margin:0 0 4px;line-height:1.5}
#ucw-pre input,#ucw-pre select{border:1px solid var(--ucw-line-soft);padding:10px 11px;font-size:13.5px;font-family:inherit;background:#fff;color:var(--ucw-ink);border-radius:2px}
#ucw-pre button{background:var(--ucw-ink);color:var(--ucw-sand);border:none;padding:12px;font-size:13.5px;font-weight:600;border-radius:2px;cursor:pointer;transition:background .2s}
#ucw-pre button:hover:not(:disabled){background:var(--ucw-tide)}
#ucw-pre button:disabled{opacity:.5;cursor:not-allowed}
#ucw-body{flex:1;overflow-y:auto;padding:14px;display:none;flex-direction:column;gap:9px;min-height:200px}
#ucw-body.ucw-visible{display:flex}
.ucw-msg{max-width:80%;padding:9px 12px;font-size:13.5px;line-height:1.5;border-radius:3px;word-break:break-word}
.ucw-msg.guest{align-self:flex-end;background:var(--ucw-brass);color:var(--ucw-lagoon)}
.ucw-msg.staff{align-self:flex-start;background:#fff;border:1px solid var(--ucw-line-soft)}
.ucw-msg.system{align-self:center;font-family:ui-monospace,monospace;font-size:11px;opacity:.55;text-align:center}
.ucw-msg img.ucw-attach{max-width:100%;border-radius:2px;margin-top:6px;display:block}
.ucw-meta{display:flex;gap:6px;align-items:center;margin-top:4px;font-family:ui-monospace,monospace;font-size:10px;opacity:.6}
.ucw-msg.guest .ucw-meta{justify-content:flex-end}
.ucw-typing{align-self:flex-start;font-family:ui-monospace,monospace;font-size:11.5px;opacity:.55;font-style:italic}
#ucw-form{display:none;gap:8px;padding:10px;border-top:1px solid var(--ucw-line-soft);background:#fff;flex-shrink:0}
#ucw-form.ucw-visible{display:flex}
#ucw-form input[type=text]{flex:1;border:1px solid var(--ucw-line-soft);padding:10px;font-size:13.5px;font-family:inherit;border-radius:2px}
#ucw-form button{background:var(--ucw-tide);color:#fff;border:none;padding:0 15px;font-size:13px;border-radius:2px;cursor:pointer}
#ucw-attach-btn{background:none;border:1px solid var(--ucw-line-soft);width:38px;border-radius:2px;cursor:pointer;font-size:15px;color:var(--ucw-ink)}
@media (max-width:480px){#ucw-fab{right:16px;bottom:16px}#ucw-panel{right:12px;bottom:84px;width:calc(100vw - 24px)}}
`;
  const styleEl = document.createElement("style");
  styleEl.textContent = css;
  document.head.appendChild(styleEl);

  /* ============================================================
     MARKUP
     ============================================================ */
  const root = document.createElement("div");
  root.id = "ucw-root";
  root.innerHTML = `
    <button id="ucw-fab" aria-label="Chat with us" aria-expanded="false">💬<span class="ucw-badge" id="ucwBadge">0</span></button>
    <div id="ucw-panel" role="dialog" aria-label="Chat with Uyeh Hotel">
      <div id="ucw-head">
        <div>
          <div class="ucw-title">Talk to us</div>
          <div class="ucw-sub"><span class="ucw-dot" id="ucwDot"></span><span id="ucwStatus">Not connected</span></div>
        </div>
        <button class="ucw-close" id="ucwClose" aria-label="Close chat">✕</button>
      </div>
      <div id="ucw-banner"></div>
      <div id="ucw-pre">
        <p>Tell us a bit about yourself and we'll connect you with the right branch.</p>
        <select id="ucwBranch"><option value="">Loading locations…</option></select>
        <input type="text" id="ucwName" placeholder="Your name" />
        <input type="email" id="ucwEmail" placeholder="Your email" />
        <input type="text" id="ucwSubject" placeholder="What's this about?" />
        <button id="ucwStart" type="button">Start chat</button>
      </div>
      <div id="ucw-body"></div>
      <form id="ucw-form">
        <button type="button" id="ucw-attach-btn" aria-label="Attach a file">📎</button>
        <input type="file" id="ucwFile" accept="image/*,application/pdf" style="display:none" />
        <input type="text" id="ucwInput" placeholder="Type a message…" autocomplete="off" />
        <button type="submit">Send</button>
      </form>
    </div>
  `;
  document.body.appendChild(root);

  /* ============================================================
     STATE
     ============================================================ */
  const $ = (id) => document.getElementById(id);
  let socket = null;
  let ticketId = localStorage.getItem("ucw_ticketId") || null;
  let accessToken = localStorage.getItem("ucw_accessToken") || null;
  let branchId = configuredBranchId || localStorage.getItem("ucw_branchId") || null;
  let unread = 0;
  let panelOpen = false;
  let typingTimeout = null;

  function guestLoginToken() {
    return localStorage.getItem(CW_GUEST_TOKEN_KEY);
  }
  function setBanner(text, isErr) {
    const b = $("ucw-banner");
    b.textContent = text;
    b.className = "show" + (isErr ? " ucw-err" : "");
  }
  function clearBanner() { $("ucw-banner").className = ""; }
  function setStatus(text, online) {
    $("ucwStatus").textContent = text;
    $("ucwDot").className = "ucw-dot" + (online ? " online" : "");
  }
  function addMsg(html, kind, isHtml) {
    const div = document.createElement("div");
    div.className = "ucw-msg " + kind;
    if (isHtml) div.innerHTML = html; else div.textContent = html;
    $("ucw-body").appendChild(div);
    $("ucw-body").scrollTop = $("ucw-body").scrollHeight;
    return div;
  }
  function bumpUnread() {
    if (panelOpen) return;
    unread += 1;
    const badge = $("ucwBadge");
    badge.textContent = unread > 9 ? "9+" : String(unread);
    badge.classList.add("show");
  }
  function clearUnread() {
    unread = 0;
    $("ucwBadge").classList.remove("show");
  }

  /* ============================================================
     BRANCH RESOLUTION — a ticket must belong to one branch. If the
     page didn't set data-branch-id, fetch the list and let the guest
     pick (homepage / generic pages).
     ============================================================ */
  function loadBranchPicker() {
    const sel = $("ucwBranch");
    if (branchId) { sel.style.display = "none"; return; }
    fetch(`${CW_API}/api/branches`)
      .then((r) => r.json())
      .then((d) => {
        const branches = d.branches || [];
        sel.innerHTML = branches.length
          ? `<option value="">Choose a location…</option>` + branches.map((b) => `<option value="${b.id}">${b.name}</option>`).join("")
          : `<option value="">No locations available</option>`;
      })
      .catch(() => { sel.innerHTML = `<option value="">Couldn't load locations</option>`; });
  }

  /* ============================================================
     SOCKET.IO — loaded lazily, only once a chat actually starts
     ============================================================ */
  function loadSocketIO(cb) {
    if (window.io) return cb();
    const s = document.createElement("script");
    s.src = "https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js";
    s.onload = cb;
    s.onerror = () => setBanner("Couldn't load chat — please email us instead.", true);
    document.head.appendChild(s);
  }

  function connectSocket(token) {
    setStatus("Connecting…", false);
    socket = window.io(CW_API, {
      auth: { token },
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 8000,
    });

    socket.on("connect", () => {
      setStatus("Online", true);
      clearBanner();
      socket.emit("join_ticket", { ticketId }, (ack) => {
        if (!ack || !ack.ok) setBanner(ack && ack.error ? ack.error : "Couldn't join this chat.", true);
        else if (panelOpen) socket.emit("mark_read", { ticketId });
      });
    });

    socket.on("disconnect", () => setStatus("Reconnecting…", false));
    socket.on("connect_error", () => setBanner("Connection trouble — retrying…", true));

    socket.on("new_message", (msg) => {
      if (msg.senderType === "GUEST") return; // our own sends render optimistically already
      const html = (msg.message ? escapeHtml(msg.message) : "") +
        (msg.attachmentUrl ? (msg.attachmentType === "image"
          ? `<img class="ucw-attach" src="${msg.attachmentUrl}" alt="Attachment" />`
          : `<a href="${msg.attachmentUrl}" target="_blank" rel="noopener">📎 Attachment</a>`) : "");
      addMsg(html, "staff", true);
      bumpUnread();
      if (panelOpen) socket.emit("mark_read", { ticketId });
    });

    socket.on("messages_read", () => {
      document.querySelectorAll(".ucw-msg.guest .ucw-meta").forEach((el) => { el.textContent = "Read"; });
    });

    socket.on("staff_typing", (d) => {
      let t = document.getElementById("ucwTypingRow");
      if (d.typing) {
        if (!t) { t = document.createElement("div"); t.id = "ucwTypingRow"; t.className = "ucw-typing"; t.textContent = "Typing…"; $("ucw-body").appendChild(t); $("ucw-body").scrollTop = $("ucw-body").scrollHeight; }
      } else if (t) { t.remove(); }
    });

    socket.on("staff_online", () => setStatus("Online", true));
    socket.on("staff_offline", () => setStatus("Away", false));
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  /* ============================================================
     STARTING / RESTORING A CHAT
     ============================================================ */
  function showPanelChatView() {
    $("ucw-pre").style.display = "none";
    $("ucw-body").classList.add("ucw-visible");
    $("ucw-form").classList.add("ucw-visible");
  }

  function startChat() {
    const chosenBranch = branchId || $("ucwBranch").value;
    const name = $("ucwName").value.trim();
    const email = $("ucwEmail").value.trim();
    const subject = $("ucwSubject").value.trim() || "Website chat";
    if (!chosenBranch) { setBanner("Please choose a location.", true); return; }
    if (!name || !email) { setBanner("Name and email are required.", true); return; }

    const btn = $("ucwStart");
    btn.disabled = true; btn.textContent = "Starting…";
    clearBanner();

    const loginToken = guestLoginToken();

    fetch(`${CW_API}/api/branches/${chosenBranch}/tickets`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(loginToken ? { Authorization: "Bearer " + loginToken } : {}),
      },
      body: JSON.stringify({ subject, message: "Chat started from the website.", guest: loginToken ? undefined : { name, email } }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (!data.ticket) throw new Error(data.error || "Could not start chat");
        ticketId = data.ticket.id;
        branchId = chosenBranch;
        accessToken = data.accessToken || loginToken;

        localStorage.setItem("ucw_ticketId", ticketId);
        localStorage.setItem("ucw_branchId", branchId);
        if (data.accessToken) localStorage.setItem("ucw_accessToken", data.accessToken);

        showPanelChatView();
        addMsg("You're connected — a team member will join shortly.", "system");
        loadSocketIO(() => connectSocket(accessToken));
      })
      .catch((err) => {
        setBanner(err.message || "Couldn't start chat — please email us instead.", true);
        btn.disabled = false; btn.textContent = "Start chat";
      });
  }

  function restoreChat() {
    showPanelChatView();
    addMsg("Reconnecting to your chat…", "system");
    loadSocketIO(() => connectSocket(accessToken || guestLoginToken()));
  }

  /* ============================================================
     SENDING
     ============================================================ */
  function sendMessage(text, attachmentUrl, attachmentType) {
    if (!socket || !socket.connected) { setBanner("Not connected yet — one moment.", true); return; }
    socket.emit("guest_message", { ticketId, message: text, attachmentUrl, attachmentType }, (ack) => {
      if (ack && ack.ok) {
        const html = (text ? escapeHtml(text) : "") +
          (attachmentUrl ? (attachmentType === "image" ? `<img class="ucw-attach" src="${attachmentUrl}" />` : `<a href="${attachmentUrl}" target="_blank" rel="noopener">📎 Attachment</a>`) : "");
        const el = addMsg(html, "guest", true);
        const meta = document.createElement("div");
        meta.className = "ucw-meta";
        meta.textContent = "Sent";
        el.appendChild(meta);
      } else {
        setBanner((ack && ack.error) || "Message failed to send.", true);
      }
    });
  }

  async function uploadAttachment(file) {
    const fd = new FormData();
    fd.append("file", file);
    const headers = {};
    if (!guestLoginToken()) headers["X-Ticket-Access-Token"] = accessToken || "";
    else headers["Authorization"] = "Bearer " + guestLoginToken();
    const res = await fetch(`${CW_API}/api/branches/${branchId}/tickets/${ticketId}/attachment`, { method: "POST", headers, body: fd });
    if (!res.ok) throw new Error("Upload failed");
    return res.json();
  }

  /* ============================================================
     EVENTS
     ============================================================ */
  $("ucw-fab").addEventListener("click", () => {
    panelOpen = !panelOpen;
    $("ucw-panel").classList.toggle("ucw-open", panelOpen);
    $("ucw-fab").setAttribute("aria-expanded", String(panelOpen));
    if (panelOpen) { clearUnread(); if (socket && socket.connected && ticketId) socket.emit("mark_read", { ticketId }); }
  });
  $("ucwClose").addEventListener("click", () => {
    panelOpen = false;
    $("ucw-panel").classList.remove("ucw-open");
    $("ucw-fab").setAttribute("aria-expanded", "false");
  });
  $("ucwStart").addEventListener("click", startChat);

  $("ucw-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("ucwInput");
    const text = input.value.trim();
    if (!text) return;
    sendMessage(text);
    input.value = "";
    socket && socket.emit("typing_stop", { ticketId });
  });

  $("ucwInput").addEventListener("input", () => {
    if (!socket || !socket.connected) return;
    socket.emit("typing_start", { ticketId });
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => socket.emit("typing_stop", { ticketId }), 1500);
  });

  $("ucw-attach-btn").addEventListener("click", () => $("ucwFile").click());
  $("ucwFile").addEventListener("change", async () => {
    const file = $("ucwFile").files[0];
    if (!file) return;
    setBanner("Uploading…");
    try {
      const { attachmentUrl, attachmentType } = await uploadAttachment(file);
      clearBanner();
      sendMessage("", attachmentUrl, attachmentType);
    } catch (err) {
      setBanner("Upload failed — try again.", true);
    }
    $("ucwFile").value = "";
  });

  /* ============================================================
     BOOT
     ============================================================ */
  loadBranchPicker();
  if (ticketId && (accessToken || guestLoginToken())) {
    restoreChat();
  }
})();