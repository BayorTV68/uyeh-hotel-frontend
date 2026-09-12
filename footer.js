/* =====================================================================
   Shared site footer.
   Drop this on every page (index, location, about, blog, contact, ...):

       <div id="siteFooter"></div>
       <script src="footer.js"></script>

   It injects its own scoped markup + styles, pulls branding (name, logo,
   email, phone, about blurb) from GET /settings the same way the
   homepage does, wires up the newsletter form, and sets the copyright
   year. No page-specific setup required — just the two lines above.

   Styles are scoped under #siteFooter with their own CSS variables and
   an "ft-" class prefix, so it won't collide with a host page's design
   tokens or class names, and it doesn't assume the host page has loaded
   the same fonts/vars as indexs.html.
   ===================================================================== */
(function () {
  "use strict";

  const API_BASE = "https://uyeh-hotel-backend.onrender.com/api";

  const mount = document.getElementById("siteFooter") || (function () {
    const d = document.createElement("div");
    d.id = "siteFooter";
    document.body.appendChild(d);
    return d;
  })();

  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));

  const STYLE = `
  #siteFooter{--f-ink:#14181f;--f-ink-deep:#0d1015;--f-ivory:#f6f1e7;--f-brass:#b98d45;--f-brass-light:#d9b876;--f-line:rgba(237,230,214,.16);--f-muted:rgba(237,230,214,.66);--f-font-display:'Fraunces',Georgia,serif;--f-font-body:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}
  #siteFooter *{box-sizing:border-box}
  #siteFooter{background:var(--f-ink-deep);padding:70px 0 30px;border-top:1px solid var(--f-line);font-family:var(--f-font-body);color:var(--f-ivory)}
  #siteFooter .ft-wrap{max-width:1180px;margin:0 auto;padding:0 28px}
  #siteFooter a{color:inherit;text-decoration:none}
  #siteFooter a:hover{color:var(--f-brass-light)}
  #siteFooter .ft-grid{display:grid;grid-template-columns:1.4fr repeat(3,1fr);gap:34px}
  @media(max-width:820px){#siteFooter .ft-grid{grid-template-columns:1fr 1fr}}
  #siteFooter .ft-brand{font-family:var(--f-font-display);font-size:1.22rem;letter-spacing:.02em;display:inline-block}
  #siteFooter .ft-brand-logo{height:30px;width:auto;display:block}
  #siteFooter .ft-about{max-width:34ch;margin-top:10px;font-size:.9rem;color:var(--f-muted)}
  #siteFooter h5{font-size:.72rem;letter-spacing:.18em;text-transform:uppercase;color:var(--f-brass-light);margin:0 0 14px}
  #siteFooter ul{list-style:none;display:flex;flex-direction:column;gap:9px;font-size:.88rem;padding:0;margin:0}
  #siteFooter .ft-newsletter-copy{font-size:.85rem;margin-bottom:14px;max-width:26ch;color:var(--f-muted)}
  #siteFooter .ft-newsletter-form{display:flex;flex-direction:column;gap:8px}
  #siteFooter .ft-newsletter-form input{padding:10px 12px;border-radius:2px;border:1px solid var(--f-line);background:rgba(255,255,255,.06);color:var(--f-ivory);font-size:.85rem;font:inherit}
  #siteFooter .ft-btn{display:inline-flex;align-items:center;justify-content:center;padding:10px;border-radius:2px;font-size:.82rem;font-weight:600;border:1px solid transparent;cursor:pointer;background:var(--f-brass);color:var(--f-ink);transition:background .25s;width:100%}
  #siteFooter .ft-btn:hover{background:var(--f-brass-light)}
  #siteFooter .ft-btn:disabled{opacity:.6;cursor:default}
  #siteFooter .ft-newsletter-note{font-size:.76rem;margin-top:8px;color:var(--f-muted);min-height:1em}
  #siteFooter .ft-bottom{margin-top:44px;padding-top:20px;border-top:1px solid var(--f-line);display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;font-size:.78rem;color:var(--f-muted)}
  #siteFooter .ft-legal a{margin-left:14px}
  #siteFooter .ft-legal a:first-child{margin-left:0}
  `;

  const HTML = `
  <div class="ft-wrap">
    <div class="ft-grid">
      <div>
        <a href="index.html" class="ft-brand" id="ftBrand">Our Hotel</a>
        <p class="ft-about" id="ftAbout">Multiple locations, one company, one booking system — built directly by the team that runs it.</p>
      </div>
      <div>
        <h5>Explore</h5>
        <ul>
          <li><a href="index.html#locations">Locations</a></li>
          <li><a href="index.html#experiences">Experiences</a></li>
          <li><a href="blog.html">Blog</a></li>
          <li><a href="about.html">About</a></li>
          <li><a href="contact.html">Contact</a></li>
        </ul>
      </div>
      <div>
        <h5>Get in touch</h5>
        <ul>
          <li><a href="mailto:hello@ourhotel.com" id="ftEmail">hello@ourhotel.com</a></li>
          <li><a href="tel:" id="ftPhone">Phone available on each branch page</a></li>
        </ul>
      </div>
      <div>
        <h5>Newsletter</h5>
        <p class="ft-newsletter-copy">Offers and news from every location.</p>
        <form class="ft-newsletter-form" id="ftNewsletterForm">
          <label for="ftNewsletterEmail" style="position:absolute;left:-9999px;">Email address</label>
          <input type="email" id="ftNewsletterEmail" placeholder="you@email.com" required>
          <button type="submit" class="ft-btn" id="ftNewsletterSubmit">Subscribe</button>
        </form>
        <p class="ft-newsletter-note" id="ftNewsletterNote" role="status" aria-live="polite"></p>
      </div>
    </div>
    <div class="ft-bottom">
      <span>&copy; <span id="ftYear"></span> <span id="ftCopyrightName">Our Hotel</span>. All rights reserved.</span>
      <span class="ft-legal"><a href="privacy.html">Privacy</a><a href="terms.html">Terms</a></span>
    </div>
  </div>
  `;

  const styleTag = document.createElement("style");
  styleTag.textContent = STYLE;
  document.head.appendChild(styleTag);
  mount.innerHTML = HTML;

  const $ = (id) => document.getElementById(id);
  $("ftYear").textContent = new Date().getFullYear();

  async function hydrate() {
    try {
      const res = await fetch(`${API_BASE}/settings`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
      const settings = data.settings || {};
      const name = settings.platformName || "Our Hotel";
      $("ftCopyrightName").textContent = name;

      const brandEl = $("ftBrand");
      if (settings.logoUrl) {
        brandEl.innerHTML = `<img class="ft-brand-logo" src="${esc(settings.logoUrl)}" alt="${esc(name)}">`;
      } else {
        brandEl.textContent = name;
      }

      if (settings.footerAbout) $("ftAbout").textContent = settings.footerAbout;

      const email = settings.footerEmail || "hello@ourhotel.com";
      const emailEl = $("ftEmail");
      emailEl.textContent = email;
      emailEl.href = `mailto:${email}`;

      if (settings.footerPhone) {
        const phoneEl = $("ftPhone");
        phoneEl.textContent = settings.footerPhone;
        phoneEl.href = `tel:${settings.footerPhone}`;
      }
    } catch (err) {
      console.warn("Footer settings unavailable, using page defaults:", err.message);
    }
  }

  $("ftNewsletterForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("ftNewsletterSubmit"), note = $("ftNewsletterNote"), input = $("ftNewsletterEmail");
    btn.disabled = true;
    try {
      const res = await fetch(`${API_BASE}/newsletter/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: input.value }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
      note.textContent = data.message || "You're subscribed.";
      input.value = "";
    } catch (err) {
      note.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  });

  hydrate();
})();