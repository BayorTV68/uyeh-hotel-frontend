/* ============================================================
   site-controller.js — live, settings-driven site controller for
   Oxygen Hotel's guest-facing pages (index.html, location.html,
   about.html, contact.html, ...). Include this on every guest
   page with a plain <script> tag — no build step, no modules.

   Do NOT include this on admin-panel.html, hotel-manager-
   dashboard.html, or hotel-staff-dashboard.html — maintenance
   mode is meant to lock guests out, not the people who need to
   turn it back off. Those panels already have their own login
   walls and don't need this.

   Reads GET /api/settings (public, already built) and applies:
     1. Maintenance mode overlay
     2. Announcement banner
     3. Brand colors as CSS custom properties
     4. Feature flags (exposed for pages to check)
     5. SEO — title/meta/OG/analytics
     6. Custom CSS / custom head injection

   No payment-gateway section — Paystack's checkout here is
   redirect-based (initializeTransaction -> authorization_url),
   not an inline JS modal like Flutterwave, so there's no public
   key to preload. If that ever changes, this file is where it'd
   go — see the note at the bottom.
   ============================================================ */
(function (window) {
  "use strict";

  const API_BASE = window.__API_BASE__ || "/api";
  const POLL_INTERVAL_MS = 60 * 1000;
  const BANNER_DISMISS_KEY = "oxygen_banner_dismissed_v";
  const BYPASS_STORAGE_KEY = "oxygen_maintenance_bypass";

  let currentSettings = null;
  let pollTimer = null;
  let _fetching = false; // guards against overlapping fetches if a manual refresh() lands mid-poll

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    injectStyles();
    await fetchAndApply();
    pollTimer = setInterval(fetchAndApply, POLL_INTERVAL_MS);
  }

  // ── Fetch + apply ────────────────────────────────────────────
  async function fetchAndApply() {
    if (_fetching) return;
    _fetching = true;
    try {
      const urlBypass = new URLSearchParams(window.location.search).get("bypass");
      if (urlBypass) {
        sessionStorage.setItem(BYPASS_STORAGE_KEY, urlBypass);
        const clean = new URL(window.location.href);
        clean.searchParams.delete("bypass");
        history.replaceState({}, "", clean.toString());
      }
      const bypass = urlBypass || sessionStorage.getItem(BYPASS_STORAGE_KEY) || "";

      const url = bypass
        ? `${API_BASE}/settings?bypass=${encodeURIComponent(bypass)}`
        : `${API_BASE}/settings`;

      const res = await fetch(url, { cache: "no-store" });
      const data = await res.json();
      if (data && data.settings) {
        currentSettings = data.settings;
        applySettings(data.settings);
      }
    } catch (err) {
      // Backend down or network error — never block the site over this.
      console.warn("[SiteController] Could not fetch settings:", err.message);
    } finally {
      _fetching = false;
    }
  }

  function applySettings(s) {
    handleMaintenance(s);
    handleBanner(s);
    handleBrandColors(s);
    handleFeatureFlags(s);
    handleSEO(s);
    handleCustomCode(s);
  }

  // ── 1. Maintenance mode ──────────────────────────────────────
  function handleMaintenance(s) {
    if (!s.maintenanceMode) {
      removeMaintenance();
      return;
    }
    showMaintenanceOverlay(s);
  }

  function showMaintenanceOverlay(s) {
    if (document.getElementById("oxygen-maintenance-overlay")) return;

    const el = document.createElement("div");
    el.id = "oxygen-maintenance-overlay";
    el.innerHTML = `
      <div class="oxygen-maint-card">
        ${s.logoUrl ? `<img class="oxygen-maint-logo" src="${escHtml(s.logoUrl)}" alt="${escHtml(s.platformName || "Oxygen Hotel")}" onerror="this.style.display='none'">` : ""}
        <h1 class="oxygen-maint-title">${escHtml(s.maintenanceTitle || "Under Maintenance")}</h1>
        <p class="oxygen-maint-msg">${escHtml(s.maintenanceMessage || "We're performing scheduled maintenance. We'll be back shortly!")}</p>
        ${s.maintenanceETA ? `
          <div class="oxygen-maint-eta">
            <span>Estimated return:</span> <strong>${escHtml(s.maintenanceETA)}</strong>
          </div>` : ""}
        ${s.email ? `<a href="mailto:${escHtml(s.email)}" class="oxygen-maint-link">Contact us</a>` : ""}
        <p class="oxygen-maint-footer">&copy; ${new Date().getFullYear()} ${escHtml(s.platformName || "Oxygen Hotel")}</p>
      </div>
    `;
    document.body.appendChild(el);
    document.body.style.overflow = "hidden";
  }

  function removeMaintenance() {
    const el = document.getElementById("oxygen-maintenance-overlay");
    if (el) { el.remove(); document.body.style.overflow = ""; }
  }

  // ── 2. Announcement banner ───────────────────────────────────
  function handleBanner(s) {
    const existing = document.getElementById("oxygen-site-banner");
    const banner = s.banner || {};

    if (!banner.enabled || !banner.text) {
      if (existing) existing.remove();
      return;
    }

    const version = _hashStr(banner.text);
    if (sessionStorage.getItem(BANNER_DISMISS_KEY) === String(version)) {
      if (existing) existing.remove();
      return;
    }

    if (existing) {
      const textEl = existing.querySelector(".oxygen-banner-text");
      if (textEl) textEl.innerHTML = buildBannerInner(banner);
      return;
    }

    const el = document.createElement("div");
    el.id = "oxygen-site-banner";
    el.className = `oxygen-banner oxygen-banner--${banner.type || "info"}`;
    el.innerHTML = `
      <div class="oxygen-banner-inner">
        <span class="oxygen-banner-text">${buildBannerInner(banner)}</span>
        ${banner.dismissible !== false ? `<button class="oxygen-banner-close" aria-label="Dismiss">&times;</button>` : ""}
      </div>
    `;
    if (banner.dismissible !== false) {
      el.querySelector(".oxygen-banner-close").addEventListener("click", () => {
        sessionStorage.setItem(BANNER_DISMISS_KEY, String(version));
        el.remove();
      });
    }
    document.body.insertBefore(el, document.body.firstChild);
  }

  function buildBannerInner(banner) {
    const text = escHtml(banner.text);
    if (banner.link) {
      return `${text} <a href="${escHtml(banner.link)}" class="oxygen-banner-link">${escHtml(banner.linkText || "Learn more")}</a>`;
    }
    return text;
  }

  // ── 3. Brand colors ──────────────────────────────────────────
  // Lets the Director retheme the whole site from settings. Every page's
  // own CSS already defines these as :root custom properties with sane
  // hardcoded fallbacks — this only overrides them once settings load.
  function handleBrandColors(s) {
    const brand = s.brand || {};
    const root = document.documentElement.style;
    if (brand.primaryColor) root.setProperty("--ink", brand.primaryColor);
    if (brand.secondaryColor) root.setProperty("--brass", brand.secondaryColor);
    if (brand.accentColor) root.setProperty("--teal", brand.accentColor);
  }

  // ── 4. Feature flags ─────────────────────────────────────────
  // Pages check window.SiteController.isFeatureEnabled("events") etc.
  // before rendering nav links or sections for that feature, instead of
  // assuming everything is always on.
  function handleFeatureFlags(s) {
    // nothing to apply globally here — flags are exposed via the public
    // API below for each page to read when it renders its own nav/sections.
  }
  function isFeatureEnabled(name) {
    if (!currentSettings) return true; // default open before first fetch resolves
    const features = currentSettings.features || {};
    return features[`${name}Enabled`] !== false;
  }

  // ── 5. SEO ────────────────────────────────────────────────────
  function handleSEO(s) {
    const seo = s.seo || {};
    if (seo.metaTitle) document.title = seo.metaTitle;
    setMetaTag("description", seo.metaDescription);
    setMetaTag("keywords", seo.metaKeywords);
    setMetaTag("og:image", seo.ogImageUrl, "property");

    if (seo.googleAnalyticsId && !window.__oxygen_ga_loaded) {
      window.__oxygen_ga_loaded = true;
      const sc = document.createElement("script");
      sc.async = true;
      sc.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(seo.googleAnalyticsId)}`;
      document.head.appendChild(sc);
      window.dataLayer = window.dataLayer || [];
      window.gtag = function () { window.dataLayer.push(arguments); };
      window.gtag("js", new Date());
      window.gtag("config", seo.googleAnalyticsId);
    }
    // Facebook Pixel intentionally left out for now — add only if you're
    // actually running Meta ads; no point loading tracking scripts unused.
  }
  function setMetaTag(name, content, attr = "name") {
    if (!content) return;
    let tag = document.querySelector(`meta[${attr}="${name}"]`);
    if (!tag) {
      tag = document.createElement("meta");
      tag.setAttribute(attr, name);
      document.head.appendChild(tag);
    }
    tag.setAttribute("content", content);
  }

  // ── 6. Custom CSS / head ─────────────────────────────────────
  function handleCustomCode(s) {
    applyCustomBlock("oxygen-custom-css", s.customCSS, (content) => {
      const style = document.createElement("style");
      style.id = "oxygen-custom-css";
      style.textContent = content;
      document.head.appendChild(style);
    });
    applyCustomBlock("oxygen-custom-head", s.customHead, (content) => {
      const wrapper = document.createElement("div");
      wrapper.id = "oxygen-custom-head";
      wrapper.style.display = "none";
      wrapper.innerHTML = content; // Director-authored, trusted input (same trust level as customCSS)
      document.head.appendChild(wrapper);
    });
  }
  function applyCustomBlock(id, content, inject) {
    const existing = document.getElementById(id);
    if (existing) existing.remove();
    if (content) inject(content);
  }

  // ── Injected chrome styles (maintenance + banner only — page CSS
  // owns everything else) ──────────────────────────────────────
  function injectStyles() {
    if (document.getElementById("oxygen-controller-styles")) return;
    const style = document.createElement("style");
    style.id = "oxygen-controller-styles";
    style.textContent = `
      #oxygen-maintenance-overlay {
        position: fixed; inset: 0; z-index: 99999;
        background: var(--ink, #14181f);
        display: flex; align-items: center; justify-content: center;
        padding: 24px;
      }
      .oxygen-maint-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(185,141,69,0.25);
        border-radius: 8px; padding: 48px 40px; max-width: 460px; width: 100%;
        text-align: center; font-family: 'Inter', -apple-system, sans-serif;
      }
      .oxygen-maint-logo { width: 48px; height: 48px; border-radius: 8px; margin: 0 auto 20px; display: block; }
      .oxygen-maint-title { font-family: 'Fraunces', serif; font-size: 1.6rem; color: var(--brass, #b98d45); margin-bottom: 14px; }
      .oxygen-maint-msg { color: rgba(237,230,214,0.75); font-size: 0.95rem; line-height: 1.6; margin-bottom: 20px; }
      .oxygen-maint-eta { color: rgba(237,230,214,0.6); font-size: 0.85rem; margin-bottom: 20px; }
      .oxygen-maint-eta strong { color: var(--brass, #b98d45); }
      .oxygen-maint-link { color: var(--brass, #b98d45); font-size: 0.85rem; text-decoration: underline; }
      .oxygen-maint-footer { color: rgba(237,230,214,0.35); font-size: 0.75rem; margin-top: 24px; }

      .oxygen-banner { position: relative; z-index: 9998; padding: 10px 16px; font-family: 'Inter', -apple-system, sans-serif; font-size: 0.86rem; }
      .oxygen-banner--info { background: #14181f; color: #ede6d6; }
      .oxygen-banner--success { background: #2f5d5a; color: #ede6d6; }
      .oxygen-banner--warning { background: #b98d45; color: #14181f; }
      .oxygen-banner--urgent { background: #a3392a; color: #ede6d6; }
      .oxygen-banner-inner { display: flex; align-items: center; justify-content: center; gap: 12px; max-width: 1180px; margin: 0 auto; }
      .oxygen-banner-text { flex: 1; text-align: center; }
      .oxygen-banner-link { color: inherit; font-weight: 600; text-decoration: underline; white-space: nowrap; }
      .oxygen-banner-close { background: none; border: none; color: inherit; cursor: pointer; font-size: 1.1rem; opacity: 0.7; flex-shrink: 0; }
      .oxygen-banner-close:hover { opacity: 1; }
    `;
    document.head.appendChild(style);
  }

  // ── Utility ───────────────────────────────────────────────────
  function escHtml(str) {
    if (!str) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function _hashStr(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return hash;
  }

  window.SiteController = {
    refresh: fetchAndApply,
    getSettings: () => currentSettings,
    isFeatureEnabled,
  };

  // ── If you switch to Paystack Inline (popup) checkout later ───
  // window.PAYSTACK_PUBLIC_KEY would get set here from a new
  // settings.paystackPublicKey field, and you'd preload
  // https://js.paystack.co/v2/inline.js the same way handlePaymentGateway
  // preloaded Flutterwave's script above. Not needed for the current
  // redirect-based checkout — nothing to do here until that changes.
})(window);