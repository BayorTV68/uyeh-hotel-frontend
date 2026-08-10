function initNav() {
  const toggle = document.querySelector(".nav-toggle");
  const links = document.querySelector(".nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", () => links.classList.toggle("open"));
  }
}

// Populates any element with [data-settings="fieldName"] using live settings
// from the backend (phone, email, address, tagline, name, etc.)
async function hydrateSettings() {
  try {
    const { settings } = await api.getSettings();
    document.querySelectorAll("[data-settings]").forEach((el) => {
      const field = el.getAttribute("data-settings");
      if (settings[field]) el.textContent = settings[field];
    });
    document.querySelectorAll("[data-settings-href]").forEach((el) => {
      const field = el.getAttribute("data-settings-href");
      if (field === "phone" && settings.phone) el.href = `tel:${settings.phone.replace(/\s+/g, "")}`;
      if (field === "email" && settings.email) el.href = `mailto:${settings.email}`;
    });
  } catch (err) {
    // Backend not reachable yet (e.g. static preview) — page still renders with default copy.
    console.warn("Could not load live settings:", err.message);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initNav();
  hydrateSettings();
});
