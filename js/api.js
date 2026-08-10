// Point this at your deployed backend (e.g. https://api.solacehouse.com).
// Left as a relative "/api" path for local dev with a proxy, or same-origin deploys.
const API_BASE = window.__API_BASE__ || "/api";

async function apiRequest(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

const api = {
  getSettings: () => apiRequest("/settings"),
  getRoomTypes: () => apiRequest("/room-types"),
  checkAvailability: (checkIn, checkOut, roomTypeId) =>
    apiRequest(`/availability?checkIn=${checkIn}&checkOut=${checkOut}${roomTypeId ? `&roomTypeId=${roomTypeId}` : ""}`),
  createBooking: (payload) => apiRequest("/bookings", { method: "POST", body: JSON.stringify(payload) }),
  createTicket: (payload) => apiRequest("/tickets", { method: "POST", body: JSON.stringify(payload) }),
};
