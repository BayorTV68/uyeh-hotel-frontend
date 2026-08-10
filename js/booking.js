const params = new URLSearchParams(window.location.search);
const preselectedRoomTypeId = params.get("roomTypeId");

let selectedRoom = null;
let selectedDates = null;

function showNotice(message, type = "error") {
  const area = document.getElementById("notice-area");
  area.innerHTML = `<div class="notice ${type}">${message}</div>`;
}
function clearNotice() {
  document.getElementById("notice-area").innerHTML = "";
}

document.getElementById("check-availability-btn").addEventListener("click", async () => {
  clearNotice();
  const checkIn = document.getElementById("checkIn").value;
  const checkOut = document.getElementById("checkOut").value;

  if (!checkIn || !checkOut) {
    showNotice("Please choose both a check-in and check-out date.");
    return;
  }
  if (checkIn >= checkOut) {
    showNotice("Check-out must be after check-in.");
    return;
  }

  const btn = document.getElementById("check-availability-btn");
  btn.disabled = true;
  btn.textContent = "Checking…";

  try {
    const { availableRooms } = await api.checkAvailability(checkIn, checkOut, preselectedRoomTypeId || undefined);
    selectedDates = { checkIn, checkOut };
    renderAvailableRooms(availableRooms);
  } catch (err) {
    showNotice(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Check availability";
  }
});

function renderAvailableRooms(rooms) {
  const list = document.getElementById("available-rooms-list");
  const step = document.getElementById("step-rooms");
  step.style.display = "block";

  if (!rooms.length) {
    list.innerHTML = '<div class="empty-state">No rooms available for those dates. Try a different range.</div>';
    return;
  }

  list.innerHTML = rooms.map((room) => `
    <div class="room-card" style="margin-bottom: 16px;">
      <div class="room-card-body" style="display:flex; align-items:center; justify-content:space-between; gap: 16px; flex-wrap: wrap;">
        <div>
          <h3 style="font-size: 1.1rem; margin-bottom: 4px;">${room.roomType.name} — Room ${room.roomNumber}</h3>
          <p style="color:var(--text-muted); font-size: 0.88rem;">${room.roomType.currency} ${Number(room.roomType.basePrice).toLocaleString()} / night &middot; Sleeps ${room.roomType.maxOccupancy}</p>
        </div>
        <button class="btn btn-primary select-room-btn" data-room-id="${room.id}">Select</button>
      </div>
    </div>
  `).join("");

  document.querySelectorAll(".select-room-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const roomId = btn.getAttribute("data-room-id");
      selectedRoom = rooms.find((r) => r.id === roomId);
      document.getElementById("step-guest").style.display = "block";
      document.getElementById("step-guest").scrollIntoView({ behavior: "smooth" });
    });
  });
}

document.getElementById("booking-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  clearNotice();

  if (!selectedRoom || !selectedDates) {
    showNotice("Please select a room first.");
    return;
  }

  const payload = {
    roomId: selectedRoom.id,
    checkIn: selectedDates.checkIn,
    checkOut: selectedDates.checkOut,
    guestsCount: Number(document.getElementById("guestsCount").value) || 1,
    specialRequests: document.getElementById("specialRequests").value || undefined,
    guest: {
      name: document.getElementById("guestName").value,
      email: document.getElementById("guestEmail").value,
      phone: document.getElementById("guestPhone").value || undefined,
    },
  };

  const btn = document.getElementById("submit-booking-btn");
  btn.disabled = true;
  btn.textContent = "Booking…";

  try {
    await api.createBooking(payload);
    document.getElementById("step-dates").style.display = "none";
    document.getElementById("step-rooms").style.display = "none";
    document.getElementById("step-guest").style.display = "none";
    document.getElementById("step-confirmed").style.display = "block";
    document.getElementById("step-confirmed").scrollIntoView({ behavior: "smooth" });
  } catch (err) {
    showNotice(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Confirm booking";
  }
});
