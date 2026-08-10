function showNotice(message, type = "error") {
  document.getElementById("notice-area").innerHTML = `<div class="notice ${type}">${message}</div>`;
}

document.getElementById("contact-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("contact-submit-btn");
  btn.disabled = true;
  btn.textContent = "Sending…";

  try {
    await api.createTicket({
      subject: document.getElementById("subject").value,
      message: document.getElementById("message").value,
      guest: {
        name: document.getElementById("name").value,
        email: document.getElementById("email").value,
      },
    });
    showNotice("Message sent — we'll reply by email shortly.", "success");
    document.getElementById("contact-form").reset();
  } catch (err) {
    showNotice(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Send message";
  }
});
