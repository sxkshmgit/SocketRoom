async function checkBackend() {
  const el = document.getElementById("status");
  try {
    const res = await fetch("/health");
    if (!res.ok) throw new Error(res.status);
    const data = await res.json();
    el.textContent = `Backend: ${data.status}`;
  } catch {
    el.textContent = "Backend unreachable";
  }
}

checkBackend();