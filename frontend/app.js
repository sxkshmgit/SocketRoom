"use strict";

const TOKEN_KEY = "socketroom_token";

// Limits mirror the backend schemas (backend/app/schemas.py).
const USERNAME = { min: 3, max: 32, pattern: /^[A-Za-z0-9_]+$/ };
const EMAIL = { max: 254, pattern: /^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$/ };
const PASSWORD = { min: 8, max: 128 };

const FIELD_LABELS = { username: "Username", email: "Email", password: "Password" };

const $ = (id) => document.getElementById(id);

const views = { loading: $("loading-view"), auth: $("auth-view"), app: $("app-view") };
const loginForm = $("login-form");
const registerForm = $("register-form");
const tabs = { login: $("tab-login"), register: $("tab-register") };
const forms = { login: loginForm, register: registerForm };

// Chat elements and state.
const chat = {
  status: $("connection-status"),
  list: $("message-list"),
  form: $("message-form"),
  input: $("message-input"),
  send: $("send-button"),
  reconnect: $("reconnect-button"),
  error: $("chat-error"),
};
const MESSAGE_MAX = 2000; // backend limit, counted in characters after trimming
const MAX_MESSAGES_SHOWN = 200;
let socket = null;
let currentUser = "";
let reconnecting = false;
// ---------- session token (sessionStorage) ----------

function getToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function setToken(token) {
  try {
    sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage unavailable: the session just won't survive a reload */
  }
}

function clearToken() {
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* nothing to clear */
  }
}

// ---------- API ----------

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status; // 0 means the request never reached the server
  }
}

async function request(path, { method = "GET", body, token } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError("Can't reach the server. Check your connection and try again.", 0);
  }

  let data = null;
  try {
    data = await res.json();
  } catch {
    /* empty or non-JSON body */
  }

  if (!res.ok) throw new ApiError(describeError(res.status, data), res.status);
  return data;
}

// FastAPI sends `detail` as a string (401, 409) or a list of problems (422).
function describeError(status, data) {
  const detail = data && data.detail;

  if (Array.isArray(detail)) {
    const messages = detail.map(describeValidationIssue);
    return [...new Set(messages)].join(" ") || "Please check the details you entered.";
  }
  if (typeof detail === "string" && status < 500) return detail;
  if (status >= 500) return "The server had a problem. Please try again in a moment.";
  return "Something went wrong. Please try again.";
}

function describeValidationIssue(issue) {
  const loc = issue && Array.isArray(issue.loc) ? issue.loc : [];
  const field = String(loc[loc.length - 1] ?? "");
  const label = FIELD_LABELS[field] || "That field";
  const ctx = (issue && issue.ctx) || {};

  switch (issue && issue.type) {
    case "missing":
      return `${label} is required.`;
    case "string_too_short":
      return `${label} must be at least ${Number(ctx.min_length)} characters.`;
    case "string_too_long":
      return `${label} must be at most ${Number(ctx.max_length)} characters.`;
    case "string_pattern_mismatch":
      if (field === "username") return "Username can only contain letters, numbers and underscores.";
      if (field === "email") return "Please enter a valid email address.";
      return `${label} has an invalid format.`;
    case "string_type":
      return `${label} must be text.`;
    default:
      return `${label} is not valid.`;
  }
}

// ---------- client-side validation ----------

function validateLogin({ username, password }) {
  const problems = [];
  if (!username) problems.push("Enter your username.");
  else if (username.length > USERNAME.max) problems.push("Username is too long.");
  if (!password) problems.push("Enter your password.");
  else if (password.length > PASSWORD.max) problems.push("Password is too long.");
  return problems;
}

function validateRegister({ username, email, password }) {
  const problems = [];

  if (!username) problems.push("Username is required.");
  else if (username.length < USERNAME.min || username.length > USERNAME.max)
    problems.push(`Username must be ${USERNAME.min}–${USERNAME.max} characters.`);
  else if (!USERNAME.pattern.test(username))
    problems.push("Username can only contain letters, numbers and underscores.");

  if (!email) problems.push("Email is required.");
  else if (email.length > EMAIL.max || !EMAIL.pattern.test(email))
    problems.push("Please enter a valid email address.");

  if (!password) problems.push("Password is required.");
  else if (password.length < PASSWORD.min || password.length > PASSWORD.max)
    problems.push(`Password must be ${PASSWORD.min}–${PASSWORD.max} characters.`);

  return problems;
}

// ---------- UI helpers (text is always set with textContent) ----------

function showView(name) {
  for (const [key, el] of Object.entries(views)) el.hidden = key !== name;
}

function setError(form, message) {
  form.querySelector(".form-error").textContent = message;
}

function focusFirstField(form) {
  const field = form.querySelector("input");
  if (field) field.focus();
}

function setBusy(form, busy) {
  form.dataset.busy = busy ? "true" : "";
  for (const el of form.elements) el.disabled = busy;
  for (const tab of Object.values(tabs)) tab.disabled = busy;

  const button = form.querySelector('button[type="submit"]');
  button.setAttribute("aria-busy", String(busy));
  button.textContent = busy ? button.dataset.busyLabel : button.dataset.label;
}

function switchTab(name) {
  for (const [key, tab] of Object.entries(tabs)) {
    tab.setAttribute("aria-selected", String(key === name));
  }
  for (const [key, form] of Object.entries(forms)) {
    form.hidden = key !== name;
    setError(form, "");
  }
  focusFirstField(forms[name]);
}

function resetForms() {
  for (const form of Object.values(forms)) {
    form.reset();
    setError(form, "");
  }
}

function enterApp(username) {
  $("current-user").textContent = username;
  resetForms();
  showView("app");
  startChat(username);
}

// ---------- auth flows ----------

// Logs in, verifies the token with /auth/me, and only then stores it.
async function signIn(username, password) {
  const login = await request("/auth/login", {
    method: "POST",
    body: { username, password },
  });
  if (!login || typeof login.access_token !== "string") {
    throw new ApiError("Unexpected response from the server.", 0);
  }

  const user = await request("/auth/me", { token: login.access_token });
  if (!user || typeof user.username !== "string") {
    throw new ApiError("Unexpected response from the server.", 0);
  }

  setToken(login.access_token);
  enterApp(user.username);
}

async function handleLogin(event) {
  event.preventDefault();
  if (loginForm.dataset.busy) return;

  const credentials = {
    username: $("login-username").value.trim(),
    password: $("login-password").value,
  };

  const problems = validateLogin(credentials);
  if (problems.length) {
    setError(loginForm, problems.join(" "));
    return;
  }

  setError(loginForm, "");
  setBusy(loginForm, true);
  try {
    await signIn(credentials.username, credentials.password);
  } catch (err) {
    setError(loginForm, err.message);
    setBusy(loginForm, false);
    focusFirstField(loginForm);
    return;
  }
  setBusy(loginForm, false);
}

async function handleRegister(event) {
  event.preventDefault();
  if (registerForm.dataset.busy) return;

  const details = {
    username: $("register-username").value.trim(),
    email: $("register-email").value.trim().toLowerCase(),
    password: $("register-password").value,
  };

  const problems = validateRegister(details);
  if (problems.length) {
    setError(registerForm, problems.join(" "));
    return;
  }

  setError(registerForm, "");
  setBusy(registerForm, true);
  try {
    await request("/auth/register", { method: "POST", body: details });
  } catch (err) {
    setError(registerForm, err.message);
    setBusy(registerForm, false);
    focusFirstField(registerForm);
    return;
  }

  // Account exists now: log in automatically.
  try {
    await signIn(details.username, details.password);
  } catch (err) {
    switchTab("login");
    $("login-username").value = details.username;
    setError(
      loginForm,
      `Your account was created, but automatic login failed. ${err.message} Please log in.`
    );
  }
  setBusy(registerForm, false);
}

function handleLogout() {
  closeChat();
  clearToken();
  resetForms();
  showView("auth");
  switchTab("login");
}

async function restoreSession() {
  const token = getToken();
  if (!token) {
    showView("auth");
    return;
  }

  try {
    const user = await request("/auth/me", { token });
    if (!user || typeof user.username !== "string") throw new ApiError("Bad response", 401);
    enterApp(user.username);
  } catch (err) {
    showView("auth");
    if (err.status === 401) {
      clearToken();
      setError(loginForm, "Your session has expired. Please log in again.");
    } else {
      // Server unreachable or failing: keep the token, the user can retry later.
      setError(loginForm, `Couldn't restore your session. ${err.message}`);
    }
  }
}
// ---------- chat (WebSocket) ----------

function socketUrl() {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}/ws`;
}

function setChatError(message) {
  chat.error.textContent = message;
}

function setConnection(state, text) {
  chat.status.dataset.state = state;
  chat.status.textContent = text;
  const connected = state === "connected";
  chat.input.disabled = !connected;
  chat.send.disabled = !connected;
  chat.reconnect.hidden = state !== "disconnected";
}

function describeClose(code, wasOpen) {
  switch (code) {
    case 1008:
      return "Disconnected: the server rejected your session or a message (1008).";
    case 1003:
      return "Disconnected: the server doesn't accept that kind of data (1003).";
    case 1013:
      return "Disconnected: you were too slow to keep up with messages (1013).";
    case 1006:
      return wasOpen ? "Connection lost." : "Couldn't connect to the server.";
    default:
      return "Disconnected.";
  }
}

// Closes the current socket. Its handlers ignore events once `socket` changes.
function detachSocket() {
  if (!socket) return;
  const old = socket;
  socket = null;
  old.close(1000);
}

function openSocket() {
  const token = getToken();
  if (!token) {
    expireSession();
    return;
  }

  detachSocket();
  const ws = new WebSocket(socketUrl());
  let wasOpen = false;
  socket = ws;
  setConnection("connecting", "Connecting…");

  ws.addEventListener("open", () => {
    if (socket !== ws) return;
    wasOpen = true;
    // The server sends no confirmation after auth. The token was verified with
    // /auth/me moments ago; a rejected token shows up as a 1008 close below.
    ws.send(JSON.stringify({ type: "auth", token }));
    setConnection("connected", "Connected");
  });

  ws.addEventListener("message", (event) => {
    if (socket !== ws) return;
    handleSocketMessage(event.data);
  });

  ws.addEventListener("close", (event) => {
    if (socket !== ws) return;
    socket = null;
    setConnection("disconnected", describeClose(event.code, wasOpen));
  });
}

function handleSocketMessage(raw) {
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    return;
  }
  if (
    !data ||
    data.type !== "message" ||
    typeof data.sender !== "string" ||
    typeof data.content !== "string"
  ) {
    return;
  }
  appendMessage(data.sender, data.content);
}

function appendMessage(sender, content) {
  const list = chat.list;
  const own = sender === currentUser;
  const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 40;

  const item = document.createElement("li");
  item.className = "message";
  item.dataset.own = String(own);

  const name = document.createElement("span");
  name.className = "message-sender";
  name.textContent = own ? `${sender} (you)` : sender;

  const text = document.createElement("span");
  text.className = "message-content";
  text.textContent = content;

  item.append(name, text);
  list.append(item);

  while (list.children.length > MAX_MESSAGES_SHOWN) list.firstElementChild.remove();
  if (own || nearBottom) list.scrollTop = list.scrollHeight;
}

function startChat(username) {
  currentUser = username;
  chat.list.replaceChildren();
  chat.input.value = "";
  setChatError("");
  openSocket();
}

function closeChat() {
  detachSocket();
  currentUser = "";
  chat.list.replaceChildren();
  chat.input.value = "";
  setChatError("");
  setConnection("disconnected", "Disconnected");
}

function expireSession() {
  closeChat();
  clearToken();
  resetForms();
  showView("auth");
  switchTab("login");
  setError(loginForm, "Your session has expired. Please log in again.");
}

function handleSend(event) {
  event.preventDefault();
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    setChatError("You are not connected.");
    return;
  }

  const content = chat.input.value.trim();
  if (!content) {
    setChatError("Type a message first.");
    return;
  }
  const length = Array.from(content).length;
  if (length > MESSAGE_MAX) {
    setChatError(`Message is too long (${length}/${MESSAGE_MAX} characters).`);
    return;
  }

  setChatError("");
  socket.send(JSON.stringify({ type: "message", content }));
  chat.input.value = "";
  chat.input.focus();
}

async function handleReconnect() {
  if (reconnecting) return;
  reconnecting = true;
  setChatError("");
  setConnection("connecting", "Checking your session…");

  try {
    await request("/auth/me", { token: getToken() });
    if (views.app.hidden) return; // logged out while we were checking
    openSocket();
  } catch (err) {
    if (err.status === 401) {
      expireSession();
    } else {
      setConnection("disconnected", err.message);
    }
  } finally {
    reconnecting = false;
  }
}
// ---------- backend health (unchanged behaviour) ----------

async function checkBackend() {
  const el = $("status");
  try {
    const res = await fetch("/health");
    if (!res.ok) throw new Error(res.status);
    const data = await res.json();
    el.textContent = `Backend: ${data.status}`;
  } catch {
    el.textContent = "Backend unreachable";
  }
}

// ---------- wiring ----------

tabs.login.addEventListener("click", () => switchTab("login"));
tabs.register.addEventListener("click", () => switchTab("register"));
loginForm.addEventListener("submit", handleLogin);
registerForm.addEventListener("submit", handleRegister);
$("logout-button").addEventListener("click", handleLogout);
chat.form.addEventListener("submit", handleSend);
chat.reconnect.addEventListener("click", handleReconnect);

showView("loading");
checkBackend();
restoreSession();