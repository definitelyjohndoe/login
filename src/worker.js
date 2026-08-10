// Everything the old Pages Functions folder did (login, logout, me,
// and the dashboard-gating middleware) now lives in this one Worker.
// Only paths listed in wrangler.jsonc's run_worker_first ever reach this
// code — every other request (index.html, style.css, etc.) is served
// straight from the static assets, no Worker invocation needed.

import credsFile from "../creds.txt";

const SESSION_HOURS = 2;

async function sign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function verify(cookieValue, secret) {
  if (!cookieValue || !secret) return null;
  const parts = cookieValue.split(".");
  if (parts.length !== 3) return null;
  const [username, expires, sig] = parts;
  const payload = `${username}.${expires}`;

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  let sigBytes;
  try {
    sigBytes = Uint8Array.from(
      atob(sig.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0)
    );
  } catch {
    return null;
  }

  const valid = await crypto.subtle.verify("HMAC", key, sigBytes, enc.encode(payload));
  if (!valid) return null;
  if (Date.now() > Number(expires)) return null;
  return username;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function parseCreds(text) {
  const map = new Map();
  text.split("\n").forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return;
    const idx = trimmed.indexOf(":");
    if (idx === -1) return;
    map.set(trimmed.slice(0, idx), trimmed.slice(idx + 1));
  });
  return map;
}

function json(status, obj, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

async function handleLogin(request, env) {
  let username = "";
  let password = "";

  const contentType = request.headers.get("Content-Type") || "";
  if (contentType.includes("application/json")) {
    const body = await request.json().catch(() => ({}));
    username = (body.username || "").trim();
    password = body.password || "";
  } else {
    const form = await request.formData().catch(() => null);
    username = (form?.get("username") || "").toString().trim();
    password = (form?.get("password") || "").toString();
  }

  if (!username || !password) {
    return json(400, { ok: false, error: "Username and password are required." });
  }

  const creds = parseCreds(credsFile);
  const valid = creds.has(username) && creds.get(username) === password;

  if (!valid) {
    return json(401, { ok: false, error: "Invalid username or password." });
  }

  const secret = env.SESSION_SECRET;
  if (!secret) {
    return json(500, { ok: false, error: "Server misconfigured: SESSION_SECRET is not set." });
  }

  const expires = Date.now() + 1000 * 60 * 60 * SESSION_HOURS;
  const payload = `${username}.${expires}`;
  const sig = await sign(payload, secret);
  const cookieValue = `${payload}.${sig}`;

  return json(
    200,
    { ok: true, username },
    {
      "Set-Cookie": `session=${cookieValue}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${
        SESSION_HOURS * 3600
      }`,
    }
  );
}

function handleLogout() {
  return json(
    200,
    { ok: true },
    { "Set-Cookie": "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" }
  );
}

async function handleMe(request, env) {
  const cookie = getCookie(request, "session");
  const username = await verify(cookie, env.SESSION_SECRET);
  if (!username) return json(401, { ok: false });
  return json(200, { ok: true, username });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (pathname === "/api/login" && request.method === "POST") {
      return handleLogin(request, env);
    }
    if (pathname === "/api/logout" && request.method === "POST") {
      return handleLogout();
    }
    if (pathname === "/api/me" && request.method === "GET") {
      return handleMe(request, env);
    }
    if (pathname === "/dashboard" || pathname === "/dashboard.html") {
      const cookie = getCookie(request, "session");
      const username = await verify(cookie, env.SESSION_SECRET);
      if (!username) {
        return Response.redirect(new URL("/?authRequired=1", url), 302);
      }
      return env.ASSETS.fetch(request);
    }

    // Shouldn't normally be reached (run_worker_first scopes which paths
    // hit this Worker at all), but fall back to serving assets just in case.
    return env.ASSETS.fetch(request);
  },
};
