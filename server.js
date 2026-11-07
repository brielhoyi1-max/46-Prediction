const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const ROOT = __dirname;

function loadEnvFile() {
  const file = path.join(ROOT, ".env");
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!match || match[1] in process.env) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[match[1]] = value;
  }
}
loadEnvFile();

const IS_PRODUCTION = process.env.NODE_ENV === "production";
const HOST = process.env.HOST || (IS_PRODUCTION ? "0.0.0.0" : "127.0.0.1");
const PORT = Number(process.env.PORT || 41746);
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY || "";
const LEGACY_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const SUPABASE_KEY = SUPABASE_SECRET_KEY || LEGACY_SERVICE_ROLE_KEY;
const ADMIN_CODE = process.env.ADMIN_ACCESS_CODE || (IS_PRODUCTION ? "" : "46046P");
const SESSION_TTL = 8 * 60 * 60 * 1000;
const sessions = new Map();
const userSessions = new Map();
const attempts = new Map();
const MIME = {".html":"text/html; charset=utf-8",".css":"text/css; charset=utf-8",".js":"text/javascript; charset=utf-8",".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".webp":"image/webp",".svg":"image/svg+xml",".ico":"image/x-icon"};

function readCookie(req, name) {
  for (const item of String(req.headers.cookie || "").split(";")) {
    const [key, ...value] = item.trim().split("=");
    if (key === name) return value.join("=");
  }
  return "";
}
function isAdmin(req) {
  const token = readCookie(req, "46p_admin");
  const expires = sessions.get(token);
  if (!expires || expires < Date.now()) { sessions.delete(token); return false; }
  return true;
}
function respond(res, status, body, headers = {}) {
  res.writeHead(status, {"Cache-Control":"no-store", "X-Content-Type-Options":"nosniff", ...headers});
  res.end(body);
}
function json(res, status, value, headers = {}) {
  return respond(res, status, JSON.stringify(value), {"Content-Type":"application/json; charset=utf-8", ...headers});
}
function requestBody(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (Buffer.byteLength(body) > maxBytes) { reject(new Error("too_large")); req.destroy(); }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function hashPersonalCode(code) {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => crypto.scrypt(code, salt, 64, (error, key) => {
    if (error) return reject(error);
    resolve(`scrypt$${salt.toString("hex")}$${key.toString("hex")}`);
  }));
}
function verifyPersonalCode(code, stored) {
  const [scheme, saltHex, hashHex] = String(stored || "").split("$");
  if (scheme !== "scrypt" || !/^[a-f0-9]{32}$/i.test(saltHex || "") || !/^[a-f0-9]{128}$/i.test(hashHex || "")) return Promise.resolve(false);
  return new Promise((resolve, reject) => crypto.scrypt(code, Buffer.from(saltHex, "hex"), 64, (error, key) => {
    if (error) return reject(error);
    resolve(safeEqual(key.toString("hex"), hashHex));
  }));
}
function currentUserSession(req) {
  const token = readCookie(req, "46p_user");
  const session = userSessions.get(token);
  if (!session || session.expires < Date.now()) {
    userSessions.delete(token);
    return null;
  }
  return {token, ...session};
}
function setUserSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  userSessions.set(token, {userId, expires:Date.now() + SESSION_TTL});
  return {"Set-Cookie":`46p_user=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${secureCookie()}`};
}
function userDto(row) {
  return {id:row.id, username:row.username, diamonds:Number(row.diamonds), energy:Number(row.energy)};
}
function hitRateLimit(ip) {
  const now = Date.now();
  const record = attempts.get(ip) || {count:0, until:now + 10 * 60 * 1000};
  if (record.until < now) { record.count = 0; record.until = now + 10 * 60 * 1000; }
  record.count++;
  attempts.set(ip, record);
  return record.count > 30;
}
function getSupabaseConfig() {
  if (!SUPABASE_URL || !SUPABASE_KEY) return null;
  try {
    const url = new URL(SUPABASE_URL);
    if (url.protocol !== "https:" || !url.hostname.endsWith(".supabase.co")) return null;
    return url;
  } catch { return null; }
}
async function supabase(table, query = "", options = {}) {
  const base = getSupabaseConfig();
  if (!base) throw new Error("database_not_configured");
  const url = `${base.origin}/rest/v1/${encodeURIComponent(table)}${query ? `?${query}` : ""}`;
  let response;
  try {
    response = await fetch(url, {
      method: options.method || "GET",
      headers: {
        apikey: SUPABASE_KEY,
        // Modern sb_secret keys are sent only as `apikey`; legacy service_role JWTs also need Authorization.
        ...(LEGACY_SERVICE_ROLE_KEY && !SUPABASE_SECRET_KEY ? {Authorization:`Bearer ${LEGACY_SERVICE_ROLE_KEY}`} : {}),
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(options.prefer ? {Prefer:options.prefer} : {})
      },
      ...(options.body === undefined ? {} : {body:JSON.stringify(options.body)})
    });
  } catch (cause) {
    const error = new Error("database_unreachable", {cause});
    error.code = "database_unreachable";
    throw error;
  }
  const raw = await response.text();
  if (!response.ok) {
    const error = new Error("database_request_failed");
    error.status = response.status;
    throw error;
  }
  return raw ? JSON.parse(raw) : null;
}
function expectedSameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}
function secureCookie() { return IS_PRODUCTION ? "; Secure" : ""; }

const server = http.createServer(async (req, res) => {
  const hostForUrl = req.headers.host || `${HOST}:${PORT}`;
  let url;
  try { url = new URL(req.url, `http://${hostForUrl}`); }
  catch { return respond(res, 400, "Bad request"); }

  if (url.pathname.startsWith("/api/") && req.method !== "GET" && req.method !== "HEAD" && !expectedSameOrigin(req)) {
    return json(res, 403, {error:"origin_denied"});
  }

  if (url.pathname === "/api/health" && req.method === "GET") {
    return json(res, 200, {ok:true, databaseConfigured:Boolean(getSupabaseConfig()), adminConfigured:Boolean(ADMIN_CODE)});
  }

  if (url.pathname === "/api/database/health" && req.method === "GET") {
    if (!getSupabaseConfig()) return json(res, 503, {ok:false, error:"database_not_configured"});
    try {
      await supabase("users", "select=id&limit=1");
      return json(res, 200, {ok:true});
    } catch (error) {
      console.error("Supabase health check failed:", error.code || error.status || error.name || "unknown_error");
      return json(res, 503, {ok:false, error:error.code || "database_connection_failed"});
    }
  }

  if (url.pathname === "/api/auth/register" && req.method === "POST") {
    const ip = req.socket.remoteAddress || "unknown";
    if (hitRateLimit(ip)) return json(res, 429, {error:"too_many_attempts"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    try {
      const data = JSON.parse(await requestBody(req, 2048));
      const username = String(data.username || "").normalize("NFKC").trim();
      const personalCode = String(data.personalCode || "");
      if (!/^[\p{L}\p{N} _.-]{2,32}$/u.test(username)) return json(res, 400, {error:"invalid_username"});
      if (personalCode.length < 12 || personalCode.length > 128 || /\s/.test(personalCode)) return json(res, 400, {error:"invalid_personal_code"});
      const recoveryCodeHash = await hashPersonalCode(personalCode);
      const rows = await supabase("users", "select=id,username,diamonds,energy,status", {
        method:"POST",
        prefer:"return=representation",
        body:{username, recovery_code_hash:recoveryCodeHash, diamonds:100, energy:0, status:"active"}
      });
      const row = Array.isArray(rows) ? rows[0] : null;
      if (!row) return json(res, 503, {error:"account_creation_failed"});
      return json(res, 201, {ok:true, user:userDto(row)}, setUserSession(res, row.id));
    } catch (error) {
      if (error.status === 409) return json(res, 409, {error:"username_taken"});
      console.error("Account registration failed:", error.code || error.status || error.name || "unknown_error");
      if (error.code === "database_unreachable") return json(res, 503, {error:"database_unreachable"});
      if (error.status === 401 || error.status === 403) return json(res, 503, {error:"database_key_invalid"});
      if (error.status === 400 || error.status === 404) return json(res, 503, {error:"database_schema_error"});
      return json(res, 503, {error:"account_creation_failed"});
    }
  }

  if (url.pathname === "/api/auth/login" && req.method === "POST") {
    const ip = req.socket.remoteAddress || "unknown";
    if (hitRateLimit(ip)) return json(res, 429, {error:"too_many_attempts"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    try {
      const data = JSON.parse(await requestBody(req, 2048));
      const username = String(data.username || "").normalize("NFKC").trim();
      const personalCode = String(data.personalCode || "");
      if (!username || !personalCode || personalCode.length > 128) return json(res, 401, {error:"invalid_credentials"});
      const query = new URLSearchParams({select:"id,username,diamonds,energy,status,recovery_code_hash", username_normalized:`eq.${username.toLowerCase()}`, limit:"1"}).toString();
      const rows = await supabase("users", query);
      const row = Array.isArray(rows) ? rows[0] : null;
      if (!row || row.status !== "active" || !(await verifyPersonalCode(personalCode, row.recovery_code_hash))) return json(res, 401, {error:"invalid_credentials"});
      return json(res, 200, {ok:true, user:userDto(row)}, setUserSession(res, row.id));
    } catch {
      return json(res, 503, {error:"login_unavailable"});
    }
  }

  if (url.pathname === "/api/auth/session" && req.method === "GET") {
    const session = currentUserSession(req);
    if (!session) return json(res, 200, {authenticated:false});
    try {
      const query = new URLSearchParams({select:"id,username,diamonds,energy,status", id:`eq.${session.userId}`, limit:"1"}).toString();
      const rows = await supabase("users", query);
      const row = Array.isArray(rows) ? rows[0] : null;
      if (!row || row.status !== "active") return json(res, 200, {authenticated:false});
      return json(res, 200, {authenticated:true, user:userDto(row)});
    } catch {
      return json(res, 503, {error:"session_unavailable"});
    }
  }

  if (url.pathname === "/api/auth/logout" && req.method === "POST") {
    userSessions.delete(readCookie(req, "46p_user"));
    return json(res, 200, {ok:true}, {"Set-Cookie":`46p_user=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookie()}`});
  }

  if (url.pathname === "/api/admin/auth" && req.method === "POST") {
    const ip = req.socket.remoteAddress || "unknown";
    if (hitRateLimit(ip)) return json(res, 429, {error:"too_many_attempts"});
    if (!ADMIN_CODE) return json(res, 503, {error:"admin_access_not_configured"});
    try {
      const data = JSON.parse(await requestBody(req, 2048));
      if (!safeEqual(data.code || "", ADMIN_CODE)) return json(res, 401, {error:"invalid_code"});
      const token = crypto.randomBytes(32).toString("hex");
      sessions.set(token, Date.now() + SESSION_TTL);
      return json(res, 200, {ok:true}, {"Set-Cookie":`46p_admin=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${secureCookie()}`});
    } catch {
      return json(res, 400, {error:"invalid_request"});
    }
  }
  if (url.pathname === "/api/admin/logout" && req.method === "POST") {
    sessions.delete(readCookie(req, "46p_admin"));
    return json(res, 200, {ok:true}, {"Set-Cookie":`46p_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookie()}`});
  }
  if (url.pathname === "/api/admin/session" && req.method === "GET") return json(res, 200, {authenticated:isAdmin(req)});

  // Read endpoints use only the server-side secret key. Browser code never sees it.
  if (url.pathname === "/api/predictions" && req.method === "GET") {
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    try {
      const rows = await supabase("predictions", "select=id,title,description,category,image_url,source_url,yes_label,no_label,closes_at,min_diamonds,energy_per_diamond,status,outcome,created_at,resolved_at&order=created_at.desc");
      return json(res, 200, rows);
    } catch { return json(res, 503, {error:"database_unavailable"}); }
  }
  if (url.pathname === "/api/admin/predictions" && req.method === "GET") {
    if (!isAdmin(req)) return json(res, 401, {error:"admin_required"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    try {
      const rows = await supabase("predictions", "select=*,votes(id,user_id,choice,diamonds,created_at,users(username))&order=created_at.desc");
      return json(res, 200, rows);
    } catch { return json(res, 503, {error:"database_unavailable"}); }
  }

  if (url.pathname === "/api/admin/predictions" && req.method === "POST") {
    if (!isAdmin(req)) return json(res, 401, {error:"admin_required"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    try {
      const data = JSON.parse(await requestBody(req, 3 * 1024 * 1024));
      const title = String(data.title || "").trim();
      const deadline = new Date(data.closes_at);
      if (title.length < 3 || title.length > 240 || !Number.isFinite(deadline.getTime()) || deadline <= new Date()) return json(res, 400, {error:"invalid_prediction"});
      const rows = await supabase("predictions", "select=*", {method:"POST", prefer:"return=representation", body:{
        title, description:String(data.description || "").slice(0,5000), category:String(data.category || "Autre").slice(0,80),
        image_url:String(data.image_url || "").slice(0, 2_800_000) || null, source_url:String(data.source_url || "").slice(0,2000) || null,
        yes_label:String(data.yes_label || "Oui").slice(0,120), no_label:String(data.no_label || "Non").slice(0,120),
        closes_at:deadline.toISOString(), min_diamonds:Math.max(1, Math.floor(Number(data.min_diamonds)||1)), energy_per_diamond:Math.max(0, Number(data.energy_per_diamond)||0), status:"open"
      }});
      return json(res, 201, Array.isArray(rows) ? rows[0] : {});
    } catch { return json(res, 503, {error:"database_unavailable"}); }
  }
  if (url.pathname.startsWith("/api/admin/predictions/") && req.method === "DELETE") {
    if (!isAdmin(req)) return json(res, 401, {error:"admin_required"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    const predictionId = decodeURIComponent(url.pathname.slice("/api/admin/predictions/".length));
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(predictionId)) return json(res, 400, {error:"invalid_prediction_id"});
    try {
      const rows = await supabase("predictions", `id=eq.${predictionId}&status=neq.resolved`, {method:"PATCH",prefer:"return=representation",body:{status:"cancelled"}});
      if (!Array.isArray(rows) || !rows.length) return json(res, 404, {error:"prediction_not_found"});
      return json(res, 200, {ok:true});
    } catch { return json(res, 503, {error:"database_unavailable"}); }
  }

  if (url.pathname === "/api/admin/announcements" && req.method === "GET") {
    if (!isAdmin(req)) return json(res, 401, {error:"admin_required"});
    try { return json(res, 200, await supabase("announcements", "select=id,title,message,image_url,video_url,created_at&order=created_at.desc")); }
    catch { return json(res, 503, {error:"database_unavailable"}); }
  }
  if (url.pathname === "/api/admin/announcements" && req.method === "POST") {
    if (!isAdmin(req)) return json(res, 401, {error:"admin_required"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    try {
      const data = JSON.parse(await requestBody(req, 2 * 1024 * 1024));
      const title = String(data.title || "").trim(), message = String(data.message || "").trim();
      const image = String(data.image_url || ""), video = String(data.video_url || "");
      if (!title || title.length > 160 || message.length > 5000 || image.length > 1_500_000 || video.length > 2000) return json(res, 400, {error:"invalid_announcement"});
      const inserted = await supabase("announcements", "select=id,title,message,image_url,video_url,created_at", {method:"POST",prefer:"return=representation",body:{title,message,image_url:image||null,video_url:video||null}});
      const announcement = Array.isArray(inserted) ? inserted[0] : null;
      if (!announcement) return json(res, 503, {error:"announcement_failed"});
      const people = await supabase("users", "select=id&status=eq.active&limit=10000");
      if (Array.isArray(people) && people.length) {
        const notifications = people.map(person => ({user_id:person.id,announcement_id:announcement.id,kind:"announcement",title,message}));
        for (let offset=0; offset<notifications.length; offset+=500) await supabase("notifications", "", {method:"POST",prefer:"return=minimal",body:notifications.slice(offset,offset+500)});
      }
      return json(res, 201, announcement);
    } catch { return json(res, 503, {error:"announcement_failed"}); }
  }
  if (url.pathname === "/api/notifications" && req.method === "GET") {
    const session = currentUserSession(req);
    if (!session) return json(res, 401, {error:"login_required"});
    try {
      const notifications = await supabase("notifications", `select=id,title,message,created_at,announcement_id&user_id=eq.${session.userId}&order=created_at.desc&limit=200`);
      const ids = [...new Set((notifications||[]).map(x=>x.announcement_id).filter(Boolean))];
      const announcements = ids.length ? await supabase("announcements", `select=id,image_url,video_url&id=in.(${ids.join(",")})`) : [];
      const byId = new Map((announcements||[]).map(x=>[x.id,x]));
      return json(res, 200, (notifications||[]).map(x=>({...x,...(byId.get(x.announcement_id)||{})})));
    } catch { return json(res, 503, {error:"notifications_unavailable"}); }
  }
  if (url.pathname === "/api/notifications/read" && req.method === "POST") {
    const session = currentUserSession(req);
    if (!session) return json(res, 401, {error:"login_required"});
    try {
      await supabase("notifications", `user_id=eq.${session.userId}&read_at=is.null`, {method:"PATCH",prefer:"return=minimal",body:{read_at:new Date().toISOString()}});
      return json(res, 200, {ok:true});
    } catch { return json(res, 503, {error:"notifications_unavailable"}); }
  }

  if (url.pathname === "/api/admin/users" && req.method === "GET") {
    if (!isAdmin(req)) return json(res, 401, {error:"admin_required"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    try {
      // JD was the explicitly identified trial account; mark it inactive once so it cannot log in or appear in admin lists.
      const trialRows = await supabase("users", "select=id&username_normalized=eq.jd&status=eq.active&limit=1");
      if (Array.isArray(trialRows) && trialRows[0]) {
        await supabase("users", `id=eq.${trialRows[0].id}&status=eq.active`, {method:"PATCH",prefer:"return=minimal",body:{status:"deleted"}});
      }
      const rows = await supabase("users", "select=id,username,diamonds,energy,status,created_at&status=neq.deleted&order=created_at.desc");
      return json(res, 200, Array.isArray(rows) ? rows : []);
    } catch { return json(res, 503, {error:"database_unavailable"}); }
  }
  if (url.pathname.startsWith("/api/admin/users/") && url.pathname.endsWith("/recovery-code") && req.method === "POST") {
    if (!isAdmin(req)) return json(res, 401, {error:"admin_required"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    const userId = decodeURIComponent(url.pathname.slice("/api/admin/users/".length, -"/recovery-code".length));
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId)) return json(res, 400, {error:"invalid_user_id"});
    try {
      const accounts = await supabase("users", `select=id,username&id=eq.${userId}&status=eq.active&limit=1`);
      if (!Array.isArray(accounts) || !accounts[0]) return json(res, 404, {error:"user_not_found"});
      const temporaryCode = crypto.randomBytes(18).toString("base64url");
      const recoveryCodeHash = await hashPersonalCode(temporaryCode);
      const updated = await supabase("users", `id=eq.${userId}&status=eq.active`, {method:"PATCH",prefer:"return=representation",body:{recovery_code_hash:recoveryCodeHash}});
      if (!Array.isArray(updated) || !updated.length) return json(res, 404, {error:"user_not_found"});
      try { await supabase("admin_audit_log", "", {method:"POST",prefer:"return=minimal",body:{action:"recovery_code_reset",target_type:"user",target_id:userId,details:{username:accounts[0].username}}}); } catch { console.error("Recovery reset audit entry failed"); }
      return json(res, 200, {ok:true,username:accounts[0].username,temporaryCode});
    } catch { return json(res, 503, {error:"recovery_reset_failed"}); }
  }
  if (url.pathname.startsWith("/api/admin/users/") && req.method === "DELETE") {
    if (!isAdmin(req)) return json(res, 401, {error:"admin_required"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    const userId = decodeURIComponent(url.pathname.slice("/api/admin/users/".length));
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId)) return json(res, 400, {error:"invalid_user_id"});
    try {
      const rows = await supabase("users", `id=eq.${userId}&status=eq.active`, {method:"PATCH",prefer:"return=representation",body:{status:"deleted"}});
      if (!Array.isArray(rows) || !rows.length) return json(res, 404, {error:"user_not_found"});
      return json(res, 200, {ok:true});
    } catch { return json(res, 503, {error:"database_unavailable"}); }
  }
  if (url.pathname === "/api/admin/users/balance" && req.method === "POST") {
    if (!isAdmin(req)) return json(res, 401, {error:"admin_required"});
    if (!getSupabaseConfig()) return json(res, 503, {error:"database_not_configured"});
    try {
      const data = JSON.parse(await requestBody(req, 4096));
      const userId = String(data.userId || ""), currency = String(data.currency || ""), amount = Math.trunc(Number(data.amount)), reason = String(data.reason || "").trim();
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId) || !["diamonds","energy"].includes(currency) || !Number.isSafeInteger(amount) || amount === 0 || Math.abs(amount) > 1000000 || !reason || reason.length > 240) return json(res, 400, {error:"invalid_adjustment"});
      // Read the selected account, then apply the change and keep a ledger entry.
      const accounts = await supabase("users", `select=id,username,diamonds,energy,status&id=eq.${userId}&status=eq.active&limit=1`);
      const account = Array.isArray(accounts) ? accounts[0] : null;
      if (!account) return json(res, 404, {error:"user_not_found"});
      const next = Number(account[currency]) + amount;
      if (!Number.isSafeInteger(next) || next < 0 || next > 2147483647) return json(res, 400, {error:"invalid_balance"});
      const updated = await supabase("users", `id=eq.${userId}&${currency}=eq.${account[currency]}`, {method:"PATCH",prefer:"return=representation",body:{[currency]:next}});
      if (!Array.isArray(updated) || !updated.length) return json(res, 409, {error:"balance_changed"});
      await supabase("wallet_transactions", "", {method:"POST",prefer:"return=minimal",body:{user_id:userId,currency,amount,reason:"admin_adjustment"}});
      await supabase("admin_audit_log", "", {method:"POST",prefer:"return=minimal",body:{action:"balance_adjustment",target_type:"user",target_id:userId,details:{currency,amount,reason}}});
      return json(res, 200, {ok:true,user:updated[0]});
    } catch { return json(res, 503, {error:"adjustment_failed"}); }
  }

  if (req.method !== "GET" && req.method !== "HEAD") return respond(res, 405, "Method not allowed");
  let pathname;
  try { pathname = decodeURIComponent(url.pathname); } catch { return respond(res, 400, "Bad request"); }
  if (pathname === "/") pathname = "/index.html";
  const basename = path.basename(pathname);
  if (basename.startsWith(".") || basename === "server.js" || basename === "start-46prediction.bat" || basename === ".env.example") return respond(res, 404, "Not found");
  if (basename.startsWith("admin") && basename.endsWith(".html") && !isAdmin(req)) {
    res.writeHead(302, {"Location":"/","Cache-Control":"no-store"});
    return res.end();
  }
  const target = path.resolve(ROOT, "." + pathname);
  const relative = path.relative(ROOT, target);
  if (relative.startsWith("..") || path.isAbsolute(relative) || !fs.existsSync(target) || !fs.statSync(target).isFile()) return respond(res, 404, "Not found");
  const type = MIME[path.extname(target).toLowerCase()] || "application/octet-stream";
  res.writeHead(200, {"Content-Type":type,"Cache-Control":"no-cache","X-Content-Type-Options":"nosniff"});
  if (req.method === "HEAD") return res.end();
  fs.createReadStream(target).pipe(res);
});

server.listen(PORT, HOST, () => {
  console.log(`46 Prediction server listening on ${HOST}:${PORT}`);
  console.log(`Supabase database: ${getSupabaseConfig() ? "configured" : "not yet configured"}`);
  console.log(`Admin code: ${ADMIN_CODE ? "configured" : "missing (required in production)"}`);
});
