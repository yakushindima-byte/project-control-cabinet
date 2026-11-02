/* PROJECT CONTROL PRO — сервер личного кабинета.
   Express + PostgreSQL. Данные компании хранятся одним JSON-документом, правки приходят операциями. */
"use strict";
const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const http = require("http");
const https = require("https");
const tls = require("tls");
const TEMPLATE = require("./template.json");

const PORT = +process.env.PORT || 8080;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_DAYS = 30;
const INVITE_DAYS = 7;
const MAX_DOC = 5 * 1024 * 1024;

/* ---------- база */
function poolConfig() {
  const ssl = process.env.PGSSL === "1" ? { rejectUnauthorized: false } : false;
  if (process.env.DATABASE_URL) return { connectionString: process.env.DATABASE_URL, ssl, max: 10 };
  return { ssl, max: 10 }; // PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE берутся из окружения
}
const pool = new Pool(poolConfig());
const q = (text, params) => pool.query(text, params);

async function migrate() {
  await q(`
  create table if not exists companies (
    id serial primary key, name text not null, access_until timestamptz not null,
    blocked boolean not null default false, note text, created_at timestamptz not null default now());
  create table if not exists users (
    id serial primary key, company_id int not null references companies(id) on delete cascade,
    email text not null unique, name text, pass text not null, role text not null default 'member',
    created_at timestamptz not null default now(), last_login timestamptz);
  create table if not exists sessions (
    token_hash text primary key, user_id int references users(id) on delete cascade,
    is_admin boolean not null default false, expires timestamptz not null);
  create table if not exists codes (
    code text primary key, days int not null, note text, created_at timestamptz not null default now(),
    used_at timestamptz, used_by int references companies(id) on delete set null);
  create table if not exists invites (
    token_hash text primary key, company_id int not null references companies(id) on delete cascade,
    created_by int, created_at timestamptz not null default now(), expires timestamptz not null, used_at timestamptz);
  create table if not exists company_data (
    company_id int primary key references companies(id) on delete cascade, data jsonb not null,
    version int not null default 1, updated_at timestamptz not null default now(), updated_by int);
  create table if not exists orders (
    id serial primary key, order_id text not null unique, kind text not null, company_id int references companies(id) on delete set null,
    days int not null, amount int not null, email text, name text, company_name text, pass text, client_hash text,
    status text not null default 'new', bank_status text, payment_id text, code text,
    created_at timestamptz not null default now(), paid_at timestamptz);
  create index if not exists users_company on users(company_id);
  create index if not exists sessions_user on sessions(user_id);`);
}

/* ---------- утилиты */
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const token = (n = 32) => crypto.randomBytes(n).toString("base64url");
function hashPass(p) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(p, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString("hex")}$${h.toString("hex")}`;
}
function checkPass(p, stored) {
  const [alg, salt, h] = String(stored).split("$");
  if (alg !== "scrypt") return false;
  const x = crypto.scryptSync(p, Buffer.from(salt, "hex"), 64, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(x, Buffer.from(h, "hex"));
}
const CODE_ABC = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function newCode() { let s = ""; const b = crypto.randomBytes(8); for (let i = 0; i < 8; i++) s += CODE_ABC[b[i] % CODE_ABC.length]; return `PCP-${s.slice(0, 4)}-${s.slice(4)}`; }
const normCode = c => String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/^PCP/, "").replace(/^(.{4})(.{4})$/, "PCP-$1-$2");
const normEmail = e => String(e || "").trim().toLowerCase();
const okEmail = e => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e);
const str = (v, n = 200) => String(v ?? "").trim().slice(0, n);
class HttpErr extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const fail = (code, msg) => { throw new HttpErr(code, msg); };

/* простое ограничение попыток входа */
const tries = new Map();
function limit(key, max = 10, ms = 15 * 60 * 1000) {
  const now = Date.now(), t = tries.get(key) || { n: 0, at: now };
  if (now - t.at > ms) { t.n = 0; t.at = now; }
  t.n++; tries.set(key, t);
  if (t.n > max) fail(429, "Слишком много попыток. Подождите 15 минут.");
}
setInterval(() => { const now = Date.now(); for (const [k, t] of tries) if (now - t.at > 3600e3) tries.delete(k); }, 600e3).unref();

/* ---------- приложение */
const app = express();
app.set("trust proxy", true);
app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));
app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "same-origin");
  res.set("X-Frame-Options", "DENY");
  next();
});
// защита от подделки запросов: все изменения — только из наших страниц
app.use("/api", (req, res, next) => {
  if (req.method !== "GET" && req.path !== "/pay/notify" && req.get("X-PCP") !== "1") return res.status(403).json({ error: "Запрос отклонён" });
  res.set("Cache-Control", "no-store");
  next();
});

function setCookie(req, res, name, val, days) {
  const secure = req.secure || req.get("x-forwarded-proto") === "https";
  res.cookie(name, val, { httpOnly: true, sameSite: "lax", secure, path: "/", maxAge: days * 864e5 });
}
function cookie(req, name) {
  const m = (req.get("cookie") || "").split(/;\s*/).find(x => x.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : "";
}
async function newSession(req, res, userId, isAdmin) {
  const t = token();
  await q("insert into sessions(token_hash,user_id,is_admin,expires) values($1,$2,$3,now()+($4||' days')::interval)", [sha(t), userId, isAdmin, String(isAdmin ? 1 : SESSION_DAYS)]);
  setCookie(req, res, isAdmin ? "pcp_admin" : "pcp_sid", t, isAdmin ? 1 : SESSION_DAYS);
}

const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const auth = wrap(async (req, res, next) => {
  const t = cookie(req, "pcp_sid");
  if (!t) fail(401, "Войдите в кабинет");
  const r = await q(`select u.id, u.email, u.name, u.role, u.company_id, c.name as company, c.access_until, c.blocked
                     from sessions s join users u on u.id=s.user_id join companies c on c.id=u.company_id
                     where s.token_hash=$1 and s.expires>now() and not s.is_admin`, [sha(t)]);
  if (!r.rowCount) fail(401, "Сессия закончилась, войдите снова");
  const u = r.rows[0];
  u.active = !u.blocked && new Date(u.access_until) > new Date();
  req.user = u; next();
});
const owner = (req, res, next) => req.user.role === "owner" ? next() : next(new HttpErr(403, "Доступно только владельцу кабинета"));
const admin = wrap(async (req, res, next) => {
  const t = cookie(req, "pcp_admin");
  if (!t) fail(401, "Нужен вход администратора");
  const r = await q("select 1 from sessions where token_hash=$1 and is_admin and expires>now()", [sha(t)]);
  if (!r.rowCount) fail(401, "Нужен вход администратора");
  next();
});

/* ---------- регистрация и вход */
function checkNewUser(b) {
  const email = normEmail(b.email), password = String(b.password || ""), name = str(b.name, 100);
  if (!okEmail(email)) fail(400, "Проверьте адрес почты");
  if (password.length < 8) fail(400, "Пароль — не короче 8 символов");
  if (password.length > 200) fail(400, "Слишком длинный пароль");
  if (!name) fail(400, "Укажите имя");
  if (b.consent !== true) fail(400, "Нужно согласие на обработку персональных данных");
  return { email, password, name };
}

app.post("/api/register", wrap(async (req, res) => {
  limit("reg:" + req.ip, 20);
  const { email, password, name } = checkNewUser(req.body);
  const company = str(req.body.company, 150);
  if (!company) fail(400, "Укажите название компании");
  const code = normCode(req.body.code);
  const c = await pool.connect();
  try {
    await c.query("begin");
    const k = await c.query("select * from codes where code=$1 for update", [code]);
    if (!k.rowCount) fail(400, "Код не найден. Проверьте, что он введён без ошибок");
    if (k.rows[0].used_at) fail(400, "Этот код уже использован");
    if ((await c.query("select 1 from users where email=$1", [email])).rowCount) fail(400, "Такая почта уже зарегистрирована — войдите");
    const co = await c.query("insert into companies(name,access_until,note) values($1, now()+($2||' days')::interval, $3) returning id", [company, String(k.rows[0].days), k.rows[0].note]);
    const cid = co.rows[0].id;
    const u = await c.query("insert into users(company_id,email,name,pass,role,last_login) values($1,$2,$3,$4,'owner',now()) returning id", [cid, email, name, hashPass(password)]);
    const data = JSON.parse(JSON.stringify(TEMPLATE)); data.settings.company = company;
    await c.query("insert into company_data(company_id,data,updated_by) values($1,$2,$3)", [cid, data, u.rows[0].id]);
    await c.query("update codes set used_at=now(), used_by=$1 where code=$2", [cid, code]);
    await c.query("commit");
    await newSession(req, res, u.rows[0].id, false);
    res.json({ ok: true });
  } catch (e) { await c.query("rollback").catch(() => {}); throw e; } finally { c.release(); }
}));

app.post("/api/join", wrap(async (req, res) => {
  limit("join:" + req.ip, 20);
  const { email, password, name } = checkNewUser(req.body);
  const th = sha(String(req.body.invite || ""));
  const c = await pool.connect();
  try {
    await c.query("begin");
    const i = await c.query("select * from invites where token_hash=$1 for update", [th]);
    if (!i.rowCount || i.rows[0].used_at || new Date(i.rows[0].expires) < new Date()) fail(400, "Приглашение недействительно или устарело. Попросите новое");
    if ((await c.query("select 1 from users where email=$1", [email])).rowCount) fail(400, "Такая почта уже зарегистрирована");
    const u = await c.query("insert into users(company_id,email,name,pass,role,last_login) values($1,$2,$3,$4,'member',now()) returning id", [i.rows[0].company_id, email, name, hashPass(password)]);
    await c.query("update invites set used_at=now() where token_hash=$1", [th]);
    await c.query("commit");
    await newSession(req, res, u.rows[0].id, false);
    res.json({ ok: true });
  } catch (e) { await c.query("rollback").catch(() => {}); throw e; } finally { c.release(); }
}));

app.get("/api/invite-info", wrap(async (req, res) => {
  const r = await q("select c.name from invites i join companies c on c.id=i.company_id where i.token_hash=$1 and i.used_at is null and i.expires>now()", [sha(String(req.query.t || ""))]);
  if (!r.rowCount) fail(404, "Приглашение недействительно или устарело");
  res.json({ company: r.rows[0].name });
}));

app.post("/api/login", wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  limit("login:" + req.ip, 30); limit("login:" + email, 10);
  const r = await q("select id, pass from users where email=$1", [email]);
  if (!r.rowCount || !checkPass(String(req.body.password || ""), r.rows[0].pass)) fail(400, "Неверная почта или пароль");
  await q("update users set last_login=now() where id=$1", [r.rows[0].id]);
  await newSession(req, res, r.rows[0].id, false);
  res.json({ ok: true });
}));

app.post("/api/logout", wrap(async (req, res) => {
  const t = cookie(req, "pcp_sid");
  if (t) await q("delete from sessions where token_hash=$1", [sha(t)]);
  res.clearCookie("pcp_sid", { path: "/" });
  res.json({ ok: true });
}));

app.get("/api/me", auth, (req, res) => {
  const u = req.user;
  res.json({ id: u.id, email: u.email, name: u.name, role: u.role, company: u.company, accessUntil: u.access_until, blocked: u.blocked, active: u.active });
});

app.post("/api/password", auth, wrap(async (req, res) => {
  limit("pw:" + req.user.id, 10);
  const r = await q("select pass from users where id=$1", [req.user.id]);
  if (!checkPass(String(req.body.old || ""), r.rows[0].pass)) fail(400, "Текущий пароль указан неверно");
  const p = String(req.body.password || "");
  if (p.length < 8 || p.length > 200) fail(400, "Новый пароль — не короче 8 символов");
  await q("update users set pass=$1 where id=$2", [hashPass(p), req.user.id]);
  await q("delete from sessions where user_id=$1 and token_hash<>$2", [req.user.id, sha(cookie(req, "pcp_sid"))]);
  res.json({ ok: true });
}));

/* ---------- команда и продление */
app.get("/api/team", auth, wrap(async (req, res) => {
  const r = await q("select id, email, name, role, created_at, last_login from users where company_id=$1 order by role desc, created_at", [req.user.company_id]);
  res.json({ members: r.rows, me: req.user.id });
}));
app.post("/api/team/invite", auth, owner, wrap(async (req, res) => {
  const n = await q("select count(*)::int n from invites where company_id=$1 and created_at>now()-interval '1 day'", [req.user.company_id]);
  if (n.rows[0].n >= 30) fail(429, "Слишком много приглашений за сутки");
  const t = token(18);
  await q("insert into invites(token_hash,company_id,created_by,expires) values($1,$2,$3,now()+($4||' days')::interval)", [sha(t), req.user.company_id, req.user.id, String(INVITE_DAYS)]);
  res.json({ token: t, days: INVITE_DAYS });
}));
app.delete("/api/team/:id", auth, owner, wrap(async (req, res) => {
  const id = +req.params.id;
  if (id === req.user.id) fail(400, "Нельзя удалить самого себя");
  const r = await q("delete from users where id=$1 and company_id=$2 and role<>'owner'", [id, req.user.company_id]);
  if (!r.rowCount) fail(404, "Сотрудник не найден");
  res.json({ ok: true });
}));
app.post("/api/redeem", auth, owner, wrap(async (req, res) => {
  limit("redeem:" + req.user.company_id, 10);
  const code = normCode(req.body.code);
  const c = await pool.connect();
  try {
    await c.query("begin");
    const k = await c.query("select * from codes where code=$1 for update", [code]);
    if (!k.rowCount) fail(400, "Код не найден");
    if (k.rows[0].used_at) fail(400, "Этот код уже использован");
    const r = await c.query("update companies set access_until=greatest(access_until, now())+($1||' days')::interval where id=$2 returning access_until", [String(k.rows[0].days), req.user.company_id]);
    await c.query("update codes set used_at=now(), used_by=$1 where code=$2", [req.user.company_id, code]);
    await c.query("commit");
    res.json({ accessUntil: r.rows[0].access_until, days: k.rows[0].days });
  } catch (e) { await c.query("rollback").catch(() => {}); throw e; } finally { c.release(); }
}));

/* ---------- данные */
app.get("/api/data", auth, wrap(async (req, res) => {
  const r = await q("select data, version from company_data where company_id=$1", [req.user.company_id]);
  res.json({ data: r.rows[0].data, version: r.rows[0].version, readonly: !req.user.active });
}));
app.get("/api/version", auth, wrap(async (req, res) => {
  const r = await q("select version from company_data where company_id=$1", [req.user.company_id]);
  res.json({ version: r.rows[0].version, readonly: !req.user.active });
}));

const ARR_RE = /^(projects|budget|payments|purchases|repl|stages|works|kp\.fot|kp\.blocks\.[0-3]\.rows)$/;
const KEY_RE = /^[A-Za-z][A-Za-z0-9_]{0,30}$/;
const SETTINGS_KEYS = new Set(["company", "repDate", "startCash", "startDate", "target", "crit", "tax", "horizon", "lagTol", "ganttStart"]);
const KP_KEYS = new Set(["obj", "cust", "link", "s", "e", "nmck", "vat", "price", "ins", "reserve"]);
const LISTS = new Set(["systems", "cost", "stages", "exec", "contr", "units", "pms", "reasons", "delays"]);
function val(v) {
  if (v === null || v === undefined || v === "") return undefined;
  if (typeof v === "number") { if (!Number.isFinite(v)) fail(400, "Неверное число"); return v; }
  if (typeof v === "string") return v.slice(0, 1000);
  fail(400, "Неверное значение");
}
function arrAt(doc, p) {
  if (!ARR_RE.test(p)) fail(400, "Неизвестная таблица");
  const a = p.split(".").reduce((o, k) => (o == null ? o : o[k]), doc);
  if (!Array.isArray(a)) fail(400, "Таблица не найдена");
  return a;
}
const okId = id => typeof id === "string" && /^[A-Za-z0-9_-]{4,40}$/.test(id);
function applyOp(doc, op) {
  switch (op && op.t) {
    case "set": {
      const a = arrAt(doc, op.a), row = a.find(r => r._id === op.id);
      if (!row) return; // строку уже удалили — правка не нужна
      if (!KEY_RE.test(op.k)) fail(400, "Неверное поле");
      const v = val(op.v); if (v === undefined) delete row[op.k]; else row[op.k] = v;
      return;
    }
    case "add": {
      const a = arrAt(doc, op.a);
      if (a.length >= 5000) fail(400, "Слишком много строк");
      const src = op.row || {}, row = {};
      if (!okId(src._id)) fail(400, "Неверная строка");
      if (a.some(r => r._id === src._id)) return;
      row._id = src._id;
      for (const [k, v0] of Object.entries(src)) { if (k === "_id") continue; if (!KEY_RE.test(k)) fail(400, "Неверное поле"); const v = val(v0); if (v !== undefined) row[k] = v; }
      if (op.at === "start") a.unshift(row); else a.push(row);
      return;
    }
    case "del": {
      const a = arrAt(doc, op.a), i = a.findIndex(r => r._id === op.id);
      if (i >= 0) a.splice(i, 1);
      return;
    }
    case "obj": {
      const keys = op.o === "settings" ? SETTINGS_KEYS : op.o === "kp" ? KP_KEYS : null;
      if (!keys || !keys.has(op.k)) fail(400, "Неверный параметр");
      const v = val(op.v), obj = doc[op.o];
      if (v === undefined) obj[op.k] = ""; else obj[op.k] = v;
      return;
    }
    case "list": case "listDel": {
      if (!LISTS.has(op.l)) fail(400, "Неверный справочник");
      const v = str(op.v, 150); if (!v) return;
      const L = doc.lists[op.l] || (doc.lists[op.l] = []);
      if (op.t === "list") { if (!L.includes(v) && L.length < 500) L.push(v); }
      else { const i = L.indexOf(v); if (i >= 0) L.splice(i, 1); }
      return;
    }
    default: fail(400, "Неизвестная операция");
  }
}
app.post("/api/ops", auth, wrap(async (req, res) => {
  if (!req.user.active) fail(403, req.user.blocked ? "Доступ приостановлен" : "Доступ закончился — продлите его, чтобы вносить изменения");
  const ops = req.body.ops;
  if (!Array.isArray(ops) || !ops.length || ops.length > 500) fail(400, "Нет изменений");
  const c = await pool.connect();
  try {
    await c.query("begin");
    const r = await c.query("select data, version from company_data where company_id=$1 for update", [req.user.company_id]);
    const doc = r.rows[0].data;
    ops.forEach(op => applyOp(doc, op));
    const json = JSON.stringify(doc);
    if (json.length > MAX_DOC) fail(400, "Слишком много данных в кабинете");
    const u = await c.query("update company_data set data=$1, version=version+1, updated_at=now(), updated_by=$2 where company_id=$3 returning version", [json, req.user.id, req.user.company_id]);
    await c.query("commit");
    res.json({ version: u.rows[0].version, prev: r.rows[0].version });
  } catch (e) { await c.query("rollback").catch(() => {}); throw e; } finally { c.release(); }
}));


/* ---------- оплата через интернет-эквайринг Т-Банка */
const TB = {
  key: process.env.TBANK_TERMINAL_KEY || "", pass: process.env.TBANK_PASSWORD || "",
  api: (process.env.TBANK_API || "https://securepay.tinkoff.ru/v2").replace(/\/$/, ""),
  receipt: process.env.TBANK_RECEIPT === "1", taxation: process.env.TBANK_TAXATION || "usn_income",
  tax: process.env.TBANK_TAX || "none", ffd: process.env.TBANK_FFD || "1.2",
};
const SITE = (process.env.SITE_URL || "").replace(/\/$/, "");
function daysTitle(d) { if (d % 365 === 0) { const y = d / 365; return y === 1 ? "1 год" : `${y} ${y < 5 ? "года" : "лет"}`; } if (d % 30 === 0) { const m = d / 30; return m === 1 ? "1 месяц" : `${m} ${m < 5 ? "месяца" : "месяцев"}`; } return `${d} дн.`; }
const PLANS = String(process.env.PLANS || "").split(/[,;]/).map(x => x.trim()).filter(Boolean).map(x => {
  const [d, r, ...t] = x.split(":"); const days = Math.round(+d), rub = Math.round(+r);
  return days > 0 && rub > 0 ? { id: String(days), days, rub, title: t.join(":").trim() || daysTitle(days) } : null;
}).filter(Boolean);
const payOn = () => !!(TB.key && TB.pass && PLANS.length);
function tbToken(params) {
  const o = { Password: TB.pass };
  for (const [k, v] of Object.entries(params)) { if (k === "Token" || v === null || v === undefined || typeof v === "object") continue; o[k] = typeof v === "boolean" ? String(v) : String(v); }
  return crypto.createHash("sha256").update(Object.keys(o).sort().map(k => o[k]).join(""), "utf8").digest("hex");
}
// корневые сертификаты + сертификаты Минцифры, если Timeweb их установил
let CA = null;
for (const f of [process.env.TBANK_CA_FILE, "/usr/local/share/tci_node_ca_bundle.crt", "/usr/local/share/ca-certificates/russian-trusted/russian_trusted_ca_bundle.crt"]) {
  try { if (f && fs.existsSync(f)) { CA = [...tls.rootCertificates, fs.readFileSync(f, "utf8")]; break; } } catch (e) {}
}
function tbCall(method, body) {
  const b = { TerminalKey: TB.key, ...body }; b.Token = tbToken(b);
  const data = JSON.stringify(b), u = new URL(`${TB.api}/${method}`), mod = u.protocol === "http:" ? http : https;
  return new Promise((resolve, reject) => {
    const r = mod.request(u, { method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) }, timeout: 20000, ...(CA && u.protocol === "https:" ? { ca: CA } : {}) }, res => {
      let t = ""; res.on("data", c => t += c); res.on("end", () => { try { resolve(JSON.parse(t)); } catch (e) { reject(new Error("Банк вернул неожиданный ответ")); } });
    });
    r.on("timeout", () => r.destroy(new Error("Банк не ответил вовремя"))); r.on("error", reject); r.end(data);
  });
}
const siteOf = req => SITE || `${req.protocol}://${req.get("host")}`;
const newOrderId = () => `PCP-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
function planOf(id) { const p = PLANS.find(x => x.id === String(id)); if (!p) fail(400, "Выберите тариф"); return p; }

async function startPayment(req, res, o) {
  const amount = o.rub * 100;
  const init = {
    Amount: amount, OrderId: o.orderId, Description: `PROJECT CONTROL PRO: доступ на ${o.title}`.slice(0, 140),
    NotificationURL: `${siteOf(req)}/api/pay/notify`, SuccessURL: `${siteOf(req)}/pay.html?order=${o.orderId}`, FailURL: `${siteOf(req)}/pay.html?order=${o.orderId}&fail=1`,
  };
  if (TB.receipt) init.Receipt = { Email: o.email, Taxation: TB.taxation, FfdVersion: TB.ffd, Items: [{ Name: `Доступ к онлайн-сервису PROJECT CONTROL PRO на ${o.title}`.slice(0, 128), Price: amount, Quantity: 1, Amount: amount, Tax: TB.tax, PaymentMethod: "full_payment", PaymentObject: "service", ...(TB.ffd === "1.2" ? { MeasurementUnit: "шт" } : {}) }] };
  let r;
  try { r = await tbCall("Init", init); } catch (e) { console.error("Т-Банк Init:", e.message); await q("update orders set status='failed', bank_status=$1 where order_id=$2", ["INIT_ERROR", o.orderId]); fail(502, "Банк сейчас недоступен. Попробуйте через минуту"); }
  if (!r.Success || !r.PaymentURL) { console.error("Т-Банк Init отказ:", r.ErrorCode, r.Message, r.Details); await q("update orders set status='failed', bank_status=$1 where order_id=$2", [`INIT_${r.ErrorCode || "ERR"}`, o.orderId]); fail(502, `Банк отклонил платёж: ${r.Message || r.ErrorCode || "ошибка"}${r.Details ? ". " + r.Details : ""}`); }
  await q("update orders set payment_id=$1, bank_status=$2 where order_id=$3", [String(r.PaymentId), r.Status || "NEW", o.orderId]);
  res.json({ url: r.PaymentURL, order: o.orderId });
}

app.get("/api/pay/plans", (req, res) => res.json({ enabled: payOn(), plans: payOn() ? PLANS : [] }));

app.post("/api/pay/checkout-new", wrap(async (req, res) => {
  if (!payOn()) fail(503, "Оплата на сайте пока не подключена");
  limit("pay:" + req.ip, 20);
  const { email, password, name } = checkNewUser(req.body);
  const company = str(req.body.company, 150); if (!company) fail(400, "Укажите название компании");
  if (req.body.offer !== true) fail(400, "Нужно принять условия оферты");
  const p = planOf(req.body.plan);
  if ((await q("select 1 from users where email=$1", [email])).rowCount) fail(400, "Такая почта уже зарегистрирована — войдите и продлите доступ в кабинете");
  const orderId = newOrderId(), client = token(18);
  await q("insert into orders(order_id,kind,days,amount,email,name,company_name,pass,client_hash) values($1,'new',$2,$3,$4,$5,$6,$7,$8)", [orderId, p.days, p.rub * 100, email, name, company, hashPass(password), sha(client)]);
  setCookie(req, res, "pcp_order", client, 2);
  await startPayment(req, res, { orderId, rub: p.rub, title: p.title, email });
}));

app.post("/api/pay/checkout-renew", auth, owner, wrap(async (req, res) => {
  if (!payOn()) fail(503, "Оплата на сайте пока не подключена");
  limit("payr:" + req.user.company_id, 20);
  const p = planOf(req.body.plan), orderId = newOrderId();
  await q("insert into orders(order_id,kind,company_id,days,amount,email,name,company_name) values($1,'renew',$2,$3,$4,$5,$6,$7)", [orderId, req.user.company_id, p.days, p.rub * 100, req.user.email, req.user.name, req.user.company]);
  await startPayment(req, res, { orderId, rub: p.rub, title: p.title, email: req.user.email });
}));

const FAILED = new Set(["REJECTED", "CANCELED", "DEADLINE_EXPIRED", "AUTH_FAIL", "REVERSED", "REFUNDED", "PARTIAL_REFUNDED"]);
async function applyBankStatus(orderId, bankStatus, amount, paymentId) {
  const c = await pool.connect();
  try {
    await c.query("begin");
    const r = await c.query("select * from orders where order_id=$1 for update", [orderId]);
    if (!r.rowCount) { await c.query("rollback"); return "unknown"; }
    const o = r.rows[0];
    if (paymentId && o.payment_id && String(paymentId) !== String(o.payment_id)) { await c.query("rollback"); return "mismatch"; }
    if (o.status === "paid" || o.status === "paid_code") {
      if (FAILED.has(bankStatus) && /REFUND|REVERS/.test(bankStatus)) await c.query("update orders set bank_status=$1 where id=$2", [bankStatus, o.id]); // возврат — видно в админке
      await c.query("commit"); return o.status;
    }
    if (bankStatus === "CONFIRMED") {
      if (amount != null && +amount !== o.amount) { console.error("Сумма не совпала", orderId, amount, o.amount); await c.query("update orders set bank_status='AMOUNT_MISMATCH' where id=$1", [o.id]); await c.query("commit"); return "mismatch"; }
      let status = "paid", companyId = o.company_id, code = null;
      if (o.kind === "new") {
        const exists = (await c.query("select 1 from users where email=$1", [o.email])).rowCount;
        if (exists) { code = newCode(); await c.query("insert into codes(code,days,note) values($1,$2,$3)", [code, o.days, `Оплата ${o.order_id}: почта уже была зарегистрирована`]); status = "paid_code"; }
        else {
          const co = await c.query("insert into companies(name,access_until,note) values($1, now()+($2||' days')::interval, $3) returning id", [o.company_name, String(o.days), `Оплата на сайте ${o.order_id}`]);
          companyId = co.rows[0].id;
          const u = await c.query("insert into users(company_id,email,name,pass,role) values($1,$2,$3,$4,'owner') returning id", [companyId, o.email, o.name, o.pass]);
          const data = JSON.parse(JSON.stringify(TEMPLATE)); data.settings.company = o.company_name;
          await c.query("insert into company_data(company_id,data,updated_by) values($1,$2,$3)", [companyId, data, u.rows[0].id]);
        }
      } else {
        await c.query("update companies set access_until=greatest(access_until, now())+($1||' days')::interval where id=$2", [String(o.days), o.company_id]);
      }
      await c.query("update orders set status=$1, bank_status='CONFIRMED', paid_at=now(), company_id=$2, code=$3, pass=null where id=$4", [status, companyId, code, o.id]);
      await c.query("commit"); return status;
    }
    if (FAILED.has(bankStatus)) await c.query("update orders set status='failed', bank_status=$1 where id=$2", [bankStatus, o.id]);
    else await c.query("update orders set bank_status=$1 where id=$2", [bankStatus, o.id]);
    await c.query("commit"); return FAILED.has(bankStatus) ? "failed" : o.status;
  } catch (e) { await c.query("rollback").catch(() => {}); throw e; } finally { c.release(); }
}

app.post("/api/pay/notify", wrap(async (req, res) => {
  const b = req.body || {};
  const given = String(b.Token || ""), want = tbToken(b);
  if (!TB.pass || b.TerminalKey !== TB.key || given.length !== want.length || !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(want))) {
    console.error("Уведомление с неверной подписью", b.OrderId); return res.status(400).type("text").send("BAD TOKEN");
  }
  await applyBankStatus(String(b.OrderId || ""), String(b.Status || ""), b.Amount, b.PaymentId);
  res.type("text").send("OK");
}));

app.get("/api/pay/status", wrap(async (req, res) => {
  let r = await q("select * from orders where order_id=$1", [str(req.query.order, 60)]);
  if (!r.rowCount) fail(404, "Заказ не найден");
  let o = r.rows[0];
  // уведомление от банка могло задержаться — уточняем статус сами
  if (o.status === "new" && o.payment_id && Date.now() - new Date(o.created_at) > 4000) {
    try { const g = await tbCall("GetState", { PaymentId: o.payment_id }); if (g.Success && g.OrderId === o.order_id) { await applyBankStatus(o.order_id, g.Status, g.Amount, g.PaymentId); o = (await q("select * from orders where id=$1", [o.id])).rows[0]; } } catch (e) { console.error("Т-Банк GetState:", e.message); }
  }
  const mine = o.client_hash && sha(cookie(req, "pcp_order")) === o.client_hash;
  const out = { status: o.status === "paid_code" ? "paid" : o.status, kind: o.kind, days: o.days, amount: o.amount / 100 };
  if (o.company_id) { const c = await q("select access_until from companies where id=$1", [o.company_id]); if (c.rowCount) out.accessUntil = c.rows[0].access_until; }
  if (o.status === "paid_code" && mine) out.code = o.code;
  if (o.status === "paid" && o.kind === "new" && mine) {
    const u = await q("select id from users where email=$1 and company_id=$2", [o.email, o.company_id]);
    if (u.rowCount) { await newSession(req, res, u.rows[0].id, false); await q("update users set last_login=now() where id=$1", [u.rows[0].id]); out.loggedIn = true; }
    await q("update orders set client_hash=null where id=$1", [o.id]); res.clearCookie("pcp_order", { path: "/" });
  }
  res.json(out);
}));

/* ---------- админка */
app.post("/api/admin/login", wrap(async (req, res) => {
  limit("admin:" + req.ip, 8);
  if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 10) fail(503, "Пароль администратора не задан в переменной ADMIN_PASSWORD (не короче 10 символов)");
  const a = Buffer.from(sha(String(req.body.password || ""))), b = Buffer.from(sha(ADMIN_PASSWORD));
  if (!crypto.timingSafeEqual(a, b)) fail(400, "Неверный пароль");
  await newSession(req, res, null, true);
  res.json({ ok: true });
}));
app.post("/api/admin/logout", wrap(async (req, res) => {
  const t = cookie(req, "pcp_admin"); if (t) await q("delete from sessions where token_hash=$1", [sha(t)]);
  res.clearCookie("pcp_admin", { path: "/" }); res.json({ ok: true });
}));
app.get("/api/admin/overview", admin, wrap(async (req, res) => {
  const co = await q(`select c.id, c.name, c.access_until, c.blocked, c.note, c.created_at, d.updated_at,
      (select count(*)::int from users u where u.company_id=c.id) users,
      (select max(last_login) from users u where u.company_id=c.id) last_login,
      (select email from users u where u.company_id=c.id and role='owner' order by id limit 1) owner_email
      from companies c left join company_data d on d.company_id=c.id order by c.created_at desc`);
  const us = await q("select id, company_id, email, name, role, last_login from users order by company_id, role desc, id");
  const codes = await q("select k.code, k.days, k.note, k.created_at, k.used_at, c.name company from codes k left join companies c on c.id=k.used_by order by k.created_at desc limit 300");
  const orders = await q("select order_id, kind, days, amount, email, company_name, status, bank_status, code, created_at, paid_at from orders order by created_at desc limit 300");
  res.json({ companies: co.rows, users: us.rows, codes: codes.rows, orders: orders.rows, pay: { enabled: payOn(), plans: PLANS, receipt: TB.receipt, test: /DEMO$/i.test(TB.key) } });
}));
app.post("/api/admin/codes", admin, wrap(async (req, res) => {
  const days = Math.round(+req.body.days), count = Math.round(+req.body.count || 1), note = str(req.body.note, 200);
  if (!(days >= 1 && days <= 3660)) fail(400, "Срок — от 1 до 3660 дней");
  if (!(count >= 1 && count <= 50)) fail(400, "За раз — от 1 до 50 кодов");
  const out = [];
  for (let i = 0; i < count; i++) { const c = newCode(); await q("insert into codes(code,days,note) values($1,$2,$3)", [c, days, note]); out.push(c); }
  res.json({ codes: out });
}));
app.delete("/api/admin/codes/:code", admin, wrap(async (req, res) => {
  const r = await q("delete from codes where code=$1 and used_at is null", [normCode(req.params.code)]);
  if (!r.rowCount) fail(404, "Код не найден или уже использован");
  res.json({ ok: true });
}));
app.post("/api/admin/companies/:id", admin, wrap(async (req, res) => {
  const id = +req.params.id, b = req.body;
  if (b.addDays) await q("update companies set access_until=greatest(access_until, now())+($1||' days')::interval where id=$2", [String(Math.round(+b.addDays)), id]);
  if (b.accessUntil) { const d = new Date(b.accessUntil + "T23:59:59+03:00"); if (isNaN(d)) fail(400, "Неверная дата"); await q("update companies set access_until=$1 where id=$2", [d, id]); }
  if (typeof b.blocked === "boolean") await q("update companies set blocked=$1 where id=$2", [b.blocked, id]);
  if (typeof b.note === "string") await q("update companies set note=$1 where id=$2", [str(b.note, 200), id]);
  res.json({ ok: true });
}));
app.delete("/api/admin/companies/:id", admin, wrap(async (req, res) => {
  const r = await q("select name from companies where id=$1", [+req.params.id]);
  if (!r.rowCount) fail(404, "Компания не найдена");
  if (str(req.body.confirm, 200) !== r.rows[0].name) fail(400, "Для удаления введите точное название компании");
  await q("delete from companies where id=$1", [+req.params.id]);
  res.json({ ok: true });
}));
app.post("/api/admin/users/:id/reset", admin, wrap(async (req, res) => {
  const p = token(9);
  const r = await q("update users set pass=$1 where id=$2 returning email", [hashPass(p), +req.params.id]);
  if (!r.rowCount) fail(404, "Пользователь не найден");
  await q("delete from sessions where user_id=$1", [+req.params.id]);
  res.json({ email: r.rows[0].email, password: p });
}));

/* ---------- страницы */
app.get("/health", wrap(async (req, res) => { await q("select 1"); res.type("text").send("ok"); }));
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
app.use(["/app.html", "/login.html", "/admin.html", "/pay.html"], (req, res, next) => { res.set("Content-Security-Policy", CSP); res.set("Cache-Control", "no-cache"); next(); });
app.get(["/app", "/login", "/admin", "/pricing", "/offer", "/privacy"], (req, res) => res.redirect(req.path + ".html"));
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"], setHeaders: (res, p) => { if (p.endsWith(".html")) res.set("Cache-Control", "no-cache"); } }));

app.use("/api", (req, res) => res.status(404).json({ error: "Не найдено" }));
app.use((err, req, res, next) => {
  if (err instanceof HttpErr) return res.status(err.code).json({ error: err.message });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Слишком большой запрос" });
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Неверный запрос" });
  console.error(new Date().toISOString(), req.method, req.path, err);
  res.status(500).json({ error: "Ошибка сервера. Попробуйте ещё раз через минуту" });
});

/* чистка устаревших сессий и приглашений */
setInterval(() => { q("delete from sessions where expires<now()").catch(() => {}); q("delete from invites where expires<now()-interval '30 days'").catch(() => {}); }, 3600e3).unref();

migrate().then(() => {
  app.listen(PORT, "0.0.0.0", () => console.log(`PROJECT CONTROL PRO: порт ${PORT}`));
}).catch(e => { console.error("Не удалось подключиться к базе данных:", e.message); process.exit(1); });
