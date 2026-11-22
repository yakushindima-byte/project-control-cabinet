/* Отправка писем через SMTP без сторонних библиотек.
   Переменные: SMTP_HOST, SMTP_PORT (465 — SSL, 587/25 — STARTTLS), SMTP_USER, SMTP_PASS, MAIL_FROM (по умолчанию SMTP_USER). */
const net = require("net");
const tls = require("tls");
const crypto = require("crypto");
const os = require("os");

const CFG = {
  host: process.env.SMTP_HOST || "",
  port: +process.env.SMTP_PORT || 465,
  user: process.env.SMTP_USER || "",
  pass: process.env.SMTP_PASS || "",
  from: process.env.MAIL_FROM || process.env.SMTP_USER || "",
  name: process.env.MAIL_NAME || "PROJECT CONTROL PRO",
  insecure: process.env.SMTP_INSECURE === "1",   // только для проверки на тестовом сервере
};
CFG.secure = process.env.SMTP_SECURE ? process.env.SMTP_SECURE === "1" : CFG.port === 465;   // SSL сразу или STARTTLS
const mailOn = () => !!(CFG.host && CFG.user && CFG.pass && CFG.from);

const b64 = s => Buffer.from(s, "utf8").toString("base64");
const hdr = s => /^[\x20-\x7E]*$/.test(s) ? s : `=?UTF-8?B?${b64(s)}?=`;
const wrap76 = s => s.replace(/.{1,76}/g, "$&\r\n");
const addrOk = a => /^[^\s<>@"]{1,64}@[^\s<>@"]{1,190}$/.test(a);

function session(sock) {
  let buf = "", waiters = [], lines = [];
  const feed = () => {
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).replace(/\r$/, ""); buf = buf.slice(i + 1);
      lines.push(line);
      if (/^\d{3} /.test(line) || /^\d{3}$/.test(line)) { const all = lines; lines = []; const w = waiters.shift(); if (w) w.ok({ code: +line.slice(0, 3), text: all.join("\n") }); }
    }
  };
  const onData = d => { buf += d.toString("utf8"); feed(); };
  const onErr = e => { while (waiters.length) waiters.shift().no(e); };
  sock.on("data", onData); sock.on("error", onErr);
  sock.on("close", () => onErr(new Error("SMTP: соединение закрыто")));
  const read = () => new Promise((ok, no) => waiters.push({ ok, no }));
  const cmd = async (line, expect) => {
    const p = read();
    if (line !== null) sock.write(line + "\r\n");
    const r = await p;
    if (expect && !expect.includes(r.code)) throw new Error(`SMTP ${r.code}: ${r.text.slice(0, 200)}`);
    return r;
  };
  const detach = () => { sock.removeListener("data", onData); sock.removeListener("error", onErr); };
  return { cmd, detach };
}

function connect() {
  return new Promise((ok, no) => {
    const opts = { host: CFG.host, port: CFG.port, servername: CFG.host, rejectUnauthorized: !CFG.insecure };
    const s = CFG.secure ? tls.connect(opts, () => ok(s)) : net.connect({ host: CFG.host, port: CFG.port }, () => ok(s));
    s.setTimeout(20000, () => s.destroy(new Error("SMTP: нет ответа от сервера")));
    s.once("error", no);
  });
}

async function sendMail({ to, subject, html, text }) {
  if (!mailOn()) throw new Error("Почта не настроена");
  if (!addrOk(to)) throw new Error("Неверный адрес");
  let sock = await connect(), s = session(sock);
  const ehlo = "EHLO " + ((os.hostname() || "").replace(/[^A-Za-z0-9.-]/g, "") || "localhost");
  try {
    await s.cmd(null, [220]);
    let r = await s.cmd(ehlo, [250]);
    if (!CFG.secure) {
      if (!/STARTTLS/i.test(r.text)) throw new Error("SMTP: сервер не поддерживает STARTTLS");
      await s.cmd("STARTTLS", [220]);
      s.detach();
      sock = await new Promise((ok, no) => { const t = tls.connect({ socket: sock, servername: CFG.host, rejectUnauthorized: !CFG.insecure }, () => ok(t)); t.once("error", no); });
      s = session(sock);
      await s.cmd(ehlo, [250]);
    }
    await s.cmd("AUTH LOGIN", [334]);
    await s.cmd(b64(CFG.user), [334]);
    await s.cmd(b64(CFG.pass), [235]);
    await s.cmd(`MAIL FROM:<${CFG.from}>`, [250]);
    await s.cmd(`RCPT TO:<${to}>`, [250, 251]);
    await s.cmd("DATA", [354]);
    const id = `<${crypto.randomBytes(12).toString("hex")}@${CFG.from.split("@")[1]}>`;
    const bnd = "b" + crypto.randomBytes(10).toString("hex");
    const msg = [
      `From: ${hdr(CFG.name)} <${CFG.from}>`, `To: <${to}>`, `Subject: ${hdr(subject)}`, `Date: ${new Date().toUTCString().replace("GMT", "+0000")}`,
      `Message-ID: ${id}`, "MIME-Version: 1.0", `Content-Type: multipart/alternative; boundary="${bnd}"`, "",
      `--${bnd}`, "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: base64", "", wrap76(b64(text || "")),
      `--${bnd}`, "Content-Type: text/html; charset=utf-8", "Content-Transfer-Encoding: base64", "", wrap76(b64(html || "")),
      `--${bnd}--`, "",
    ].join("\r\n");
    await s.cmd(msg + "\r\n.", [250]);
    await s.cmd("QUIT", [221]).catch(() => {});
  } finally { sock.end(); }
}

// Простое письмо в стиле продукта
function layout(title, bodyHtml, btn) {
  const esc = x => String(x ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  return `<!doctype html><html><body style="margin:0;background:#F2F4F8;font-family:Arial,sans-serif;color:#0F1B2D">
<div style="max-width:560px;margin:0 auto;padding:24px 16px"><div style="background:#0B1F3A;color:#fff;font-weight:700;padding:14px 20px;border-radius:10px 10px 0 0;letter-spacing:.3px">PROJECT CONTROL <span style="color:#6FA8FF">PRO</span></div>
<div style="background:#fff;padding:22px 20px;border-radius:0 0 10px 10px;border:1px solid #DCE2EA;border-top:0"><h1 style="font-size:18px;margin:0 0 12px">${esc(title)}</h1>${bodyHtml}
${btn ? `<p style="margin:20px 0 6px"><a href="${esc(btn.url)}" style="display:inline-block;background:#1565C0;color:#fff;text-decoration:none;font-weight:700;padding:11px 18px;border-radius:7px">${esc(btn.text)}</a></p><p style="font-size:12px;color:#5B6A80;word-break:break-all">Если кнопка не открывается, скопируйте ссылку: ${esc(btn.url)}</p>` : ""}
</div><p style="font-size:11px;color:#5B6A80;text-align:center">Это автоматическое письмо от сервиса PROJECT CONTROL PRO.</p></div></body></html>`;
}

module.exports = { mailOn, sendMail, layout, CFG };
