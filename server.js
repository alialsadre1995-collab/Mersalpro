/* SERVER.JS CONTENT FROM CONVERSATION - BCRYPT VERSION */
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
let geoip; try { geoip = require("geoip-lite"); } catch { geoip = null; }
const SALT_ROUNDS = 10;
const app = express();
app.set("trust proxy", true);
app.use(express.static(path.join(__dirname, "public")));
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" }, pingInterval: 25000, pingTimeout: 60000 });
const PORT = process.env.PORT || 3000;
const rolesPath = process.env.ROLES_PATH || path.join(__dirname, "roles.json");
let roles = { admins: [], mods: [], bans: [] };
function saveRoles() {
  const dir = path.dirname(rolesPath);
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  const tmp = rolesPath + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(roles, null, 2));
  fs.renameSync(tmp, rolesPath);
}
function initDefaultRoles() {
  roles = {
    admins: [{ nick: "ArabAdmin", passHash: bcrypt.hashSync("az77@", SALT_ROUNDS) }],
    mods:   [{ nick: "CHAN1",     passHash: bcrypt.hashSync("chan1@", SALT_ROUNDS) }],
    bans: []
  };
  saveRoles();
}
function loadRoles() {
  if (!fs.existsSync(rolesPath)) {
    initDefaultRoles();
    return;
  }
  try {
    roles = JSON.parse(fs.readFileSync(rolesPath, "utf-8"));
    roles.admins = Array.isArray(roles.admins) ? roles.admins : [];
    roles.mods   = Array.isArray(roles.mods)   ? roles.mods   : [];
    roles.bans   = Array.isArray(roles.bans)   ? roles.bans   : [];
  } catch (e) {
    console.error("roles.json فاسد — سنعيد إنشاء أدوار افتراضية.", e);
    initDefaultRoles();
  }
  migratePlainToHash();
}
function migratePlainToHash() {
  let changed = false;
  for (const a of roles.admins) {
    if (a.pass && !a.passHash) { a.passHash = bcrypt.hashSync(a.pass, SALT_ROUNDS); delete a.pass; changed = true; }
  }
  for (const m of roles.mods) {
    if (m.pass && !m.passHash) { m.passHash = bcrypt.hashSync(m.pass, SALT_ROUNDS); delete m.pass; changed = true; }
  }
  if (changed) saveRoles();
}
loadRoles();
const users = new Map();
const byNick = new Map();
const history = [];
const lastSeenByIP = new Map();
const failedLogins = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [ip, t] of lastSeenByIP) if (now - t > 6*60*60*1000) lastSeenByIP.delete(ip);
  for (const [k, o] of failedLogins) if (now - o.ts > 30*60*1000) failedLogins.delete(k);
}, 60*60*1000);
function sanitizeNick(n){
  n = (n || "").trim();
  const ok = /^[A-Za-z0-9_\u0600-\u06FF]{3,20}$/.test(n);
  return ok ? n : "Guest" + Math.floor(Math.random()*9000+1000);
}
function ensureUniqueNick(n){
  if (!byNick.has(n)) return n;
  let i = 2;
  while (byNick.has(`${n}_${i}`)) i++;
  return `${n}_${i}`;
}
function countryFromIP(ip){
  try { return geoip?.lookup(ip)?.country || "??"; }
  catch { return "??"; }
}
function sanitizeText(s) {
  return String(s || "").slice(0, 2000).replace(/[<>&"']/g, ch =>
    ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[ch]));
}
function pushHistory(evt){
  history.push(evt);
  if (history.length > 200) history.shift();
}
function canShowJoinLeave(ip){
  const now = Date.now();
  const last = lastSeenByIP.get(ip) || 0;
  lastSeenByIP.set(ip, now);
  return (now - last) > 5 * 60 * 1000;
}
function broadcastUsers(){
  io.emit("users", [...users.values()].map(u => ({
    nick: u.nick,
    country: u.country,
    admin: u.role === "admin",
    mod: u.role === "mod"
  })));
}
function emitSystemAll(text, extra = {}) {
  const evt = { type: "system", text, ...extra };
  pushHistory(evt);
  io.emit("system", evt);
}
function emitSystemTo(socket, text, extra = {}) {
  const evt = { type: "system", text, ...extra };
  socket.emit("system", evt);
}
function checkPassRow(row, passStr) {
  if (!row || !row.passHash || !passStr) return false;
  try { return bcrypt.compareSync(passStr, row.passHash); }
  catch { return false; }
}
function tooManyAttempts(key) {
  const o = failedLogins.get(key);
  return o && o.count >= 10 && Date.now() - o.ts < 10*60*1000;
}
function onLoginFail(key) {
  const o = failedLogins.get(key) || { count: 0, ts: Date.now() };
  o.count += 1; o.ts = Date.now();
  failedLogins.set(key, o);
}
function onLoginSuccess(key) {
  failedLogins.delete(key);
}
function extractIP(socket) {
  let ip = socket.request?.connection?.remoteAddress || socket.handshake.address || "";
  ip = ip.toString().replace(/^::ffff:/, "");
  ip = ip.split(",")[0].trim();
  return ip || "0.0.0.0";
}
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});
io.on("connection", socket => {
  const ip = extractIP(socket);
  if (roles.bans.includes(ip)) {
    socket.emit("banned", "🚫 محظور");
    return socket.disconnect(true);
  }
  socket.on("login", ({ nick, pass } = {}, ack) => {
    const clean = sanitizeNick(nick);
    const passStr = (pass || "").toString();
    if (tooManyAttempts(ip) || tooManyAttempts(clean)) {
      if (typeof ack === "function") ack({ ok: false, error: "too_many_attempts" });
      return;
    }
    const adminRow = roles.admins.find(a => a.nick.toLowerCase() === clean.toLowerCase());
    const isAdmin = !!adminRow && checkPassRow(adminRow, passStr);
    const modRow = !isAdmin && roles.mods.find(m => m.nick.toLowerCase() === clean.toLowerCase());
    const isMod = !!modRow && checkPassRow(modRow, passStr);
    if ((adminRow && !isAdmin) || (modRow && !isMod)) {
      onLoginFail(ip); onLoginFail(clean);
      if (typeof ack === "function") ack({ ok: false, error: "bad_credentials" });
      return;
    }
    let role = "user";
    let display = ensureUniqueNick(clean);
    if (isAdmin) {
      const fixed = adminRow.nick;
      const oldId = byNick.get(fixed);
      if (oldId) {
        io.sockets.sockets.get(oldId)?.disconnect(true);
        users.delete(oldId);
        byNick.delete(fixed);
      }
      display = fixed;
      role = "admin";
    } else if (isMod) {
      const fixed = modRow.nick;
      const oldId = byNick.get(fixed);
      if (oldId) {
        io.sockets.sockets.get(oldId)?.disconnect(true);
        users.delete(oldId);
        byNick.delete(fixed);
      }
      display = fixed;
      role = "mod";
    }
    const country = countryFromIP(ip);
    const user = { id: socket.id, nick: display, ip, country, role };
    users.set(socket.id, user);
    byNick.set(display, socket.id);
    onLoginSuccess(ip); onLoginSuccess(clean);
    socket.emit("history", history);
    emitSystemTo(socket,
      "أهلًا وسهلًا بكم في شات دردشة العرب 😍❤️\n😍☺️\n🥳\n😎\n❤️",
      { color: "#ffb03a" }
    );
    if (canShowJoinLeave(ip)) {
      emitSystemAll(`✅ ${display} دخل [${country}]`);
    }
    if (role === "admin") {
      emitSystemAll(`ChanServ ${display} تم توكيل`);
    }
    broadcastUsers();
    if (typeof ack === "function") {
      ack({ ok: true, user: { nick: display, admin: role === "admin", mod: role === "mod" } });
    }
  });
  socket.on("msg", text => {
    const u = users.get(socket.id);
    if (!u) return;
    const evt = {
      type: "msg",
      nick: u.nick,
      country: u.country,
      text: sanitizeText(text)
    };
    pushHistory(evt);
    io.emit("msg", evt);
  });
  socket.on("pm", ({ to, text } = {}) => {
    const u = users.get(socket.id);
    if (!u) return;
    const toId = byNick.get(to);
    if (!toId) {
      return socket.emit("pm:error", { to, reason: "offline" });
    }
    const evt = { type: "pm", from: u.nick, to, text: sanitizeText(text) };
    io.to(toId).emit("pm", evt);
    socket.emit("pm", evt);
  });
  socket.on("typing", on => {
    const u = users.get(socket.id);
    if (!u) return;
    socket.broadcast.emit("typing", { on: !!on, nick: u.nick });
  });
  socket.on("admin:action", ({ action, target } = {}) => {
    const me = users.get(socket.id);
    if (!(me && (me.role === "admin" || me.role === "mod"))) return;
    const tId = byNick.get(target);
    const t = tId ? users.get(tId) : null;
    switch (action) {
      case "kick":
        if (t) {
          io.to(t.id).emit("kicked", "تم طردك");
          io.sockets.sockets.get(t.id)?.disconnect(true);
        }
        break;
      case "ban":
        if (me.role !== "admin") return;
        if (t) {
          if (!roles.bans.includes(t.ip)) roles.bans.push(t.ip);
          try { saveRoles(); } catch (e) { console.error("saveRoles ban error:", e); }
          io.to(t.id).emit("banned", "🚫 محظور");
          io.sockets.sockets.get(t.id)?.disconnect(true);
        }
        break;
      case "clear":
        history.length = 0;
        io.emit("clear");
        emitSystemAll("🧹 تم مسح السجل");
        break;
    }
    broadcastUsers();
  });
  socket.on("admin:listBans", () => {
    const me = users.get(socket.id);
    if (me?.role !== "admin") return;
    socket.emit("admin:bans", roles.bans);
  });
  socket.on("admin:unban", ip => {
    const me = users.get(socket.id);
    if (me?.role !== "admin") return;
    roles.bans = roles.bans.filter(x => x !== ip);
    try { saveRoles(); } catch (e) { console.error("saveRoles unban error:", e); }
    socket.emit("admin:unbanOk", ip);
  });
  socket.on("admin:listMods", () => {
    const me = users.get(socket.id);
    if (me?.role !== "admin") return;
    socket.emit("admin:mods", roles.mods.map(m => m.nick));
  });
  socket.on("admin:addMod", nick => {
    const me = users.get(socket.id);
    if (me?.role !== "admin") return;
    const clean = sanitizeNick(nick);
    if (!roles.mods.find(m => m.nick.toLowerCase() === clean.toLowerCase())) {
      roles.mods.push({ nick: clean, passHash: null });
      try { saveRoles(); } catch (e) { console.error("saveRoles addMod error:", e); }
    }
    socket.emit("admin:addModOk", clean);
    broadcastUsers();
  });
  socket.on("admin:removeMod", nick => {
    const me = users.get(socket.id);
    if (me?.role !== "admin") return;
    roles.mods = roles.mods.filter(m => m.nick !== nick);
    try { saveRoles(); } catch (e) { console.error("saveRoles removeMod error:", e); }
    socket.emit("admin:removeModOk", nick);
    broadcastUsers();
  });
  socket.on("admin:setModPass", ({ nick, pass } = {}) => {
    const me = users.get(socket.id);
    if (me?.role !== "admin") return;
    const row = roles.mods.find(m => m.nick === nick);
    if (!row) return socket.emit("admin:setModPassErr", { nick, reason: "not_found" });
    if (!pass || typeof pass !== "string" || pass.length < 4) {
      return socket.emit("admin:setModPassErr", { nick, reason: "weak_pass" });
    }
    try {
      row.passHash = bcrypt.hashSync(pass, SALT_ROUNDS);
      delete row.pass;
      saveRoles();
      socket.emit("admin:setModPassOk", nick);
    } catch (e) {
      console.error("setModPass error:", e);
      socket.emit("admin:setModPassErr", { nick, reason: "server_error" });
    }
  });
  socket.on("admin:setAdminPass", ({ nick, pass } = {}) => {
    const me = users.get(socket.id);
    if (me?.role !== "admin") return;
    const row = roles.admins.find(a => a.nick === nick);
    if (!row) return socket.emit("admin:setAdminPassErr", { nick, reason: "not_found" });
    if (!pass || typeof pass !== "string" || pass.length < 6) {
      return socket.emit("admin:setAdminPassErr", { nick, reason: "weak_pass" });
    }
    try {
      row.passHash = bcrypt.hashSync(pass, SALT_ROUNDS);
      delete row.pass;
      saveRoles();
      socket.emit("admin:setAdminPassOk", nick);
    } catch (e) {
      console.error("setAdminPass error:", e);
      socket.emit("admin:setAdminPassErr", { nick, reason: "server_error" });
    }
  });
  socket.on("whois", (nick) => {
    const me = users.get(socket.id);
    const tId = byNick.get(nick);
    const t = tId ? users.get(tId) : null;
    if (!t) return socket.emit("whois", { found: false });
    socket.emit("whois", {
      found: true,
      nick: t.nick,
      country: t.country,
      ip: me?.role === "admin" ? t.ip : undefined
    });
  });
  socket.on("disconnect", () => {
    const u = users.get(socket.id);
    if (!u) return;
    users.delete(socket.id);
    byNick.delete(u.nick);
    if (canShowJoinLeave(u.ip)) {
      emitSystemAll(`❌ ${u.nick} خرج`);
    }
    broadcastUsers();
  });
});
server.listen(PORT, () => {
  console.log(`🚀 ArabChat running on http://localhost:${PORT}`);
});
