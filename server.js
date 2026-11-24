require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const required = ["SESSION_SECRET", "ADMIN_USERNAME", "ADMIN_PASSWORD_SCRYPT_HEX"];
for (const k of required) if (!process.env[k] || process.env[k].startsWith("REPLACE_")) {
  console.error(`Configuration manquante ou invalide: ${k}`); process.exit(1);
}
if (process.env.SESSION_SECRET.length < 32) { console.error("SESSION_SECRET doit contenir au moins 32 caractères."); process.exit(1); }
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || "./data");
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
const db = new Database(path.join(DATA_DIR, "app.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS leads (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL,
 phone TEXT DEFAULT '', service TEXT DEFAULT '', details TEXT DEFAULT '',
 status TEXT NOT NULL DEFAULT 'new', quote_amount REAL, follow_up_date TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, lead_id INTEGER,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const app = express();
if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
    imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], objectSrc: ["'none'"],
    frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"]
  }
}}));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR, concurrentDB: true }),
  name: "suivi.sid", secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production", maxAge: 8 * 60 * 60 * 1000 }
}));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: "draft-7", legacyHeaders: false });
app.use("/api", apiLimiter);

function auth(req, res, next) { if (!req.session.user) return res.status(401).json({ error: "Connexion requise." }); next(); }
function csrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const token = req.get("x-csrf-token");
  if (!req.session.csrf || !token || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(req.session.csrf))) {
    return res.status(403).json({ error: "Jeton de sécurité invalide. Rechargez la page." });
  }
  next();
}
app.get("/health", (req,res) => res.json({ ok: true }));
app.post("/api/login", loginLimiter, (req,res) => {
  const { username, password } = req.body || {};
  const salt = "change-this-salt";
  const expected = Buffer.from(process.env.ADMIN_PASSWORD_SCRYPT_HEX, "hex");
  const actual = crypto.scryptSync(String(password || ""), salt, 64);
  const userOk = String(username || "") === process.env.ADMIN_USERNAME;
  const passOk = expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  if (!userOk || !passOk) return res.status(401).json({ error: "Identifiants incorrects." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Erreur de session." });
    req.session.user = process.env.ADMIN_USERNAME;
    req.session.csrf = crypto.randomBytes(32).toString("hex");
    res.json({ ok: true, csrf: req.session.csrf });
  });
});
app.post("/api/logout", auth, csrf, (req,res) => req.session.destroy(() => res.json({ ok: true })));
app.get("/api/session", (req,res) => res.json({ authenticated: !!req.session.user, csrf: req.session.csrf || null, appName: process.env.APP_NAME || "Suivi des devis" }));
app.use("/api", auth, csrf);

const validStatuses = new Set(["new", "to_quote", "sent", "won", "lost"]);
const clean = (v, max=1000) => String(v ?? "").trim().slice(0,max);
function validateLead(b) {
  const name=clean(b.name,100), email=clean(b.email,180), phone=clean(b.phone,40);
  const service=clean(b.service,120), details=clean(b.details,3000);
  if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: "Nom et adresse e-mail valide obligatoires." };
  return { name,email,phone,service,details };
}
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({
  host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === "true",
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
}) : null;

app.get("/api/leads", (req,res) => {
  const rows = db.prepare("SELECT * FROM leads ORDER BY created_at DESC").all();
  res.json(rows);
});
app.post("/api/leads", (req,res) => {
  const v=validateLead(req.body || {});
  if (v.error) return res.status(400).json({ error:v.error });
  const info=db.prepare("INSERT INTO leads(name,email,phone,service,details) VALUES(@name,@email,@phone,@service,@details)").run(v);
  db.prepare("INSERT INTO audit(action,lead_id) VALUES(?,?)").run("created",info.lastInsertRowid);
  res.status(201).json(db.prepare("SELECT * FROM leads WHERE id=?").get(info.lastInsertRowid));
});
app.patch("/api/leads/:id", (req,res) => {
  const id=Number(req.params.id), b=req.body || {};
  if (!Number.isSafeInteger(id) || id<1) return res.status(400).json({error:"Identifiant invalide."});
  const current=db.prepare("SELECT * FROM leads WHERE id=?").get(id);
  if (!current) return res.status(404).json({error:"Demande introuvable."});
  const status=b.status === undefined ? current.status : clean(b.status,20);
  if (!validStatuses.has(status)) return res.status(400).json({error:"Statut invalide."});
  let amount=current.quote_amount;
  if (b.quote_amount !== undefined) {
    amount = b.quote_amount === null || b.quote_amount === "" ? null : Number(b.quote_amount);
    if (amount !== null && (!Number.isFinite(amount) || amount<0 || amount>10000000)) return res.status(400).json({error:"Montant invalide."});
  }
  const follow=b.follow_up_date === undefined ? current.follow_up_date : (b.follow_up_date ? clean(b.follow_up_date,10) : null);
  if (follow && !/^\\d{4}-\\d{2}-\\d{2}$/.test(follow)) return res.status(400).json({error:"Date de relance invalide."});
  db.prepare("UPDATE leads SET status=?,quote_amount=?,follow_up_date=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(status,amount,follow,id);
  db.prepare("INSERT INTO audit(action,lead_id) VALUES(?,?)").run("updated",id);
  res.json(db.prepare("SELECT * FROM leads WHERE id=?").get(id));
});
app.delete("/api/leads/:id", (req,res) => {
  const id=Number(req.params.id);
  if (!Number.isSafeInteger(id) || id<1) return res.status(400).json({error:"Identifiant invalide."});
  db.prepare("DELETE FROM leads WHERE id=?").run(id);
  db.prepare("INSERT INTO audit(action,lead_id) VALUES(?,?)").run("deleted",id);
  res.json({ok:true});
});
app.get("/api/export.csv", (req,res) => {
  const rows=db.prepare("SELECT id,name,email,phone,service,details,status,quote_amount,follow_up_date,created_at,updated_at FROM leads ORDER BY created_at DESC").all();
  const cols=Object.keys(rows[0] || {id:"",name:"",email:"",phone:"",service:"",details:"",status:"",quote_amount:"",follow_up_date:"",created_at:"",updated_at:""});
  const esc=v=>`"${String(v ?? "").replace(/"/g,'""')}"`;
  res.setHeader("Content-Type","text/csv; charset=utf-8");
  res.setHeader("Content-Disposition",'attachment; filename="demandes-devis.csv"');
  res.send("\\uFEFF"+[cols.map(esc).join(";"),...rows.map(r=>cols.map(c=>esc(r[c])).join(";"))].join("\\r\\n"));
});
app.post("/api/leads/:id/notify", async (req,res) => {
  if (!mailer || !process.env.MAIL_FROM) return res.status(503).json({error:"E-mail non configuré. Renseignez les paramètres SMTP."});
  const lead=db.prepare("SELECT * FROM leads WHERE id=?").get(Number(req.params.id));
  if (!lead) return res.status(404).json({error:"Demande introuvable."});
  try {
    await mailer.sendMail({from:process.env.MAIL_FROM,to:lead.email,subject:"Nous avons bien reçu votre demande",
      text:`Bonjour ${lead.name},\\n\\nNous avons bien reçu votre demande concernant : ${lead.service || "votre projet"}. Nous revenons vers vous dès que possible.\\n\\n${process.env.BUSINESS_NAME || "Notre équipe"}`});
    db.prepare("INSERT INTO audit(action,lead_id) VALUES(?,?)").run("ack_email_sent",lead.id);
    res.json({ok:true});
  } catch(e) { console.error("SMTP error",e.message); res.status(502).json({error:"Envoi e-mail impossible. Vérifiez la configuration SMTP."}); }
});
app.use(express.static(path.join(__dirname,"public"), { etag:true, maxAge:"1h" }));
app.use((err,req,res,next) => { console.error(err); res.status(500).json({error:"Erreur interne."}); });
app.listen(PORT,"0.0.0.0",()=>console.log(`Suivi des devis démarré sur le port ${PORT}`));
