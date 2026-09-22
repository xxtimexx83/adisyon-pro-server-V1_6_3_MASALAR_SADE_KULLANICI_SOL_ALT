const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, "cloud-data.json");
const sessions = new Map();
const resetCodes = new Map();

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

function baseData() {
  return { businesses: {}, users: {}, states: {} };
}
function readData() {
  try {
    if (!fs.existsSync(DATA_FILE)) return baseData();
    return { ...baseData(), ...JSON.parse(fs.readFileSync(DATA_FILE, "utf8")) };
  } catch {
    return baseData();
  }
}
function writeData(data) {
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), "utf8");
  if (fs.existsSync(DATA_FILE)) fs.unlinkSync(DATA_FILE);
  fs.renameSync(tmp, DATA_FILE);
}
function id(prefix="id") {
  return prefix + "_" + crypto.randomBytes(8).toString("hex");
}
function businessCode() {
  return "AP-" + crypto.randomBytes(3).toString("hex").toUpperCase();
}
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const test = crypto.scryptSync(String(password), salt, 64);
  const stored = Buffer.from(hash, "hex");
  return stored.length === test.length && crypto.timingSafeEqual(stored, test);
}
function publicUser(u) {
  return { id:u.id, businessId:u.businessId, name:u.name, username:u.username, email:u.email || "", role:u.role, active:u.active !== false };
}
function defaultTenantState() {
  return {
    tableCount: 12,
    tables: {},
    products: [],
    kitchenTickets: [],
    kitchenStatuses: {},
    dailySales: [],
    settings: { currency:"TRY", timezone:"Europe/Istanbul" }
  };
}
function auth(req,res,next){
  const h = String(req.headers.authorization || "");
  if (!h.startsWith("Bearer ")) return res.status(401).json({error:"Oturum gerekli"});
  const token = h.slice(7).trim();
  const s = sessions.get(token);
  if (!s) return res.status(401).json({error:"Oturum geçersiz"});
  if (s.expiresAt && s.expiresAt < Date.now()) {
    sessions.delete(token);
    return res.status(401).json({error:"Oturum süresi doldu"});
  }
  req.session = { token, ...s };
  next();
}
function manager(req,res,next){
  if (req.session.role !== "manager") return res.status(403).json({error:"Sadece yönetici"});
  next();
}

app.get("/api/health",(req,res)=>res.json({ok:true,service:"ADİSYON PRO BULUT",version:"1.4.1"}));

app.post("/api/register-business",(req,res)=>{
  const businessName = String(req.body?.businessName || "").trim();
  const ownerName = String(req.body?.ownerName || "").trim();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  if (!businessName || !ownerName || !email || password.length < 6) {
    return res.status(400).json({error:"İşletme adı, yönetici adı, e-posta ve en az 6 karakter şifre gerekli."});
  }

  const data = readData();
  const emailExists = Object.values(data.users).some(u => String(u.email||"").toLowerCase() === email);
  if (emailExists) return res.status(409).json({error:"Bu e-posta zaten kayıtlı."});

  let code = businessCode();
  while (Object.values(data.businesses).some(b => b.code === code)) code = businessCode();

  const businessId = id("biz");
  const userId = id("usr");
  const hp = hashPassword(password);

  data.businesses[businessId] = {
    id: businessId, code, name: businessName,
    createdAt: Date.now(), active: true
  };
  data.users[userId] = {
    id:userId, businessId, name:ownerName,
    username: email, email, role:"manager",
    passwordSalt:hp.salt, passwordHash:hp.hash, active:true
  };
  data.states[businessId] = defaultTenantState();
  writeData(data);

  res.json({ok:true, business:{id:businessId,code,name:businessName}, user:publicUser(data.users[userId])});
});

app.post("/api/login",(req,res)=>{
  const code = String(req.body?.businessCode || "").trim().toUpperCase();
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");

  const data = readData();
  const business = Object.values(data.businesses).find(b => b.code === code && b.active !== false);
  if (!business) return res.status(401).json({error:"İşletme kodu veya kullanıcı bilgileri hatalı."});

  const user = Object.values(data.users).find(u =>
    u.businessId === business.id &&
    u.active !== false &&
    (String(u.username||"").toLowerCase() === username || String(u.email||"").toLowerCase() === username)
  );
  if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    return res.status(401).json({error:"İşletme kodu veya kullanıcı bilgileri hatalı."});
  }

  const token = crypto.randomBytes(32).toString("hex");
  const rememberMe = req.body?.rememberMe === true;
  sessions.set(token, {
    userId:user.id,businessId:business.id,role:user.role,name:user.name,
    createdAt:Date.now(), expiresAt: Date.now() + (rememberMe ? 30*24*60*60*1000 : 12*60*60*1000)
  });
  res.json({ok:true,token,rememberMe,user:publicUser(user),business});
});


app.post("/api/forgot-password",(req,res)=>{
  const code = String(req.body?.businessCode || "").trim().toUpperCase();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const data = readData();
  const business = Object.values(data.businesses).find(b=>b.code===code && b.active!==false);
  if(!business) return res.status(404).json({error:"İşletme bulunamadı."});
  const user = Object.values(data.users).find(u=>u.businessId===business.id && String(u.email||"").toLowerCase()===email && u.active!==false);
  if(!user) return res.status(404).json({error:"Bu işletmede bu e-posta bulunamadı."});
  const resetCode = String(Math.floor(100000 + Math.random()*900000));
  resetCodes.set(code+"|"+email,{code:resetCode,userId:user.id,expiresAt:Date.now()+10*60*1000});
  // V1.1 yerel geliştirme: e-posta servisi bağlanana kadar kod yanıt içinde gösterilir.
  res.json({ok:true,devResetCode:resetCode,message:"Şifre sıfırlama kodu oluşturuldu."});
});

app.post("/api/reset-password",(req,res)=>{
  const businessCode = String(req.body?.businessCode || "").trim().toUpperCase();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const code = String(req.body?.code || "").trim();
  const newPassword = String(req.body?.newPassword || "");
  if(newPassword.length<6) return res.status(400).json({error:"Yeni şifre en az 6 karakter olmalı."});
  const key=businessCode+"|"+email;
  const entry=resetCodes.get(key);
  if(!entry || entry.expiresAt<Date.now() || entry.code!==code) return res.status(400).json({error:"Kod geçersiz veya süresi dolmuş."});
  const data=readData();
  const user=data.users[entry.userId];
  if(!user) return res.status(404).json({error:"Kullanıcı bulunamadı."});
  const hp=hashPassword(newPassword);
  user.passwordSalt=hp.salt; user.passwordHash=hp.hash;
  writeData(data); resetCodes.delete(key);
  res.json({ok:true,message:"Şifreniz değiştirildi."});
});

app.post("/api/logout",auth,(req,res)=>{
  sessions.delete(req.session.token);
  res.json({ok:true});
});
app.get("/api/me",auth,(req,res)=>{
  const data = readData();
  const user = data.users[req.session.userId];
  const business = data.businesses[req.session.businessId];
  if (!user || !business) return res.status(404).json({error:"Hesap bulunamadı"});
  res.json({user:publicUser(user),business});
});

/* Her istekte sadece oturumun işletmesinin verisi döner. */
app.get("/api/state",auth,(req,res)=>{
  const data = readData();
  res.json(data.states[req.session.businessId] || defaultTenantState());
});
app.put("/api/state",auth,(req,res)=>{
  const data = readData();
  data.states[req.session.businessId] = {
    ...(data.states[req.session.businessId] || defaultTenantState()),
    ...(req.body || {})
  };
  writeData(data);
  res.json({ok:true});
});

/* Yönetici personel oluşturabilir. */
app.get("/api/users",auth,manager,(req,res)=>{
  const data = readData();
  res.json(Object.values(data.users).filter(u=>u.businessId===req.session.businessId).map(publicUser));
});
app.post("/api/users",auth,manager,(req,res)=>{
  const name = String(req.body?.name || "").trim();
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const role = String(req.body?.role || "waiter");
  const allowed = ["manager","cashier","waiter","kitchen"];
  if (!name || !username || password.length < 4 || !allowed.includes(role)) {
    return res.status(400).json({error:"Geçersiz kullanıcı bilgileri."});
  }
  const data = readData();
  const dup = Object.values(data.users).some(u=>u.businessId===req.session.businessId && String(u.username).toLowerCase()===username);
  if (dup) return res.status(409).json({error:"Bu kullanıcı adı bu işletmede zaten var."});
  const hp = hashPassword(password);
  const uid = id("usr");
  data.users[uid] = {
    id:uid,businessId:req.session.businessId,name,username,email:"",role,
    passwordSalt:hp.salt,passwordHash:hp.hash,active:true
  };
  writeData(data);
  res.json({ok:true,user:publicUser(data.users[uid])});
});

/* V1.3 - Yönetici kullanıcı işlemleri */
app.put("/api/users/:id/password",auth,manager,(req,res)=>{
  const newPassword=String(req.body?.password||"");
  if(newPassword.length<4) return res.status(400).json({error:"Şifre en az 4 karakter olmalı."});
  const data=readData(), user=data.users[req.params.id];
  if(!user || user.businessId!==req.session.businessId) return res.status(404).json({error:"Kullanıcı bulunamadı."});
  const hp=hashPassword(newPassword); user.passwordSalt=hp.salt; user.passwordHash=hp.hash; writeData(data);
  res.json({ok:true,message:user.name+" şifresi değiştirildi."});
});
app.put("/api/users/:id/active",auth,manager,(req,res)=>{
  const data=readData(), user=data.users[req.params.id];
  if(!user || user.businessId!==req.session.businessId) return res.status(404).json({error:"Kullanıcı bulunamadı."});
  if(user.id===req.session.userId && req.body?.active===false) return res.status(400).json({error:"Kendi yönetici hesabınızı pasif yapamazsınız."});
  user.active=req.body?.active!==false; writeData(data); res.json({ok:true,user:publicUser(user)});
});
app.delete("/api/users/:id",auth,manager,(req,res)=>{
  const data=readData(), user=data.users[req.params.id];
  if(!user || user.businessId!==req.session.businessId) return res.status(404).json({error:"Kullanıcı bulunamadı."});
  if(user.id===req.session.userId) return res.status(400).json({error:"Kendi yönetici hesabınızı silemezsiniz."});
  delete data.users[user.id]; writeData(data); res.json({ok:true});
});

app.listen(PORT,"0.0.0.0",()=>{
  console.log(`ADİSYON PRO BULUT V1.4: http://localhost:${PORT}`);
});
