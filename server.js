require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const dataDir = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "market.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 phone TEXT NOT NULL DEFAULT '',
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','seller','admin')),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 seller_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 name TEXT NOT NULL,
 category TEXT NOT NULL DEFAULT 'متنوع',
 description TEXT NOT NULL DEFAULT '',
 price INTEGER NOT NULL CHECK(price >= 0),
 old_price INTEGER NOT NULL DEFAULT 0 CHECK(old_price >= 0),
 emoji TEXT NOT NULL DEFAULT '🛍️',
 image_url TEXT NOT NULL DEFAULT '',
 stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 customer_name TEXT NOT NULL,
 phone TEXT NOT NULL,
 address TEXT NOT NULL,
 notes TEXT NOT NULL DEFAULT '',
 items_json TEXT NOT NULL,
 total INTEGER NOT NULL CHECK(total >= 0),
 status TEXT NOT NULL DEFAULT 'جديد',
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS seller_applications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 phone TEXT NOT NULL,
 business_type TEXT NOT NULL,
 details TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'قيد المراجعة',
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const seedCount = db.prepare("SELECT COUNT(*) AS n FROM products").get().n;
if (!seedCount) {
 const seed = [
  ["هاتف ذكي - فئة اقتصادية","إلكترونيات","هاتف للاستخدام اليومي. تحقق من المواصفات والضمان قبل الشراء.",185000,210000,"📱",4],
  ["سماعة بلوتوث لاسلكية","إلكترونيات","سماعة لاسلكية للاستخدام اليومي.",28000,35000,"🎧",15],
  ["ساعة يد كلاسيكية","ملابس وأحذية","ساعة أنيقة للاستخدام اليومي والهدايا.",22000,0,"⌚",8],
  ["حذاء رياضي يومي","ملابس وأحذية","حذاء رياضي. تأكد من المقاس المتاح.",42000,48000,"👟",10],
  ["عطر أنيق","عطور وتجميل","اسأل البائع عن الحجم والأصالة.",18000,22000,"🧴",12],
  ["طقم أكواب للقهوة","المنزل والأثاث","طقم أكواب مناسب للبيت والضيافة.",15000,18000,"☕",20],
  ["عسل طبيعي - عبوة","أطعمة ومشروبات","تحقق من الوزن والمصدر والتعبئة مع البائع.",16000,19000,"🍯",14],
  ["قهوة مطحونة","أطعمة ومشروبات","قهوة للتحضير المنزلي.",8500,0,"☕",25],
  ["حقيبة ظهر عملية","ملابس وأحذية","حقيبة للاستخدام اليومي والدراسة.",24000,29000,"🎒",9],
  ["مصباح مكتبي LED","المنزل والأثاث","مصباح مكتبي. اسأل عن الضمان ومصدر الطاقة.",19500,0,"💡",7],
  ["كيك منزلي","أطعمة ومشروبات","اتفق مع البائع على النكهة والحجم وموعد الاستلام.",12000,0,"🍰",5],
  ["خدمة صيانة الهواتف","خدمات","السعر تقديري ويحتاج إلى تأكيد مقدم الخدمة.",10000,0,"🧰",20]
 ];
 const insert = db.prepare("INSERT INTO products(name,category,description,price,old_price,emoji,stock) VALUES(?,?,?,?,?,?,?)");
 const tx = db.transaction(rows => rows.forEach(r => insert.run(...r)));
 tx(seed);
}

const adminEmail = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || "";
if (adminEmail && adminPassword && !adminPassword.startsWith("غيّر_")) {
 const existing = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
 if (!existing) {
   const hash = bcrypt.hashSync(adminPassword, 12);
   db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?, 'admin')")
     .run("مدير السوق", adminEmail, "", hash);
   console.log("Initial admin account created:", adminEmail);
 }
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(session({
 name: "omd.sid",
 secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
 resave: false,
 saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: "lax", secure: isProduction, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use("/api/orders", rateLimit({ windowMs: 15 * 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false }));

// Basic same-origin protection for browser write requests.
app.use("/api", (req, res, next) => {
 if (["POST","PUT","PATCH","DELETE"].includes(req.method) && req.get("origin")) {
   const origin = req.get("origin");
   const host = req.get("host");
   if (!host || new URL(origin).host !== host) return res.status(403).json({ error: "طلب من مصدر غير مسموح" });
 }
 next();
});

function currentUser(req) {
 if (!req.session.userId) return null;
 return db.prepare("SELECT id,name,email,phone,role,created_at FROM users WHERE id=?").get(req.session.userId) || null;
}
function requireAuth(req,res,next) {
 const user = currentUser(req);
 if (!user) return res.status(401).json({ error: "سجّل الدخول أولاً" });
 req.user = user; next();
}
function requireAdmin(req,res,next) {
 const user = currentUser(req);
 if (!user || user.role !== "admin") return res.status(403).json({ error: "هذه الصفحة مخصصة للإدارة" });
 req.user = user; next();
}
function cleanText(value, max=500) { return String(value ?? "").trim().slice(0,max); }
function validPhone(phone) { return /^[0-9+\s()-]{7,22}$/.test(phone); }
function publicProduct(row) {
 return { ...row, active: Boolean(row.active), price: Number(row.price), old_price: Number(row.old_price), stock: Number(row.stock) };
}

app.get("/api/health", (req,res) => res.json({ ok:true, service:"Omdurman Market API" }));
app.get("/api/me", (req,res) => res.json({ user: currentUser(req) }));

app.post("/api/auth/register", (req,res) => {
 const name=cleanText(req.body.name,100), email=cleanText(req.body.email,180).toLowerCase();
 const phone=cleanText(req.body.phone,22), password=String(req.body.password||"");
 if (name.length<2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !validPhone(phone) || password.length<10) {
   return res.status(400).json({ error:"أدخل اسماً صحيحاً وبريداً إلكترونياً ورقم هاتف وكلمة مرور لا تقل عن 10 أحرف." });
 }
 try {
   const hash=bcrypt.hashSync(password,12);
   const result=db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?, 'customer')").run(name,email,phone,hash);
   req.session.userId=Number(result.lastInsertRowid);
   res.status(201).json({ user:currentUser(req) });
 } catch(e) {
   if (String(e.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error:"هذا البريد الإلكتروني مسجل بالفعل." });
   console.error(e); res.status(500).json({ error:"تعذر إنشاء الحساب." });
 }
});
app.post("/api/auth/login", (req,res) => {
 const email=cleanText(req.body.email,180).toLowerCase(), password=String(req.body.password||"");
 const user=db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if (!user || !bcrypt.compareSync(password,user.password_hash)) return res.status(401).json({ error:"البريد الإلكتروني أو كلمة المرور غير صحيحة." });
 req.session.regenerate(err => {
  if(err) return res.status(500).json({error:"تعذر بدء الجلسة."});
  req.session.userId=user.id;
  res.json({ user:currentUser(req) });
 });
});
app.post("/api/auth/logout", (req,res) => req.session.destroy(err => {
 res.clearCookie("omd.sid"); if(err) return res.status(500).json({error:"تعذر تسجيل الخروج"}); res.json({ok:true});
}));

app.get("/api/products", (req,res) => {
 const q=cleanText(req.query.q,100), category=cleanText(req.query.category,80);
 const rows=db.prepare(`SELECT p.id,p.name,p.category,p.description,p.price,p.old_price,p.emoji,p.image_url,p.stock,p.seller_id,p.created_at,u.name AS seller_name
 FROM products p LEFT JOIN users u ON u.id=p.seller_id
 WHERE p.active=1 AND p.name LIKE ? AND p.category LIKE ? ORDER BY p.id DESC LIMIT 200`)
 .all(`%${q}%`, category && category!=="الكل" ? category : "%").map(publicProduct);
 res.json({products:rows});
});
app.get("/api/products/:id", (req,res) => {
 const p=db.prepare("SELECT p.*,u.name AS seller_name FROM products p LEFT JOIN users u ON u.id=p.seller_id WHERE p.id=? AND p.active=1").get(Number(req.params.id));
 if(!p) return res.status(404).json({error:"المنتج غير موجود"});
 res.json({product:publicProduct(p)});
});

app.post("/api/orders", requireAuth, (req,res) => {
 const customer_name=cleanText(req.body.customer_name,100), phone=cleanText(req.body.phone,22);
 const address=cleanText(req.body.address,500), notes=cleanText(req.body.notes,500);
 const items=Array.isArray(req.body.items)?req.body.items:[];
 if(customer_name.length<2 || !validPhone(phone) || address.length<5 || items.length<1 || items.length>50)
  return res.status(400).json({error:"أكمل الاسم ورقم الهاتف والعنوان وأضف منتجات إلى الطلب."});
 const quantities=new Map();
 for(const item of items){const id=Number(item.id), qty=Number(item.qty);if(!Number.isInteger(id)||!Number.isInteger(qty)||qty<1||qty>50)return res.status(400).json({error:"تفاصيل المنتجات غير صحيحة"});quantities.set(id,(quantities.get(id)||0)+qty);}
 const ids=[...quantities.keys()], products=db.prepare(`SELECT id,name,price,stock,active FROM products WHERE id IN (${ids.map(()=>"?").join(",")})`).all(...ids);
 if(products.length!==ids.length || products.some(p=>!p.active))return res.status(400).json({error:"بعض المنتجات لم تعد متاحة"});
 const normalized=[];
 let total=0;
 for(const p of products){const qty=quantities.get(p.id);if(p.stock<qty)return res.status(409).json({error:`الكمية المتاحة من ${p.name} غير كافية`});normalized.push({id:p.id,name:p.name,price:p.price,qty});total+=p.price*qty;}
 const createOrder=db.transaction(()=>{
   for(const p of products){const qty=quantities.get(p.id);const changed=db.prepare("UPDATE products SET stock=stock-? WHERE id=? AND stock>=?").run(qty,p.id,qty);if(changed.changes!==1)throw new Error("STOCK_RACE");}
   return db.prepare("INSERT INTO orders(user_id,customer_name,phone,address,notes,items_json,total) VALUES(?,?,?,?,?,?,?)")
     .run(req.user.id,customer_name,phone,address,notes,JSON.stringify(normalized),total);
 });
 try { const result=createOrder();res.status(201).json({order:{id:Number(result.lastInsertRowid),total,status:"جديد"},message:"تم تسجيل الطلب. سيتواصل معك المتجر لتأكيد التفاصيل."}); }
 catch(e){if(e.message==="STOCK_RACE")return res.status(409).json({error:"تغير المخزون أثناء الطلب؛ حدّث السلة وحاول مجدداً"});console.error(e);res.status(500).json({error:"تعذر حفظ الطلب"});}
});
app.get("/api/my/orders", requireAuth, (req,res) => {
 const orders=db.prepare("SELECT id,customer_name,phone,address,notes,items_json,total,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.user.id);
 res.json({orders:orders.map(o=>({...o,items:JSON.parse(o.items_json)}))});
});

app.post("/api/seller-applications", (req,res) => {
 const name=cleanText(req.body.name,100), phone=cleanText(req.body.phone,22), business_type=cleanText(req.body.business_type,100), details=cleanText(req.body.details,1000);
 if(name.length<2 || !validPhone(phone) || business_type.length<2 || details.length<5)return res.status(400).json({error:"يرجى إكمال بيانات التاجر بشكل صحيح."});
 const r=db.prepare("INSERT INTO seller_applications(name,phone,business_type,details) VALUES(?,?,?,?)").run(name,phone,business_type,details);
 res.status(201).json({ok:true,id:Number(r.lastInsertRowid),message:"وصل طلبك المبدئي. ستتم مراجعته من الإدارة."});
});

app.get("/api/admin/summary", requireAdmin, (req,res) => {
 res.json({
  users:db.prepare("SELECT COUNT(*) n FROM users").get().n,
  products:db.prepare("SELECT COUNT(*) n FROM products WHERE active=1").get().n,
  orders:db.prepare("SELECT COUNT(*) n FROM orders").get().n,
  pending:db.prepare("SELECT COUNT(*) n FROM orders WHERE status='جديد'").get().n,
  applications:db.prepare("SELECT COUNT(*) n FROM seller_applications WHERE status='قيد المراجعة'").get().n
 });
});
app.get("/api/admin/products", requireAdmin, (req,res) => {
 res.json({products:db.prepare("SELECT * FROM products ORDER BY id DESC").all().map(publicProduct)});
});
app.post("/api/admin/products", requireAdmin, (req,res) => {
 const p=readProduct(req.body);if(p.error)return res.status(400).json({error:p.error});
 const r=db.prepare("INSERT INTO products(name,category,description,price,old_price,emoji,image_url,stock,seller_id,active) VALUES(?,?,?,?,?,?,?,?,?,?)")
 .run(p.name,p.category,p.description,p.price,p.old_price,p.emoji,p.image_url,p.stock,null,p.active?1:0);
 res.status(201).json({product:db.prepare("SELECT * FROM products WHERE id=?").get(Number(r.lastInsertRowid))});
});
app.put("/api/admin/products/:id", requireAdmin, (req,res) => {
 const p=readProduct(req.body);if(p.error)return res.status(400).json({error:p.error});
 const r=db.prepare("UPDATE products SET name=?,category=?,description=?,price=?,old_price=?,emoji=?,image_url=?,stock=?,active=? WHERE id=?")
 .run(p.name,p.category,p.description,p.price,p.old_price,p.emoji,p.image_url,p.stock,p.active?1:0,Number(req.params.id));
 if(!r.changes)return res.status(404).json({error:"المنتج غير موجود"});
 res.json({ok:true});
});
function readProduct(body){
 const name=cleanText(body.name,160),category=cleanText(body.category,80),description=cleanText(body.description,1500);
 const price=Number(body.price),old_price=Number(body.old_price||0),stock=Number(body.stock);
 const emoji=cleanText(body.emoji||"🛍️",12),image_url=cleanText(body.image_url,1000);
 if(name.length<2||category.length<2||!Number.isSafeInteger(price)||price<0||!Number.isSafeInteger(old_price)||old_price<0||!Number.isInteger(stock)||stock<0||stock>1000000)return {error:"تحقق من اسم المنتج والقسم والأسعار والمخزون."};
 if(image_url && !/^https:\/\/|^\/uploads\//i.test(image_url))return {error:"رابط الصورة يجب أن يبدأ بـ https:// أو /uploads/."};
 return {name,category,description,price,old_price,stock,emoji,image_url,active:body.active!==false&&body.active!==0&&body.active!=="0"};
}
app.get("/api/admin/orders", requireAdmin, (req,res) => {
 const orders=db.prepare("SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 300").all();
 res.json({orders:orders.map(o=>({...o,items:JSON.parse(o.items_json)}))});
});
app.patch("/api/admin/orders/:id", requireAdmin, (req,res) => {
 const allowed=["جديد","تم التأكيد","قيد التجهيز","في الطريق","مكتمل","ملغي"];
 const status=cleanText(req.body.status,40);if(!allowed.includes(status))return res.status(400).json({error:"حالة الطلب غير صالحة"});
 const r=db.prepare("UPDATE orders SET status=? WHERE id=?").run(status,Number(req.params.id));
 if(!r.changes)return res.status(404).json({error:"الطلب غير موجود"});
 res.json({ok:true});
});
app.get("/api/admin/seller-applications", requireAdmin, (req,res) => res.json({applications:db.prepare("SELECT * FROM seller_applications ORDER BY id DESC LIMIT 300").all()}));
app.patch("/api/admin/seller-applications/:id", requireAdmin, (req,res) => {
 const status=cleanText(req.body.status,40);if(!["قيد المراجعة","مقبول","مرفوض"].includes(status))return res.status(400).json({error:"الحالة غير صالحة"});
 const r=db.prepare("UPDATE seller_applications SET status=? WHERE id=?").run(status,Number(req.params.id));
 if(!r.changes)return res.status(404).json({error:"الطلب غير موجود"});res.json({ok:true});
});

app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"حدث خطأ داخلي غير متوقع"});});
app.listen(PORT,()=>console.log(`Omdurman Market running at http://localhost:${PORT}`));
 
