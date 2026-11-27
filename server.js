const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false } : false
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "12mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new PgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || "change-this-secret-before-production",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7 * 86400000 }
}));
app.use(express.static("public"));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));

const q = (sql, params=[]) => pool.query(sql, params);
const money = n => Math.round(Number(n) * 100) / 100;
const clean = s => String(s ?? "").trim();
const email = s => clean(s).toLowerCase();
const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
function requireAuth(req,res,next){ if(!req.session.user) return res.status(401).json({error:"Connectez-vous pour continuer."}); next(); }
function requireRole(...roles){ return (req,res,next)=>{ if(!req.session.user) return res.status(401).json({error:"Connexion requise."}); if(!roles.includes(req.session.user.role)) return res.status(403).json({error:"Accès refusé."}); next(); }; }
async function notify(userId,kind,title,body="",targetUrl=""){ if(userId) await q("INSERT INTO notifications(user_id,kind,title,body,target_url) VALUES($1,$2,$3,$4,$5)",[userId,kind,title,body,targetUrl]); }
function validEmail(s){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }

async function init(){
  await q(`CREATE TABLE IF NOT EXISTS users(
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    phone TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('customer','seller','affiliate','admin')),
    active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS products(
    id BIGSERIAL PRIMARY KEY, seller_id BIGINT NOT NULL REFERENCES users(id),
    title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '',
    image_url TEXT NOT NULL DEFAULT '', price NUMERIC(12,2) NOT NULL CHECK(price > 0),
    stock INTEGER NOT NULL CHECK(stock >= 0), commission NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(commission >= 0),
    delivery_fee NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(delivery_fee >= 0),
    active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS orders(
    id BIGSERIAL PRIMARY KEY, order_code TEXT UNIQUE NOT NULL,
    product_id BIGINT NOT NULL REFERENCES products(id), seller_id BIGINT NOT NULL REFERENCES users(id),
    customer_id BIGINT NOT NULL REFERENCES users(id), affiliate_id BIGINT REFERENCES users(id),
    quantity INTEGER NOT NULL CHECK(quantity > 0), unit_price NUMERIC(12,2) NOT NULL,
    commission_each NUMERIC(12,2) NOT NULL DEFAULT 0, delivery_fee NUMERIC(12,2) NOT NULL DEFAULT 0,
    total NUMERIC(12,2) NOT NULL, customer_name TEXT NOT NULL, customer_phone TEXT NOT NULL,
    delivery_address TEXT NOT NULL, delivery_method TEXT NOT NULL CHECK(delivery_method IN ('delivery','pickup')),
    payment_method TEXT NOT NULL DEFAULT 'cash' CHECK(payment_method='cash'),
    payment_status TEXT NOT NULL DEFAULT 'unpaid' CHECK(payment_status IN ('unpaid','paid')),
    status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','accepted','preparing','ready','shipped','delivered','cancelled')),
    commission_status TEXT NOT NULL DEFAULT 'pending' CHECK(commission_status IN ('pending','available','paid','cancelled')),
    created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS commission_ledger(
    id BIGSERIAL PRIMARY KEY, order_id BIGINT UNIQUE NOT NULL REFERENCES orders(id),
    affiliate_id BIGINT NOT NULL REFERENCES users(id), amount NUMERIC(12,2) NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','available','paid','cancelled')),
    created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS withdrawal_requests(
    id BIGSERIAL PRIMARY KEY, affiliate_id BIGINT NOT NULL REFERENCES users(id),
    amount NUMERIC(12,2) NOT NULL CHECK(amount > 0), payout_details TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'requested' CHECK(status IN ('requested','approved','rejected','paid')),
    created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS messages(
    id BIGSERIAL PRIMARY KEY, sender_id BIGINT NOT NULL REFERENCES users(id), recipient_id BIGINT NOT NULL REFERENCES users(id),
    body TEXT NOT NULL DEFAULT '', attachment_name TEXT, attachment_type TEXT, attachment_data TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(), read_at TIMESTAMPTZ,
    CHECK(sender_id <> recipient_id), CHECK(length(body) <= 5000), CHECK(length(COALESCE(attachment_data,'')) <= 10000000))`);
  await q(`CREATE TABLE IF NOT EXISTS notifications(
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', target_url TEXT NOT NULL DEFAULT '',
    read_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS social_posts(
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id), body TEXT NOT NULL DEFAULT '',
    media_url TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW(), CHECK(length(body)<=5000))`);
  await q(`CREATE TABLE IF NOT EXISTS post_comments(
    id BIGSERIAL PRIMARY KEY, post_id BIGINT NOT NULL REFERENCES social_posts(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id), body TEXT NOT NULL CHECK(length(body)<=2000), created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS post_reactions(
    post_id BIGINT NOT NULL REFERENCES social_posts(id) ON DELETE CASCADE, user_id BIGINT NOT NULL REFERENCES users(id),
    reaction TEXT NOT NULL DEFAULT 'like', created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY(post_id,user_id))`);
  await q(`CREATE TABLE IF NOT EXISTS social_groups(
    id BIGSERIAL PRIMARY KEY, owner_id BIGINT NOT NULL REFERENCES users(id), name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '', visibility TEXT NOT NULL DEFAULT 'public' CHECK(visibility IN ('public','private')),
    created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS group_members(
    group_id BIGINT NOT NULL REFERENCES social_groups(id) ON DELETE CASCADE, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner','member')), joined_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY(group_id,user_id))`);
  await q(`CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id,recipient_id,created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id,created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_social_posts_date ON social_posts(created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_products_active ON products(active, created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id, created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id, created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_orders_affiliate ON orders(affiliate_id, created_at DESC)`);
  if(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD){
    const e=email(process.env.ADMIN_EMAIL);
    const found=await q("SELECT id FROM users WHERE email=$1",[e]);
    if(!found.rowCount){
      const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD,12);
      await q("INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,'admin')",["Administrateur",e,hash]);
    }
  }
}

app.get("/health", asyncRoute(async(req,res)=>{await q("SELECT 1");res.json({ok:true,service:"WinCash"});}));

app.post("/api/register", asyncRoute(async(req,res)=>{
  const name=clean(req.body.name), e=email(req.body.email), phone=clean(req.body.phone);
  const password=String(req.body.password||""), role=clean(req.body.role);
  if(name.length<2 || !validEmail(e) || password.length<8 || !["customer","seller","affiliate"].includes(role))
    return res.status(400).json({error:"Vérifiez les champs. Mot de passe : 8 caractères minimum."});
  if(phone.length<5) return res.status(400).json({error:"Ajoutez un numéro de téléphone valide."});
  const hash=await bcrypt.hash(password,12);
  try{
    const r=await q("INSERT INTO users(name,email,phone,password_hash,role) VALUES($1,$2,$3,$4,$5) RETURNING id,name,email,phone,role",
      [name,e,phone,hash,role]);
    req.session.user=r.rows[0]; res.status(201).json({user:r.rows[0]});
  }catch(err){if(err.code==="23505") return res.status(409).json({error:"Cette adresse e-mail est déjà utilisée."}); throw err;}
}));

app.post("/api/login", asyncRoute(async(req,res)=>{
  const e=email(req.body.email), password=String(req.body.password||"");
  const r=await q("SELECT id,name,email,phone,role,password_hash,active FROM users WHERE email=$1",[e]);
  if(!r.rowCount || !r.rows[0].active || !(await bcrypt.compare(password,r.rows[0].password_hash)))
    return res.status(401).json({error:"E-mail ou mot de passe incorrect."});
  const {password_hash,active,...user}=r.rows[0]; req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Erreur de session."});req.session.user=user;res.json({user});});
}));
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));

app.get("/api/products", asyncRoute(async(req,res)=>{
  const r=await q(`SELECT p.id,p.title,p.description,p.category,p.image_url,p.price,p.stock,p.commission,p.delivery_fee,p.created_at,u.name seller_name
    FROM products p JOIN users u ON u.id=p.seller_id WHERE p.active=TRUE AND p.stock>0 ORDER BY p.created_at DESC`);
  res.json({products:r.rows});
}));
app.post("/api/products",requireRole("seller"),asyncRoute(async(req,res)=>{
  const b=req.body, title=clean(b.title), description=clean(b.description), category=clean(b.category), image=clean(b.image_url);
  const price=money(b.price), stock=Number(b.stock), commission=money(b.commission||0), fee=money(b.delivery_fee||0);
  if(title.length<3 || !Number.isFinite(price)||price<=0||!Number.isInteger(stock)||stock<0||commission<0||fee<0)
    return res.status(400).json({error:"Vérifiez le nom, le prix, le stock et les montants."});
  if(commission>price) return res.status(400).json({error:"La commission ne peut pas dépasser le prix du produit."});
  const r=await q(`INSERT INTO products(seller_id,title,description,category,image_url,price,stock,commission,delivery_fee)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [req.session.user.id,title,description,category,image,price,stock,commission,fee]);
  res.status(201).json({product:r.rows[0]});
}));
app.get("/api/my/products",requireRole("seller"),asyncRoute(async(req,res)=>{
  const r=await q("SELECT * FROM products WHERE seller_id=$1 ORDER BY created_at DESC",[req.session.user.id]);res.json({products:r.rows});
}));
app.patch("/api/products/:id",requireRole("seller"),asyncRoute(async(req,res)=>{
  const b=req.body;
  const r=await q(`UPDATE products SET title=COALESCE($1,title),description=COALESCE($2,description),
    price=COALESCE($3,price),stock=COALESCE($4,stock),commission=COALESCE($5,commission),
    delivery_fee=COALESCE($6,delivery_fee),active=COALESCE($7,active)
    WHERE id=$8 AND seller_id=$9 RETURNING *`,
    [b.title===undefined?null:clean(b.title),b.description===undefined?null:clean(b.description),
     b.price===undefined?null:money(b.price),b.stock===undefined?null:Number(b.stock),
     b.commission===undefined?null:money(b.commission),b.delivery_fee===undefined?null:money(b.delivery_fee),
     b.active===undefined?null:!!b.active,req.params.id,req.session.user.id]);
  if(!r.rowCount)return res.status(404).json({error:"Produit introuvable."});
  res.json({product:r.rows[0]});
}));

app.post("/api/orders",requireAuth,asyncRoute(async(req,res)=>{
  const b=req.body, productId=Number(b.product_id), qty=Number(b.quantity);
  const customerName=clean(b.customer_name), customerPhone=clean(b.customer_phone), address=clean(b.address);
  const method=clean(b.delivery_method), affiliateId=b.affiliate_id?Number(b.affiliate_id):null;
  if(!Number.isInteger(productId)||!Number.isInteger(qty)||qty<1||customerName.length<2||customerPhone.length<5||address.length<4||!["delivery","pickup"].includes(method))
    return res.status(400).json({error:"Complétez les informations de commande."});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const pr=await client.query("SELECT * FROM products WHERE id=$1 AND active=TRUE FOR UPDATE",[productId]);
    if(!pr.rowCount) throw Object.assign(new Error("Produit indisponible."),{status:404});
    const p=pr.rows[0];
    if(p.stock<qty) throw Object.assign(new Error("Stock insuffisant."),{status:400});
    let aff=null;
    if(affiliateId){
      const ar=await client.query("SELECT id,role,active FROM users WHERE id=$1",[affiliateId]);
      if(!ar.rowCount||ar.rows[0].role!=="affiliate"||!ar.rows[0].active) throw Object.assign(new Error("Lien affilié invalide."),{status:400});
      if(Number(affiliateId)===Number(req.session.user.id)) throw Object.assign(new Error("Vous ne pouvez pas être votre propre affilié."),{status:400});
      aff=affiliateId;
    }
    if(Number(p.seller_id)===Number(req.session.user.id)) throw Object.assign(new Error("Vous ne pouvez pas commander votre propre produit."),{status:400});
    const deliveryFee=method==="pickup"?0:Number(p.delivery_fee);
    const total=money(Number(p.price)*qty+deliveryFee);
    const code="WC-"+crypto.randomBytes(4).toString("hex").toUpperCase();
    const ins=await client.query(`INSERT INTO orders(order_code,product_id,seller_id,customer_id,affiliate_id,quantity,unit_price,commission_each,delivery_fee,total,customer_name,customer_phone,delivery_address,delivery_method)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [code,p.id,p.seller_id,req.session.user.id,aff,qty,p.price,aff?p.commission:0,deliveryFee,total,customerName,customerPhone,address,method]);
    await client.query("UPDATE products SET stock=stock-$1 WHERE id=$2",[qty,p.id]);
    if(aff) await client.query("INSERT INTO commission_ledger(order_id,affiliate_id,amount) VALUES($1,$2,$3)",
      [ins.rows[0].id,aff,money(Number(p.commission)*qty)]);
    await client.query("COMMIT"); res.status(201).json({order:ins.rows[0]});
  }catch(err){await client.query("ROLLBACK");res.status(err.status||400).json({error:err.message||"Commande impossible."});}
  finally{client.release();}
}));

app.get("/api/orders",requireAuth,asyncRoute(async(req,res)=>{
  const u=req.session.user; let sql,params;
  if(u.role==="admin"){sql=`SELECT o.*,p.title product_title,s.name seller_name,c.name customer_user_name,a.name affiliate_name FROM orders o JOIN products p ON p.id=o.product_id JOIN users s ON s.id=o.seller_id JOIN users c ON c.id=o.customer_id LEFT JOIN users a ON a.id=o.affiliate_id ORDER BY o.created_at DESC`;params=[];}
  else if(u.role==="seller"){sql=`SELECT o.*,p.title product_title,a.name affiliate_name FROM orders o JOIN products p ON p.id=o.product_id LEFT JOIN users a ON a.id=o.affiliate_id WHERE o.seller_id=$1 ORDER BY o.created_at DESC`;params=[u.id];}
  else if(u.role==="affiliate"){sql=`SELECT o.*,p.title product_title,s.name seller_name FROM orders o JOIN products p ON p.id=o.product_id JOIN users s ON s.id=o.seller_id WHERE o.affiliate_id=$1 ORDER BY o.created_at DESC`;params=[u.id];}
  else {sql=`SELECT o.*,p.title product_title,s.name seller_name FROM orders o JOIN products p ON p.id=o.product_id JOIN users s ON s.id=o.seller_id WHERE o.customer_id=$1 ORDER BY o.created_at DESC`;params=[u.id];}
  const r=await q(sql,params);res.json({orders:r.rows});
}));
app.patch("/api/orders/:id/status",requireRole("seller","admin"),asyncRoute(async(req,res)=>{
  const allowed=["accepted","preparing","ready","shipped","delivered","cancelled"];
  const status=clean(req.body.status); if(!allowed.includes(status))return res.status(400).json({error:"Statut invalide."});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const r=await client.query("SELECT * FROM orders WHERE id=$1 FOR UPDATE",[req.params.id]);
    if(!r.rowCount)throw Object.assign(new Error("Commande introuvable."),{status:404});
    const o=r.rows[0], u=req.session.user;
    if(u.role!=="admin"&&Number(o.seller_id)!==Number(u.id))throw Object.assign(new Error("Accès refusé."),{status:403});
    if(o.status==="cancelled"||o.status==="delivered")throw Object.assign(new Error("Cette commande est déjà clôturée."),{status:400});
    if(status==="cancelled"){
      await client.query("UPDATE products SET stock=stock+$1 WHERE id=$2",[o.quantity,o.product_id]);
      await client.query("UPDATE commission_ledger SET status='cancelled' WHERE order_id=$1",[o.id]);
      await client.query("UPDATE orders SET commission_status='cancelled' WHERE id=$1",[o.id]);
    }
    if(status==="delivered"&&o.payment_status!=="paid")throw Object.assign(new Error("Confirmez d'abord le paiement en espèces avant de clôturer la livraison."),{status:400});
    if(status==="delivered"&&o.affiliate_id){
      await client.query("UPDATE commission_ledger SET status='available' WHERE order_id=$1 AND status='pending'",[o.id]);
      await client.query("UPDATE orders SET commission_status='available' WHERE id=$1",[o.id]);
    }
    await client.query("UPDATE orders SET status=$1,updated_at=NOW() WHERE id=$2",[status,o.id]);
    await client.query("COMMIT");res.json({ok:true});
  }catch(err){await client.query("ROLLBACK");res.status(err.status||400).json({error:err.message});}
  finally{client.release();}
}));
app.post("/api/orders/:id/confirm-cash",requireRole("seller","admin"),asyncRoute(async(req,res)=>{
  const r=await q("SELECT * FROM orders WHERE id=$1",[req.params.id]);
  if(!r.rowCount)return res.status(404).json({error:"Commande introuvable."});
  if(req.session.user.role!=="admin"&&Number(r.rows[0].seller_id)!==Number(req.session.user.id))return res.status(403).json({error:"Accès refusé."});
  if(r.rows[0].status==="cancelled")return res.status(400).json({error:"Commande annulée."});
  await q("UPDATE orders SET payment_status='paid',updated_at=NOW() WHERE id=$1",[req.params.id]);
  res.json({ok:true,message:"Paiement en espèces confirmé."});
}));
app.get("/api/affiliate/summary",requireRole("affiliate"),asyncRoute(async(req,res)=>{
  const r=await q(`SELECT COALESCE(SUM(amount) FILTER(WHERE status='pending'),0) pending,
    COALESCE(SUM(amount) FILTER(WHERE status='available'),0) available,
    COALESCE(SUM(amount) FILTER(WHERE status='paid'),0) paid FROM commission_ledger WHERE affiliate_id=$1`,[req.session.user.id]);
  const w=await q("SELECT * FROM withdrawal_requests WHERE affiliate_id=$1 ORDER BY created_at DESC",[req.session.user.id]);
  res.json({summary:r.rows[0],withdrawals:w.rows});
}));
app.post("/api/affiliate/withdraw",requireRole("affiliate"),asyncRoute(async(req,res)=>{
  const amount=money(req.body.amount), details=clean(req.body.payout_details);
  if(amount<=0||details.length<5)return res.status(400).json({error:"Montant ou coordonnées de retrait invalides."});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    await client.query("SELECT id FROM users WHERE id=$1 FOR UPDATE",[req.session.user.id]);
    const r=await client.query("SELECT COALESCE(SUM(amount),0) available FROM commission_ledger WHERE affiliate_id=$1 AND status='available'",[req.session.user.id]);
    const available=money(r.rows[0].available);
    if(amount<=0 || Math.abs(available-amount)>0.01)
      throw Object.assign(new Error("Pour cette première version, demandez le retrait de la totalité de votre solde disponible ("+available+" Kz)."),{status:400});
    if(available<=0)throw Object.assign(new Error("Aucune commission disponible."),{status:400});
    await client.query("UPDATE commission_ledger SET status='paid' WHERE affiliate_id=$1 AND status='available'",[req.session.user.id]);
    await client.query("INSERT INTO withdrawal_requests(affiliate_id,amount,payout_details,status) VALUES($1,$2,$3,'requested')",[req.session.user.id,amount,details]);
    await client.query("COMMIT");res.json({ok:true,message:"Demande enregistrée. L'administrateur traitera le paiement manuellement."});
  }catch(err){await client.query("ROLLBACK");res.status(err.status||400).json({error:err.message});}
  finally{client.release();}
}));
app.get("/api/admin/overview",requireRole("admin"),asyncRoute(async(req,res)=>{
  const [users,products,orders,withdrawals]=await Promise.all([
    q("SELECT role,COUNT(*)::int count FROM users GROUP BY role"),
    q("SELECT COUNT(*)::int count FROM products"),
    q("SELECT status,COUNT(*)::int count,COALESCE(SUM(total),0) total FROM orders GROUP BY status"),
    q("SELECT w.*,u.name affiliate_name,u.email FROM withdrawal_requests w JOIN users u ON u.id=w.affiliate_id ORDER BY w.created_at DESC")
  ]);
  res.json({users:users.rows,products:products.rows[0]?.count||0,orders:orders.rows,withdrawals:withdrawals.rows});
}));
app.patch("/api/admin/withdrawals/:id",requireRole("admin"),asyncRoute(async(req,res)=>{
  const status=clean(req.body.status);if(!["approved","rejected","paid"].includes(status))return res.status(400).json({error:"Statut invalide."});
  const r=await q("UPDATE withdrawal_requests SET status=$1 WHERE id=$2 RETURNING *",[status,req.params.id]);
  if(!r.rowCount)return res.status(404).json({error:"Demande introuvable."});
  res.json({withdrawal:r.rows[0]});
}));
app.get("/api/affiliate/link/:productId",requireRole("affiliate"),asyncRoute(async(req,res)=>{
  const r=await q("SELECT id FROM products WHERE id=$1 AND active=TRUE",[req.params.productId]);
  if(!r.rowCount)return res.status(404).json({error:"Produit introuvable."});
  const origin=`${req.protocol}://${req.get("host")}`;
  res.json({link:`${origin}/?product=${req.params.productId}&ref=${req.session.user.id}`});
}));

// MESSAGERIE PRIVEE, PIECES JOINTES ET NOTIFICATIONS
app.get("/api/members",requireAuth,asyncRoute(async(req,res)=>{
 const term=`%${clean(req.query.q).slice(0,60)}%`;
 const r=await q("SELECT id,name,role FROM users WHERE active=TRUE AND id<>$1 AND name ILIKE $2 ORDER BY name LIMIT 50",[req.session.user.id,term]); res.json({members:r.rows});
}));
app.get("/api/messages/:userId",requireAuth,asyncRoute(async(req,res)=>{
 const other=Number(req.params.userId); if(!Number.isInteger(other)||other===Number(req.session.user.id))return res.status(400).json({error:"Destinataire invalide."});
 const r=await q(`SELECT m.id,m.sender_id,m.recipient_id,m.body,m.attachment_name,m.attachment_type,m.attachment_data,m.created_at,m.read_at,u.name sender_name
 FROM messages m JOIN users u ON u.id=m.sender_id WHERE (m.sender_id=$1 AND m.recipient_id=$2) OR (m.sender_id=$2 AND m.recipient_id=$1) ORDER BY m.created_at ASC LIMIT 200`,[req.session.user.id,other]);
 await q("UPDATE messages SET read_at=NOW() WHERE sender_id=$1 AND recipient_id=$2 AND read_at IS NULL",[other,req.session.user.id]); res.json({messages:r.rows});
}));
app.post("/api/messages",requireAuth,asyncRoute(async(req,res)=>{
 const to=Number(req.body.recipient_id), body=clean(req.body.body), a=req.body.attachment||null;
 if(!Number.isInteger(to)||to===Number(req.session.user.id)||body.length>5000||(!body&&!a))return res.status(400).json({error:"Message invalide."});
 if(a&&(!/^data:(image\/(png|jpeg|gif|webp)|application\/pdf|text\/plain);base64,/.test(a.data||"")||String(a.data).length>10000000||clean(a.name).length>180))return res.status(400).json({error:"Pièce jointe non autorisée (images, PDF ou texte, 7 Mo maximum)."});
 const u=await q("SELECT id FROM users WHERE id=$1 AND active=TRUE",[to]); if(!u.rowCount)return res.status(404).json({error:"Membre introuvable."});
 const r=await q(`INSERT INTO messages(sender_id,recipient_id,body,attachment_name,attachment_type,attachment_data) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,created_at`,[req.session.user.id,to,body,a?clean(a.name):null,a?(a.data.split(';')[0].replace('data:','')):null,a?a.data:null]);
 await notify(to,"message","Nouveau message",body.slice(0,160),"/social.html?chat="+req.session.user.id); res.status(201).json({message:r.rows[0]});
}));
app.get("/api/notifications",requireAuth,asyncRoute(async(req,res)=>{const r=await q("SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100",[req.session.user.id]);res.json({notifications:r.rows});}));
app.patch("/api/notifications/:id/read",requireAuth,asyncRoute(async(req,res)=>{const r=await q("UPDATE notifications SET read_at=NOW() WHERE id=$1 AND user_id=$2 RETURNING id",[req.params.id,req.session.user.id]);if(!r.rowCount)return res.status(404).json({error:"Notification introuvable."});res.json({ok:true});}));
app.post("/api/notifications/read-all",requireAuth,asyncRoute(async(req,res)=>{await q("UPDATE notifications SET read_at=NOW() WHERE user_id=$1 AND read_at IS NULL",[req.session.user.id]);res.json({ok:true});}));
// FIL SOCIAL : PUBLICATIONS, COMMENTAIRES, REACTIONS
app.get("/api/social/posts",requireAuth,asyncRoute(async(req,res)=>{const r=await q(`SELECT p.*,u.name author_name,(SELECT COUNT(*)::int FROM post_comments c WHERE c.post_id=p.id) comments_count,(SELECT COUNT(*)::int FROM post_reactions x WHERE x.post_id=p.id) reactions_count,(SELECT reaction FROM post_reactions x WHERE x.post_id=p.id AND x.user_id=$1) my_reaction FROM social_posts p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 100`,[req.session.user.id]);res.json({posts:r.rows});}));
app.post("/api/social/posts",requireAuth,asyncRoute(async(req,res)=>{const body=clean(req.body.body),media=clean(req.body.media_url);if(!body&&!media||body.length>5000||media.length>2000)return res.status(400).json({error:"Publication invalide."});const r=await q("INSERT INTO social_posts(user_id,body,media_url) VALUES($1,$2,$3) RETURNING *",[req.session.user.id,body,media]);res.status(201).json({post:r.rows[0]});}));
app.post("/api/social/posts/:id/comments",requireAuth,asyncRoute(async(req,res)=>{const body=clean(req.body.body);if(!body||body.length>2000)return res.status(400).json({error:"Commentaire invalide."});const p=await q("SELECT user_id FROM social_posts WHERE id=$1",[req.params.id]);if(!p.rowCount)return res.status(404).json({error:"Publication introuvable."});const r=await q("INSERT INTO post_comments(post_id,user_id,body) VALUES($1,$2,$3) RETURNING *",[req.params.id,req.session.user.id,body]);if(Number(p.rows[0].user_id)!==Number(req.session.user.id))await notify(p.rows[0].user_id,"comment","Nouveau commentaire",body.slice(0,150),"/social.html");res.status(201).json({comment:r.rows[0]});}));
app.get("/api/social/posts/:id/comments",requireAuth,asyncRoute(async(req,res)=>{const r=await q("SELECT c.*,u.name author_name FROM post_comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=$1 ORDER BY c.created_at ASC",[req.params.id]);res.json({comments:r.rows});}));
app.post("/api/social/posts/:id/react",requireAuth,asyncRoute(async(req,res)=>{const reaction=clean(req.body.reaction||"like");if(!["like","love","support"].includes(reaction))return res.status(400).json({error:"Réaction invalide."});await q("INSERT INTO post_reactions(post_id,user_id,reaction) VALUES($1,$2,$3) ON CONFLICT(post_id,user_id) DO UPDATE SET reaction=EXCLUDED.reaction",[req.params.id,req.session.user.id,reaction]);res.json({ok:true});}));
// GROUPES PUBLICS/PRIVES
app.get("/api/social/groups",requireAuth,asyncRoute(async(req,res)=>{const r=await q(`SELECT g.*,u.name owner_name,(SELECT COUNT(*)::int FROM group_members gm WHERE gm.group_id=g.id) members_count,EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=g.id AND gm.user_id=$1) joined FROM social_groups g JOIN users u ON u.id=g.owner_id WHERE g.visibility='public' OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=g.id AND gm.user_id=$1) ORDER BY g.created_at DESC`,[req.session.user.id]);res.json({groups:r.rows});}));
app.post("/api/social/groups",requireAuth,asyncRoute(async(req,res)=>{const name=clean(req.body.name),description=clean(req.body.description),visibility=clean(req.body.visibility||"public");if(name.length<3||name.length>100||description.length>1000||!["public","private"].includes(visibility))return res.status(400).json({error:"Informations du groupe invalides."});const r=await q("INSERT INTO social_groups(owner_id,name,description,visibility) VALUES($1,$2,$3,$4) RETURNING *",[req.session.user.id,name,description,visibility]);await q("INSERT INTO group_members(group_id,user_id,role) VALUES($1,$2,'owner')",[r.rows[0].id,req.session.user.id]);res.status(201).json({group:r.rows[0]});}));
app.post("/api/social/groups/:id/join",requireAuth,asyncRoute(async(req,res)=>{const g=await q("SELECT * FROM social_groups WHERE id=$1",[req.params.id]);if(!g.rowCount)return res.status(404).json({error:"Groupe introuvable."});if(g.rows[0].visibility==="private")return res.status(403).json({error:"Ce groupe est privé : demandez une invitation à son propriétaire."});await q("INSERT INTO group_members(group_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[req.params.id,req.session.user.id]);res.json({ok:true});}));

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"Erreur interne. Réessayez plus tard."});});
app.get("*",(req,res)=>res.sendFile(require("path").join(__dirname,"public","index.html")));

init().then(()=>app.listen(port,()=>console.log(`WinCash running on ${port}`))).catch(err=>{console.error("Database initialization failed:",err);process.exit(1);});
