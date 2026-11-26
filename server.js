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
app.use(express.json({ limit: "6mb" }));
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
function requireRole(...roles){ return (req,res,next)=>{ if(!req.session.user) return res.status(401).json({error:"Connexion requise."}); if(!(req.session.user.roles||[req.session.user.role]).some(r=>roles.includes(r))) return res.status(403).json({error:"Accès refusé."}); next(); }; }
function validEmail(s){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }

async function init(){
  await q(`CREATE TABLE IF NOT EXISTS users(
    id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    phone TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('customer','seller','affiliate','admin')),
    roles TEXT[] NOT NULL DEFAULT ARRAY['customer'],
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
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS roles TEXT[] NOT NULL DEFAULT ARRAY['customer']`);
  await q(`UPDATE users SET roles=ARRAY[role] WHERE roles IS NULL OR cardinality(roles)=0 OR (roles=ARRAY['customer'] AND role<>'customer')`);
  await q(`UPDATE products SET active=FALSE WHERE commission<=0`);
  await q(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS affiliate_name_snapshot TEXT NOT NULL DEFAULT ''`);
  await q(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS affiliate_phone_snapshot TEXT NOT NULL DEFAULT ''`);
  await q(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS affiliate_email_snapshot TEXT NOT NULL DEFAULT ''`);
  await q(`CREATE TABLE IF NOT EXISTS conversations(id BIGSERIAL PRIMARY KEY, user_a BIGINT NOT NULL REFERENCES users(id), user_b BIGINT NOT NULL REFERENCES users(id), created_at TIMESTAMPTZ DEFAULT NOW(), CHECK(user_a < user_b), UNIQUE(user_a,user_b))`);
  await q(`CREATE TABLE IF NOT EXISTS messages(id BIGSERIAL PRIMARY KEY, conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE, sender_id BIGINT NOT NULL REFERENCES users(id), body TEXT NOT NULL, attachment_url TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS social_groups(id BIGSERIAL PRIMARY KEY, owner_id BIGINT NOT NULL REFERENCES users(id), name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', is_public BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS group_members(group_id BIGINT NOT NULL REFERENCES social_groups(id) ON DELETE CASCADE, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, joined_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY(group_id,user_id))`);
  await q(`CREATE TABLE IF NOT EXISTS group_messages(id BIGSERIAL PRIMARY KEY, group_id BIGINT NOT NULL REFERENCES social_groups(id) ON DELETE CASCADE, sender_id BIGINT NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS pages(id BIGSERIAL PRIMARY KEY, owner_id BIGINT NOT NULL REFERENCES users(id), name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE TABLE IF NOT EXISTS page_followers(page_id BIGINT NOT NULL REFERENCES pages(id) ON DELETE CASCADE, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY(page_id,user_id))`);
  await q(`CREATE TABLE IF NOT EXISTS posts(id BIGSERIAL PRIMARY KEY, author_id BIGINT NOT NULL REFERENCES users(id), page_id BIGINT REFERENCES pages(id) ON DELETE CASCADE, body TEXT NOT NULL DEFAULT '', media_url TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW())`);
  await q(`CREATE INDEX IF NOT EXISTS idx_products_active ON products(active, created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id, created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id, created_at DESC)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_orders_affiliate ON orders(affiliate_id, created_at DESC)`);
  if(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD){
    const e=email(process.env.ADMIN_EMAIL);
    const found=await q("SELECT id FROM users WHERE email=$1",[e]);
    const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD,12);
    if(!found.rowCount){
      await q("INSERT INTO users(name,email,password_hash,role,roles) VALUES($1,$2,$3,'admin',ARRAY['admin'])",["Administrateur",e,hash]);
    } else {
      await q("UPDATE users SET password_hash=$2,role='admin',roles=CASE WHEN 'admin'=ANY(roles) THEN roles ELSE array_append(roles,'admin') END,active=TRUE WHERE email=$1",[e,hash]);
    }
  }
}

app.get("/health", asyncRoute(async(req,res)=>{await q("SELECT 1");res.json({ok:true,service:"WinCash"});}));

app.post("/api/register", asyncRoute(async(req,res)=>{
  const name=clean(req.body.name), e=email(req.body.email), phone=clean(req.body.phone);
  const password=String(req.body.password||""), role=clean(req.body.role);
  if(name.length<2 || !validEmail(e) || password.length<8 || !["customer","seller","affiliate"].includes(role)) return res.status(400).json({error:"Vérifiez les champs. Mot de passe : 8 caractères minimum."});
  if(phone.length<5) return res.status(400).json({error:"Ajoutez un numéro de téléphone valide."});
  const existing=await q("SELECT * FROM users WHERE email=$1",[e]);
  if(existing.rowCount){
    if(!(await bcrypt.compare(password,existing.rows[0].password_hash))) return res.status(409).json({error:"Cette adresse existe déjà. Connectez-vous avec son mot de passe pour ajouter un rôle."});
    const r=await q("UPDATE users SET roles=CASE WHEN $2=ANY(roles) THEN roles ELSE array_append(roles,$2) END, phone=CASE WHEN phone='' THEN $3 ELSE phone END WHERE id=$1 RETURNING id,name,email,phone,role,roles",[existing.rows[0].id,role,phone]);
    req.session.user=r.rows[0]; return res.status(200).json({user:r.rows[0],message:"Rôle ajouté au compte existant."});
  }
  const hash=await bcrypt.hash(password,12);
  const r=await q("INSERT INTO users(name,email,phone,password_hash,role,roles) VALUES($1,$2,$3,$4,$5,ARRAY[$5]) RETURNING id,name,email,phone,role,roles",[name,e,phone,hash,role]);
  req.session.user=r.rows[0]; res.status(201).json({user:r.rows[0]});
}));
app.post("/api/login", asyncRoute(async(req,res)=>{
  const e=email(req.body.email), password=String(req.body.password||"");
  const r=await q("SELECT id,name,email,phone,role,roles,password_hash,active FROM users WHERE email=$1",[e]);
  if(!r.rowCount || !r.rows[0].active || !(await bcrypt.compare(password,r.rows[0].password_hash)))
    return res.status(401).json({error:"E-mail ou mot de passe incorrect."});
  const {password_hash,active,...user}=r.rows[0]; req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Erreur de session."});req.session.user=user;res.json({user});});
}));
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));

app.get("/api/products", asyncRoute(async(req,res)=>{
  const r=await q(`SELECT p.id,p.title,p.description,p.category,p.image_url,p.price,p.stock,p.commission,p.delivery_fee,p.created_at,u.name seller_name,u.phone seller_phone,u.email seller_email
    FROM products p JOIN users u ON u.id=p.seller_id WHERE p.active=TRUE AND p.stock>0 ORDER BY p.created_at DESC`);
  res.json({products:r.rows});
}));
app.post("/api/products",requireRole("seller"),asyncRoute(async(req,res)=>{
  const b=req.body, title=clean(b.title), description=clean(b.description), category=clean(b.category), image=clean(b.image_url);
  const price=money(b.price), stock=Number(b.stock), commission=money(b.commission||0), fee=money(b.delivery_fee||0);
  if(title.length<3 || !Number.isFinite(price)||price<=0||!Number.isInteger(stock)||stock<0||commission<=0||fee<0)
    return res.status(400).json({error:"Vérifiez le nom, le prix, le stock et indiquez une commission affilié supérieure à zéro."});
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
  if(b.commission!==undefined && (!Number.isFinite(Number(b.commission)) || Number(b.commission)<=0)) return res.status(400).json({error:"Chaque produit doit conserver une commission affilié supérieure à zéro."});
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
      const ar=await client.query("SELECT id,role,roles,active FROM users WHERE id=$1",[affiliateId]);
      if(!ar.rowCount||!(ar.rows[0].roles||[ar.rows[0].role]).includes("affiliate")||!ar.rows[0].active) throw Object.assign(new Error("Lien affilié invalide."),{status:400});
      if(Number(affiliateId)===Number(req.session.user.id)) throw Object.assign(new Error("Vous ne pouvez pas être votre propre affilié."),{status:400});
      aff=affiliateId;
    }
    if(Number(p.seller_id)===Number(req.session.user.id)) throw Object.assign(new Error("Vous ne pouvez pas commander votre propre produit."),{status:400});
    const deliveryFee=method==="pickup"?0:Number(p.delivery_fee);
    const total=money(Number(p.price)*qty+deliveryFee);
    const code="WC-"+crypto.randomBytes(4).toString("hex").toUpperCase();
    const ins=await client.query(`INSERT INTO orders(order_code,product_id,seller_id,customer_id,affiliate_id,quantity,unit_price,commission_each,delivery_fee,total,customer_name,customer_phone,delivery_address,delivery_method,affiliate_name_snapshot,affiliate_phone_snapshot,affiliate_email_snapshot)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,
      [code,p.id,p.seller_id,req.session.user.id,aff,qty,p.price,aff?p.commission:0,deliveryFee,total,customerName,customerPhone,address,method,aff?(await client.query("SELECT name FROM users WHERE id=$1",[aff])).rows[0].name:"",aff?(await client.query("SELECT phone FROM users WHERE id=$1",[aff])).rows[0].phone:"",aff?(await client.query("SELECT email FROM users WHERE id=$1",[aff])).rows[0].email:""]);
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
app.get("/media/:productId",asyncRoute(async(req,res)=>{const r=await q("SELECT image_url FROM products WHERE id=$1",[req.params.productId]);if(!r.rowCount||!r.rows[0].image_url)return res.status(404).end();const value=r.rows[0].image_url;const m=value.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);if(m){res.type(m[1]);return res.send(Buffer.from(m[2],"base64"));}return res.redirect(value);}));
app.get("/share/:productId",asyncRoute(async(req,res)=>{const r=await q("SELECT p.*,u.name seller_name FROM products p JOIN users u ON u.id=p.seller_id WHERE p.id=$1 AND p.active=TRUE",[req.params.productId]);if(!r.rowCount)return res.status(404).send("Produit introuvable");const p=r.rows[0],ref=Number(req.query.ref)||0;const escHtml=v=>String(v||"").replace(/[&<>\"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'\"':"&quot;","'":"&#39;"}[c]));const url=`${req.protocol}://${req.get("host")}/?product=${p.id}&ref=${ref}&sig=${encodeURIComponent(req.query.sig||"")}`;res.type("html").send(`<!doctype html><html><head><meta charset="utf-8"><meta property="og:type" content="product"><meta property="og:title" content="${escHtml(p.title)}"><meta property="og:description" content="${escHtml(p.description)} — ${p.price} Kz"><meta property="og:image" content="${escHtml(`${req.protocol}://${req.get("host")}/media/${p.id}`)}"><meta property="og:url" content="${url}"><meta name="twitter:card" content="summary_large_image"><meta http-equiv="refresh" content="0;url=${url}"><title>${escHtml(p.title)} — WinCash</title></head><body><a href="${url}">Voir le produit sur WinCash</a></body></html>`);}));
app.get("/api/affiliate/link/:productId",requireRole("affiliate"),asyncRoute(async(req,res)=>{
  const r=await q("SELECT id FROM products WHERE id=$1 AND active=TRUE",[req.params.productId]);
  if(!r.rowCount)return res.status(404).json({error:"Produit introuvable."});
  const origin=`${req.protocol}://${req.get("host")}`;
  const sig=crypto.createHmac("sha256",process.env.SESSION_SECRET||"change-this-secret-before-production").update(`${req.params.productId}:${req.session.user.id}`).digest("hex");
  res.json({link:`${origin}/share/${req.params.productId}?ref=${req.session.user.id}&sig=${sig}`});
}));

// Public member profile and account role management
app.get("/api/members",requireAuth,asyncRoute(async(req,res)=>{const term=`%${clean(req.query.q)}%`;const r=await q("SELECT id,name,phone,roles FROM users WHERE active=TRUE AND id<>$1 AND (name ILIKE $2 OR email ILIKE $2) ORDER BY name LIMIT 50",[req.session.user.id,term]);res.json({members:r.rows});}));
app.get("/api/public/members/:id",asyncRoute(async(req,res)=>{const r=await q("SELECT id,name,phone,email,roles FROM users WHERE id=$1 AND active=TRUE",[req.params.id]);if(!r.rowCount)return res.status(404).json({error:"Membre introuvable."});res.json({member:r.rows[0]});}));
app.post("/api/me/roles",requireAuth,asyncRoute(async(req,res)=>{const role=clean(req.body.role);if(!["customer","seller","affiliate"].includes(role))return res.status(400).json({error:"Rôle invalide."});const r=await q("UPDATE users SET roles=CASE WHEN $2=ANY(roles) THEN roles ELSE array_append(roles,$2) END WHERE id=$1 RETURNING roles",[req.session.user.id,role]);req.session.user.roles=r.rows[0].roles;res.json({roles:r.rows[0].roles});}));
app.post("/api/me/active-role",requireAuth,asyncRoute(async(req,res)=>{const role=clean(req.body.role);if(!(req.session.user.roles||[]).includes(role))return res.status(403).json({error:"Ce rôle n'est pas activé sur votre compte."});req.session.user.role=role;res.json({role});}));
app.post("/api/me/delete",requireAuth,asyncRoute(async(req,res)=>{const r=await q("SELECT password_hash FROM users WHERE id=$1",[req.session.user.id]);if(!r.rowCount||!(await bcrypt.compare(String(req.body.password||""),r.rows[0].password_hash)))return res.status(403).json({error:"Mot de passe incorrect."});const marker=`deleted-${req.session.user.id}-${Date.now()}@invalid.local`;await q("UPDATE users SET name='Compte supprimé',email=$2,phone='',password_hash=$3,active=FALSE,roles=ARRAY[]::TEXT[] WHERE id=$1",[req.session.user.id,marker,await bcrypt.hash(crypto.randomBytes(32).toString('hex'),12)]);req.session.destroy(()=>res.json({ok:true,message:"Compte désactivé et données de profil anonymisées. Les traces nécessaires aux commandes et obligations légales sont conservées."}));}));
// Direct messages: any registered member may start a conversation with another active member.
app.post("/api/conversations",requireAuth,asyncRoute(async(req,res)=>{const other=Number(req.body.member_id);if(!Number.isInteger(other)||other===Number(req.session.user.id))return res.status(400).json({error:"Destinataire invalide."});const a=Math.min(other,Number(req.session.user.id)),b=Math.max(other,Number(req.session.user.id));const u=await q("SELECT id FROM users WHERE id=$1 AND active=TRUE",[other]);if(!u.rowCount)return res.status(404).json({error:"Membre introuvable."});const r=await q("INSERT INTO conversations(user_a,user_b) VALUES($1,$2) ON CONFLICT(user_a,user_b) DO UPDATE SET user_a=EXCLUDED.user_a RETURNING id",[a,b]);res.json({conversation_id:r.rows[0].id});}));
app.get("/api/conversations",requireAuth,asyncRoute(async(req,res)=>{const id=req.session.user.id;const r=await q("SELECT c.id,CASE WHEN c.user_a=$1 THEN b.id ELSE a.id END member_id,CASE WHEN c.user_a=$1 THEN b.name ELSE a.name END member_name FROM conversations c JOIN users a ON a.id=c.user_a JOIN users b ON b.id=c.user_b WHERE c.user_a=$1 OR c.user_b=$1 ORDER BY c.created_at DESC",[id]);res.json({conversations:r.rows});}));
app.get("/api/conversations/:id/messages",requireAuth,asyncRoute(async(req,res)=>{const c=await q("SELECT id FROM conversations WHERE id=$1 AND (user_a=$2 OR user_b=$2)",[req.params.id,req.session.user.id]);if(!c.rowCount)return res.status(403).json({error:"Accès refusé."});const r=await q("SELECT m.*,u.name sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE conversation_id=$1 ORDER BY m.created_at LIMIT 200",[req.params.id]);res.json({messages:r.rows});}));
app.post("/api/conversations/:id/messages",requireAuth,asyncRoute(async(req,res)=>{const body=clean(req.body.body);if(!body||body.length>5000)return res.status(400).json({error:"Message vide ou trop long."});const c=await q("SELECT id FROM conversations WHERE id=$1 AND (user_a=$2 OR user_b=$2)",[req.params.id,req.session.user.id]);if(!c.rowCount)return res.status(403).json({error:"Accès refusé."});const r=await q("INSERT INTO messages(conversation_id,sender_id,body) VALUES($1,$2,$3) RETURNING *",[req.params.id,req.session.user.id,body]);res.status(201).json({message:r.rows[0]});}));
// Public/private groups
app.get("/api/groups",requireAuth,asyncRoute(async(req,res)=>{const r=await q("SELECT g.*,u.name owner_name FROM social_groups g JOIN users u ON u.id=g.owner_id WHERE g.is_public=TRUE OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=g.id AND gm.user_id=$1) ORDER BY g.created_at DESC",[req.session.user.id]);res.json({groups:r.rows});}));
app.post("/api/groups",requireAuth,asyncRoute(async(req,res)=>{const name=clean(req.body.name);if(name.length<3)return res.status(400).json({error:"Nom de groupe trop court."});const r=await q("INSERT INTO social_groups(owner_id,name,description,is_public) VALUES($1,$2,$3,$4) RETURNING *",[req.session.user.id,name,clean(req.body.description),req.body.is_public!==false]);await q("INSERT INTO group_members(group_id,user_id) VALUES($1,$2)",[r.rows[0].id,req.session.user.id]);res.status(201).json({group:r.rows[0]});}));
app.post("/api/groups/:id/join",requireAuth,asyncRoute(async(req,res)=>{const g=await q("SELECT id,is_public FROM social_groups WHERE id=$1",[req.params.id]);if(!g.rowCount)return res.status(404).json({error:"Groupe introuvable."});if(!g.rows[0].is_public)return res.status(403).json({error:"Groupe privé."});await q("INSERT INTO group_members(group_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[req.params.id,req.session.user.id]);res.json({ok:true});}));
app.get("/api/groups/:id/messages",requireAuth,asyncRoute(async(req,res)=>{const m=await q("SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2",[req.params.id,req.session.user.id]);if(!m.rowCount)return res.status(403).json({error:"Rejoignez le groupe pour lire ses messages."});const r=await q("SELECT gm.*,u.name sender_name FROM group_messages gm JOIN users u ON u.id=gm.sender_id WHERE group_id=$1 ORDER BY gm.created_at LIMIT 200",[req.params.id]);res.json({messages:r.rows});}));
app.post("/api/groups/:id/messages",requireAuth,asyncRoute(async(req,res)=>{const body=clean(req.body.body);const m=await q("SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2",[req.params.id,req.session.user.id]);if(!m.rowCount)return res.status(403).json({error:"Vous ne faites pas partie du groupe."});if(!body||body.length>5000)return res.status(400).json({error:"Message invalide."});const r=await q("INSERT INTO group_messages(group_id,sender_id,body) VALUES($1,$2,$3) RETURNING *",[req.params.id,req.session.user.id,body]);res.status(201).json({message:r.rows[0]});}));
// Public shop pages and posts
app.get("/api/pages",asyncRoute(async(req,res)=>{const r=await q("SELECT p.*,u.name owner_name FROM pages p JOIN users u ON u.id=p.owner_id ORDER BY p.created_at DESC");res.json({pages:r.rows});}));
app.post("/api/pages",requireAuth,asyncRoute(async(req,res)=>{const name=clean(req.body.name);if(name.length<3)return res.status(400).json({error:"Nom de page trop court."});const r=await q("INSERT INTO pages(owner_id,name,description) VALUES($1,$2,$3) RETURNING *",[req.session.user.id,name,clean(req.body.description)]);res.status(201).json({page:r.rows[0]});}));
app.post("/api/pages/:id/follow",requireAuth,asyncRoute(async(req,res)=>{await q("INSERT INTO page_followers(page_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[req.params.id,req.session.user.id]);res.json({ok:true});}));
app.get("/api/posts",asyncRoute(async(req,res)=>{const r=await q("SELECT p.*,u.name author_name,pg.name page_name FROM posts p JOIN users u ON u.id=p.author_id LEFT JOIN pages pg ON pg.id=p.page_id ORDER BY p.created_at DESC LIMIT 100");res.json({posts:r.rows});}));
app.post("/api/posts",requireAuth,asyncRoute(async(req,res)=>{const body=clean(req.body.body),media=clean(req.body.media_url);if(!body&&!media)return res.status(400).json({error:"Ajoutez un texte ou un média."});const pageId=req.body.page_id?Number(req.body.page_id):null;if(pageId){const own=await q("SELECT id FROM pages WHERE id=$1 AND owner_id=$2",[pageId,req.session.user.id]);if(!own.rowCount)return res.status(403).json({error:"Vous ne gérez pas cette page."});}const r=await q("INSERT INTO posts(author_id,page_id,body,media_url) VALUES($1,$2,$3,$4) RETURNING *",[req.session.user.id,pageId,body,media]);res.status(201).json({post:r.rows[0]});}));

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"Erreur interne. Réessayez plus tard."});});
app.get("/admin",(req,res)=>res.sendFile(require("path").join(__dirname,"public","admin.html")));
app.get("*",(req,res)=>res.sendFile(require("path").join(__dirname,"public","index.html")));

init().then(()=>app.listen(port,()=>console.log(`WinCash running on ${port}`))).catch(err=>{console.error("Database initialization failed:",err);process.exit(1);});
