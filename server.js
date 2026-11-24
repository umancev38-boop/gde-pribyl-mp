import express from "express";
import crypto from "node:crypto";
import pg from "pg";

const { Pool } = pg;
const app = express();
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
app.use(express.json({ limit: "2mb" }));

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://gde-pribyl-mp.onrender.com";
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin === FRONTEND_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", FRONTEND_ORIGIN);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});


const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 30;
const rateBuckets = new Map();

function rateLimit({ windowMs = RATE_LIMIT_WINDOW_MS, max = RATE_LIMIT_MAX } = {}) {
  return (req, res, next) => {
    const now = Date.now();
    const key = String(req.ip || req.socket.remoteAddress || "unknown");
    let bucket = rateBuckets.get(key);
    if (!bucket || now - bucket.startedAt >= windowMs) {
      bucket = { startedAt: now, count: 0 };
      rateBuckets.set(key, bucket);
    }
    bucket.count += 1;
    if (bucket.count > max) {
      const retryAfter = Math.max(1, Math.ceil((windowMs - (now - bucket.startedAt)) / 1000));
      res.setHeader("Retry-After", String(retryAfter));
      return res.status(429).json({ error: "Слишком много запросов. Подожди немного и повтори." });
    }
    if (rateBuckets.size > 5000) {
      for (const [bucketKey, value] of rateBuckets) {
        if (now - value.startedAt >= windowMs) rateBuckets.delete(bucketKey);
      }
    }
    next();
  };
}

const PORT = Number(process.env.PORT || 3000);
const SITE_URL = process.env.SITE_URL || "https://gde-pribyl-mp.onrender.com";
const MERCHANT_LOGIN = process.env.ROBOKASSA_MERCHANT_LOGIN || "";
const PASSWORD_1 = process.env.ROBOKASSA_PASSWORD_1 || "";
const PASSWORD_2 = process.env.ROBOKASSA_PASSWORD_2 || "";
const HASH_ALGORITHM = (process.env.ROBOKASSA_HASH || "MD5").toLowerCase();
const TEST_MODE = process.env.ROBOKASSA_TEST_MODE === "true";
const DATABASE_URL = process.env.DATABASE_URL || "";
const ALLOWED_HASHES = new Set(["md5", "sha1", "sha256", "sha384", "sha512"]);

let plans = {};
try {
  plans = JSON.parse(process.env.PLAN_CONFIG_JSON || "{}");
} catch {
  console.error("PLAN_CONFIG_JSON is not valid JSON");
}

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
      max: 5,
      connectionTimeoutMillis: 5000
    })
  : null;

function digest(value) {
  return crypto.createHash(HASH_ALGORITHM).update(value, "utf8").digest("hex").toLowerCase();
}
function safeEqual(a, b) {
  const left = Buffer.from(String(a).toLowerCase());
  const right = Buffer.from(String(b).toLowerCase());
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function sortedShp(params) {
  return Object.keys(params)
    .filter((key) => key.toLowerCase().startsWith("shp_"))
    .sort((a, b) => a.localeCompare(b))
    .map((key) => `${key}=${params[key]}`);
}
function paymentSignature(amount, invoiceId, encodedReceipt, extraParams = {}) {
  const tail = sortedShp(extraParams);
  return digest([
    MERCHANT_LOGIN,
    amount,
    invoiceId,
    encodedReceipt,
    PASSWORD_1,
    ...tail
  ].join(":"));
}
function resultSignature(params) {
  const tail = sortedShp(params);
  return digest([
    params.OutSum,
    params.InvId,
    PASSWORD_2,
    ...tail
  ].join(":"));
}
function configReady() {
  return Boolean(
    pool &&
    MERCHANT_LOGIN &&
    PASSWORD_1 &&
    PASSWORD_2 &&
    ALLOWED_HASHES.has(HASH_ALGORITHM)
  );
}

async function initDb() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS user_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions(user_id);
    CREATE TABLE IF NOT EXISTS user_products (
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      data JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS user_products_user_idx ON user_products(user_id);
    CREATE TABLE IF NOT EXISTS user_history (
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      data JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS user_history_user_idx ON user_history(user_id);
    CREATE TABLE IF NOT EXISTS payments (
      id BIGSERIAL PRIMARY KEY,
      plan_code TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      robokassa_invoice_id TEXT UNIQUE NOT NULL,
      customer_token TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMPTZ
    );
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS customer_token TEXT;
    CREATE INDEX IF NOT EXISTS payments_customer_token_idx ON payments(customer_token);
    CREATE INDEX IF NOT EXISTS payments_customer_token_idx ON payments(customer_token);
    CREATE TABLE IF NOT EXISTS subscriptions (
      id BIGSERIAL PRIMARY KEY,
      plan_code TEXT NOT NULL,
      starts_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      payment_id BIGINT NOT NULL UNIQUE REFERENCES payments(id),
      user_id BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES users(id);
    CREATE INDEX IF NOT EXISTS subscriptions_user_expiry_idx ON subscriptions(user_id, expires_at DESC);
  `);
}


const SESSION_COOKIE = "gpm_session";
const SESSION_DAYS = 30;
const PLAN_ENTITLEMENTS = {
  free: { products: 5, history: 20, analytics: false, csvExport: false, targetMargin: false, teamSeats: 1 },
  pro: { products: 200, history: 1000, analytics: false, csvExport: false, targetMargin: true, teamSeats: 1 },
  business: { products: 5000, history: 10000, analytics: true, csvExport: true, targetMargin: true, teamSeats: 5 }
};
const hashToken = token => crypto.createHash("sha256").update(token).digest("hex");
function cookieValue(req,name) {
  const item=String(req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));
  return item ? decodeURIComponent(item.slice(name.length+1)) : "";
}
function sessionCookie(res,token) {
  res.cookie(SESSION_COOKIE,token,{httpOnly:true,secure:true,sameSite:"lax",path:"/",maxAge:SESSION_DAYS*86400000});
}
function clearSession(res) {
  res.clearCookie(SESSION_COOKIE,{httpOnly:true,secure:true,sameSite:"lax",path:"/"});
}
function sameOrigin(req,res,next) {
  if(req.headers.origin!==FRONTEND_ORIGIN) return res.status(403).json({error:"Запрос отклонён: неверный источник."});
  next();
}
function derivePassword(password,salt) {
  return new Promise((resolve,reject)=>crypto.scrypt(password,salt,64,{N:16384,r:8,p:1,maxmem:64*1024*1024},(err,key)=>err?reject(err):resolve(key.toString("hex"))));
}
async function createUserSession(userId,res) {
  const token=crypto.randomBytes(32).toString("base64url");
  await pool.query("INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 days')",[hashToken(token),userId]);
  sessionCookie(res,token);
}
async function requireUser(req,res,next) {
  if(!pool) return res.status(503).json({error:"База данных не настроена."});
  try {
    const token=cookieValue(req,SESSION_COOKIE);
    if(!token||token.length>128) return res.status(401).json({error:"Войди в аккаунт, чтобы продолжить."});
    const result=await pool.query(`SELECT u.id,u.email FROM user_sessions s JOIN users u ON u.id=s.user_id
      WHERE s.token_hash=$1 AND s.expires_at>NOW() LIMIT 1`,[hashToken(token)]);
    if(!result.rowCount) return res.status(401).json({error:"Сессия завершена. Войди снова."});
    req.user=result.rows[0]; next();
  } catch(error) {
    console.error("Session lookup failed:",error.message);
    res.status(500).json({error:"Не удалось проверить сессию."});
  }
}
async function accountPlan(userId) {
  const result=await pool.query("SELECT plan_code,expires_at FROM subscriptions WHERE user_id=$1 AND expires_at>NOW() ORDER BY expires_at DESC LIMIT 1",[userId]);
  const code=String(result.rows[0]?.plan_code||"free").toLowerCase();
  const plan=code.includes("business")?"business":code.includes("pro")?"pro":"free";
  return {plan,expiresAt:result.rows[0]?.expires_at||null,limits:PLAN_ENTITLEMENTS[plan]};
}
app.post("/api/auth/register",rateLimit({max:5}),sameOrigin,async(req,res)=>{
  const email=String(req.body?.email||"").trim().toLowerCase();
  const password=String(req.body?.password||"");
  if(email.length>254||!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) return res.status(400).json({error:"Укажи корректный e-mail."});
  if(password.length<10||password.length>128) return res.status(400).json({error:"Пароль должен содержать от 10 до 128 символов."});
  try {
    const salt=crypto.randomBytes(16).toString("hex");
    const passwordHash=await derivePassword(password,salt);
    const created=await pool.query("INSERT INTO users(email,password_salt,password_hash) VALUES($1,$2,$3) ON CONFLICT(email) DO NOTHING RETURNING id,email",[email,salt,passwordHash]);
    if(!created.rowCount) return res.status(409).json({error:"Аккаунт с таким e-mail уже существует."});
    await createUserSession(created.rows[0].id,res);
    return res.status(201).json({user:created.rows[0],plan:"free",limits:PLAN_ENTITLEMENTS.free});
  } catch(error) {
    console.error("Registration failed:",error.message);
    res.status(500).json({error:"Не удалось создать аккаунт."});
  }
});
app.post("/api/auth/login",rateLimit({max:10}),sameOrigin,async(req,res)=>{
  const email=String(req.body?.email||"").trim().toLowerCase();
  const password=String(req.body?.password||"");
  if(email.length>254||password.length>128) return res.status(400).json({error:"Проверь e-mail и пароль."});
  try {
    const found=await pool.query("SELECT id,email,password_salt,password_hash FROM users WHERE email=$1",[email]);
    if(!found.rowCount) return res.status(401).json({error:"Неверный e-mail или пароль."});
    const user=found.rows[0],candidate=await derivePassword(password,user.password_salt);
    if(!safeEqual(candidate,user.password_hash)) return res.status(401).json({error:"Неверный e-mail или пароль."});
    await createUserSession(user.id,res);
    return res.json({user:{id:user.id,email:user.email},...await accountPlan(user.id)});
  } catch(error) {
    console.error("Login failed:",error.message);
    res.status(500).json({error:"Не удалось выполнить вход."});
  }
});
app.get("/api/auth/me",requireUser,async(req,res)=>{
  res.setHeader("Cache-Control","no-store, private");
  res.json({user:req.user,...await accountPlan(req.user.id)});
});
app.post("/api/auth/logout",sameOrigin,async(req,res)=>{
  const token=cookieValue(req,SESSION_COOKIE);
  if(pool&&token) await pool.query("DELETE FROM user_sessions WHERE token_hash=$1",[hashToken(token)]).catch(()=>{});
  clearSession(res);res.json({ok:true});
});
app.get("/api/account/data",requireUser,async(req,res)=>{
  try {
    const [products,history,plan]=await Promise.all([
      pool.query("SELECT data FROM user_products WHERE user_id=$1 ORDER BY created_at",[req.user.id]),
      pool.query("SELECT data FROM user_history WHERE user_id=$1 ORDER BY created_at",[req.user.id]),
      accountPlan(req.user.id)
    ]);
    res.setHeader("Cache-Control","no-store, private");
    res.json({products:products.rows.map(x=>x.data),history:history.rows.map(x=>x.data),...plan});
  } catch(error) {
    console.error("Account data read failed:",error.message);
    res.status(500).json({error:"Не удалось загрузить данные аккаунта."});
  }
});
app.put("/api/account/data",requireUser,sameOrigin,async(req,res)=>{
  const products=req.body?.products,history=req.body?.history;
  if(!Array.isArray(products)||!Array.isArray(history)) return res.status(400).json({error:"Ожидаются массивы products и history."});
  try {
    const plan=await accountPlan(req.user.id);
    if(products.length>plan.limits.products||history.length>plan.limits.history) return res.status(403).json({error:"Лимит тарифа превышен.",plan:plan.plan,limits:plan.limits});
    if(Buffer.byteLength(JSON.stringify({products,history}),"utf8")>1800000) return res.status(413).json({error:"Размер данных превышает 1,8 МБ."});
    if([...products,...history].some(x=>!x||typeof x!=="object"||Array.isArray(x))) return res.status(400).json({error:"Некорректная запись данных."});
    const client=await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("DELETE FROM user_products WHERE user_id=$1",[req.user.id]);
      await client.query("DELETE FROM user_history WHERE user_id=$1",[req.user.id]);
      for(const item of products) await client.query("INSERT INTO user_products(user_id,data) VALUES($1,$2::jsonb)",[req.user.id,JSON.stringify(item)]);
      for(const item of history) await client.query("INSERT INTO user_history(user_id,data) VALUES($1,$2::jsonb)",[req.user.id,JSON.stringify(item)]);
      await client.query("COMMIT");
    } catch(error) { await client.query("ROLLBACK").catch(()=>{});throw error; }
    finally { client.release(); }
    res.json({saved:true,productCount:products.length,historyCount:history.length,plan:plan.plan,limits:plan.limits});
  } catch(error) {
    console.error("Account data save failed:",error.message);
    res.status(500).json({error:"Не удалось сохранить данные аккаунта."});
  }
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    version: "1.0.0-auth-stage",
    accountsConfigured: Boolean(pool),
    serverSideQuotas: true,
    paymentsConfigured: configReady(),
    databaseConfigured: Boolean(pool),
    merchantConfigured: Boolean(MERCHANT_LOGIN),
    passwordsConfigured: Boolean(PASSWORD_1 && PASSWORD_2),
    plansConfigured: Object.keys(plans).length > 0,
    testMode: TEST_MODE
  });
});

app.post("/api/payments/create", rateLimit({ max: 8 }), async (req, res) => {
  if (!configReady()) {
    return res.status(503).json({ error: "Платежи пока не настроены на сервере." });
  }
  const planCode = String(req.body?.plan || "");
  const customerToken = String(req.body?.customerToken || "").toLowerCase();
  const email = String(req.body?.email || "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(customerToken)) {
    return res.status(400).json({ error: "Не удалось определить клиентскую сессию. Обнови страницу и повтори попытку." });
  }
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Укажи корректный e-mail для отправки чека." });
  }
  const plan = plans[planCode];
  if (!plan || !Number.isFinite(Number(plan.amount)) || Number(plan.amount) <= 0 ||
      !Number.isInteger(Number(plan.days)) || Number(plan.days) < 1) {
    return res.status(400).json({ error: "Неизвестный или не настроенный тариф." });
  }

  const amount = Number(plan.amount).toFixed(2);
  const client = await pool.connect();
  try {
    const invoiceId = String(Date.now()) + String(crypto.randomInt(1000, 9999));
    await client.query(
      "INSERT INTO payments(plan_code, amount, status, robokassa_invoice_id, customer_token) VALUES($1,$2,'pending',$3,$4)",
      [planCode, amount, invoiceId, customerToken]
    );

    const itemName = `Подписка Где прибыль МП ${String(plan.label || planCode).slice(0, 70)}`.slice(0, 128);
    const receipt = JSON.stringify({
      items: [{
        name: itemName,
        quantity: 1,
        sum: Number(amount),
        payment_object: "service",
        tax: "none"
      }]
    });
    const params = {
      MerchantLogin: MERCHANT_LOGIN,
      OutSum: amount,
      InvId: invoiceId,
      Description: `Подписка Где прибыль МП ${String(plan.label || planCode).slice(0, 80)}`,
      Email: email,
      Receipt: encodeURIComponent(receipt),
      Culture: "ru",
      Encoding: "utf-8",
      Shp_customer: customerToken
    };
    if (TEST_MODE) params.IsTest = "1";
    params.SignatureValue = paymentSignature(amount, invoiceId, encodeURIComponent(receipt), { Shp_customer: customerToken });

    res.json({
      paymentUrl: "https://auth.robokassa.ru/Merchant/Index.aspx",
      paymentParams: params
    });
  } catch (error) {
    console.error("Payment creation failed:", error.message);
    res.status(500).json({ error: "Не удалось создать платёж." });
  } finally {
    client.release();
  }
});

async function handleResult(req, res) {
  if (!configReady()) return res.status(503).send("SERVICE_UNAVAILABLE");
  const params = { ...req.query, ...req.body };
  const invoiceId = String(params.InvId || "");
  const amount = String(params.OutSum || "");
  const signature = String(params.SignatureValue || "");
  const customerToken = String(params.Shp_customer || "").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(customerToken) || !/^\d+$/.test(invoiceId) || !/^\d+\.\d{2}$/.test(amount) ||
      !safeEqual(resultSignature(params), signature)) {
    return res.status(400).send("BAD_SIGNATURE");
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const found = await client.query(
      "SELECT * FROM payments WHERE robokassa_invoice_id=$1 FOR UPDATE",
      [invoiceId]
    );
    if (!found.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).send("UNKNOWN_INVOICE");
    }
    const payment = found.rows[0];
    if (payment.customer_token !== customerToken) {
      await client.query("ROLLBACK");
      return res.status(400).send("CUSTOMER_MISMATCH");
    }
    if (Number(payment.amount).toFixed(2) !== Number(amount).toFixed(2)) {
      await client.query("ROLLBACK");
      return res.status(400).send("AMOUNT_MISMATCH");
    }
    if (payment.status !== "paid") {
      const plan = plans[payment.plan_code];
      if (!plan || !Number.isInteger(Number(plan.days)) || Number(plan.days) < 1) {
        await client.query("ROLLBACK");
        return res.status(500).send("PLAN_CONFIG_ERROR");
      }
      await client.query(
        "UPDATE payments SET status='paid', paid_at=NOW() WHERE id=$1",
        [payment.id]
      );
      await client.query(
        `INSERT INTO subscriptions(plan_code, starts_at, expires_at, payment_id)
         SELECT $1, start_at, start_at + ($2::int * INTERVAL '1 day'), $3
         FROM (
           SELECT GREATEST(NOW(), COALESCE(MAX(s.expires_at), NOW())) AS start_at
           FROM subscriptions s
           JOIN payments p ON p.id = s.payment_id
           WHERE p.customer_token = $4
         ) active_period`,
        [payment.plan_code, Number(plan.days), payment.id, customerToken]
      );
    }
    await client.query("COMMIT");
    return res.type("text/plain").send(`OK${invoiceId}`);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Robokassa callback failed:", error.message);
    return res.status(500).send("PROCESSING_ERROR");
  } finally {
    client.release();
  }
}

app.post("/api/robokassa/result", handleResult);
app.get("/payment/success", (_req, res) => res.redirect(`${SITE_URL}/?payment=return`));
app.get("/payment/fail", (_req, res) => res.redirect(`${SITE_URL}/?payment=failed`));

app.get("/api/subscription/status", rateLimit({ max: 60 }), async (req, res) => {
  res.setHeader("Cache-Control", "no-store, private");
  if (!pool) return res.status(503).json({ error: "База данных не настроена." });
  const customerToken = String(req.query.customerToken || "").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(customerToken)) {
    return res.status(400).json({ error: "Некорректный идентификатор клиентской сессии." });
  }
  try {
    const result = await pool.query(
      `SELECT s.plan_code, s.starts_at, s.expires_at
       FROM subscriptions s
       JOIN payments p ON p.id = s.payment_id
       WHERE p.customer_token = $1 AND s.expires_at > NOW()
       ORDER BY s.expires_at DESC LIMIT 1`,
      [customerToken]
    );
    res.json({ subscription: result.rows[0] || null });
  } catch (error) {
    console.error("Subscription lookup failed:", error.message);
    res.status(500).json({ error: "Не удалось получить статус подписки." });
  }
});

app.listen(PORT, async () => {
  try {
    await initDb();
    console.log(`Где прибыль МП API 0.8 listening on ${PORT}`);
    console.log("Payment configuration:", JSON.stringify({
      databaseConfigured: Boolean(pool),
      merchantConfigured: Boolean(MERCHANT_LOGIN),
      passwordsConfigured: Boolean(PASSWORD_1 && PASSWORD_2),
      plansConfigured: Object.keys(plans).length > 0,
      planCodes: Object.keys(plans),
      testMode: TEST_MODE,
      hashAlgorithm: HASH_ALGORITHM
    }));
  } catch (error) {
    console.error("Database initialization failed:", error.message);
    process.exit(1);
  }
});
