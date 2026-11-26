import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { PLAN_ENTITLEMENTS, normalizePlanCode, isWithinPlanLimits } from "./lib/entitlements.js";
import { MarketplaceApiError, parseEncryptionKey, encryptCredentials, decryptCredentials, normalizeMarketplaceCredentials, fetchMarketplaceSnapshot } from "./lib/marketplaces.js";

const { Pool } = pg;
const app = express();
const ROOT_DIR = path.dirname(fileURLToPath(import.meta.url));
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
app.use(express.json({ limit: "2mb" }));

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || process.env.SITE_URL || "https://gde-pribyl-mp.onrender.com";
const FRONTEND_ORIGINS = new Set([
  "https://gde-pribyl-mp.onrender.com",
  "https://gde-pribyl-mp.layero.app",
  FRONTEND_ORIGIN,
  ...(process.env.FRONTEND_ORIGINS || "").split(",").map((value) => value.trim()).filter(Boolean),
]);
function requestOrigin(req) {
  return `${req.protocol}://${req.get("host")}`;
}
function isAllowedOrigin(req) {
  const origin = req.headers.origin;
  return !origin || FRONTEND_ORIGINS.has(origin) || origin === requestOrigin(req);
}
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && isAllowedOrigin(req)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  if (req.method === "OPTIONS") {
    if (!isAllowedOrigin(req)) return res.sendStatus(403);
    return res.sendStatus(204);
  }
  next();
});


const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 30;
function rateLimit({ windowMs = RATE_LIMIT_WINDOW_MS, max = RATE_LIMIT_MAX } = {}) {
  // Each route gets an independent bucket. Sharing one IP bucket across
  // unrelated endpoints lets login attempts exhaust marketplace/payment limits.
  const rateBuckets = new Map();
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
const API_PUBLIC_URL = process.env.API_PUBLIC_URL || "https://gde-pribyl-mp-api.onrender.com";
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "";
const SMSC_API_KEY = process.env.SMSC_API_KEY || "";
const SMSC_SENDER = process.env.SMSC_SENDER || "";
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
  const requiredPlans = ["pro", "business"];
  const plansReady = requiredPlans.every((code) => {
    const plan = plans[code];
    return plan && Number.isFinite(Number(plan.amount)) && Number(plan.amount) > 0 &&
      Number.isInteger(Number(plan.days)) && Number(plan.days) >= 1;
  });
  return Boolean(pool && MERCHANT_LOGIN && PASSWORD_1 && PASSWORD_2 &&
    ALLOWED_HASHES.has(HASH_ALGORITHM) && plansReady);
}

async function initDb() {
  if (!pool) throw new Error("DATABASE_URL is not configured");
  const client=await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock(73291428615001)");
    await client.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      email_verified BOOLEAN NOT NULL DEFAULT TRUE
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique_idx ON users(phone) WHERE phone IS NOT NULL;
    CREATE TABLE IF NOT EXISTS phone_auth_codes (phone TEXT PRIMARY KEY, code_hash TEXT NOT NULL, code_salt TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS auth_tokens (
      token_hash TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL CHECK (purpose IN ('verify_email','password_reset')),
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS auth_tokens_user_purpose_idx ON auth_tokens(user_id,purpose);
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
    CREATE TABLE IF NOT EXISTS user_data_tombstones (
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      record_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, record_id)
    );
    CREATE TABLE IF NOT EXISTS user_data_versions (
      user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      version BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS marketplace_integrations (
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      marketplace TEXT NOT NULL CHECK (marketplace IN ('wildberries','ozon')),
      encrypted_credentials TEXT NOT NULL,
      nonce TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      snapshot JSONB,
      last_synced_at TIMESTAMPTZ,
      last_error TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, marketplace)
    );
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
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES users(id);
    CREATE INDEX IF NOT EXISTS payments_user_idx ON payments(user_id);
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
  } finally {
    await client.query("SELECT pg_advisory_unlock(73291428615001)").catch(()=>{});
    client.release();
  }
}


function stableRecordSerialize(value) {
  if (Array.isArray(value)) return "[" + value.map(stableRecordSerialize).join(",") + "]";
  if (value && typeof value === "object") return "{" + Object.keys(value).sort().map(key => JSON.stringify(key) + ":" + stableRecordSerialize(value[key])).join(",") + "}";
  return JSON.stringify(value);
}
function legacyRecordId(value, namespace) {
  const input=namespace+":"+stableRecordSerialize(value);
  let hash=0xcbf29ce484222325n;
  for(let i=0;i<input.length;i++){hash^=BigInt(input.charCodeAt(i));hash=BigInt.asUintN(64,hash*0x100000001b3n);}
  return "legacy:"+hash.toString(16).padStart(16,"0");
}

const SESSION_COOKIE = "gpm_session";
const SESSION_DAYS = 30;
const hashToken = token => crypto.createHash("sha256").update(token).digest("hex");
function cookieValue(req,name) {
  const item=String(req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));
  if (!item) return "";
  try { return decodeURIComponent(item.slice(name.length+1)); } catch { return ""; }
}
function sessionCookie(res,token) {
  res.cookie(SESSION_COOKIE,token,{httpOnly:true,secure:true,sameSite:"none",path:"/",maxAge:SESSION_DAYS*86400000});
}
function clearSession(res) {
  res.clearCookie(SESSION_COOKIE,{httpOnly:true,secure:true,sameSite:"none",path:"/"});
}
function sameOrigin(req,res,next) {
  if (!req.headers.origin || !isAllowedOrigin(req)) {
    return res.status(403).json({error:"Запрос отклонён: неверный источник."});
  }
  next();
}
function derivePassword(password,salt) {
  return new Promise((resolve,reject)=>crypto.scrypt(password,salt,64,{N:16384,r:8,p:1,maxmem:64*1024*1024},(err,key)=>err?reject(err):resolve(key.toString("hex"))));
}
async function createUserSession(userId, db = pool) {
  const token=crypto.randomBytes(32).toString("base64url");
  await db.query("INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '30 days')",[hashToken(token),userId]);
  return token;
}
async function createAuthToken(userId,purpose,expiresInHours) {
  const token=crypto.randomBytes(32).toString("base64url");
  await pool.query("DELETE FROM auth_tokens WHERE user_id=$1 AND purpose=$2",[userId,purpose]);
  await pool.query("INSERT INTO auth_tokens(token_hash,user_id,purpose,expires_at) VALUES($1,$2,$3,NOW()+($4::int * INTERVAL '1 hour'))",
    [hashToken(token),userId,purpose,expiresInHours]);
  return token;
}
async function sendAccountEmail(to,subject,html) {
  if(!RESEND_API_KEY||!EMAIL_FROM) throw new Error("Email delivery is not configured");
  const response=await fetch("https://api.resend.com/emails",{
    method:"POST",
    headers:{"Authorization":"Bearer "+RESEND_API_KEY,"Content-Type":"application/json"},
    body:JSON.stringify({from:EMAIL_FROM,to:[to],subject,html})
  });
  if(!response.ok) {
    const detail=await response.text().catch(()=>"");
    console.error("Email provider rejected message:",response.status,detail.slice(0,500));
    throw new Error("Email provider request failed");
  }
}
async function sendVerificationEmail(userId,email) {
  const token=await createAuthToken(userId,"verify_email",24);
  const url=API_PUBLIC_URL+"/api/auth/verify-email?token="+encodeURIComponent(token);
  await sendAccountEmail(email,"Подтверждение e-mail для Где прибыль",
    '<p>Подтверди адрес электронной почты для аккаунта «Где прибыль».</p><p><a href="'+url+'">Подтвердить e-mail</a></p><p>Ссылка действует 24 часа. Если ты не создавал аккаунт, просто проигнорируй письмо.</p>');
}
function normalizePhone(value) {
  const raw=String(value||"").trim();
  if(!/^\+?[0-9 ()-]+$/.test(raw)) return "";
  const digits=raw.replace(/\D/g,"");
  return digits.length>=10&&digits.length<=15?digits:"";
}
async function sendSmsCode(phone,code) {
  if(!SMSC_API_KEY) throw new Error("SMS provider is not configured");
  const body=new URLSearchParams({apikey:SMSC_API_KEY,phones:phone,mes:`Код входа Где прибыль: ${code}. Никому его не сообщай.`,fmt:"3",charset:"utf-8"});
  if(SMSC_SENDER) body.set("sender",SMSC_SENDER);
  const response=await fetch("https://smsc.ru/sys/send.php",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});
  let result={};
  try { result=await response.json(); } catch { throw new Error("SMS provider returned an invalid response"); }
  if(!response.ok||result.error||result.error_code||!result.id) {
    console.error("SMS provider rejected message:",response.status,JSON.stringify(result).slice(0,400));
    throw new Error("SMS provider request failed");
  }
}
async function requireUser(req,res,next) {
  if(!pool) return res.status(503).json({error:"База данных не настроена."});
  try {
    const token=cookieValue(req,SESSION_COOKIE);
    if(!token||token.length>128) return res.status(401).json({error:"Войди в аккаунт, чтобы продолжить."});
    const result=await pool.query(`SELECT u.id,u.email,u.phone FROM user_sessions s JOIN users u ON u.id=s.user_id
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
  const plan=normalizePlanCode(result.rows[0]?.plan_code);
  return {plan,expiresAt:result.rows[0]?.expires_at||null,limits:PLAN_ENTITLEMENTS[plan]};
}
app.post("/api/auth/sms/request",rateLimit({max:4,windowMs:600000}),sameOrigin,async(req,res)=>{
  const phone=normalizePhone(req.body?.phone);
  if(!phone) return res.status(400).json({error:"Укажи номер телефона в международном формате, например +79991234567."});
  if(!SMSC_API_KEY) return res.status(503).json({error:"Отправка СМС пока не подключена на сервере. Код регистрации уже подготовлен."});
  const code=String(crypto.randomInt(100000,1000000));
  const salt=crypto.randomBytes(16).toString("hex");
  const codeHash=crypto.createHash("sha256").update(salt+":"+code).digest("hex");
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))",[phone]);
    const previous=await client.query("SELECT last_sent_at FROM phone_auth_codes WHERE phone=$1 FOR UPDATE",[phone]);
    if(previous.rowCount&&Date.now()-new Date(previous.rows[0].last_sent_at).getTime()<60000) {
      await client.query("ROLLBACK");
      return res.status(429).json({error:"Код уже отправлялся. Подожди минуту перед повторным запросом."});
    }
    await client.query("INSERT INTO phone_auth_codes(phone,code_hash,code_salt,expires_at,attempts,last_sent_at,created_at) VALUES($1,$2,$3,NOW()+make_interval(mins => 5),0,NOW(),NOW()) ON CONFLICT(phone) DO UPDATE SET code_hash=EXCLUDED.code_hash,code_salt=EXCLUDED.code_salt,expires_at=EXCLUDED.expires_at,attempts=0,last_sent_at=NOW(),created_at=NOW()",[phone,codeHash,salt]);
    await client.query("COMMIT");
    await sendSmsCode(phone,code);
    return res.json({ok:true,message:"Если номер доступен, СМС с кодом отправлено. Код действует 5 минут."});
  } catch(error) {
    await client.query("ROLLBACK").catch(()=>{});
    await pool.query("DELETE FROM phone_auth_codes WHERE phone=$1 AND code_hash=$2",[phone,codeHash]).catch(()=>{});
    console.error("SMS code request failed:",error.message);
    return res.status(503).json({error:"Не удалось отправить СМС. Проверь номер или попробуй позже."});
  } finally { client.release(); }
});
app.post("/api/auth/sms/verify",rateLimit({max:8,windowMs:600000}),sameOrigin,async(req,res)=>{
  const phone=normalizePhone(req.body?.phone);
  const code=String(req.body?.code||"").trim();
  if(!phone||!/^[0-9]{6}$/.test(code)) return res.status(400).json({error:"Проверь номер телефона и шестизначный код."});
  const client=await pool.connect();
  try {
    await client.query("BEGIN");
    const stored=await client.query("SELECT code_hash,code_salt,expires_at,attempts FROM phone_auth_codes WHERE phone=$1 FOR UPDATE",[phone]);
    if(!stored.rowCount||new Date(stored.rows[0].expires_at).getTime()<=Date.now()||Number(stored.rows[0].attempts)>=5) {
      await client.query("DELETE FROM phone_auth_codes WHERE phone=$1",[phone]);
      await client.query("COMMIT");
      return res.status(400).json({error:"Код истёк или больше недействителен. Запроси новый."});
    }
    const candidate=crypto.createHash("sha256").update(stored.rows[0].code_salt+":"+code).digest("hex");
    if(!safeEqual(candidate,stored.rows[0].code_hash)) {
      await client.query("UPDATE phone_auth_codes SET attempts=attempts+1 WHERE phone=$1",[phone]);
      await client.query("COMMIT");
      return res.status(400).json({error:"Неверный код. Проверь СМС и попробуй ещё раз."});
    }
    await client.query("DELETE FROM phone_auth_codes WHERE phone=$1",[phone]);
    let found=await client.query("SELECT id,phone,email FROM users WHERE phone=$1 AND phone_verified=TRUE FOR UPDATE",[phone]);
    if(!found.rowCount) {
      const salt=crypto.randomBytes(16).toString("hex");
      const randomPassword=crypto.randomBytes(32).toString("base64url");
      const passwordHash=await derivePassword(randomPassword,salt);
      const created=await client.query("INSERT INTO users(email,phone,phone_verified,password_salt,password_hash,email_verified) VALUES(NULL,$1,TRUE,$2,$3,TRUE) ON CONFLICT DO NOTHING RETURNING id,phone,email",[phone,salt,passwordHash]);
      found=created.rowCount?created:await client.query("SELECT id,phone,email FROM users WHERE phone=$1 AND phone_verified=TRUE FOR UPDATE",[phone]);
    }
    if(!found.rowCount) throw new Error("Could not create or load phone account");
    const user=found.rows[0];
    const sessionToken=await createUserSession(user.id,client);
    await client.query("COMMIT");
    sessionCookie(res,sessionToken);
    return res.json({user:{id:user.id,email:user.email,phone:user.phone},...await accountPlan(user.id)});
  } catch(error) {
    await client.query("ROLLBACK").catch(()=>{});
    console.error("SMS verification failed:",error.message);
    return res.status(500).json({error:"Не удалось подтвердить номер. Попробуй ещё раз."});
  } finally { client.release(); }
});
app.post("/api/auth/register",rateLimit({max:5}),sameOrigin,async(req,res)=>{
  if(!pool) return res.status(503).json({error:"Регистрация временно недоступна."});
  const email=String(req.body?.email||"").trim().toLowerCase();
  const password=String(req.body?.password||"");
  if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:"Укажи корректный e-mail."});
  if(password.length<10||password.length>128) return res.status(400).json({error:"Пароль должен содержать от 10 до 128 символов."});
  const client=await pool.connect();
  let userId=null;
  try {
    const salt=crypto.randomBytes(16).toString("hex");
    const passwordHash=await derivePassword(password,salt);
    await client.query("BEGIN");
    const created=await client.query("INSERT INTO users(email,password_salt,password_hash,email_verified) VALUES($1,$2,$3,FALSE) ON CONFLICT(email) DO NOTHING RETURNING id,email",[email,salt,passwordHash]);
    if(!created.rowCount) { await client.query("ROLLBACK"); return res.status(409).json({error:"Аккаунт с таким e-mail уже существует."}); }
    userId=created.rows[0].id;
    await client.query("COMMIT");
    await sendVerificationEmail(userId,email);
    return res.status(201).json({verificationRequired:true,message:"Аккаунт создан. Проверь почту и перейди по ссылке из письма для подтверждения e-mail."});
  } catch(error) {
    await client.query("ROLLBACK").catch(()=>{});
    if(userId) await pool.query("DELETE FROM users WHERE id=$1 AND email_verified=FALSE",[userId]).catch(()=>{});
    console.error("Registration failed:",error.message);
    res.status(503).json({error:RESEND_API_KEY&&EMAIL_FROM?"Не удалось отправить письмо. Повтори регистрацию позже.":"Отправка писем ещё не настроена на сервере. Регистрация временно недоступна."});
  } finally { client.release(); }
});
app.post("/api/auth/login",rateLimit({max:10}),sameOrigin,async(req,res)=>{
  if(!pool) return res.status(503).json({error:"Вход временно недоступен."});
  const email=String(req.body?.email||"").trim().toLowerCase();
  const password=String(req.body?.password||"");
  if(email.length>254||password.length>128) return res.status(400).json({error:"Проверь e-mail и пароль."});
  try {
    const found=await pool.query("SELECT id,email,password_salt,password_hash,email_verified FROM users WHERE email=$1",[email]);
    if(!found.rowCount) return res.status(401).json({error:"Неверный e-mail или пароль."});
    const user=found.rows[0],candidate=await derivePassword(password,user.password_salt);
    if(!safeEqual(candidate,user.password_hash)) return res.status(401).json({error:"Неверный e-mail или пароль."});
    if(!user.email_verified) return res.status(403).json({error:"Сначала подтверди e-mail. Проверь почту или запроси новое письмо."});
    const token=await createUserSession(user.id);
    sessionCookie(res,token);
    return res.json({user:{id:user.id,email:user.email},...await accountPlan(user.id)});
  } catch(error) {
    console.error("Login failed:",error.message);
    res.status(500).json({error:"Не удалось выполнить вход."});
  }
});
app.post("/api/auth/resend-verification",rateLimit({max:3}),sameOrigin,async(req,res)=>{
  const email=String(req.body?.email||"").trim().toLowerCase();
  if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:"Укажи корректный e-mail."});
  try {
    const found=await pool.query("SELECT id,email,email_verified FROM users WHERE email=$1",[email]);
    if(found.rowCount&&!found.rows[0].email_verified) await sendVerificationEmail(found.rows[0].id,email);
    return res.json({ok:true,message:"Если аккаунт существует и ещё не подтверждён, письмо отправлено."});
  } catch(error) {
    console.error("Verification resend failed:",error.message);
    res.status(503).json({error:"Не удалось отправить письмо. Проверь настройки почты сервера."});
  }
});
app.get("/api/auth/verify-email",rateLimit({max:20}),async(req,res)=>{
  const token=String(req.query?.token||"");
  if(!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return res.redirect(SITE_URL+"/?verified=invalid");
  try {
    const result=await pool.query("UPDATE users SET email_verified=TRUE WHERE id=(SELECT user_id FROM auth_tokens WHERE token_hash=$1 AND purpose='verify_email' AND expires_at>NOW()) RETURNING id",
      [hashToken(token)]);
    await pool.query("DELETE FROM auth_tokens WHERE token_hash=$1",[hashToken(token)]);
    return res.redirect(SITE_URL+(result.rowCount?"/?verified=1":"/?verified=expired"));
  } catch(error) {
    console.error("Email verification failed:",error.message);
    return res.redirect(SITE_URL+"/?verified=error");
  }
});
app.post("/api/auth/forgot-password",rateLimit({max:3}),sameOrigin,async(req,res)=>{
  const email=String(req.body?.email||"").trim().toLowerCase();
  if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:"Укажи корректный e-mail."});
  try {
    const found=await pool.query("SELECT id,email FROM users WHERE email=$1 AND email_verified=TRUE",[email]);
    if(found.rowCount) {
      const token=await createAuthToken(found.rows[0].id,"password_reset",1);
      const url=SITE_URL+"/?reset="+encodeURIComponent(token);
      await sendAccountEmail(email,"Сброс пароля для Где прибыль",
        '<p>Получен запрос на смену пароля аккаунта «Где прибыль».</p><p><a href="'+url+'">Задать новый пароль</a></p><p>Ссылка действует 1 час. Если ты не запрашивал смену пароля, проигнорируй письмо.</p>');
    }
    return res.json({ok:true,message:"Если подтверждённый аккаунт с таким адресом существует, письмо для сброса пароля отправлено."});
  } catch(error) {
    console.error("Password reset request failed:",error.message);
    res.status(503).json({error:"Не удалось отправить письмо. Проверь настройки почты сервера."});
  }
});
app.post("/api/auth/reset-password",rateLimit({max:5}),sameOrigin,async(req,res)=>{
  const token=String(req.body?.token||"");
  const password=String(req.body?.password||"");
  if(!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return res.status(400).json({error:"Ссылка недействительна или устарела."});
  if(password.length<10||password.length>128) return res.status(400).json({error:"Пароль должен содержать от 10 до 128 символов."});
  try {
    const salt=crypto.randomBytes(16).toString("hex");
    const passwordHash=await derivePassword(password,salt);
    const client=await pool.connect();
    try {
      await client.query("BEGIN");
      const changed=await client.query("UPDATE users SET password_salt=$1,password_hash=$2 WHERE id=(SELECT user_id FROM auth_tokens WHERE token_hash=$3 AND purpose='password_reset' AND expires_at>NOW()) RETURNING id",
        [salt,passwordHash,hashToken(token)]);
      if(!changed.rowCount) { await client.query("ROLLBACK"); return res.status(400).json({error:"Ссылка недействительна или срок её действия истёк. Запроси новое письмо."}); }
      await client.query("DELETE FROM user_sessions WHERE user_id=$1",[changed.rows[0].id]);
      await client.query("DELETE FROM auth_tokens WHERE user_id=$1",[changed.rows[0].id]);
      await client.query("COMMIT");
      clearSession(res);
      return res.json({ok:true,message:"Пароль изменён. Теперь войди с новым паролем."});
    } catch(error) { await client.query("ROLLBACK").catch(()=>{}); throw error; }
    finally { client.release(); }
  } catch(error) {
    console.error("Password reset failed:",error.message);
    res.status(500).json({error:"Не удалось изменить пароль."});
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
  let client;
  try {
    await pool.query("INSERT INTO user_data_versions(user_id,version) VALUES($1,0) ON CONFLICT(user_id) DO NOTHING",[req.user.id]);
    client=await pool.connect();
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const [products,history,subscription,version,tombstones]=await Promise.all([
      client.query("SELECT data FROM user_products WHERE user_id=$1 ORDER BY created_at",[req.user.id]),
      client.query("SELECT data FROM user_history WHERE user_id=$1 ORDER BY created_at",[req.user.id]),
      client.query("SELECT plan_code,expires_at FROM subscriptions WHERE user_id=$1 AND expires_at>NOW() ORDER BY expires_at DESC LIMIT 1",[req.user.id]),
      client.query("SELECT version FROM user_data_versions WHERE user_id=$1",[req.user.id]),
      client.query("SELECT record_id FROM user_data_tombstones WHERE user_id=$1",[req.user.id])
    ]);
    const migrateLegacyRows=(rows,namespace)=>rows.map(row=>{
      const data=row.data;
      if(!data||typeof data!=="object"||Array.isArray(data)) throw new Error("Invalid stored account record");
      return data.id?data:{...data,id:legacyRecordId(data,namespace)};
    });
    const productRows=migrateLegacyRows(products.rows,"products");
    const historyRows=migrateLegacyRows(history.rows,"history");
    const deletedIds=tombstones.rows.map(row=>row.record_id);
    const deletedSet=new Set(deletedIds);
    const planCode=normalizePlanCode(subscription.rows[0]?.plan_code);
    const plan={plan:planCode,expiresAt:subscription.rows[0]?.expires_at||null,limits:PLAN_ENTITLEMENTS[planCode]};
    await client.query("COMMIT");
    res.setHeader("Cache-Control","no-store, private");
    res.json({products:productRows.filter(row=>!deletedSet.has(row.id)),history:historyRows.filter(row=>!deletedSet.has(row.id)),deletedIds,version:Number(version.rows[0].version),...plan});
  } catch(error) {
    if(client) await client.query("ROLLBACK").catch(()=>{});
    console.error("Account data read failed:",error.message);
    res.status(500).json({error:"Не удалось загрузить данные аккаунта."});
  } finally {
    client?.release();
  }
});
app.put("/api/account/data",requireUser,sameOrigin,async(req,res)=>{
  const products=req.body?.products,history=req.body?.history,expectedVersion=req.body?.expectedVersion,deletedIds=req.body?.deletedIds??[];
  if(!Array.isArray(products)||!Array.isArray(history)) return res.status(400).json({error:"Ожидаются массивы products и history."});
  if(!Number.isSafeInteger(expectedVersion)||expectedVersion<0) return res.status(400).json({error:"Ожидается корректная версия данных expectedVersion."});
  if(!Array.isArray(deletedIds)||deletedIds.length>50000||deletedIds.some(id=>typeof id!=="string"||id.length<1||id.length>128)) return res.status(400).json({error:"Некорректный список удалённых записей."});
  try {
    const plan=await accountPlan(req.user.id);
    if(!isWithinPlanLimits(plan.plan,products.length,history.length)) return res.status(403).json({error:"Лимит тарифа превышен.",plan:plan.plan,limits:plan.limits});
    if(Buffer.byteLength(JSON.stringify({products,history,deletedIds}),"utf8")>1800000) return res.status(413).json({error:"Размер данных превышает 1,8 МБ."});
    if([...products,...history].some(x=>!x||typeof x!=="object"||Array.isArray(x))) return res.status(400).json({error:"Некорректная запись данных."});
    const client=await pool.connect();
    let activeProducts=products,activeHistory=history;
    let conflictVersion=null,versionConflict=false;
    try {
      await client.query("BEGIN");
      await client.query("INSERT INTO user_data_versions(user_id,version) VALUES($1,0) ON CONFLICT(user_id) DO NOTHING",[req.user.id]);
      const current=await client.query("SELECT version FROM user_data_versions WHERE user_id=$1 FOR UPDATE",[req.user.id]);
      const currentVersion=Number(current.rows[0].version);
      if(currentVersion!==expectedVersion) {
        conflictVersion=currentVersion;
        versionConflict=true;
        await client.query("ROLLBACK");
      } else {
        if(deletedIds.length) await client.query("INSERT INTO user_data_tombstones(user_id,record_id) SELECT $1,value FROM jsonb_array_elements_text($2::jsonb) AS value ON CONFLICT(user_id,record_id) DO NOTHING",[req.user.id,JSON.stringify(deletedIds)]);
        const allDeleted=await client.query("SELECT record_id FROM user_data_tombstones WHERE user_id=$1",[req.user.id]);
        const deletedSet=new Set(allDeleted.rows.map(row=>row.record_id));
        activeProducts=products.filter(row=>!deletedSet.has(row.id));
        activeHistory=history.filter(row=>!deletedSet.has(row.id));
        await client.query("DELETE FROM user_products WHERE user_id=$1",[req.user.id]);
        await client.query("DELETE FROM user_history WHERE user_id=$1",[req.user.id]);
        if(activeProducts.length) await client.query("INSERT INTO user_products(user_id,data) SELECT $1,value FROM jsonb_array_elements($2::jsonb) AS value",[req.user.id,JSON.stringify(activeProducts)]);
        if(activeHistory.length) await client.query("INSERT INTO user_history(user_id,data) SELECT $1,value FROM jsonb_array_elements($2::jsonb) AS value",[req.user.id,JSON.stringify(activeHistory)]);
        const updated=await client.query("UPDATE user_data_versions SET version=version+1,updated_at=NOW() WHERE user_id=$1 RETURNING version",[req.user.id]);
        await client.query("COMMIT");
        conflictVersion=Number(updated.rows[0].version);
      }
    } catch(error) { await client.query("ROLLBACK").catch(()=>{});throw error; }
    finally { client.release(); }
    if(versionConflict) return res.status(409).json({error:"Данные изменились на другом устройстве. Загрузи актуальную версию и повтори синхронизацию.",code:"SYNC_VERSION_CONFLICT",currentVersion:conflictVersion});
    res.json({saved:true,version:conflictVersion,productCount:activeProducts.length,historyCount:activeHistory.length,deletedCount:deletedIds.length,plan:plan.plan,limits:plan.limits});
  } catch(error) {
    console.error("Account data save failed:",error.message);
    res.status(500).json({error:"Не удалось сохранить данные аккаунта."});
  }
});


const MARKETPLACE_NAMES = Object.freeze({ wildberries: "Wildberries", ozon: "Ozon" });
function requirePaidMarketplacePlan(req, res, next) {
  accountPlan(req.user.id).then(plan => {
    if (plan.plan !== "pro" && plan.plan !== "business") {
      return res.status(403).json({ error: "Подключение маркетплейсов доступно в PRO и BUSINESS.", plan: plan.plan });
    }
    next();
  }).catch(error => {
    console.error("Marketplace plan lookup failed:", error.message);
    res.status(500).json({ error: "Не удалось проверить тариф аккаунта." });
  });
}
function marketplaceParam(req, res, next) {
  if (!Object.hasOwn(MARKETPLACE_NAMES, req.params.marketplace)) {
    return res.status(404).json({ error: "Неизвестный маркетплейс." });
  }
  next();
}
function marketplaceError(res, error) {
  if (error instanceof MarketplaceApiError) return res.status(error.status).json({ error: error.message });
  if (error?.message?.includes("MARKETPLACE_ENCRYPTION_KEY")) {
    return res.status(503).json({ error: "Защищённое хранилище ключей ещё не настроено на сервере." });
  }
  console.error("Marketplace integration failed:", error?.message || "unknown error");
  return res.status(502).json({ error: "Не удалось выполнить запрос к маркетплейсу. Проверь подключение и повтори позже." });
}
async function loadMarketplaceCredentials(userId, marketplace) {
  const found = await pool.query(
    "SELECT encrypted_credentials, nonce, auth_tag FROM marketplace_integrations WHERE user_id=$1 AND marketplace=$2",
    [userId, marketplace]
  );
  if (!found.rowCount) return null;
  const row = found.rows[0];
  return {
    credentials: decryptCredentials({ ciphertext: row.encrypted_credentials, nonce: row.nonce, authTag: row.auth_tag }, parseEncryptionKey()),
    encryptedCredentials: row.encrypted_credentials,
    nonce: row.nonce,
    authTag: row.auth_tag
  };
}
async function syncMarketplace(userId, marketplace, credentialRecord) {
  const snapshot = await fetchMarketplaceSnapshot(marketplace, credentialRecord.credentials);
  const updated = await pool.query(
    "UPDATE marketplace_integrations SET snapshot=$4::jsonb,last_synced_at=NOW(),last_error=NULL,updated_at=NOW() WHERE user_id=$1 AND marketplace=$2 AND encrypted_credentials=$3 AND nonce=$5 AND auth_tag=$6",
    [userId, marketplace, credentialRecord.encryptedCredentials, JSON.stringify(snapshot), credentialRecord.nonce, credentialRecord.authTag]
  );
  if (!updated.rowCount) {
    throw new MarketplaceApiError("Ключи маркетплейса изменились во время обновления. Повтори синхронизацию.", 409);
  }
  return snapshot;
}

app.get("/api/marketplaces", requireUser, requirePaidMarketplacePlan, async (req, res) => {
  try {
    const found = await pool.query(
      "SELECT marketplace,last_synced_at,last_error,snapshot,updated_at FROM marketplace_integrations WHERE user_id=$1 ORDER BY marketplace",
      [req.user.id]
    );
    const connections = Object.fromEntries(found.rows.map(row => [row.marketplace, {
      connected: true,
      lastSyncedAt: row.last_synced_at,
      lastError: row.last_error,
      updatedAt: row.updated_at,
      snapshot: row.snapshot
    }]));
    res.setHeader("Cache-Control", "no-store, private");
    res.json({ connections });
  } catch (error) {
    console.error("Marketplace connections read failed:", error.message);
    res.status(500).json({ error: "Не удалось получить состояние подключений." });
  }
});

app.put("/api/marketplaces/:marketplace/credentials", rateLimit({ max: 5 }), requireUser, sameOrigin, requirePaidMarketplacePlan, marketplaceParam, async (req, res) => {
  const marketplace = req.params.marketplace;
  try {
    const key = parseEncryptionKey();
    const credentials = normalizeMarketplaceCredentials(marketplace, req.body);
    const snapshot = await fetchMarketplaceSnapshot(marketplace, credentials);
    const encrypted = encryptCredentials(credentials, key);
    await pool.query(
      `INSERT INTO marketplace_integrations(user_id,marketplace,encrypted_credentials,nonce,auth_tag,snapshot,last_synced_at,last_error,updated_at)
       VALUES($1,$2,$3,$4,$5,$6::jsonb,NOW(),NULL,NOW())
       ON CONFLICT(user_id,marketplace) DO UPDATE SET
         encrypted_credentials=EXCLUDED.encrypted_credentials,nonce=EXCLUDED.nonce,auth_tag=EXCLUDED.auth_tag,
         snapshot=EXCLUDED.snapshot,last_synced_at=NOW(),last_error=NULL,updated_at=NOW()`,
      [req.user.id, marketplace, encrypted.ciphertext, encrypted.nonce, encrypted.authTag, JSON.stringify(snapshot)]
    );
    res.setHeader("Cache-Control", "no-store, private");
    res.json({ connected: true, marketplace, snapshot });
  } catch (error) {
    return marketplaceError(res, error);
  }
});

app.post("/api/marketplaces/:marketplace/refresh", rateLimit({ max: 5 }), requireUser, sameOrigin, requirePaidMarketplacePlan, marketplaceParam, async (req, res) => {
  const marketplace = req.params.marketplace;
  let credentialRecord = null;
  try {
    credentialRecord = await loadMarketplaceCredentials(req.user.id, marketplace);
    if (!credentialRecord) return res.status(404).json({ error: "Этот маркетплейс ещё не подключён." });
    const snapshot = await syncMarketplace(req.user.id, marketplace, credentialRecord);
    res.setHeader("Cache-Control", "no-store, private");
    res.json({ connected: true, marketplace, snapshot });
  } catch (error) {
    if (error instanceof MarketplaceApiError && credentialRecord) {
      await pool.query(
        "UPDATE marketplace_integrations SET last_error=$6,updated_at=NOW() WHERE user_id=$1 AND marketplace=$2 AND encrypted_credentials=$3 AND nonce=$4 AND auth_tag=$5",
        [req.user.id, marketplace, credentialRecord.encryptedCredentials, credentialRecord.nonce, credentialRecord.authTag, error.message]
      ).catch(() => {});
    }
    return marketplaceError(res, error);
  }
});

app.delete("/api/marketplaces/:marketplace", rateLimit({ max: 5 }), requireUser, sameOrigin, requirePaidMarketplacePlan, marketplaceParam, async (req, res) => {
  try {
    await pool.query("DELETE FROM marketplace_integrations WHERE user_id=$1 AND marketplace=$2", [req.user.id, req.params.marketplace]);
    res.json({ disconnected: true, marketplace: req.params.marketplace });
  } catch (error) {
    console.error("Marketplace disconnect failed:", error.message);
    res.status(500).json({ error: "Не удалось отключить маркетплейс." });
  }
});

app.get("/", (_req, res) => res.sendFile(path.join(ROOT_DIR, "index.html")));
app.get("/legal.html", (_req, res) => res.sendFile(path.join(ROOT_DIR, "legal.html")));

app.get("/health", async (_req, res) => {
  let databaseHealthy=false;
  if(pool) { try { await pool.query("SELECT 1"); databaseHealthy=true; } catch(error) { console.error("Health database check failed:",error.message); } }
  const healthy=Boolean(pool)&&databaseHealthy;
  res.setHeader("Cache-Control","no-store");
  res.status(healthy?200:503).json({
    ok: healthy, version: "1.0.0", accountsConfigured: Boolean(pool), serverSideQuotas: true,
    paymentsConfigured: configReady(), smsConfigured: Boolean(SMSC_API_KEY), databaseConfigured: Boolean(pool), databaseHealthy, marketplaceEncryptionConfigured: Boolean(process.env.MARKETPLACE_ENCRYPTION_KEY),
    merchantConfigured: Boolean(MERCHANT_LOGIN), passwordsConfigured: Boolean(PASSWORD_1 && PASSWORD_2),
    plansConfigured: Object.keys(plans).length > 0, testMode: TEST_MODE, entitlements: PLAN_ENTITLEMENTS,
    planSummary: Object.fromEntries(Object.entries(plans).map(([code, plan]) => [code, { amount: Number(plan.amount), days: Number(plan.days), label: String(plan.label || code) }]))
  });
});

app.post("/api/payments/create", rateLimit({ max: 8 }), requireUser, sameOrigin, async (req, res) => {
  if (!configReady()) {
    return res.status(503).json({ error: "Платежи пока не настроены на сервере." });
  }
  const planCode = String(req.body?.plan || "");
  const email = req.user.email;
  const userId = req.user.id;
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
      "INSERT INTO payments(plan_code, amount, status, robokassa_invoice_id, user_id) VALUES($1,$2,'pending',$3,$4)",
      [planCode, amount, invoiceId, userId]
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
      Receipt: encodeURIComponent(receipt),
      Culture: "ru",
      Encoding: "utf-8",
      Shp_user: String(userId)
    };
    if (email) params.Email = email;
    if (TEST_MODE) params.IsTest = "1";
    params.SignatureValue = paymentSignature(amount, invoiceId, encodeURIComponent(receipt), { Shp_user: String(userId) });

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
  const userId = String(params.Shp_user || "");
  if (!/^\d+$/.test(userId) || !/^\d+$/.test(invoiceId) || !/^\d+\.\d{2}$/.test(amount) ||
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
    if (String(payment.user_id || "") !== userId) {
      await client.query("ROLLBACK");
      return res.status(400).send("USER_MISMATCH");
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
        `INSERT INTO subscriptions(plan_code, starts_at, expires_at, payment_id, user_id)
         SELECT $1, start_at, start_at + ($2::int * INTERVAL '1 day'), $3, $4
         FROM (
           SELECT GREATEST(NOW(), COALESCE(MAX(s.expires_at), NOW())) AS start_at
           FROM subscriptions s WHERE s.user_id = $4
         ) active_period`,
        [payment.plan_code, Number(plan.days), payment.id, Number(userId)]
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

app.get("/api/subscription/status", rateLimit({ max: 60 }), requireUser, async (req, res) => {
  res.setHeader("Cache-Control", "no-store, private");
  try {
    const plan = await accountPlan(req.user.id);
    res.json({ subscription: plan.plan === "free" ? null : { plan_code: plan.plan, expires_at: plan.expiresAt }, ...plan });
  } catch (error) {
    console.error("Subscription lookup failed:", error.message);
    res.status(500).json({ error: "Не удалось получить статус подписки." });
  }
});

async function verifyDbRoundTrip() {
  const client=await pool.connect();
  const marker=crypto.randomUUID();
  try {
    await client.query("BEGIN");
    const created=await client.query("INSERT INTO users(email,password_salt,password_hash) VALUES($1,$2,$3) RETURNING id",["health-"+marker+"@invalid.local","health-check","health-check"]);
    const userId=created.rows[0].id;
    const token=crypto.randomBytes(32).toString("base64url");
    await client.query("INSERT INTO user_sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '1 minute')",[hashToken(token),userId]);
    await client.query("INSERT INTO user_products(user_id,data) VALUES($1,$2::jsonb)",[userId,JSON.stringify({id:marker,name:"health-check"})]);
    await client.query("INSERT INTO user_history(user_id,data) VALUES($1,$2::jsonb)",[userId,JSON.stringify({id:marker,profit:1})]);
    const result=await client.query("SELECT u.email,s.token_hash,p.data AS product,h.data AS history FROM users u JOIN user_sessions s ON s.user_id=u.id JOIN user_products p ON p.user_id=u.id JOIN user_history h ON h.user_id=u.id WHERE u.id=$1",[userId]);
    if(result.rowCount!==1 || result.rows[0].product.id!==marker || result.rows[0].history.id!==marker || result.rows[0].token_hash!==hashToken(token)) throw new Error("PostgreSQL read/write round-trip returned unexpected data");
    await client.query("ROLLBACK");
  } catch(error) { await client.query("ROLLBACK").catch(()=>{}); throw error; }
  finally { client.release(); }
}
app.listen(PORT, async () => {
  try {
    await initDb();
    await verifyDbRoundTrip();
    console.log("PostgreSQL read/write smoke test passed (transaction rolled back)");
    console.log(`Где прибыль МП API 1.0.0 listening on ${PORT}`);
    console.log("Payment configuration:", JSON.stringify({
      databaseConfigured: Boolean(pool),
      smsConfigured: Boolean(SMSC_API_KEY),
      merchantConfigured: Boolean(MERCHANT_LOGIN),
      passwordsConfigured: Boolean(PASSWORD_1 && PASSWORD_2),
      plansConfigured: Object.keys(plans).length > 0,
      planCodes: Object.keys(plans),
      testMode: TEST_MODE,
      emailConfigured: Boolean(RESEND_API_KEY && EMAIL_FROM),
      hashAlgorithm: HASH_ALGORITHM
    }));
  } catch (error) {
    console.error("Database initialization failed:", error.message);
    process.exit(1);
  }
});
