import express from "express";
import crypto from "node:crypto";
import pg from "pg";

const { Pool } = pg;
const app = express();
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
app.use(express.json({ limit: "32kb" }));

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://gde-pribyl-mp.onrender.com";
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin === FRONTEND_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", FRONTEND_ORIGIN);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

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
    CREATE TABLE IF NOT EXISTS subscriptions (
      id BIGSERIAL PRIMARY KEY,
      plan_code TEXT NOT NULL,
      starts_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      payment_id BIGINT NOT NULL UNIQUE REFERENCES payments(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    version: "0.8.0",
    paymentsConfigured: configReady(),
    databaseConfigured: Boolean(pool),
    testMode: TEST_MODE
  });
});

app.post("/api/payments/create", async (req, res) => {
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

app.all("/api/robokassa/result", handleResult);
app.get("/payment/success", (_req, res) => res.redirect(`${SITE_URL}/?payment=return`));
app.get("/payment/fail", (_req, res) => res.redirect(`${SITE_URL}/?payment=failed`));

app.get("/api/subscription/status", async (req, res) => {
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
  } catch (error) {
    console.error("Database initialization failed:", error.message);
    process.exit(1);
  }
});
