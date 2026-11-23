require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const port = Number(process.env.PORT || 3000);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined });
const plans = {
  free: { name: 'Free', price: 0, limits: { products: 3, historyDays: 7, exports: false, advanced: false, teamSeats: 1 } },
  pro: { name: 'Pro', price: 490, limits: { products: 100, historyDays: 365, exports: true, advanced: true, teamSeats: 1 } },
  business: { name: 'Business', price: 990, limits: { products: 1000, historyDays: 3650, exports: true, advanced: true, teamSeats: 5 } }
};
const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) throw new Error('JWT_SECRET must be at least 32 characters');
const login = process.env.ROBOKASSA_MERCHANT_LOGIN || '';
const pass1 = process.env.ROBOKASSA_PASSWORD_1 || '';
const pass2 = process.env.ROBOKASSA_PASSWORD_2 || '';
const publicUrl = (process.env.APP_URL || '').replace(/\/$/, '');

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: publicUrl || false, credentials: true }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public'));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: true, legacyHeaders: false }));

function tokenFor(user) {
  return jwt.sign({ sub: user.id, role: user.role }, secret, { expiresIn: '7d', issuer: 'gde-pribyl-mp' });
}
function auth(req, res, next) {
  const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || req.cookies?.gpm_session;
  if (!raw) return res.status(401).json({ error: 'Требуется вход в аккаунт' });
  try { req.auth = jwt.verify(raw, secret, { issuer: 'gde-pribyl-mp' }); next(); }
  catch { return res.status(401).json({ error: 'Сессия истекла. Войди снова.' }); }
}
function admin(req, res, next) {
  if (req.auth?.role !== 'admin') return res.status(403).json({ error: 'Недостаточно прав' });
  next();
}
function signature(value) { return crypto.createHash('md5').update(value, 'utf8').digest('hex').toLowerCase(); }
function safeEqual(a, b) {
  const x = Buffer.from(String(a || '').toLowerCase());
  const y = Buffer.from(String(b || '').toLowerCase());
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function requirePaymentConfig() {
  if (!login || !pass1 || !pass2 || !publicUrl.startsWith('https://')) throw new Error('Платежи не настроены: нужны MerchantLogin, пароли и публичный HTTPS APP_URL');
}
function setSession(res, user) { res.cookie('gpm_session', tokenFor(user), { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000, path: '/' }); }
function currentUserPlan(row) {
  const plan = row?.plan && row.status === 'active' && (!row.period_end || new Date(row.period_end) > new Date()) ? row.plan : 'free';
  return { ...plans[plan], code: plan, status: row?.status || 'active', periodEnd: row?.period_end || null, autoRenew: Boolean(row?.auto_renew) };
}
async function loadUser(id) {
  const q = await pool.query('SELECT id,email,display_name,role,created_at FROM users WHERE id=$1', [id]);
  return q.rows[0] || null;
}
async function loadSubscription(id) {
  const q = await pool.query("SELECT * FROM subscriptions WHERE user_id=$1 AND status IN ('active','pending','past_due') ORDER BY created_at DESC LIMIT 1", [id]);
  return q.rows[0] || null;
}
app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, service: 'gde-pribyl-mp', version: '0.8.0' }); }
  catch { res.status(503).json({ ok: false }); }
});
app.get('/api/plans', (_req, res) => res.json(Object.entries(plans).map(([code, p]) => ({ code, ...p }))));

app.post('/api/auth/register', rateLimit({ windowMs: 60 * 60 * 1000, limit: 8 }), async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const displayName = String(req.body.displayName || '').trim().slice(0, 80);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Укажи корректный email' });
    if (password.length < 10 || password.length > 128) return res.status(400).json({ error: 'Пароль должен содержать от 10 до 128 символов' });
    const hash = await bcrypt.hash(password, 12);
    const role = process.env.ADMIN_EMAIL && email === process.env.ADMIN_EMAIL.toLowerCase() ? 'admin' : 'user';
    const created = await pool.query('INSERT INTO users(email,password_hash,display_name,role) VALUES($1,$2,$3,$4) RETURNING id,email,display_name,role', [email, hash, displayName, role]);
    const user = created.rows[0];
    await pool.query("INSERT INTO subscriptions(user_id,plan,status,price_rub) VALUES($1,'free','active',0)", [user.id]);
    setSession(res, user); res.status(201).json({ user, subscription: currentUserPlan(await loadSubscription(user.id)) });
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'Этот email уже зарегистрирован' }); next(e); }
});
app.post('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 }), async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const q = await pool.query('SELECT id,email,password_hash,display_name,role FROM users WHERE email=$1', [email]);
    if (!q.rowCount || !(await bcrypt.compare(String(req.body.password || ''), q.rows[0].password_hash))) return res.status(401).json({ error: 'Неверный email или пароль' });
    const user = q.rows[0]; delete user.password_hash;
    setSession(res, user); res.json({ user, subscription: currentUserPlan(await loadSubscription(user.id)) });
  } catch (e) { next(e); }
});
app.post('/api/auth/logout', (_req, res) => { res.clearCookie('gpm_session', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' }); res.json({ ok: true }); });
app.get('/api/me', auth, async (req, res, next) => {
  try {
    const user = await loadUser(req.auth.sub);
    if (!user) return res.status(401).json({ error: 'Аккаунт не найден' });
    res.json({ user, subscription: currentUserPlan(await loadSubscription(user.id)) });
  } catch (e) { next(e); }
});

app.post('/api/billing/checkout', auth, async (req, res, next) => {
  try {
    requirePaymentConfig();
    const plan = String(req.body.plan || '');
    if (!['pro', 'business'].includes(plan)) return res.status(400).json({ error: 'Выбери платный тариф' });
    if (req.body.recurringConsent !== true) return res.status(400).json({ error: 'Для подписки необходимо отдельно подтвердить согласие на ежемесячные автосписания' });
    if (process.env.RECURRING_ENABLED !== 'true') return res.status(503).json({ error: 'Рекуррентные платежи пока не включены. Ожидается согласование Robokassa.' });
    const user = await loadUser(req.auth.sub);
    if (!user) return res.status(401).json({ error: 'Аккаунт не найден' });
    const invoiceId = Number(String(Date.now()) + String(crypto.randomInt(100, 999)));
    const amount = plans[plan].price.toFixed(2);
    const description = 'Подписка ' + plans[plan].name + ' — Где прибыль МП';
    const signatureValue = signature([login, amount, invoiceId, pass1].join(':'));
    await pool.query('INSERT INTO payments(user_id,invoice_id,amount_rub,status,provider_payload) VALUES($1,$2,$3,\'pending\',$4)', [user.id, invoiceId, amount, JSON.stringify({ plan })]);
    const params = new URLSearchParams({
      MerchantLogin: login, OutSum: amount, InvId: String(invoiceId), Description: description,
      SignatureValue: signatureValue, Recurring: 'true', Email: user.email,
      Culture: 'ru', Encoding: 'utf-8'
    });
    const url = 'https://auth.robokassa.ru/Merchant/Index.aspx?' + params.toString();
    res.json({ paymentUrl: url, invoiceId, amount: Number(amount), currency: 'RUB', plan });
  } catch (e) { next(e); }
});

// ResultURL: подписка включается только после проверки подписи и суммы callback.
app.post('/api/billing/robokassa/result', async (req, res, next) => {
  const client = await pool.connect();
  try {
    const outSum = String(req.body.OutSum || '');
    const invId = String(req.body.InvId || '');
    const supplied = String(req.body.SignatureValue || '');
    const expected = signature([outSum, invId, pass2].join(':'));
    if (!safeEqual(supplied, expected)) return res.status(403).send('bad sign');
    await client.query('BEGIN');
    const payment = await client.query('SELECT * FROM payments WHERE invoice_id=$1 FOR UPDATE', [invId]);
    if (!payment.rowCount) { await client.query('ROLLBACK'); return res.status(404).send('not found'); }
    const p = payment.rows[0];
    if (Number(p.amount_rub).toFixed(2) !== Number(outSum).toFixed(2)) { await client.query('ROLLBACK'); return res.status(400).send('bad amount'); }
    if (p.status !== 'paid') {
      const plan = p.provider_payload.plan;
      const start = new Date();
      const end = new Date(start); end.setMonth(end.getMonth() + 1);
      const sub = await client.query(
        "INSERT INTO subscriptions(user_id,plan,status,price_rub,period_start,period_end,auto_renew,robokassa_parent_invoice,next_charge_at) VALUES($1,$2,'active',$3,$4,$5,true,$6,$5) RETURNING id",
        [p.user_id, plan, plans[plan].price, start, end, invId]
      );
      await client.query("UPDATE subscriptions SET status='canceled',auto_renew=false,canceled_at=now(),updated_at=now() WHERE user_id=$1 AND id<>$2 AND status='active'", [p.user_id, sub.rows[0].id]);
      await client.query("UPDATE payments SET status='paid',paid_at=now(),subscription_id=$2,provider_payload=provider_payload || $3::jsonb WHERE invoice_id=$1", [invId, sub.rows[0].id, JSON.stringify({ callback: req.body })]);
      await client.query('INSERT INTO audit_log(actor_user_id,event,details) VALUES($1,$2,$3)', [p.user_id, 'payment.succeeded', JSON.stringify({ invoiceId: invId, plan })]);
    }
    await client.query('COMMIT');
    res.type('text').send('OK' + invId);
  } catch (e) { await client.query('ROLLBACK'); next(e); }
  finally { client.release(); }
});
app.get('/api/billing/success', (_req, res) => res.redirect('/?payment=return'));
app.get('/api/billing/fail', (_req, res) => res.redirect('/?payment=failed'));

app.post('/api/billing/cancel', auth, async (req, res, next) => {
  try {
    const result = await pool.query("UPDATE subscriptions SET auto_renew=false,status='canceled',canceled_at=now(),updated_at=now() WHERE user_id=$1 AND status='active' RETURNING id,period_end", [req.auth.sub]);
    if (!result.rowCount) return res.status(404).json({ error: 'Активная подписка не найдена' });
    res.json({ canceled: true, accessUntil: result.rows[0].period_end });
  } catch (e) { next(e); }
});
app.get('/api/billing/payments', auth, async (req, res, next) => {
  try {
    const q = await pool.query('SELECT invoice_id,amount_rub,status,paid_at,created_at FROM payments WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100', [req.auth.sub]);
    res.json(q.rows);
  } catch (e) { next(e); }
});

app.get('/api/admin/overview', auth, admin, async (_req, res, next) => {
  try {
    const [users, subs, payments] = await Promise.all([
      pool.query('SELECT count(*)::int AS total FROM users'),
      pool.query("SELECT plan,count(*)::int AS total FROM subscriptions WHERE status='active' GROUP BY plan"),
      pool.query("SELECT count(*)::int AS total,COALESCE(sum(amount_rub),0)::numeric(12,2) AS revenue FROM payments WHERE status='paid'")
    ]);
    res.json({ users: users.rows[0].total, subscriptions: subs.rows, payments: payments.rows[0] });
  } catch (e) { next(e); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});
app.listen(port, () => console.log('Где прибыль МП API listening on ' + port));
