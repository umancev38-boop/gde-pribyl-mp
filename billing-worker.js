require('dotenv').config();
const cron = require('node-cron');
const crypto = require('crypto');
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined });
const login = process.env.ROBOKASSA_MERCHANT_LOGIN || '';
const pass1 = process.env.ROBOKASSA_PASSWORD_1 || '';
const pass2 = process.env.ROBOKASSA_PASSWORD_2 || '';
const prices = { pro: 490, business: 990 };
const md5 = s => crypto.createHash('md5').update(s).digest('hex').toLowerCase();

async function billDue() {
  if (process.env.RECURRING_ENABLED !== 'true') return;
  if (!login || !pass1 || !pass2) return console.error('Recurring billing skipped: Robokassa credentials are missing');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const due = await client.query(
      "SELECT s.*,p.email FROM subscriptions s JOIN users p ON p.id=s.user_id WHERE s.status='active' AND s.auto_renew=true AND s.next_charge_at<=now() AND s.robokassa_parent_invoice IS NOT NULL ORDER BY s.next_charge_at FOR UPDATE OF s SKIP LOCKED LIMIT 20"
    );
    for (const sub of due.rows) {
      const invoiceId = Number(String(Date.now()) + String(crypto.randomInt(100, 999)));
      const amount = Number(prices[sub.plan]).toFixed(2);
      const signature = md5([login, amount, invoiceId, pass1].join(':'));
      const body = new URLSearchParams({
        MerchantLogin: login, OutSum: amount, InvoiceID: String(invoiceId),
        PreviousInvoiceID: String(sub.robokassa_parent_invoice),
        Description: 'Продление подписки ' + sub.plan + ' — Где прибыль МП',
        SignatureValue: signature, Email: sub.email, Encoding: 'utf-8'
      });
      await client.query("INSERT INTO payments(user_id,subscription_id,invoice_id,amount_rub,status,provider_payload) VALUES($1,$2,$3,$4,'pending',$5)", [sub.user_id, sub.id, invoiceId, amount, JSON.stringify({ plan: sub.plan, renewal: true })]);
      const response = await fetch('https://auth.robokassa.ru/Merchant/Recurring', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
      const result = await response.text();
      await client.query('UPDATE payments SET provider_payload=provider_payload || $2::jsonb WHERE invoice_id=$1', [invoiceId, JSON.stringify({ recurringResponse: result.slice(0, 500) })]);
      // ResultURL is authoritative; keep access state until provider confirms the charge.
      const next = new Date(sub.next_charge_at); next.setMonth(next.getMonth() + 1);
      await client.query("UPDATE subscriptions SET next_charge_at=$2,updated_at=now() WHERE id=$1", [sub.id, next]);
    }
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); console.error('Billing worker error', e); }
  finally { client.release(); }
}
cron.schedule('*/15 * * * *', billDue);
billDue();
console.log('Recurring billing worker started');
