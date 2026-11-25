import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID, createHash } from "node:crypto";
import pg from "pg";

const databaseUrl = process.env.TEST_DATABASE_URL;

test("Robokassa payment signature, callback, replay and subscription lifecycle", {
  skip: !databaseUrl && "TEST_DATABASE_URL is not configured"
}, async () => {
  const port = 42000 + Math.floor(Math.random() * 10000);
  const origin = "http://127.0.0.1:" + port;
  const merchant = "synthetic-merchant";
  const password1 = "synthetic-password-one";
  const password2 = "synthetic-password-two";
  const plans = {
    pro: { amount: 499, days: 30, label: "PRO" },
    business: { amount: 900, days: 30, label: "BUSINESS" }
  };
  const child = spawn(process.execPath, ["server.js"], {
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(port),
      DATABASE_URL: databaseUrl,
      PGSSLMODE: "disable",
      FRONTEND_ORIGIN: origin,
      PLAN_CONFIG_JSON: JSON.stringify(plans),
      ROBOKASSA_MERCHANT_LOGIN: merchant,
      ROBOKASSA_PASSWORD_1: password1,
      ROBOKASSA_PASSWORD_2: password2,
      ROBOKASSA_HASH: "MD5",
      ROBOKASSA_TEST_MODE: "true"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let logs = "";
  child.stdout.on("data", chunk => { logs += chunk.toString(); });
  child.stderr.on("data", chunk => { logs += chunk.toString(); });
  const request = async (path, options = {}) => fetch(origin + path, options);
  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
  const signature = value => createHash("md5").update(value, "utf8").digest("hex");
  let testPool;

  try {
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      if (child.exitCode !== null) throw new Error("API process exited early: " + logs);
      try {
        const response = await request("/health");
        if (response.status === 200) { ready = true; break; }
      } catch {}
      await wait(500);
    }
    assert.equal(ready, true, "API did not become healthy: " + logs);

    const email = "robokassa-" + randomUUID() + "@example.test";
    const registration = await request("/api/auth/register", {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: "ValidPass123!" })
    });
    assert.equal(registration.status, 201);
    const cookie = registration.headers.get("set-cookie")?.match(/gpm_session=([^;]+)/)?.[1];
    assert.ok(cookie);

    const created = await request("/api/payments/create", {
      method: "POST",
      headers: {
        Origin: origin,
        Cookie: "gpm_session=" + cookie,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ plan: "pro" })
    });
    assert.equal(created.status, 200);
    const { paymentUrl, paymentParams } = await created.json();
    assert.equal(paymentUrl, "https://auth.robokassa.ru/Merchant/Index.aspx");
    assert.equal(paymentParams.MerchantLogin, merchant);
    assert.equal(paymentParams.OutSum, "499.00");
    assert.equal(paymentParams.IsTest, "1");
    const receipt = paymentParams.Receipt;
    const shp = "Shp_user=" + paymentParams.Shp_user;
    const expectedPaymentSignature = signature([
      merchant, paymentParams.OutSum, paymentParams.InvId, receipt, password1, shp
    ].join(":"));
    assert.equal(paymentParams.SignatureValue, expectedPaymentSignature);

    testPool = new pg.Pool({ connectionString: databaseUrl });
    const paymentBefore = await testPool.query(
      "SELECT id,status,amount,user_id,plan_code FROM payments WHERE robokassa_invoice_id=$1",
      [paymentParams.InvId]
    );
    assert.equal(paymentBefore.rowCount, 1);
    assert.equal(paymentBefore.rows[0].status, "pending");
    assert.equal(String(paymentBefore.rows[0].user_id), paymentParams.Shp_user);

    const callbackParams = {
      OutSum: paymentParams.OutSum,
      InvId: paymentParams.InvId,
      Shp_user: paymentParams.Shp_user
    };
    callbackParams.SignatureValue = signature([
      callbackParams.OutSum, callbackParams.InvId, password2, shp
    ].join(":"));
    const callbackBody = new URLSearchParams(callbackParams).toString();
    const callback = () => request("/api/robokassa/result", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: callbackBody
    });

    const paid = await callback();
    assert.equal(paid.status, 200);
    assert.equal(await paid.text(), "OK" + paymentParams.InvId);

    const replay = await callback();
    assert.equal(replay.status, 200);
    assert.equal(await replay.text(), "OK" + paymentParams.InvId);

    const persisted = await testPool.query(
      `SELECT p.status,p.paid_at,s.plan_code,s.user_id,s.starts_at,s.expires_at,
              (SELECT COUNT(*) FROM subscriptions WHERE payment_id=p.id) AS subscription_count
       FROM payments p JOIN subscriptions s ON s.payment_id=p.id
       WHERE p.robokassa_invoice_id=$1`,
      [paymentParams.InvId]
    );
    assert.equal(persisted.rowCount, 1);
    assert.equal(persisted.rows[0].status, "paid");
    assert.ok(persisted.rows[0].paid_at);
    assert.equal(persisted.rows[0].plan_code, "pro");
    assert.equal(String(persisted.rows[0].user_id), paymentParams.Shp_user);
    assert.equal(Number(persisted.rows[0].subscription_count), 1, "callback replay must not duplicate subscriptions");
    const durationDays = (new Date(persisted.rows[0].expires_at) - new Date(persisted.rows[0].starts_at)) / 86400000;
    assert.ok(durationDays > 29.99 && durationDays < 30.01);

    const badSignature = await request("/api/robokassa/result", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ ...callbackParams, SignatureValue: "invalid" }).toString()
    });
    assert.equal(badSignature.status, 400);
    assert.equal(await badSignature.text(), "BAD_SIGNATURE");

    const mismatchParams = { ...callbackParams, Shp_user: String(Number(callbackParams.Shp_user) + 1) };
    mismatchParams.SignatureValue = signature([
      mismatchParams.OutSum, mismatchParams.InvId, password2, "Shp_user=" + mismatchParams.Shp_user
    ].join(":"));
    const userMismatch = await request("/api/robokassa/result", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(mismatchParams).toString()
    });
    assert.equal(userMismatch.status, 400);
    assert.equal(await userMismatch.text(), "USER_MISMATCH");
  } finally {
    await testPool?.end();
    child.kill("SIGTERM");
  }
});
