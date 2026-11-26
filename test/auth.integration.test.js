import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { PLAN_ENTITLEMENTS, normalizePlanCode, isWithinPlanLimits } from "../lib/entitlements.js";

const databaseUrl = process.env.TEST_DATABASE_URL;

test("registration, login, logout, PostgreSQL sync and FREE limits", {
  skip: !databaseUrl && "TEST_DATABASE_URL is not configured"
}, async () => {
  const port = 41000 + Math.floor(Math.random() * 10000);
  const origin = "http://127.0.0.1:" + port;
  const child = spawn(process.execPath, ["server.js"], {
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(port),
      DATABASE_URL: databaseUrl,
      PGSSLMODE: "disable",
      FRONTEND_ORIGIN: origin,
      PLAN_CONFIG_JSON: "{}",
      ROBOKASSA_MERCHANT_LOGIN: "",
      ROBOKASSA_PASSWORD_1: "",
      ROBOKASSA_PASSWORD_2: ""
    },
    stdio: ["ignore", "pipe", "pipe"]
  });

  let logs = "";
  let testPool;
  child.stdout.on("data", chunk => { logs += chunk.toString(); });
  child.stderr.on("data", chunk => { logs += chunk.toString(); });

  const base = origin;
  const request = async (path, options = {}) => fetch(base + path, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {})
    }
  });
  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

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

    const preflight = await request("/api/marketplaces/ozon", {
      method: "OPTIONS",
      headers: {
        Origin: origin,
        "Access-Control-Request-Method": "DELETE",
        "Access-Control-Request-Headers": "content-type"
      }
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-origin"), origin);
    assert.equal(preflight.headers.get("access-control-allow-credentials"), "true");
    assert.ok(
      preflight.headers.get("access-control-allow-methods")?.split(",").map(value => value.trim()).includes("DELETE"),
      "CORS preflight must explicitly allow DELETE for marketplace disconnect"
    );

    testPool = new pg.Pool({ connectionString: databaseUrl });
    const originHeader = { Origin: origin };
    const seedSmsCode = async (phone, code) => {
      const salt = randomUUID();
      const codeHash = createHash("sha256").update(salt + ":" + code).digest("hex");
      await testPool.query(
        "INSERT INTO phone_auth_codes(phone,code_hash,code_salt,expires_at,attempts,last_sent_at,created_at) VALUES($1,$2,$3,NOW()+INTERVAL '5 minutes',0,NOW(),NOW()) ON CONFLICT(phone) DO UPDATE SET code_hash=EXCLUDED.code_hash,code_salt=EXCLUDED.code_salt,expires_at=EXCLUDED.expires_at,attempts=0,last_sent_at=NOW(),created_at=NOW()",
        [phone, codeHash, salt]
      );
    };
    const phone = "15551234567";
    const code = "123456";
    await seedSmsCode(phone, code);
    const registration = await request("/api/auth/sms/verify", {
      method: "POST",
      headers: { ...originHeader, "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code })
    });
    assert.equal(registration.status, 200);
    const registrationData = await registration.json();
    assert.equal(registrationData.plan, "free");
    assert.equal(registrationData.limits.products, 5);
    assert.equal(registrationData.user.phone, phone);
    const firstCookie = registration.headers.get("set-cookie")?.match(/gpm_session=([^;]+)/)?.[1];
    assert.ok(firstCookie, "registration must issue a session cookie");

    const crossOriginPayment = await request("/api/payments/create", {
      method: "POST",
      headers: { Origin: "https://attacker.example", Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ plan: "pro" })
    });
    assert.equal(crossOriginPayment.status, 403, "cross-origin requests must not create payment sessions");

    const me = await request("/api/auth/me", { headers: { Cookie: "gpm_session=" + firstCookie } });
    const marketplaceAccess = await request("/api/marketplaces", {
      headers: { Cookie: "gpm_session=" + firstCookie }
    });

    assert.equal(marketplaceAccess.status, 403, "FREE plan must not access marketplace integrations");

    for (const provider of ["wildberries", "ozon"]) {
      const credentials = provider === "wildberries"
        ? { token: "synthetic-wb-token-that-is-never-sent" }
        : { clientId: "123456", apiKey: "synthetic-ozon-key-that-is-never-sent" };
      const connect = await request("/api/marketplaces/" + provider + "/credentials", {
        method: "PUT",
        headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
        body: JSON.stringify(credentials)
      });
      assert.equal(connect.status, 403, "FREE plan must not connect " + provider);

      const refresh = await request("/api/marketplaces/" + provider + "/refresh", {
        method: "POST",
        headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
        body: "{}"
      });
      assert.equal(refresh.status, 403, "FREE plan must not refresh " + provider);

      const disconnect = await request("/api/marketplaces/" + provider, {
        method: "DELETE",
        headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie }
      });
      assert.equal(disconnect.status, 403, "FREE plan must not call " + provider + " integration routes");
    }

    const paymentAttempt = await request("/api/payments/create", {
      method: "POST",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ plan: "pro" })
    });
    assert.equal(paymentAttempt.status, 503, "Payments must remain disabled without Robokassa credentials");

    assert.equal(me.status, 200);
    assert.equal((await me.json()).user.phone, phone);

    const products = Array.from({ length: 5 }, (_, i) => ({ id: "p" + i, name: "Test product " + i }));
    const history = Array.from({ length: 20 }, (_, i) => ({ id: "h" + i, profit: i }));
    const initialData = await request("/api/account/data", { headers: { Cookie: "gpm_session=" + firstCookie } });
    assert.equal(initialData.status, 200);
    const initialVersion = (await initialData.json()).version;
    const save = await request("/api/account/data", {
      method: "PUT",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ products, history, expectedVersion: initialVersion })
    });
    assert.equal(save.status, 200);
    assert.equal((await save.json()).saved, true);

    const read = await request("/api/account/data", {
      headers: { Cookie: "gpm_session=" + firstCookie }
    });
    assert.equal(read.status, 200);
    const savedData = await read.json();
    assert.equal(savedData.products.length, 5);
    assert.equal(savedData.history.length, 20);
    assert.deepEqual(savedData.products, products);
    assert.deepEqual(savedData.history, history);
    assert.equal(savedData.version, 1);

    const staleWrite = await request("/api/account/data", {
      method: "PUT",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ products: [{ id: "stale", name: "Stale overwrite" }], history, expectedVersion: 0 })
    });
    assert.equal(staleWrite.status, 409, "a stale device version must not overwrite newer cloud data");
    assert.equal((await staleWrite.json()).code, "SYNC_VERSION_CONFLICT");
    const afterConflict = await request("/api/account/data", { headers: { Cookie: "gpm_session=" + firstCookie } });
    assert.deepEqual((await afterConflict.json()).products, products, "a rejected stale write must preserve the latest data");

    const tooManyProducts = await request("/api/account/data", {
      method: "PUT",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ products: [...products, { id: "overflow" }], history, expectedVersion: 1 })
    });
    assert.equal(tooManyProducts.status, 403);

    const tooMuchHistory = await request("/api/account/data", {
      method: "PUT",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ products, history: [...history, { id: "overflow" }], expectedVersion: 1 })
    });
    assert.equal(tooMuchHistory.status, 403);

    const deletedSave = await request("/api/account/data", {
      method: "PUT",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({
        products: [...products.slice(1), { ...products[0], id: "p-readded" }],
        history: history.slice(1),
        deletedIds: ["p0", "h0"],
        expectedVersion: 1
      })
    });
    assert.equal(deletedSave.status, 200);
    const afterDeletion = await request("/api/account/data", { headers: { Cookie: "gpm_session=" + firstCookie } });
    const deletionData = await afterDeletion.json();
    assert.ok(!deletionData.products.some(item => item.id === "p0"), "deleted product must stay deleted");
    assert.ok(!deletionData.history.some(item => item.id === "h0"), "deleted history row must stay deleted");
    assert.ok(deletionData.products.some(item => item.id === "p-readded"), "a re-added identical product with a new ID must remain active");
    assert.deepEqual(new Set(deletionData.deletedIds), new Set(["p0", "h0"]));

    await seedSmsCode(phone, code);
    const repeatSmsLogin = await request("/api/auth/sms/verify", {
      method: "POST",
      headers: { ...originHeader, "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code })
    });
    assert.equal(repeatSmsLogin.status, 200);
    assert.equal(String((await repeatSmsLogin.json()).user.id), String(registrationData.user.id),
      "a verified phone must return the existing account, not create a duplicate");

    const logout = await request("/api/auth/logout", {
      method: "POST",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: "{}"
    });
    assert.equal(logout.status, 200);
    const afterLogout = await request("/api/auth/me", { headers: { Cookie: "gpm_session=" + firstCookie } });
    assert.equal(afterLogout.status, 401);

    await seedSmsCode(phone, code);
    const login = await request("/api/auth/sms/verify", {
      method: "POST",
      headers: { ...originHeader, "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code })
    });
    assert.equal(login.status, 200);
    const secondCookie = login.headers.get("set-cookie")?.match(/gpm_session=([^;]+)/)?.[1];
    assert.ok(secondCookie, "login must issue a session cookie");

    const afterLogin = await request("/api/account/data", {
      headers: { Cookie: "gpm_session=" + secondCookie }
    });
    assert.equal(afterLogin.status, 200);
    const restored = await afterLogin.json();
    assert.deepEqual(restored.products, deletionData.products);
    assert.deepEqual(restored.history, deletionData.history);
    assert.deepEqual(restored.deletedIds, ["p0", "h0"], "deletion tombstones must survive logout and login");

    // Verify marketplace records are isolated by user_id, even for two paid accounts.
    const activatePro = async userId => {
      const payment = await testPool.query(
        "INSERT INTO payments(plan_code,amount,status,robokassa_invoice_id,user_id) VALUES('pro',0,'paid',$1,$2) RETURNING id",
        ["integration-" + randomUUID(), userId]
      );
      await testPool.query(
        "INSERT INTO subscriptions(plan_code,starts_at,expires_at,payment_id,user_id) VALUES('pro',NOW(),NOW()+INTERVAL '30 days',$1,$2)",
        [payment.rows[0].id, userId]
      );
    };
    await activatePro(registrationData.user.id);

    const otherPhone = "15559876543";
    await seedSmsCode(otherPhone, code);
    const otherRegistration = await request("/api/auth/sms/verify", {
      method: "POST",
      headers: { ...originHeader, "Content-Type": "application/json" },
      body: JSON.stringify({ phone: otherPhone, code })
    });
    assert.equal(otherRegistration.status, 200);
    const otherRegistrationData = await otherRegistration.json();
    const otherCookie = otherRegistration.headers.get("set-cookie")?.match(/gpm_session=([^;]+)/)?.[1];
    assert.ok(otherCookie);

    const otherAccountData = await request("/api/account/data", {
      headers: { Cookie: "gpm_session=" + otherCookie }
    });
    assert.equal(otherAccountData.status, 200);
    const otherData = await otherAccountData.json();
    assert.deepEqual(otherData.products, [], "a new account must not read another user's products");
    assert.deepEqual(otherData.history, [], "a new account must not read another user's history");
    assert.deepEqual(otherData.deletedIds, [], "a new account must not read another user's deletion tombstones");

    const ownerDataAfterOtherRead = await request("/api/account/data", {
      headers: { Cookie: "gpm_session=" + secondCookie }
    });
    assert.equal(ownerDataAfterOtherRead.status, 200);
    const ownerData = await ownerDataAfterOtherRead.json();
    assert.deepEqual(ownerData.products, deletionData.products);
    assert.deepEqual(ownerData.history, deletionData.history);

    await activatePro(otherRegistrationData.user.id);

    const privateSnapshot = { fetchedAt: "synthetic-test", products: 1, items: [{ productId: "700001", offerId: "PRIVATE-DEMO" }] };
    await testPool.query(
      "INSERT INTO marketplace_integrations(user_id,marketplace,encrypted_credentials,nonce,auth_tag,snapshot,last_synced_at) VALUES($1,'ozon','synthetic-ciphertext','synthetic-nonce','synthetic-tag',$2::jsonb,NOW())",
      [registrationData.user.id, JSON.stringify(privateSnapshot)]
    );

    const ownerConnections = await request("/api/marketplaces", {
      headers: { Cookie: "gpm_session=" + secondCookie }
    });
    assert.equal(ownerConnections.status, 200);
    assert.deepEqual((await ownerConnections.json()).connections.ozon.snapshot, privateSnapshot);

    const otherConnections = await request("/api/marketplaces", {
      headers: { Cookie: "gpm_session=" + otherCookie }
    });
    assert.equal(otherConnections.status, 200);
    assert.deepEqual((await otherConnections.json()).connections, {}, "another PRO user must not see the owner's marketplace record");

    const otherDisconnect = await request("/api/marketplaces/ozon", {
      method: "DELETE",
      headers: { ...originHeader, Cookie: "gpm_session=" + otherCookie }
    });
    assert.equal(otherDisconnect.status, 200);

    const ownerAfterOtherDisconnect = await request("/api/marketplaces", {
      headers: { Cookie: "gpm_session=" + secondCookie }
    });
    assert.equal(ownerAfterOtherDisconnect.status, 200);
    assert.equal((await ownerAfterOtherDisconnect.json()).connections.ozon.connected, true,
      "another user must not be able to disconnect the owner's marketplace");

    const legacyRow = { name: "Legacy row without ID", market: "Wildberries", price: 100 };
    await testPool.query("INSERT INTO user_products(user_id,data) VALUES($1,$2::jsonb)", [registrationData.user.id, JSON.stringify(legacyRow)]);
    const migratedOnceResponse = await request("/api/account/data", { headers: { Cookie: "gpm_session=" + secondCookie } });
    const migratedOnce = await migratedOnceResponse.json();
    const migratedOnceRow = migratedOnce.products.find(item => item.name === legacyRow.name);
    assert.match(migratedOnceRow.id, /^legacy:[0-9a-f]{16}$/, "legacy records must receive deterministic IDs");
    const migratedAgainResponse = await request("/api/account/data", { headers: { Cookie: "gpm_session=" + secondCookie } });
    const migratedAgain = await migratedAgainResponse.json();
    assert.equal(migratedAgain.products.find(item => item.name === legacyRow.name).id, migratedOnceRow.id,
      "legacy ID migration must remain stable across reads");
  } finally {
    await testPool?.end();
    child.kill("SIGTERM");
    await Promise.race([new Promise(resolve => child.once("exit", resolve)), wait(3000)]);
  }
});

// Regression coverage for tenant-scoped tombstones and stable legacy record IDs.


test("marketplace refresh writes are conditional on the exact credential version", () => {
  const server = readFileSync(new URL("../server.js", import.meta.url), "utf8");
  assert.ok(server.includes("async function syncMarketplace(userId, marketplace, credentialRecord)"));
  assert.ok(server.includes("WHERE user_id=$1 AND marketplace=$2 AND encrypted_credentials=$3 AND nonce=$5 AND auth_tag=$6"));
  assert.ok(server.includes("Ключи маркетплейса изменились во время обновления"));
  assert.ok(server.includes("SET last_error=$6,updated_at=NOW() WHERE user_id=$1 AND marketplace=$2 AND encrypted_credentials=$3 AND nonce=$4 AND auth_tag=$5"));
});


test("account data reads use one read-only repeatable-read snapshot", () => {
  const server = readFileSync(new URL("../server.js", import.meta.url), "utf8");
  const route = server.slice(server.indexOf('app.get("/api/account/data"'), server.indexOf('app.put("/api/account/data"'));
  assert.ok(route.includes('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'));
  assert.ok(route.includes('client.query("SELECT data FROM user_products'));
  assert.ok(route.includes('client.query("SELECT data FROM user_history'));
  assert.ok(route.includes('client.query("SELECT version FROM user_data_versions'));
  assert.ok(route.includes('client.query("SELECT record_id FROM user_data_tombstones'));
  assert.ok(route.includes('client.query("COMMIT")'));
  assert.ok(!route.includes('UPDATE user_products'));
  assert.ok(!route.includes('UPDATE user_history'));
});
