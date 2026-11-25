import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
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

    const email = "integration-" + randomUUID() + "@example.test";
    const password = "ValidPass123!";
    const originHeader = { Origin: origin };

    const registration = await request("/api/auth/register", {
      method: "POST",
      headers: originHeader,
      body: JSON.stringify({ email, password })
    });
    assert.equal(registration.status, 201);
    const registrationData = await registration.json();
    assert.equal(registrationData.plan, "free");
    assert.equal(registrationData.limits.products, 5);
    const firstCookie = registration.headers.get("set-cookie")?.match(/gpm_session=([^;]+)/)?.[1];
    assert.ok(firstCookie, "registration must issue a session cookie");

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
      headers: { Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ plan: "pro" })
    });
    assert.equal(paymentAttempt.status, 503, "Payments must remain disabled without Robokassa credentials");

    assert.equal(me.status, 200);
    assert.equal((await me.json()).user.email, email);

    const products = Array.from({ length: 5 }, (_, i) => ({ id: "p" + i, name: "Test product " + i }));
    const history = Array.from({ length: 20 }, (_, i) => ({ id: "h" + i, profit: i }));
    const save = await request("/api/account/data", {
      method: "PUT",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ products, history })
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

    const tooManyProducts = await request("/api/account/data", {
      method: "PUT",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ products: [...products, { id: "overflow" }], history })
    });
    assert.equal(tooManyProducts.status, 403);

    const tooMuchHistory = await request("/api/account/data", {
      method: "PUT",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: JSON.stringify({ products, history: [...history, { id: "overflow" }] })
    });
    assert.equal(tooMuchHistory.status, 403);

    const duplicate = await request("/api/auth/register", {
      method: "POST",
      headers: originHeader,
      body: JSON.stringify({ email, password })
    });
    assert.equal(duplicate.status, 409);

    const logout = await request("/api/auth/logout", {
      method: "POST",
      headers: { ...originHeader, Cookie: "gpm_session=" + firstCookie },
      body: "{}"
    });
    assert.equal(logout.status, 200);
    const afterLogout = await request("/api/auth/me", { headers: { Cookie: "gpm_session=" + firstCookie } });
    assert.equal(afterLogout.status, 401);

    const login = await request("/api/auth/login", {
      method: "POST",
      headers: originHeader,
      body: JSON.stringify({ email, password })
    });
    assert.equal(login.status, 200);
    const secondCookie = login.headers.get("set-cookie")?.match(/gpm_session=([^;]+)/)?.[1];
    assert.ok(secondCookie, "login must issue a session cookie");

    const afterLogin = await request("/api/account/data", {
      headers: { Cookie: "gpm_session=" + secondCookie }
    });
    assert.equal(afterLogin.status, 200);
    const restored = await afterLogin.json();
    assert.deepEqual(restored.products, products);
    assert.deepEqual(restored.history, history);
  } finally {
    child.kill("SIGTERM");
    await Promise.race([new Promise(resolve => child.once("exit", resolve)), wait(3000)]);
  }
});


test("published product and calculation limits remain stable", () => {
  assert.deepEqual(PLAN_ENTITLEMENTS.free, { products: 5, history: 20, analytics: false, csvExport: false, targetMargin: false });
  assert.deepEqual(PLAN_ENTITLEMENTS.pro, { products: 200, history: 1000, analytics: false, csvExport: false, targetMargin: true });
  assert.deepEqual(PLAN_ENTITLEMENTS.business, { products: 5000, history: 10000, analytics: true, csvExport: true, targetMargin: true });
});

test("feature access matches the published plans", () => {
  assert.equal(PLAN_ENTITLEMENTS.free.analytics, false);
  assert.equal(PLAN_ENTITLEMENTS.pro.analytics, false);
  assert.equal(PLAN_ENTITLEMENTS.business.analytics, true);
  assert.equal(PLAN_ENTITLEMENTS.free.csvExport, false);
  assert.equal(PLAN_ENTITLEMENTS.pro.csvExport, false);
  assert.equal(PLAN_ENTITLEMENTS.business.csvExport, true);
  assert.equal(PLAN_ENTITLEMENTS.free.targetMargin, false);
  assert.equal(PLAN_ENTITLEMENTS.pro.targetMargin, true);
  assert.equal(PLAN_ENTITLEMENTS.business.targetMargin, true);
});

test("plan normalization fails closed to FREE", () => {
  assert.equal(normalizePlanCode("FREE"), "free");
  assert.equal(normalizePlanCode(" Pro "), "pro");
  assert.equal(normalizePlanCode("BUSINESS"), "business");
  for (const invalid of [undefined, null, "", "enterprise", "admin", 42, {}]) {
    assert.equal(normalizePlanCode(invalid), "free");
  }
});

test("limit boundary and over-limit cases are enforced", () => {
  const cases = [
    ["free", 5, 20, true], ["free", 6, 20, false], ["free", 5, 21, false],
    ["pro", 200, 1000, true], ["pro", 201, 1000, false], ["pro", 200, 1001, false],
    ["business", 5000, 10000, true], ["business", 5001, 10000, false], ["business", 5000, 10001, false]
  ];
  for (const [plan, products, history, expected] of cases) {
    assert.equal(isWithinPlanLimits(plan, products, history), expected, plan + " " + products + "/" + history);
  }
  for (const [products, history] of [[-1, 0], [0, -1], [1.5, 0], [0, 2.5], [NaN, 0], [0, Infinity]]) {
    assert.equal(isWithinPlanLimits("business", products, history), false);
  }
});
