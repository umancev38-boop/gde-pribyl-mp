import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";

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
