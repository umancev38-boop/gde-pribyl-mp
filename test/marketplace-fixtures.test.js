import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fetchMarketplaceSnapshot } from "../../lib/marketplaces.js";

const fixture = async name => JSON.parse(await readFile(new URL("./fixtures/marketplaces/" + name, import.meta.url), "utf8"));
const ok = data => ({ ok: true, status: 200, json: async () => data });

test("WB contract simulator uses both tariff endpoints and normalizes fixture data", async () => {
  const commission = await fixture("wb-commission.json");
  const box = await fixture("wb-box.json");
  const calls = [];
  const token = "synthetic-wb-token-never-a-real-credential";
  const result = await fetchMarketplaceSnapshot("wildberries", { token }, async (url, options) => {
    calls.push({ url, options });
    return ok(url.includes("/commission") ? commission : box);
  });

  assert.equal(calls.length, 2);
  assert.ok(calls.some(call => call.url.includes("/api/v1/tariffs/commission")));
  assert.ok(calls.some(call => call.url.includes("/api/v1/tariffs/box?date=")));
  for (const call of calls) assert.equal(call.options.headers.Authorization, token);
  assert.equal(result.categories.length, 2);
  assert.equal(result.warehouses.length, 2);
  assert.equal(result.categories[0].kgvpMarketplace, 15.5);
  assert.equal(result.warehouses[0].boxDeliveryBase, 50);
  assert.equal(result.currency, "RUB");
  assert.equal(JSON.stringify(result).includes(token), false);
});

test("Ozon contract simulator follows product and price cursors across fixture pages", async () => {
  const productPages = [await fixture("ozon-products-page-1.json"), await fixture("ozon-products-page-2.json")];
  const pricePages = [await fixture("ozon-prices-page-1.json"), await fixture("ozon-prices-page-2.json")];
  const calls = [];
  const credentials = { clientId: "123456", apiKey: "synthetic-ozon-api-key-never-real" };
  const result = await fetchMarketplaceSnapshot("ozon", credentials, async (url, options) => {
    const body = JSON.parse(options.body);
    calls.push({ url, options, body });
    if (url.endsWith("/v3/product/list")) return ok(productPages[body.last_id ? 1 : 0]);
    return ok(pricePages[body.cursor ? 1 : 0]);
  });

  assert.equal(calls.length, 4);
  assert.equal(calls[0].options.headers["Client-Id"], credentials.clientId);
  assert.equal(calls[0].options.headers["Api-Key"], credentials.apiKey);
  assert.equal(calls[1].body.last_id, "synthetic-cursor-2");
  assert.equal(calls[2].body.filter.product_id.length, 3);
  assert.equal(calls[3].body.cursor, "synthetic-prices-2");
  assert.equal(result.products, 3);
  assert.equal(result.items.length, 3);
  assert.equal(result.items[0].price, 1290);
  assert.equal(result.items[0].commissions.salesPercentFbo, 15.5);
  assert.equal(result.items[0].commissions.fboDeliveryToCustomer, 82.5);
  assert.equal(JSON.stringify(result).includes(credentials.apiKey), false);
});

test("provider authentication and rate-limit failures are sanitized", async t => {
  for (const [status, message] of [[401, /ключ отклонён/], [403, /ключ отклонён/], [429, /лимит запросов/], [500, /API вернул ошибку/]]) {
    await t.test("HTTP " + status, async () => {
      await assert.rejects(
        fetchMarketplaceSnapshot("wildberries", { token: "synthetic-token" }, async () => ({
          ok: false, status, json: async () => ({ error: "sensitive provider detail" })
        })),
        error => {
          assert.match(error.message, message);
          assert.equal(error.message.includes("sensitive provider detail"), false);
          assert.equal(error.message.includes("synthetic-token"), false);
          return true;
        }
      );
    });
  }
});

test("invalid upstream JSON is handled as an incomplete provider response", async () => {
  await assert.rejects(
    fetchMarketplaceSnapshot("wildberries", { token: "synthetic-token" }, async () => ({
      ok: true, status: 200, json: async () => ({})
    })),
    /неполные тарифные данные/
  );
});
