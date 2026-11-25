import test from "node:test";
import assert from "node:assert/strict";
import {
  parseEncryptionKey, encryptCredentials, decryptCredentials,
  normalizeMarketplaceCredentials, fetchMarketplaceSnapshot
} from "../lib/marketplaces.js";

const key = "a".repeat(64);

test("encrypts credentials with authenticated AES-256-GCM and decrypts them", () => {
  const input = { clientId: "12345", apiKey: "secret-api-key-value-123456" };
  const encrypted = encryptCredentials(input, key);
  assert.notEqual(encrypted.ciphertext, JSON.stringify(input));
  assert.deepEqual(decryptCredentials(encrypted, key), input);
  assert.throws(() => decryptCredentials(encrypted, "b".repeat(64)));
});

test("rejects missing or incorrectly sized encryption keys", () => {
  assert.throws(() => parseEncryptionKey(""), /not configured/);
  assert.throws(() => parseEncryptionKey("abcd"), /32 bytes/);
});

test("validates provider credential formats and never accepts unknown providers", () => {
  assert.deepEqual(normalizeMarketplaceCredentials("wildberries", { token: "x".repeat(24) }), { token: "x".repeat(24) });
  assert.deepEqual(normalizeMarketplaceCredentials("ozon", { clientId: "123", apiKey: "x".repeat(24) }), { clientId: "123", apiKey: "x".repeat(24) });
  assert.throws(() => normalizeMarketplaceCredentials("ozon", { clientId: "abc", apiKey: "x".repeat(24) }));
  assert.throws(() => normalizeMarketplaceCredentials("other", {}));
});

test("Wildberries snapshot is normalized and contains only tariff fields", async () => {
  const fetcher = async url => ({
    ok: true, status: 200,
    json: async () => url.includes("/commission")
      ? [{ subjectID: 1, parentID: 2, parentName: "Дом", subjectName: "Посуда", kgvpMarketplace: "15", kgvpSupplier: "18", secret: "drop" }]
      : { response: { data: { currency: "руб", warehouseList: [{ warehouseName: "Коледино", boxDeliveryBase: "50", boxDeliveryLiter: "10", boxStorageBase: "1", boxStorageLiter: "0.2", token: "drop" }] } } }
  });
  const result = await fetchMarketplaceSnapshot("wildberries", { token: "x".repeat(24) }, fetcher);
  assert.equal(result.categories[0].kgvpMarketplace, 15);
  assert.equal(result.warehouses[0].warehouseName, "Коледино");
  assert.equal("secret" in result.categories[0], false);
  assert.equal("token" in result.warehouses[0], false);
});

test("Ozon snapshot paginates the full product catalogue and prices", async () => {
  const calls = [];
  const fetcher = async (url, options) => {
    const body = JSON.parse(options.body);
    calls.push({ url, body });
    return {
      ok: true, status: 200,
      json: async () => {
        if (url.endsWith("/v3/product/list")) {
          return body.last_id === ""
            ? { result: { items: [{ product_id: 987, offer_id: "SKU-1" }, { product_id: 988, offer_id: "SKU-2" }], last_id: "page-2" } }
            : { result: { items: [{ product_id: 989, offer_id: "SKU-3" }], last_id: "" } };
        }
        return body.cursor === ""
          ? { items: [{ product_id: 987, offer_id: "SKU-1", price: { price: "1290", currency_code: "RUB" }, commissions: { sales_percent_fbo: 15, fbo_deliv_to_customer_amount: 80, internal: "drop" } }], cursor: "prices-page-2" }
          : { items: [{ product_id: 988, offer_id: "SKU-2", price: { price: "990", currency_code: "RUB" }, commissions: { sales_percent_fbo: 12 } }, { product_id: 989, offer_id: "SKU-3", price: { price: "1590", currency_code: "RUB" }, commissions: { sales_percent_fbo: 17 } }], cursor: "" };
      }
    };
  };
  const result = await fetchMarketplaceSnapshot("ozon", { clientId: "123", apiKey: "x".repeat(24) }, fetcher);
  assert.equal(calls.length, 4, JSON.stringify(calls));
  assert.equal(calls[0].body.limit, 1000);
  assert.equal(calls[1].body.last_id, "page-2");
  assert.deepEqual(calls[2].body.filter.product_id, ["987", "988", "989"]);
  assert.equal(calls[3].body.cursor, "prices-page-2");
  assert.equal(result.products, 3);
  assert.equal(result.items.length, 3);
  assert.equal(result.items[0].commissions.salesPercentFbo, 15);
  assert.equal("internal" in result.items[0].commissions, false);
});

test("Ozon pagination rejects a repeated product cursor instead of saving partial data", async () => {
  const fetcher = async () => ({
    ok: true, status: 200,
    json: async () => ({ result: { items: [{ product_id: 1 }], last_id: "stuck" } })
  });
  await assert.rejects(
    fetchMarketplaceSnapshot("ozon", { clientId: "123", apiKey: "x".repeat(24) }, fetcher),
    /повторяющийся курсор/
  );
});

test("Ozon rejects malformed successful JSON instead of treating it as an empty catalogue", async () => {
  let calls = 0;
  await assert.rejects(
    fetchMarketplaceSnapshot("ozon", { clientId: "123", apiKey: "x".repeat(24) }, async () => {
      calls += 1;
      return { ok: true, status: 200, json: async () => { throw new SyntaxError("invalid JSON"); } };
    }),
    /некорректный ответ/
  );
  assert.equal(calls, 1);
});

test("marketplace API rejects null and primitive JSON payloads on successful responses", async () => {
  for (const payload of [null, "unexpected text", 42, true]) {
    await assert.rejects(
      fetchMarketplaceSnapshot("ozon", { clientId: "123", apiKey: "x".repeat(24) }, async () => ({
        ok: true, status: 200, json: async () => payload
      })),
      /некорректный ответ/
    );
  }
});
