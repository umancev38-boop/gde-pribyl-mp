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

test("Ozon snapshot reads products then commissions through the current prices endpoint", async () => {
  const calls = [];
  const fetcher = async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) });
    return {
      ok: true, status: 200,
      json: async () => url.endsWith("/v3/product/list")
        ? { result: { items: [{ product_id: 987, offer_id: "SKU-1" }] } }
        : { items: [{ product_id: 987, offer_id: "SKU-1", price: { price: "1290", currency_code: "RUB" }, commissions: { sales_percent_fbo: 15, fbo_deliv_to_customer_amount: 80, internal: "drop" } }] }
    };
  };
  const result = await fetchMarketplaceSnapshot("ozon", { clientId: "123", apiKey: "x".repeat(24) }, fetcher);
  assert.equal(calls.length, 2);
  assert.match(calls[1].url, /v5\/product\/info\/prices$/);
  assert.equal(calls[1].body.filter.product_id[0], "987");
  assert.equal(result.items[0].commissions.salesPercentFbo, 15);
  assert.equal("internal" in result.items[0].commissions, false);
});
