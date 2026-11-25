import test from "node:test";
import assert from "node:assert/strict";
import { fetchMarketplaceSnapshot } from "../lib/marketplaces.js";

const credentials = { clientId: "123", apiKey: "synthetic-ozon-key-never-real" };
const ok = data => ({ ok: true, status: 200, json: async () => data });

test("Ozon splits price requests into batches of at most 1000 product IDs", async () => {
  const productRows = Array.from({ length: 1001 }, (_, index) => ({ product_id: index + 1, offer_id: "DEMO-" + (index + 1) }));
  const priceBatches = [];
  const result = await fetchMarketplaceSnapshot("ozon", credentials, async (url, options) => {
    const body = JSON.parse(options.body);
    if (url.endsWith("/v3/product/list")) return ok({ result: { items: productRows, last_id: "" } });
    priceBatches.push(body.filter.product_id);
    return ok({ result: { items: [], cursor: "" } });
  });

  assert.deepEqual(priceBatches.map(batch => batch.length), [1000, 1]);
  assert.equal(result.products, 1001);
  assert.deepEqual(result.items, []);
});

test("Ozon repeated price cursor fails instead of returning an incomplete snapshot", async () => {
  let priceCalls = 0;
  const error = await assert.rejects(
    fetchMarketplaceSnapshot("ozon", credentials, async (url, options) => {
      const body = JSON.parse(options.body);
      if (url.endsWith("/v3/product/list")) {
        return ok({ result: { items: [{ product_id: 12345 }], last_id: "" } });
      }
      priceCalls += 1;
      return ok({ result: { items: [], cursor: "stuck-cursor" } });
    }),
    /повторяющийся курсор цен/
  );
  assert.equal(priceCalls, 2);
  assert.ok(error instanceof Error);
});

test("Ozon empty catalogue does not issue price requests", async () => {
  let priceCalls = 0;
  const result = await fetchMarketplaceSnapshot("ozon", credentials, async url => {
    if (url.endsWith("/v3/product/list")) return ok({ result: { items: [], last_id: "" } });
    priceCalls += 1;
    return ok({ result: { items: [], cursor: "" } });
  });
  assert.equal(result.products, 0);
  assert.deepEqual(result.items, []);
  assert.equal(priceCalls, 0);
});
