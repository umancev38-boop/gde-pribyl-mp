import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../index.html", import.meta.url), "utf8");

test("browser data keys are namespaced per authenticated account", () => {
  assert.match(html, /const PRODUCT_KEY_BASE='gde_pribyl_mp_products_v04'/);
  assert.match(html, /HISTORY_KEY_BASE='gde_pribyl_mp_history_v04'/);
  assert.match(html, /const next=userId===null\|\|userId===undefined\?'guest':'user_'\+String\(userId\)/);
  assert.match(html, /PRODUCT_KEY=PRODUCT_KEY_BASE\+suffix;HISTORY_KEY=HISTORY_KEY_BASE\+suffix/);
  assert.match(html, /WB_COMMISSION_KEY=WB_COMMISSION_KEY_BASE\+suffix;WB_BOX_KEY=WB_BOX_KEY_BASE\+suffix/);
});

test("account switching restores only that profile's local data", () => {
  assert.match(html, /setStorageScope\(accountUser\?\.id\?\?null\)/);
  assert.match(html, /setStorageScope\(null\);renderRecords\(\)/);
  assert.match(html, /recordsPanel\.style\.display='none'/);
  assert.match(html, /recordsPanel\.style\.display='';renderRecords\(\)/);
});
