import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../index.html", import.meta.url), "utf8");

test("browser data keys are namespaced per authenticated account", () => {
  assert.match(html, /const PRODUCT_KEY_BASE='gde_pribyl_mp_products_v04'/);
  assert.match(html, /HISTORY_KEY_BASE='gde_pribyl_mp_history_v04'/);
  assert.match(html, /DELETED_KEY_BASE='gde_pribyl_mp_deleted_v1'/);
  assert.match(html, /const next=userId===null\|\|userId===undefined\?'guest':'user_'\+String\(userId\)/);
  assert.match(html, /PRODUCT_KEY=PRODUCT_KEY_BASE\+suffix;HISTORY_KEY=HISTORY_KEY_BASE\+suffix/);
  assert.match(html, /DELETED_KEY=DELETED_KEY_BASE\+suffix/);
  assert.match(html, /WB_COMMISSION_KEY=WB_COMMISSION_KEY_BASE\+suffix;WB_BOX_KEY=WB_BOX_KEY_BASE\+suffix/);
});

test("account switching restores only that profile's local data", () => {
  assert.match(html, /setStorageScope\(accountUser\?\.id\?\?null\)/);
  assert.match(html, /setStorageScope\(null\);renderRecords\(\)/);
  assert.match(html, /recordsPanel\.style\.display='none'/);
  assert.match(html, /loadMarketplaceConnections/);
  assert.match(html, /marketplaceLoadGeneration/);
  assert.match(html, /generation!==marketplaceLoadGeneration/);
  const scopeSwitch = html.slice(html.indexOf("function setStorageScope"), html.indexOf("const parseWBNumber"));
  assert.ok(scopeSwitch.indexOf("marketplaceLoadGeneration++") < scopeSwitch.indexOf("storageScope=next"));
  assert.match(scopeSwitch, /marketplaceState\.wildberries=null;marketplaceState\.ozon=null;ozonDemoActive=false/);
  assert.match(scopeSwitch, /renderMarketplaceState\(\)/);
  assert.match(html, /recordsPanel\.style\.display='';renderRecords\(\)/);
});


test("backup restore validates size, shape, quotas and calculator values before writing", () => {
  assert.match(html, /if\(file\.size>1800000\)/);
  assert.match(html, /new TextEncoder\(\)\.encode\(raw\)\.length>1800000/);
  assert.match(html, /!\[1,BACKUP_VERSION\]\.includes\(data\.backupVersion\)/);
  assert.match(html, /data\.products\.length>limits\.products\|\|data\.history\.length>limits\.history/);
  assert.match(html, /Object\.hasOwn\(item\.values,id\)/);
  assert.match(html, /item\.values\[id\]\.length<=100/);
});

test("backup restore rolls back all local datasets if any storage write fails", () => {
  const restore = html.slice(html.indexOf("el('importData').addEventListener"), html.indexOf("function mergeUnique"));
  assert.ok(restore.indexOf("previousProducts=localStorage.getItem(PRODUCT_KEY)") < restore.indexOf("localStorage.setItem(PRODUCT_KEY,JSON.stringify(data.products))"));
  assert.ok(restore.indexOf("localStorage.setItem(PRODUCT_KEY,JSON.stringify(data.products))") < restore.indexOf("localStorage.setItem(HISTORY_KEY,JSON.stringify(data.history))"));
  assert.match(restore, /previousProducts===null\?localStorage\.removeItem\(PRODUCT_KEY\):localStorage\.setItem\(PRODUCT_KEY,previousProducts\)/);
  assert.match(restore, /previousHistory===null\?localStorage\.removeItem\(HISTORY_KEY\):localStorage\.setItem\(HISTORY_KEY,previousHistory\)/);
  assert.match(restore, /previousDeleted===null\?localStorage\.removeItem\(DELETED_KEY\):localStorage\.setItem\(DELETED_KEY,previousDeleted\)/);
});


test("cloud sync deduplicates records regardless of JSON object key order", () => {
  const sync = html.slice(html.indexOf("function stableSerialize"), html.indexOf("async function syncAccount"));
  assert.match(sync, /Object\.keys\(value\)\.sort\(\)/);
  assert.match(sync, /map\.set\(stableSerialize\(item\),item\)/);
});
