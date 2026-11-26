import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
const server = await readFile(new URL("../server.js", import.meta.url), "utf8");
const blueprint = await readFile(new URL("../render.yaml", import.meta.url), "utf8");

test("mobile browsers receive a device-width viewport", () => {
  assert.match(html, /<meta name="viewport" content="width=device-width,initial-scale=1">/);
});

test("Android touch controls remain comfortably tappable", () => {
  assert.match(html, /input,select,textarea\{font-size:16px;min-height:44px;touch-action:manipulation\}/);
  assert.match(html, /button,\.fileButton\{min-height:44px;touch-action:manipulation/);
});

test("narrow screens use a single-column calculator and avoid horizontal page overflow", () => {
  assert.match(html, /@media\(max-width:480px\)\{[\s\S]*?\.fields\{grid-template-columns:minmax\(0,1fr\)\}/);
  assert.match(html, /body\{min-width:320px;overflow-x:hidden\}/);
  assert.match(html, /\.portfolioTableWrap\{max-width:100%;overscroll-behavior-x:contain;-webkit-overflow-scrolling:touch\}/);
});

test("Render frontend keeps using the separate API while same-origin hosts use local API paths", () => {
  assert.match(html, /const API_URL=location\.hostname==='gde-pribyl-mp\.onrender\.com'\?'https:\/\/gde-pribyl-mp-api\.onrender\.com':'';/);
  assert.match(html, /credentials:'include'/);
  assert.match(html, /cache:'no-store'/);
  assert.match(blueprint, /source: \/api\/\*/);
  assert.match(blueprint, /destination: https:\/\/gde-pribyl-mp-api\.onrender\.com\/api\/\*/);
});

test("same-origin runtime serves the frontend and permits only explicit or same-origin API requests", () => {
  assert.match(server, /app\.get\("\/", \(_req, res\) => res\.sendFile\(path\.join\(ROOT_DIR, "index\.html"\)\)\)/);
  assert.match(server, /app\.get\("\/legal\.html"/);
  assert.match(server, /origin === requestOrigin\(req\)/);
  assert.match(server, /if \(!isAllowedOrigin\(req\)\) return res\.sendStatus\(403\)/);
});
