import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../index.html", import.meta.url), "utf8");

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

test("API requests target the deployed backend and include session cookies", () => {
  assert.match(html, /const API_URL='https:\/\/gde-pribyl-mp-api\.onrender\.com';/);
  assert.match(html, /credentials:'include'/);
  assert.match(html, /cache:'no-store'/);
});
