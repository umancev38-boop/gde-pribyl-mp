import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const setup = readFileSync(new URL("../SMS_SETUP.md", import.meta.url), "utf8");

test("SMS sign-in warns legacy users before a new phone creates a separate profile", () => {
  assert.ok(html.includes("Если номер новый, будет создан отдельный аккаунт."));
  assert.ok(html.includes("сначала открой его с действующей сессией и привяжи телефон"));
  assert.ok(setup.includes("Вход по новому номеру без такой привязки создаёт отдельный профиль"));
});
