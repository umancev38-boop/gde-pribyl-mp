import test from "node:test";
import assert from "node:assert/strict";
import { PLAN_ENTITLEMENTS, normalizePlanCode, isWithinPlanLimits } from "../lib/entitlements.js";

test("published product and calculation limits remain stable", () => {
  assert.deepEqual(
    Object.fromEntries(Object.entries(PLAN_ENTITLEMENTS).map(([key, value]) => [key, [value.products, value.history]])),
    { free: [5, 20], pro: [200, 1000], business: [5000, 10000] }
  );
});

test("feature access matches the published plans", () => {
  assert.equal(PLAN_ENTITLEMENTS.free.targetMargin, false);
  assert.equal(PLAN_ENTITLEMENTS.pro.targetMargin, true);
  assert.equal(PLAN_ENTITLEMENTS.pro.analytics, false);
  assert.equal(PLAN_ENTITLEMENTS.business.analytics, true);
  assert.equal(PLAN_ENTITLEMENTS.business.csvExport, true);
  assert.equal(PLAN_ENTITLEMENTS.free.csvExport, false);
  assert.equal(PLAN_ENTITLEMENTS.pro.csvExport, false);
});

test("plan normalization fails closed to FREE", () => {
  assert.equal(normalizePlanCode("BUSINESS"), "business");
  assert.equal(normalizePlanCode(" Pro "), "pro");
  assert.equal(normalizePlanCode("FREE"), "free");
  for (const invalid of [undefined, null, "", "unknown", "enterprise", "admin", 42, {}]) {
    assert.equal(normalizePlanCode(invalid), "free");
  }
});

test("limit boundary and over-limit cases are enforced", () => {
  const cases = [
    ["free", 5, 20, true], ["free", 6, 20, false], ["free", 5, 21, false],
    ["pro", 200, 1000, true], ["pro", 201, 1000, false], ["pro", 200, 1001, false],
    ["business", 5000, 10000, true], ["business", 5001, 10000, false], ["business", 5000, 10001, false]
  ];
  for (const [plan, products, history, expected] of cases) {
    assert.equal(isWithinPlanLimits(plan, products, history), expected, plan + " " + products + "/" + history);
  }
  for (const [products, history] of [[-1, 0], [0, -1], [1.5, 0], [0, 2.5], [NaN, 0], [0, Infinity]]) {
    assert.equal(isWithinPlanLimits("business", products, history), false);
  }
});
