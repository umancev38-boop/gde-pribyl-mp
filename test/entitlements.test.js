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
});

test("plan normalization fails closed to FREE", () => {
  assert.equal(normalizePlanCode("BUSINESS"), "business");
  assert.equal(normalizePlanCode("pro"), "pro");
  assert.equal(normalizePlanCode("unknown"), "free");
  assert.equal(normalizePlanCode(null), "free");
});

test("limit boundary and over-limit cases are enforced", () => {
  assert.equal(isWithinPlanLimits("free", 5, 20), true);
  assert.equal(isWithinPlanLimits("free", 6, 20), false);
  assert.equal(isWithinPlanLimits("free", 5, 21), false);
  assert.equal(isWithinPlanLimits("pro", 200, 1000), true);
  assert.equal(isWithinPlanLimits("pro", 201, 1000), false);
  assert.equal(isWithinPlanLimits("business", 5000, 10000), true);
  assert.equal(isWithinPlanLimits("business", 5001, 10000), false);
  assert.equal(isWithinPlanLimits("business", 5000, 10001), false);
  assert.equal(isWithinPlanLimits("free", -1, 0), false);
  assert.equal(isWithinPlanLimits("free", 1.5, 0), false);
});
