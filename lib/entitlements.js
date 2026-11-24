export const PLAN_ENTITLEMENTS = Object.freeze({
  free: Object.freeze({ products: 5, history: 20, analytics: false, csvExport: false, targetMargin: false, teamSeats: 1 }),
  pro: Object.freeze({ products: 200, history: 1000, analytics: false, csvExport: false, targetMargin: true, teamSeats: 1 }),
  business: Object.freeze({ products: 5000, history: 10000, analytics: true, csvExport: true, targetMargin: true, teamSeats: 5 })
});

export function normalizePlanCode(value) {
  const code = String(value || "").trim().toLowerCase();
  if (code === "business") return "business";
  if (code === "pro") return "pro";
  return "free";
}

export function isWithinPlanLimits(planCode, products, history) {
  const limits = PLAN_ENTITLEMENTS[normalizePlanCode(planCode)];
  return Number.isInteger(products) && Number.isInteger(history) &&
    products >= 0 && history >= 0 &&
    products <= limits.products && history <= limits.history;
}
