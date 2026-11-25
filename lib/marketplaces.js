import crypto from "node:crypto";

export class MarketplaceApiError extends Error {
  constructor(message, status = 502) {
    super(message);
    this.name = "MarketplaceApiError";
    this.status = status;
  }
}

export function parseEncryptionKey(value = process.env.MARKETPLACE_ENCRYPTION_KEY) {
  const raw = String(value || "").trim();
  if (!raw) throw new Error("MARKETPLACE_ENCRYPTION_KEY is not configured.");
  const key = /^[a-f0-9]{64}$/i.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
  if (key.length !== 32) throw new Error("MARKETPLACE_ENCRYPTION_KEY must encode exactly 32 bytes.");
  return key;
}

export function encryptCredentials(credentials, keyValue) {
  const key = Buffer.isBuffer(keyValue) ? keyValue : parseEncryptionKey(keyValue);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(credentials), "utf8"), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64"),
    nonce: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64")
  };
}

export function decryptCredentials(record, keyValue) {
  const key = Buffer.isBuffer(keyValue) ? keyValue : parseEncryptionKey(keyValue);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(record.nonce, "base64"));
  decipher.setAuthTag(Buffer.from(record.authTag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(record.ciphertext, "base64")),
    decipher.final()
  ]).toString("utf8");
  return JSON.parse(plaintext);
}

export function normalizeMarketplaceCredentials(marketplace, body = {}) {
  if (marketplace === "wildberries") {
    const token = String(body.token || "").trim();
    if (token.length < 20 || token.length > 4096) throw new MarketplaceApiError("Укажи действующий API-токен Wildberries.", 400);
    return { token };
  }
  if (marketplace === "ozon") {
    const clientId = String(body.clientId || "").trim();
    const apiKey = String(body.apiKey || "").trim();
    if (!/^\d{1,32}$/.test(clientId) || apiKey.length < 20 || apiKey.length > 4096) {
      throw new MarketplaceApiError("Проверь Client-Id и API-ключ Ozon.", 400);
    }
    return { clientId, apiKey };
  }
  throw new MarketplaceApiError("Неизвестный маркетплейс.", 404);
}

async function requestJson(fetcher, url, options, provider) {
  let response;
  try {
    response = await fetcher(url, { ...options, signal: AbortSignal.timeout(15000) });
  } catch {
    throw new MarketplaceApiError(provider + ": не удалось связаться с API. Проверь доступность сервиса и повтори позже.", 502);
  }
  let data;
  let invalidJson = false;
  try { data = await response.json(); } catch { invalidJson = true; }
  if (!response.ok) {
    const status = response.status === 401 || response.status === 403 ? 400 : 502;
    const message = response.status === 401 || response.status === 403
      ? provider + ": ключ отклонён или у него недостаточно прав."
      : response.status === 429
        ? provider + ": превышен лимит запросов. Повтори позже."
        : provider + ": API вернул ошибку. Проверь настройки ключа и повтори позже.";
    throw new MarketplaceApiError(message, status);
  }
  // A successful HTTP status does not mean the provider returned a complete
  // JSON document. Never interpret malformed, null, or primitive payloads as
  // an empty catalogue and overwrite the last known-good snapshot.
  if (invalidJson || data === null || typeof data !== "object") {
    throw new MarketplaceApiError(provider + ": API вернул некорректный ответ. Данные не обновлены.");
  }
  return data;
}

const numberOrNull = value => {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(String(value).replace(",", "."));
  return Number.isFinite(number) ? number : null;
};

function normalizeWb(commissionData, boxData) {
  const commissionRows = Array.isArray(commissionData) ? commissionData : Array.isArray(commissionData?.report) ? commissionData.report : [];
  const warehouseRows = boxData?.response?.data?.warehouseList || boxData?.data?.warehouseList || [];
  const categories = commissionRows.map(row => ({
    subjectID: row.subjectID ?? null,
    parentID: row.parentID ?? null,
    parentName: String(row.parentName || ""),
    subjectName: String(row.subjectName || ""),
    kgvpMarketplace: numberOrNull(row.kgvpMarketplace),
    kgvpSupplier: numberOrNull(row.kgvpSupplier)
  }));
  const warehouses = warehouseRows.map(row => ({
    warehouseName: String(row.warehouseName || ""),
    geoName: String(row.geoName || ""),
    boxDeliveryBase: numberOrNull(row.boxDeliveryBase),
    boxDeliveryLiter: numberOrNull(row.boxDeliveryLiter),
    boxDeliveryMarketplaceBase: numberOrNull(row.boxDeliveryMarketplaceBase),
    boxDeliveryMarketplaceLiter: numberOrNull(row.boxDeliveryMarketplaceLiter),
    boxStorageBase: numberOrNull(row.boxStorageBase),
    boxStorageLiter: numberOrNull(row.boxStorageLiter),
    boxDeliveryCoefExpr: numberOrNull(row.boxDeliveryCoefExpr),
    boxDeliveryMarketplaceCoefExpr: numberOrNull(row.boxDeliveryMarketplaceCoefExpr)
  }));
  if (!categories.length || !warehouses.length) {
    throw new MarketplaceApiError("Wildberries вернул неполные тарифные данные. Проверь права токена «Тарифы».");
  }
  return {
    fetchedAt: new Date().toISOString(),
    currency: String(boxData?.response?.data?.currency || boxData?.data?.currency || "RUB"),
    nextTariffDate: boxData?.response?.data?.dtNextBox || boxData?.data?.dtNextBox || null,
    categories,
    warehouses
  };
}

async function fetchWildberries(credentials, fetcher) {
  const headers = { Authorization: credentials.token };
  const date = new Date().toISOString().slice(0, 10);
  const [commissionData, boxData] = await Promise.all([
    requestJson(fetcher, "https://common-api.wildberries.ru/api/v1/tariffs/commission", { method: "GET", headers }, "Wildberries"),
    requestJson(fetcher, "https://common-api.wildberries.ru/api/v1/tariffs/box?date=" + date, { method: "GET", headers }, "Wildberries")
  ]);
  return normalizeWb(commissionData, boxData);
}

function requireOzonPage(data, cursorField, section) {
  const result = data?.result && typeof data.result === "object" && !Array.isArray(data.result)
    ? data.result
    : data;
  if (!result || typeof result !== "object" || Array.isArray(result)
      || !Array.isArray(result.items) || typeof result[cursorField] !== "string") {
    throw new MarketplaceApiError("Ozon: API вернул неполную структуру " + section + ". Данные не обновлены.");
  }
  return result;
}

async function fetchOzon(credentials, fetcher) {
  const headers = {
    "Client-Id": credentials.clientId,
    "Api-Key": credentials.apiKey,
    "Content-Type": "application/json"
  };

  // Ozon returns product-list pages through result.last_id. Keep paging until
  // the provider returns an empty cursor; reject a repeated cursor rather than
  // silently saving an incomplete catalogue.
  const productRows = [];
  const seenProductCursors = new Set();
  let lastId = "";
  for (let page = 0; page < 100; page += 1) {
    const productsData = await requestJson(fetcher, "https://api-seller.ozon.ru/v3/product/list", {
      method: "POST", headers,
      body: JSON.stringify({ filter: { visibility: "ALL" }, last_id: lastId, limit: 1000 })
    }, "Ozon");
    const result = requireOzonPage(productsData, "last_id", "каталога");
    const rows = result.items;
    if (rows.some(row => !row || typeof row !== "object" || !/^\d+$/.test(String(row.product_id ?? row.id ?? "")))) {
      throw new MarketplaceApiError("Ozon: каталог содержит товар без корректного ID. Данные не обновлены.");
    }
    productRows.push(...rows);
    const nextLastId = result.last_id;
    if (!nextLastId) break;
    if (nextLastId === lastId || seenProductCursors.has(nextLastId)) {
      throw new MarketplaceApiError("Ozon вернул повторяющийся курсор каталога. Обновление остановлено, чтобы не сохранить неполные данные.");
    }
    seenProductCursors.add(nextLastId);
    lastId = nextLastId;
    if (page === 99) {
      throw new MarketplaceApiError("Каталог Ozon превышает безопасный предел синхронизации в 100 000 товаров. Данные не сохранены как полный каталог.");
    }
  }

  const productIds = [...new Set(productRows
    .map(row => String(row.product_id ?? row.id ?? ""))
    .filter(id => /^\d+$/.test(id)))];
  if (!productIds.length) {
    return { fetchedAt: new Date().toISOString(), products: 0, items: [], note: "В кабинете пока не найдено товаров для получения индивидуальных комиссий." };
  }

  const priceRows = [];
  // The prices method accepts up to 1000 product IDs per request and may
  // itself paginate with cursor. Process batches sequentially to avoid bursts.
  for (let offset = 0; offset < productIds.length; offset += 1000) {
    const batch = productIds.slice(offset, offset + 1000);
    const seenPriceCursors = new Set();
    let cursor = "";
    for (let page = 0; page < 100; page += 1) {
      const pricesData = await requestJson(fetcher, "https://api-seller.ozon.ru/v5/product/info/prices", {
        method: "POST", headers,
        body: JSON.stringify({ cursor, filter: { product_id: batch, visibility: "ALL" }, limit: 1000 })
      }, "Ozon");
      const result = requireOzonPage(pricesData, "cursor", "цен");
      const rows = result.items;
      if (rows.some(row => !row || typeof row !== "object" || !/^\d+$/.test(String(row.product_id ?? "")))) {
        throw new MarketplaceApiError("Ozon: данные цен содержат товар без корректного ID. Данные не обновлены.");
      }
      priceRows.push(...rows);
      const nextCursor = result.cursor;
      if (!nextCursor) break;
      if (nextCursor === cursor || seenPriceCursors.has(nextCursor)) {
        throw new MarketplaceApiError("Ozon вернул повторяющийся курсор цен. Обновление остановлено, чтобы не сохранить неполные данные.");
      }
      seenPriceCursors.add(nextCursor);
      cursor = nextCursor;
      if (page === 99) {
        throw new MarketplaceApiError("Ozon не завершил выдачу цен за 100 страниц. Данные не сохранены как полный каталог.");
      }
    }
  }

  const items = priceRows.map(row => {
    const commissions = row.commissions || row.commission || {};
    return {
      productId: String(row.product_id ?? ""),
      offerId: String(row.offer_id ?? ""),
      price: numberOrNull(row.price?.price ?? row.price),
      currency: String(row.price?.currency_code || row.currency_code || "RUB"),
      volumeWeight: numberOrNull(row.volume_weight),
      acquiring: numberOrNull(row.acquiring),
      commissions: {
        salesPercentFbo: numberOrNull(commissions.sales_percent_fbo),
        salesPercentFbs: numberOrNull(commissions.sales_percent_fbs),
        salesPercentRfbs: numberOrNull(commissions.sales_percent_rfbs),
        fboDeliveryToCustomer: numberOrNull(commissions.fbo_deliv_to_customer_amount),
        fboDirectFlowMin: numberOrNull(commissions.fbo_direct_flow_trans_min_amount),
        fboDirectFlowMax: numberOrNull(commissions.fbo_direct_flow_trans_max_amount),
        fboReturn: numberOrNull(commissions.fbo_return_flow_amount),
        fbsFirstMileMin: numberOrNull(commissions.fbs_first_mile_min_amount),
        fbsFirstMileMax: numberOrNull(commissions.fbs_first_mile_max_amount),
        fbsDirectFlowMin: numberOrNull(commissions.fbs_direct_flow_trans_min_amount),
        fbsDirectFlowMax: numberOrNull(commissions.fbs_direct_flow_trans_max_amount),
        fbsDeliveryToCustomer: numberOrNull(commissions.fbs_deliv_to_customer_amount),
        fbsReturn: numberOrNull(commissions.fbs_return_flow_amount)
      }
    };
  });
  return { fetchedAt: new Date().toISOString(), products: productIds.length, items };
}
export async function fetchMarketplaceSnapshot(marketplace, credentials, fetcher = fetch) {
  if (marketplace === "wildberries") return fetchWildberries(credentials, fetcher);
  if (marketplace === "ozon") return fetchOzon(credentials, fetcher);
  throw new MarketplaceApiError("Неизвестный маркетплейс.", 404);
}
