// api/index.js (Vercel Node Serverless)
// 安全版: URL解析を極力ガードし、例外はすべてJSONで返す

const JQ_BASE = "https://api.jquants.com/v1";

// ===== ENV =====
const {
  JQ_REFRESH_TOKEN: RAW_RT,
  JQ_EMAIL,
  JQ_PASSWORD,
  PROXY_BEARER,
} = process.env;
const ENV_REFRESH_TOKEN = (RAW_RT || "").trim();

// ===== In-memory cache =====
let cache = {
  idToken: null,
  idTokenExpAt: 0,         // epoch ms
  refreshToken: ENV_REFRESH_TOKEN || null,
  resp: new Map(),         // key -> { expAt, json }
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function safeJson(res, status, body) {
  try {
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify(body));
  } catch (e) {
    // ここでさらに失敗することはほぼ無いが、念のため
    res.statusCode = 500;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Internal Server Error");
  }
}

function requireProxyBearer(req) {
  if (!PROXY_BEARER) return true; // 鍵未設定ならスキップ
  try {
    const h = req.headers?.["authorization"] || "";
    const got = h.startsWith("Bearer ") ? h.slice(7) : "";
    return got && got === PROXY_BEARER;
  } catch {
    return false;
  }
}

// ---- J-Quants fetch wrapper ----
async function jqFetch(path, params = {}, idToken) {
  const url = new URL(JQ_BASE + path);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  const headers = idToken ? { Authorization: `Bearer ${idToken}` } : {};
  let res = await fetch(url.toString(), { headers });
  if (res.status === 429) {
    await sleep(800);
    res = await fetch(url.toString(), { headers });
  }
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`JQ ${res.status}: ${txt || res.statusText}`);
  }
  return res.json();
}

// ---- Auth helpers ----
async function getRefreshTokenByPassword() {
  if (!JQ_EMAIL || !JQ_PASSWORD) {
    throw new Error("Missing JQ_EMAIL/JQ_PASSWORD for refresh-token bootstrap.");
  }
  const res = await fetch(`${JQ_BASE}/token/auth_user`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mailaddress: JQ_EMAIL, password: JQ_PASSWORD }),
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`auth_user failed: ${res.status} ${txt}`);
  }
  const data = await res.json();
  if (!data.refreshToken) throw new Error("auth_user returned no refreshToken");
  return String(data.refreshToken).trim();
}

// refresh -> id (POST が正)
// 公式仕様では refreshTokenはURLクエリで渡す（URLSearchParamsで確実にエンコード）
async function getIdTokenByRefresh(refreshToken) {
  const qs = new URLSearchParams({ refreshtoken: refreshToken });
  const url = `${JQ_BASE}/token/auth_refresh?${qs.toString()}`;
  const res = await fetch(url, { method: "POST" });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`auth_refresh failed: ${res.status} ${txt}`);
  }
  const data = await res.json();
  if (!data.idToken) throw new Error("auth_refresh returned no idToken");
  return data.idToken;
}

async function ensureIdToken() {
  const now = Date.now();
  if (cache.idToken && cache.idTokenExpAt - now > 60_000) return cache.idToken;
  if (!cache.refreshToken) {
    cache.refreshToken = ENV_REFRESH_TOKEN || (await getRefreshTokenByPassword());
  }
  const idToken = await getIdTokenByRefresh(cache.refreshToken);
  cache.idToken = idToken;
  cache.idTokenExpAt = now + 24 * 60 * 60_000; // 24h想定
  return idToken;
}

// ---- tiny resp cache ----
function getCached(key) {
  const hit = cache.resp.get(key);
  return hit && hit.expAt > Date.now() ? hit.json : null;
}
function setCached(key, jsonObj, ttlMs) {
  cache.resp.set(key, { expAt: Date.now() + ttlMs, json: jsonObj });
}

// ---- Handlers ----
async function handleHealth(_req, res) {
  safeJson(res, 200, { ok: true, ts: new Date().toISOString() });
}

async function handleAuthRefresh(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    if (!cache.refreshToken) {
      cache.refreshToken = ENV_REFRESH_TOKEN || (await getRefreshTokenByPassword());
    }
    const idToken = await getIdTokenByRefresh(cache.refreshToken);
    cache.idToken = idToken;
    cache.idTokenExpAt = Date.now() + 24 * 60 * 60_000;
    safeJson(res, 200, { idToken, expAt: cache.idTokenExpAt });
  } catch (e) {
    safeJson(res, 500, { error: String(e.message || e) });
  }
}

async function handleUniverseListed(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  const key = "universe:listed";
  const hit = getCached(key);
  if (hit) return safeJson(res, 200, hit);
  try {
    const idToken = await ensureIdToken();
    const data = await jqFetch("/listed/info", {}, idToken);
    setCached(key, data, 24 * 60 * 60_000);
    safeJson(res, 200, data);
  } catch (e) {
    safeJson(res, 500, { error: String(e.message || e) });
  }
}

function safeParseURL(req) {
  try {
    const raw = typeof req?.url === "string" ? req.url : "/";
    return new URL(raw, "http://localhost"); // ベース必須
  } catch {
    // フォールバック
    const u = new URL("http://localhost/");
    return u;
  }
}

// 置き換え：/api/prices/daily ハンドラ（安全版）
async function handlePricesDaily(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    const url = safeParseURL(req);
    const code = (url.searchParams.get("code") || "").trim();
    if (!code) return safeJson(res, 400, { error: "Missing code" });

    // 入力の正規化：数字のみ抽出 → YYYYMMDD
    const onlyDigits = (s) => (s || "").replace(/\D/g, "");
    let rawFrom = onlyDigits(url.searchParams.get("from"));
    let rawTo   = onlyDigits(url.searchParams.get("to"));

    // 未指定なら直近60日を補完（営業日≒暦60日で簡便）
    if (!rawTo) {
      rawTo = new Date().toISOString().slice(0,10).replace(/\D/g, ""); // yyyyMMdd
    }
    if (!rawFrom) {
      const d = new Date();
      d.setDate(d.getDate() - 60);
      rawFrom = d.toISOString().slice(0,10).replace(/\D/g, "");
    }

    // YYYYMMDD の簡易検証
    const isYYYYMMDD = (s) => /^\d{8}$/.test(s);
    if (!isYYYYMMDD(rawFrom) || !isYYYYMMDD(rawTo)) {
      return safeJson(res, 400, { error: "Invalid date format. Use YYYYMMDD." });
    }
    if (Number(rawFrom) > Number(rawTo)) {
      return safeJson(res, 400, { error: "`from` must be <= `to` (YYYYMMDD)" });
    }

    const cacheKey = `prices:daily:${code}:${rawFrom}:${rawTo}`;
    const hit = getCached(cacheKey);
    if (hit) return safeJson(res, 200, hit);

    const idToken = await ensureIdToken();
    const data = await jqFetch("/markets/prices/daily_quotes", { code, from: rawFrom, to: rawTo }, idToken);

    // 念のため基本構造検査（JQは daily_quotes 配列や data 配列で返ることがある）
    const rows = Array.isArray(data) ? data : (data.daily_quotes || data.data || []);
    if (!Array.isArray(rows)) {
      // JQ側の仕様変更やレスポンス異常時
      return safeJson(res, 502, { error: "Unexpected response from J-Quants", sample: data });
    }

    setCached(cacheKey, data, 5 * 60_000); // 5分キャッシュ
    return safeJson(res, 200, data);
  } catch (e) {
    return safeJson(res, 500, { error: String(e.message || e) });
  }
}



async function handleScreenLiquidity(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    const url = safeParseURL(req);
    const minVal   = Number(url.searchParams.get("min_avg_trading_value") || "100000000");
    const lookback = Number(url.searchParams.get("days") || "20");
    const market   = url.searchParams.get("market"); // Prime|Standard|Growth|All

    const idToken = await ensureIdToken();
    const uni = await jqFetch("/listed/info", {}, idToken);
    let list = Array.isArray(uni) ? uni : uni?.info || uni?.data || [];
    if (market && market !== "All") {
      const mkey = market.toLowerCase();
      list = list.filter((x) => (x.market || x.market_code || "").toString().toLowerCase().includes(mkey));
    }

    const end = new Date();
    const start = new Date(end.getTime() - 120 * 24 * 60 * 60_000);
    const to = end.toISOString().slice(0, 10);
    const from = start.toISOString().slice(0, 10);

    const sample = list.slice(0, Math.min(300, list.length));
    const out = [];
    for (const it of sample) {
      const code = it.code || it.Symbol || it.symbol || it.Code;
      if (!code) continue;
      let daily;
      try {
        daily = await jqFetch("/markets/prices/daily_quotes", { code, from, to }, idToken);
      } catch {
        continue;
      }
      const rows = Array.isArray(daily) ? daily : daily?.daily_quotes || daily?.data || [];
      if (!rows.length) continue;

      const recent = rows.slice(-lookback);
      if (!recent.length) continue;

      const avgVal =
        recent.reduce((acc, r) => {
          const c = Number(r.Close || r.close || r.endPrice || r.AdjustedClose || r.adjusted_close || 0);
          const v = Number(r.Volume || r.volume || r.turnoverVolume || 0);
          return acc + c * v;
        }, 0) / recent.length;

      if (avgVal >= minVal) {
        out.push({
          code,
          name: it.company_name || it.Name || it.companyName || "",
          market: it.market || it.Market || "",
          avg_trading_value: Math.round(avgVal),
        });
      }
    }

    out.sort((a, b) => b.avg_trading_value - a.avg_trading_value);
    safeJson(res, 200, { count: out.length, items: out });
  } catch (e) {
    safeJson(res, 500, { error: String(e.message || e) });
  }
}

// ---- Main handler (trailing slash吸収, GET/POST両対応) ----
export default async function handler(req, res) {
  try {
    // まずはパスだけ安全に取得
    const raw = typeof req?.url === "string" ? req.url : "/";
    const pathOnly = raw.split("?")[0].replace(/\/+$/, "");

    if (pathOnly === "/api/health") return handleHealth(req, res);

    if (pathOnly === "/api/auth/refresh" && (req.method === "POST" || req.method === "GET")) {
      return handleAuthRefresh(req, res);
    }

    if (pathOnly === "/api/universe/listed" && req.method === "GET") {
      return handleUniverseListed(req, res);
    }

    if (pathOnly === "/api/prices/daily" && req.method === "GET") {
      return handlePricesDaily(req, res);
    }

    if (pathOnly === "/api/screen/liquidity" && req.method === "GET") {
      return handleScreenLiquidity(req, res);
    }

    res.statusCode = 404;
    res.end("Not Found");
  } catch (e) {
    safeJson(res, 500, { error: String(e.message || e) });
  }
}
