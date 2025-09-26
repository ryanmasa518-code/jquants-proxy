// api/index.js
// Minimal J-Quants proxy for Vercel (Node runtime)
// - Handles ID token refresh from refresh token (or email/password -> refresh token)
// - Adds simple in-memory caching and rate-friendly backoff
// - Exposes a tiny set of endpoints for immediate screening use

export const config = { runtime: "nodejs18.x" }; // Vercel Node runtime

const JQ_BASE = "https://api.jquants.com/v1";

// ======== ENV VARS ========
// 必須（どちらか一方）:
// 1) JQ_REFRESH_TOKEN を直接設定
// 2) JQ_EMAIL + JQ_PASSWORD から refreshToken を取得して使う
const {
  JQ_REFRESH_TOKEN: ENV_REFRESH_TOKEN,
  JQ_EMAIL,
  JQ_PASSWORD,
  PROXY_BEARER, // (任意) このプロキシに付ける共通Bearer。Actionsで"Bearer xxx"として渡す
} = process.env;

// ======== In-Memory Cache (per instance) ========
let cache = {
  idToken: null,
  idTokenExpAt: 0, // epoch ms
  refreshToken: ENV_REFRESH_TOKEN || null,
  // simple response cache
  resp: new Map(), // key -> { expAt, json }
};

// Utility: wait
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// HTTP helpers
async function jqFetch(path, params = {}, idToken) {
  const url = new URL(JQ_BASE + path);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  });
  const res = await fetch(url.toString(), {
    headers: idToken ? { Authorization: `Bearer ${idToken}` } : {},
  });
  if (res.status === 429) {
    // simple backoff & single retry
    await sleep(800);
    const res2 = await fetch(url.toString(), {
      headers: idToken ? { Authorization: `Bearer ${idToken}` } : {},
    });
    if (!res2.ok) throw new Error(`JQ 429/Retry failed: ${res2.status}`);
    return res2.json();
  }
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`JQ ${res.status}: ${txt || res.statusText}`);
  }
  return res.json();
}

// Auth: get refresh token via email/password
async function getRefreshTokenByPassword() {
  if (!JQ_EMAIL || !JQ_PASSWORD) {
    throw new Error("Missing JQ_EMAIL/JQ_PASSWORD for refresh-token bootstrap.");
  }
  // NOTE: 実際の認証エンドポイントはJ-Quantsの仕様に従ってください。
  // 代表的なフロー: POST /v1/token/auth_user で { mailaddress, password } を送り refreshToken を得る。
  const res = await fetch(`${JQ_BASE}/token/auth_user`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mailaddress: JQ_EMAIL, password: JQ_PASSWORD }),
  });
  if (!res.ok) throw new Error(`auth_user failed: ${res.status}`);
  const data = await res.json();
  if (!data.refreshToken) throw new Error("auth_user returned no refreshToken");
  return data.refreshToken;
}

// Auth: exchange refresh -> id token
async function getIdTokenByRefresh(refreshToken) {
  // NOTE: 実際のリフレッシュ仕様に従ってください（一般的には GET /v1/token/auth_refresh?refreshtoken=...）
  const url = new URL(`${JQ_BASE}/token/auth_refresh`);
  url.searchParams.set("refreshtoken", refreshToken);
  const res = await fetch(url.toString());
  if (!res.ok) throw new Error(`auth_refresh failed: ${res.status}`);
  const data = await res.json();
  if (!data.idToken) throw new Error("auth_refresh returned no idToken");
  return data.idToken;
}

// IDトークンを取得（必要なら自動更新）
async function ensureIdToken() {
  const now = Date.now();
  // 余裕を持って早めに更新（14分）
  if (cache.idToken && cache.idTokenExpAt - now > 60_000) return cache.idToken;

  // refreshTokenがなければ、email/passwordから取得
  if (!cache.refreshToken) {
    cache.refreshToken = await getRefreshTokenByPassword();
  }
  const idToken = await getIdTokenByRefresh(cache.refreshToken);
  cache.idToken = idToken;
  cache.idTokenExpAt = now + 15 * 60_000; // 15分有効想定（実仕様に合わせて調整）
  return idToken;
}

// simple JSON response
function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

// Bearer check for this proxy (optional)
function requireProxyBearer(req) {
  if (!PROXY_BEARER) return true; // not enforced
  const h = req.headers["authorization"] || "";
  const got = h.startsWith("Bearer ") ? h.slice(7) : "";
  return got && got === PROXY_BEARER;
}

// Response cache key
function k(path, qs) {
  const p = new URL(reqOriginless(path, qs)); // for stable key
  return p.pathname + "?" + p.searchParams.toString();
}
function reqOriginless(path, qsObj) {
  const u = new URL("http://x" + path);
  Object.entries(qsObj || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") u.searchParams.set(k, String(v));
  });
  return u.toString().slice("http://x".length);
}
function getCached(key) {
  const hit = cache.resp.get(key);
  if (hit && hit.expAt > Date.now()) return hit.json;
  return null;
}
function setCached(key, json, ttlMs) {
  cache.resp.set(key, { expAt: Date.now() + ttlMs, json });
}

// Route handlers
async function handleHealth(req, res) {
  json(res, 200, { ok: true, ts: new Date().toISOString() });
}

async function handleAuthRefresh(req, res) {
  if (!requireProxyBearer(req)) return json(res, 401, { error: "Unauthorized" });
  try {
    // 明示更新
    if (!cache.refreshToken) {
      cache.refreshToken = ENV_REFRESH_TOKEN || (await getRefreshTokenByPassword());
    }
    const idToken = await getIdTokenByRefresh(cache.refreshToken);
    cache.idToken = idToken;
    cache.idTokenExpAt = Date.now() + 15 * 60_000;
    json(res, 200, { idToken, expAt: cache.idTokenExpAt });
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
}

async function handleUniverseListed(req, res) {
  if (!requireProxyBearer(req)) return json(res, 401, { error: "Unauthorized" });
  const key = "universe:listed";
  const hit = getCached(key);
  if (hit) return json(res, 200, hit);
  try {
    const idToken = await ensureIdToken();
    const data = await jqFetch("/listed/info", {}, idToken);
    // そのまま返してOK（必要なら {code, company_name, market, sector33,...} に整形）
    setCached(key, data, 24 * 60 * 60_000); // 1日キャッシュ
    json(res, 200, data);
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
}

async function handlePricesDaily(req, res, url) {
  if (!requireProxyBearer(req)) return json(res, 401, { error: "Unauthorized" });
  const code = url.searchParams.get("code");
  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");
  if (!code) return json(res, 400, { error: "Missing code" });

  const key = `prices:daily:${code}:${from || ""}:${to || ""}`;
  const hit = getCached(key);
  if (hit) return json(res, 200, hit);

  try {
    const idToken = await ensureIdToken();
    const data = await jqFetch("/markets/prices/daily_quotes", { code, from, to }, idToken);
    setCached(key, data, 5 * 60_000); // 5分キャッシュ
    json(res, 200, data);
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
}

// ===== Optional: まずは流動性スクリーニングの雛形 =====
async function handleScreenLiquidity(req, res, url) {
  if (!requireProxyBearer(req)) return json(res, 401, { error: "Unauthorized" });
  const minVal = Number(url.searchParams.get("min_avg_trading_value") || "100000000"); // 1億円
  const lookback = Number(url.searchParams.get("days") || "20");
  const market = url.searchParams.get("market"); // "Prime|Standard|Growth|All"

  try {
    // 1) universe
    const idToken = await ensureIdToken();
    const uni = await jqFetch("/listed/info", {}, idToken);
    let list = Array.isArray(uni) ? uni : uni?.info || uni?.data || [];
    if (market && market !== "All") {
      list = list.filter((x) => (x.market || x.market_code || "").toString().toLowerCase().includes(market.toLowerCase()));
    }

    // 2) 過去lookback日で平均売買代金を計算（Close*Volume）。APIコスト節約のため上位約2000件で打ち切るなども可
    const end = new Date();
    const start = new Date(end.getTime() - 120 * 24 * 60 * 60_000); // 最大でも約120日だけ取得してローカルで絞る
    const to = end.toISOString().slice(0, 10);
    const from = start.toISOString().slice(0, 10);

    const out = [];
    // 注意：API制限に配慮して、まずは先頭～数百件で試すなど、段階導入推奨
    // ここではデモ的に最大300件に制限
    const sample = list.slice(0, Math.min(300, list.length));

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
      // sell value = close * volume（出来高が株数、株価は円想定）
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

    // 降順ソート
    out.sort((a, b) => b.avg_trading_value - a.avg_trading_value);
    json(res, 200, { count: out.length, items: out });
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
}

// Main handler
export default async function handler(req, res) {
  try {
    const url = new URL(req.url, "http://localhost");
    const p = url.pathname;

    // Basic routing
    if (p === "/api/health") return handleHealth(req, res);
    if (p === "/api/auth/refresh" && req.method === "POST") return handleAuthRefresh(req, res);
    if (p === "/api/universe/listed" && req.method === "GET") return handleUniverseListed(req, res);
    if (p === "/api/prices/daily" && req.method === "GET") return handlePricesDaily(req, res, url);
    if (p === "/api/screen/liquidity" && req.method === "GET") return handleScreenLiquidity(req, res, url);

    res.statusCode = 404;
    res.end("Not Found");
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
}
