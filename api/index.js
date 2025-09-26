// api/index.js
// Minimal J-Quants proxy for Vercel (Node runtime / no inline runtime config)
// - Uses refreshToken (ENV) -> idToken (15min) 自動更新
// - In-memory cache (idToken / simple response cache)
// - Endpoints: /api/health, /api/auth/refresh, /api/universe/listed, /api/prices/daily, /api/screen/liquidity

const JQ_BASE = "https://api.jquants.com/v1";

// === ENV Vars ===
// JQ_REFRESH_TOKEN を推奨（前後空白を安全に除去）
// 代替: JQ_EMAIL + JQ_PASSWORD で初回refreshTokenを自動取得
const {
  JQ_REFRESH_TOKEN: RAW_RT,
  JQ_EMAIL,
  JQ_PASSWORD,
  PROXY_BEARER, // プロキシ用の簡易Bearer。Actions側の“Bearer 認証”に設定
} = process.env;
const ENV_REFRESH_TOKEN = (RAW_RT || "").trim();

// === Simple in-memory cache ===
let cache = {
  idToken: null,
  idTokenExpAt: 0,              // epoch ms
  refreshToken: ENV_REFRESH_TOKEN || null,
  resp: new Map(),              // key -> { expAt, json }
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

// 認可チェック（PROXY_BEARER が未設定なら認証スキップ）
function requireProxyBearer(req) {
  if (!PROXY_BEARER) return true;
  const h = req.headers["authorization"] || "";
  const got = h.startsWith("Bearer ") ? h.slice(7) : "";
  return got && got === PROXY_BEARER;
}

// --- J-Quants fetch wrapper ---
async function jqFetch(path, params = {}, idToken) {
  const url = new URL(JQ_BASE + path);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  });

  const headers = idToken ? { Authorization: `Bearer ${idToken}` } : {};
  let res = await fetch(url.toString(), { headers });

  if (res.status === 429) {
    // gentle backoff & single retry
    await sleep(800);
    res = await fetch(url.toString(), { headers });
  }

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`JQ ${res.status}: ${txt || res.statusText}`);
  }
  return res.json();
}

// --- Auth helpers ---
// 初回：メール/パスワードから refreshToken を取得（ENVが空のとき用の保険）
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

// refreshToken -> idToken 交換（URLSearchParamsで確実にエンコード）
async function getIdTokenByRefresh(refreshToken) {
  const qs = new URLSearchParams({ refreshtoken: refreshToken });
  const url = `${JQ_BASE}/token/auth_refresh?${qs.toString()}`;
  const res = await fetch(url);
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`auth_refresh failed: ${res.status} ${txt}`);
  }
  const data = await res.json();
  if (!data.idToken) throw new Error("auth_refresh returned no idToken");
  return data.idToken;
}

// idToken を確保（期限が近ければ更新）
async function ensureIdToken() {
  const now = Date.now();
  if (cache.idToken && cache.idTokenExpAt - now > 60_000) return cache.idToken;

  if (!cache.refreshToken) {
    cache.refreshToken = ENV_REFRESH_TOKEN || (await getRefreshTokenByPassword());
  }
  const idToken = await getIdTokenByRefresh(cache.refreshToken);
  cache.idToken = idToken;
  // 公式の有効時間に依存。ここでは 15 分想定で少し余裕を持って運用
  cache.idTokenExpAt = now + 15 * 60_000;
  return idToken;
}

// --- tiny resp cache helpers ---
function getCached(key) {
  const hit = cache.resp.get(key);
  return hit && hit.expAt > Date.now() ? hit.json : null;
}
function setCached(key, jsonObj, ttlMs) {
  cache.resp.set(key, { expAt: Date.now() + ttlMs, json: jsonObj });
}

// --- Handlers ---
async function handleHealth(_req, res) {
  json(res, 200, { ok: true, ts: new Date().toISOString() });
}

async function handleAuthRefresh(req, res) {
  if (!requireProxyBearer(req)) return json(res, 401, { error: "Unauthorized" });
  try {
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
  const to   = url.searchParams.get("to");
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

// デモ用：平均売買代金スクリーナ（直近lookback日）
async function handleScreenLiquidity(req, res, url) {
  if (!requireProxyBearer(req)) return json(res, 401, { error: "Unauthorized" });

  const minVal   = Number(url.searchParams.get("min_avg_trading_value") || "100000000"); // 1億円
  const lookback = Number(url.searchParams.get("days") || "20");
  const market   = url.searchParams.get("market"); // Prime|Standard|Growth|All

  try {
    const idToken = await ensureIdToken();

    // 1) ユニバース
    const uni = await jqFetch("/listed/info", {}, idToken);
    let list = Array.isArray(uni) ? uni : uni?.info || uni?.data || [];
    if (market && market !== "All") {
      const mkey = market.toLowerCase();
      list = list.filter((x) => (x.market || x.market_code || "").toString().toLowerCase().includes(mkey));
    }

    // 2) 価格取得範囲
    const end = new Date();
    const start = new Date(end.getTime() - 120 * 24 * 60 * 60_000); // 120日分だけ取得
    const to = end.toISOString().slice(0, 10);
    const from = start.toISOString().slice(0, 10);

    // 3) サンプル上限（API負荷対策として最初は絞る）
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

      // 平均売買代金 ≒ Close * Volume の平均
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
    json(res, 200, { count: out.length, items: out });
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
}

// --- Main router (GET/POST両対応 & 末尾スラッシュ吸収) ---
export default async function handler(req, res) {
  try {
    const url = new URL(req.url, "http://localhost");
    const p = url.pathname.replace(/\/+$/, ""); // strip trailing slash

    if (p === "/api/health") return handleHealth(req, res);

    if (p === "/api/auth/refresh" && (req.method === "POST" || req.method === "GET")) {
      return handleAuthRefresh(req, res);
    }

    if (p === "/api/universe/listed" && req.method === "GET") {
      return handleUniverseListed(req, res);
    }

    if (p === "/api/prices/daily" && req.method === "GET") {
      return handlePricesDaily(req, res, url);
    }

    if (p === "/api/screen/liquidity" && req.method === "GET") {
      return handleScreenLiquidity(req, res, url);
    }

    res.statusCode = 404;
    res.end("Not Found");
  } catch (e) {
    json(res, 500, { error: String(e.message || e) });
  }
}
