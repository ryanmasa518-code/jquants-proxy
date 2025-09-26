// api/index.js — J-Quants proxy (safe/full)
// - Bearer 認証(ヘッダ/クエリ/代替ヘッダ) ※開発用に緩めています。公開前に絞ってください。
// - 例外は JSON で返却（FUNCTION_INVOCATION_FAILED 回避）
// - Endpoints:
//   /api/health
//   /api/debug
//   /api/debug/routes
//   /api/auth/refresh (POST/GET)
//   /api/universe/listed
//   /api/prices/daily
//   /api/fins/statements
//   /api/screen/liquidity
//   /api/screen/basic

const JQ_BASE = "https://api.jquants.com/v1";

const {
  JQ_REFRESH_TOKEN: RAW_RT,
  JQ_EMAIL,
  JQ_PASSWORD,
  PROXY_BEARER,
} = process.env;
const ENV_REFRESH_TOKEN = (RAW_RT || "").trim();

let cache = {
  idToken: null,
  idTokenExpAt: 0,
  refreshToken: ENV_REFRESH_TOKEN || null,
  resp: new Map(),
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function safeJson(res, status, body) {
  try {
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify(body));
  } catch {
    res.statusCode = 500;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Internal Server Error");
  }
}

function safeParseURL(req) {
  try {
    const raw = typeof req?.url === "string" ? req.url : "/";
    return new URL(raw, "http://localhost");
  } catch {
    return new URL("http://localhost/");
  }
}

// 認可: Authorization / X-Proxy-Key / ?key= を許可（開発用）
function requireProxyBearer(req) {
  if (!PROXY_BEARER) return true; // env 未設定時はスキップ
  try {
    const h = (req.headers?.["authorization"] || "").toString();
    const bearer = h.startsWith("Bearer ") ? h.slice(7) : "";
    const xkey = (req.headers?.["x-proxy-key"] || "").toString();
    const url = safeParseURL(req);
    const qkey = (url.searchParams.get("key") || "").toString();
    const token = bearer || xkey || qkey;
    return !!token && token === PROXY_BEARER;
  } catch {
    return false;
  }
}

// ---- utils for numbers/fields ----
function num(v) { const n = Number(v); return Number.isFinite(n) ? n : 0; }
function pick(obj, keys) { for (const k of keys) if (obj && obj[k] != null) return obj[k]; }

// ---- J-Quants fetch wrapper ----
async function jqFetch(path, params = {}, idToken) {
  const url = new URL(JQ_BASE + path);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  const headers = idToken ? { Authorization: `Bearer ${idToken}` } : {};
  let res = await fetch(url.toString(), { headers });
  if (res.status === 429) { await sleep(800); res = await fetch(url.toString(), { headers }); }
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`JQ ${res.status}: ${txt || res.statusText}`);
  }
  return res.json();
}

// ---- Auth helpers ----
async function getRefreshTokenByPassword() {
  if (!JQ_EMAIL || !JQ_PASSWORD) throw new Error("Missing JQ_EMAIL/JQ_PASSWORD for refresh-token bootstrap.");
  const res = await fetch(`${JQ_BASE}/token/auth_user`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mailaddress: JQ_EMAIL, password: JQ_PASSWORD }),
  });
  if (!res.ok) { const txt = await res.text().catch(() => ""); throw new Error(`auth_user failed: ${res.status} ${txt}`); }
  const data = await res.json();
  if (!data.refreshToken) throw new Error("auth_user returned no refreshToken");
  return String(data.refreshToken).trim();
}

// refresh -> id (POST が正)
async function getIdTokenByRefresh(refreshToken) {
  const qs = new URLSearchParams({ refreshtoken: refreshToken });
  const url = `${JQ_BASE}/token/auth_refresh?${qs.toString()}`;
  const res = await fetch(url, { method: "POST" });
  if (!res.ok) { const txt = await res.text().catch(() => ""); throw new Error(`auth_refresh failed: ${res.status} ${txt}`); }
  const data = await res.json();
  if (!data.idToken) throw new Error("auth_refresh returned no idToken");
  return data.idToken;
}

async function ensureIdToken() {
  const now = Date.now();
  if (cache.idToken && cache.idTokenExpAt - now > 60_000) return cache.idToken;
  if (!cache.refreshToken) cache.refreshToken = ENV_REFRESH_TOKEN || (await getRefreshTokenByPassword());
  const idToken = await getIdTokenByRefresh(cache.refreshToken);
  cache.idToken = idToken;
  cache.idTokenExpAt = now + 24 * 60 * 60_000; // 24h
  return idToken;
}

// ---- tiny resp cache ----
function getCached(key) { const hit = cache.resp.get(key); return hit && hit.expAt > Date.now() ? hit.json : null; }
function setCached(key, jsonObj, ttlMs) { cache.resp.set(key, { expAt: Date.now() + ttlMs, json: jsonObj }); }

// ---- handlers ----
async function handleHealth(_req, res) { safeJson(res, 200, { ok: true, ts: new Date().toISOString() }); }
async function handleDebug(req, res) {
  const got = (req.headers?.["authorization"]||"").toString();
  const token = got.startsWith("Bearer ") ? got.slice(7) : "";
  const masked = token ? token.slice(0,3) + "***" + token.slice(-3) : "";
  const env = (process.env.PROXY_BEARER || "").toString();
  const envMasked = env ? env.slice(0,3) + "***" + env.slice(-3) : "";
  const match = !!env && env === token;
  safeJson(res, 200, { hasEnv: !!env, gotAuthHeader: !!got, headerMasked: masked, envMasked, match });
}
async function handleDebugRoutes(req, res) {
  const raw = typeof req?.url === "string" ? req.url : "/";
  const pathOnly = raw.split("?")[0].replace(/\/+$/, "");
  safeJson(res, 200, {
    pathOnly,
    routes: [
      "/api/health",
      "/api/debug",
      "/api/debug/routes",
      "/api/auth/refresh",
      "/api/universe/listed",
      "/api/prices/daily",
      "/api/fins/statements",
      "/api/screen/liquidity",
      "/api/screen/basic",
    ]
  });
}

async function handleAuthRefresh(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    if (!cache.refreshToken) cache.refreshToken = ENV_REFRESH_TOKEN || (await getRefreshTokenByPassword());
    const idToken = await getIdTokenByRefresh(cache.refreshToken);
    cache.idToken = idToken; cache.idTokenExpAt = Date.now() + 24 * 60 * 60_000;
    safeJson(res, 200, { idToken, expAt: cache.idTokenExpAt });
  } catch (e) { safeJson(res, 500, { error: String(e.message || e) }); }
}

async function handleUniverseListed(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  const key = "universe:listed"; const hit = getCached(key); if (hit) return safeJson(res, 200, hit);
  try {
    const idToken = await ensureIdToken();
    const data = await jqFetch("/listed/info", {}, idToken);
    setCached(key, data, 24 * 60 * 60_000);
    safeJson(res, 200, data);
  } catch (e) { safeJson(res, 500, { error: String(e.message || e) }); }
}

async function handlePricesDaily(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    const url = safeParseURL(req);
    const code = (url.searchParams.get("code") || "").trim();
    if (!code) return safeJson(res, 400, { error: "Missing code" });

    const digits = (s) => (s || "").replace(/\D/g, "");
    let from = digits(url.searchParams.get("from"));
    let to   = digits(url.searchParams.get("to"));
    if (!to)   to   = new Date().toISOString().slice(0,10).replace(/\D/g, "");
    if (!from) { const d = new Date(); d.setDate(d.getDate() - 60); from = d.toISOString().slice(0,10).replace(/\D/g, ""); }
    if (!/^\d{8}$/.test(from) || !/^\d{8}$/.test(to)) return safeJson(res, 400, { error: "Invalid date format. Use YYYYMMDD." });
    if (Number(from) > Number(to)) return safeJson(res, 400, { error: "`from` must be <= `to`" });

    const cacheKey = `prices:daily:${code}:${from}:${to}`;
    const hit = getCached(cacheKey); if (hit) return safeJson(res, 200, hit);

    const idToken = await ensureIdToken();
    // ←← ここが正しい：/prices/daily_quotes
    const data = await jqFetch("/prices/daily_quotes", { code, from, to }, idToken);
    setCached(cacheKey, data, 5 * 60_000);
    safeJson(res, 200, data);
  } catch (e) { safeJson(res, 500, { error: String(e.message || e) }); }
}

// ===== A) fins/statements =====
function sortRecent(a, b) {
  const pick = (o, ks) => { for (const k of ks) if (o && o[k] != null) return o[k]; };
  const da = pick(a, ["DisclosedDate","disclosedDate","date"]) || `${pick(a,["FiscalYear","fiscalYear","fy"]) || ""}${pick(a,["FiscalQuarter","fiscalQuarter","fq"]) || ""}`;
  const db = pick(b, ["DisclosedDate","disclosedDate","date"]) || `${pick(b,["FiscalYear","fiscalYear","fy"]) || ""}${pick(b,["FiscalQuarter","fiscalQuarter","fq"]) || ""}`;
  return String(db).localeCompare(String(da));
}
function extractPerShareLatest(rows) {
  const p = (o, ks) => { for (const k of ks) if (o && o[k] != null) return o[k]; };
  for (const r of rows) {
    const eps = p(r, ["EPS","EarningsPerShare","BasicEPS","basicEps","eps"]);
    const bps = p(r, ["BPS","BookValuePerShare","bps"]);
    const dps = p(r, ["DPS","DividendPerShare","dividend","dividendPerShare","dividendsPerShare"]);
    if (eps != null || bps != null || dps != null) return { eps: num(eps), bps: num(bps), dps: num(dps) };
  }
  return { eps: 0, bps: 0, dps: 0 };
}
function ttmFromQuarterly(rows, fields) {
  const q = rows.filter(r => ((r.Type||r.type||"")+"").toLowerCase().includes("q"));
  const recent4 = (q.length ? q : rows).slice(0, 4);
  const out = {};
  for (const [label, candidates] of Object.entries(fields)) {
    out[label] = recent4.reduce((acc, r) => acc + num((() => { for (const k of candidates) if (r[k]!=null) return r[k]; return 0; })()), 0);
  }
  return out;
}
async function fetchLatestClose(idToken, code) {
  const to = new Date(); const from = new Date(to.getTime() - 90*24*60*60_000);
  const fmt = (d) => d.toISOString().slice(0,10).replace(/\D/g, "");
  const data = await jqFetch("/prices/daily_quotes", { code, from: fmt(from), to: fmt(to) }, idToken);
  const rows = Array.isArray(data) ? data : (data.daily_quotes || data.data || []);
  const last = rows[rows.length-1] || {};
  const close = num((() => { for (const k of ["Close","close","endPrice","AdjustedClose","adjusted_close"]) if (last[k]!=null) return last[k]; return 0; })());
  return close;
}
async function handleFinsStatements(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    const url = safeParseURL(req);
    const code = (url.searchParams.get("code") || "").trim();
    if (!code) return safeJson(res, 400, { error: "Missing code" });

    const idToken = await ensureIdToken();
    const resp = await jqFetch("/fins/statements", { code }, idToken);
    const rows0 = Array.isArray(resp) ? resp : (resp.statements || resp.data || []);
    if (!rows0.length) return safeJson(res, 404, { error: "No statements" });
    const rows = [...rows0].sort(sortRecent);

    const ttm = ttmFromQuarterly(rows, {
      revenue: ["NetSales","netSales","Revenue","revenue"],
      op:      ["OperatingIncome","operatingIncome"],
      ni:      ["NetIncome","netIncome","Profit","profit","ProfitAttributableToOwnersOfParent","netIncomeAttributableToOwnersOfParent"],
    });

    const shares = num((() => { for (const k of ["SharesOutstanding","sharesOutstanding","NumberOfIssuedAndOutstandingShares","issuedShares"]) if (rows[0] && rows[0][k]!=null) return rows[0][k]; return 0; })());
    const perShare = extractPerShareLatest(rows);
    const epsTTM = (shares > 0 && ttm.ni) ? (ttm.ni / shares) : perShare.eps;

    const close = await fetchLatestClose(idToken, code);
    const mc = shares > 0 ? shares * close : 0;

    const per = epsTTM > 0 ? (close / epsTTM) : null;
    const pbr = perShare.bps > 0 ? (close / perShare.bps) : null;
    const divYield = (perShare.dps > 0 && close > 0) ? (perShare.dps / close) : 0;

    const equity = num((rows[0] && (() => { for (const k of ["Equity","equity","TotalEquity","totalEquity","NetAssets","netAssets"]) if (rows[0][k]!=null) return rows[0][k]; return 0; })()));
    const assets = num((rows[0] && (() => { for (const k of ["TotalAssets","totalAssets","Assets","assets"]) if (rows[0][k]!=null) return rows[0][k]; return 0; })()));
    const roe = (equity > 0 && ttm.ni) ? (ttm.ni / equity) : null;
    const roa = (assets > 0 && ttm.ni) ? (ttm.ni / assets) : null;

    const summary = { code, close, marketCap: mc, eps_ttm: epsTTM, bps: perShare.bps, dps: perShare.dps, per, pbr, dividend_yield: divYield, roe, roa };
    safeJson(res, 200, { summary, raw_count: rows.length });
  } catch (e) { safeJson(res, 500, { error: String(e.message || e) }); }
}

// ===== liquidity (既存) =====
async function handleScreenLiquidity(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    const url = safeParseURL(req);
    const minVal   = Number(url.searchParams.get("min_avg_trading_value") || "100000000");
    const lookback = Number(url.searchParams.get("days") || "20");
    const market   = url.searchParams.get("market");

    const idToken = await ensureIdToken();
    const uni = await jqFetch("/listed/info", {}, idToken);
    let list = Array.isArray(uni) ? uni : uni?.info || uni?.data || [];
    if (market && market !== "All") {
      const mkey = market.toLowerCase();
      list = list.filter((x) => (x.market || x.market_code || "").toString().toLowerCase().includes(mkey));
    }

    const end = new Date(); const start = new Date(end.getTime() - 120*24*60*60_000);
    const to = end.toISOString().slice(0,10).replace(/\D/g,"");
    const from = start.toISOString().slice(0,10).replace(/\D/g,"");

    const sample = list.slice(0, Math.min(300, list.length));
    const out = [];
    for (const it of sample) {
      const code = it.code || it.Symbol || it.symbol || it.Code; if (!code) continue;
      let daily; try { daily = await jqFetch("/prices/daily_quotes", { code, from, to }, idToken); } catch { continue; }
      const rows = Array.isArray(daily) ? daily : daily?.daily_quotes || daily?.data || [];
      if (!rows.length) continue;
      const recent = rows.slice(-lookback); if (!recent.length) continue;
      const avgVal = recent.reduce((acc, r) => {
        const c = num(pick(r, ["Close","close","endPrice","AdjustedClose","adjusted_close"]));
        const v = num(pick(r, ["Volume","volume","turnoverVolume"]));
        return acc + c * v;
      }, 0) / recent.length;
      if (avgVal >= minVal) out.push({ code, name: it.company_name || it.Name || it.companyName || "", market: it.market || it.Market || "", avg_trading_value: Math.round(avgVal) });
    }
    out.sort((a,b)=> b.avg_trading_value - a.avg_trading_value);
    safeJson(res, 200, { count: out.length, items: out });
  } catch (e) { safeJson(res, 500, { error: String(e.message || e) }); }
}

// ===== B) screen/basic =====
async function calcAvgTradingValue(idToken, code, lookbackDays = 20) {
  const to = new Date(); const from = new Date(to.getTime() - 90*24*60*60_000);
  const fmt = (d) => d.toISOString().slice(0,10).replace(/\D/g,"");
  const data = await jqFetch("/prices/daily_quotes", { code, from: fmt(from), to: fmt(to) }, idToken);
  const rows = Array.isArray(data) ? data : (data.daily_quotes || data.data || []);
  const recent = rows.slice(-lookbackDays); if (!recent.length) return 0;
  const avg = recent.reduce((a,r)=> a + num(pick(r, ["Close","close","endPrice","AdjustedClose","adjusted_close"])) * num(pick(r,["Volume","volume","turnoverVolume"])), 0)/recent.length;
  return Math.round(avg);
}
async function calcMomentum(idToken, code) {
  const to = new Date(); const from = new Date(to.getTime() - 400*24*60*60_000);
  const fmt = (d) => d.toISOString().slice(0,10).replace(/\D/g,"");
  const data = await jqFetch("/prices/daily_quotes", { code, from: fmt(from), to: fmt(to) }, idToken);
  const rows = Array.isArray(data) ? data : (data.daily_quotes || data.data || []);
  if (rows.length < 40) return { r1m:0, r3m:0, r6m:0, r12m:0 };
  const close = (r)=> num(pick(r, ["Close","close","endPrice","AdjustedClose","adjusted_close"]));
  const last = close(rows[rows.length-1]);
  const findAgo = (days)=> close(rows[Math.max(rows.length - 1 - Math.round(days),0)]);
  const ret = (cur, prev)=> (prev>0 ? (cur/prev - 1) : 0);
  return { r1m:ret(last,findAgo(21)), r3m:ret(last,findAgo(63)), r6m:ret(last,findAgo(126)), r12m:ret(last,findAgo(252)) };
}
function scoreRow(x) {
  let s = 0;
  const lv = Math.min(1, Math.max(0, (x.avg_trading_value - 1e8) / (5e8 - 1e8)));
  s += lv * 20;
  if (x.per) { s += Math.min(1, Math.max(0, (15 - x.per) / (15 - 6))) * 15; }
  if (x.pbr) { s += Math.min(1, Math.max(0, (1.2 - x.pbr) / (1.2 - 0.6))) * 15; }
  const clip=(v,lo,hi)=> Math.min(hi,Math.max(lo,v));
  const scale=(v,lo,hi)=> (clip(v,lo,hi)-lo)/(hi-lo);
  s += scale(x.mom_3m||0, -0.10, 0.20) * 15;
  s += scale(x.mom_6m||0, -0.10, 0.20) * 15;
  s += Math.min(1, (x.dividend_yield||0)/0.04) * 20;
  return Math.round(s);
}
async function handleScreenBasic(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    const url = safeParseURL(req);
    const market = (url.searchParams.get("market") || "All").trim();
    const limit  = Number(url.searchParams.get("limit") || "30");
    const liqMin = Number(url.searchParams.get("liquidity_min") || "100000000");
    const perLt  = url.searchParams.get("per_lt");
    const pbrLt  = url.searchParams.get("pbr_lt");
    const divGt  = url.searchParams.get("div_yield_gt");
    const mom3Gt = url.searchParams.get("mom3m_gt");

    const idToken = await ensureIdToken();
    const uni = await jqFetch("/listed/info", {}, idToken);
    let list = Array.isArray(uni) ? uni : (uni.info || uni.data || []);
    if (market && market !== "All") {
      const mkey = market.toLowerCase();
      list = list.filter(x => (x.market || x.market_code || "").toString().toLowerCase().includes(mkey));
    }

    const sample = list.slice(0, Math.min(300, list.length));
    const out = [];
    for (const it of sample) {
      const code = it.code || it.Symbol || it.symbol || it.Code;
      const name = it.company_name || it.Name || it.companyName || "";
      if (!code) continue;
      try {
        const avgVal = await calcAvgTradingValue(idToken, code, 20);
        if (avgVal < liqMin) continue;

        const fs = await jqFetch("/fins/statements", { code }, idToken);
        const rows0 = Array.isArray(fs) ? fs : (fs.statements || fs.data || []);
        if (!rows0.length) continue;
        const rows = [...rows0].sort(sortRecent);
        const perShare = extractPerShareLatest(rows);

        const lastClose = await fetchLatestClose(idToken, code);
        const mom = await calcMomentum(idToken, code);

        const per = (perShare.eps > 0) ? (lastClose / perShare.eps) : null;
        const pbr = (perShare.bps > 0) ? (lastClose / perShare.bps) : null;
        const divYield = (perShare.dps > 0 && lastClose > 0) ? (perShare.dps / lastClose) : 0;

        if (perLt && per != null && !(per < Number(perLt))) continue;
        if (pbrLt && pbr != null && !(pbr < Number(pbrLt))) continue;
        if (divGt && !(divYield >= Number(divGt))) continue;
        if (mom3Gt && !((mom.r3m || 0) >= Number(mom3Gt))) continue;

        const row = { code, name, per, pbr, dividend_yield: divYield, mom_3m: mom.r3m, mom_6m: mom.r6m, mom_12m: mom.r12m, avg_trading_value: avgVal };
        row.score = scoreRow(row);
        out.push(row);
      } catch { continue; }
    }
    out.sort((a,b)=> b.score - a.score);
    safeJson(res, 200, { count: out.length, items: out.slice(0, limit) });
  } catch (e) { safeJson(res, 500, { error: String(e.message || e) }); }
}

// ---- router ----
export default async function handler(req, res) {
  try {
    const raw = typeof req?.url === "string" ? req.url : "/";
    const pathOnly = raw.split("?")[0].replace(/\/+$/, "");

    if (pathOnly === "/api/health") return handleHealth(req, res);
    if (pathOnly === "/api/debug" && req.method === "GET") return handleDebug(req, res);
    if (pathOnly === "/api/debug/routes" && req.method === "GET") return handleDebugRoutes(req, res);

    if (pathOnly === "/api/auth/refresh" && (req.method === "POST" || req.method === "GET")) return handleAuthRefresh(req, res);
    if (pathOnly === "/api/universe/listed" && req.method === "GET") return handleUniverseListed(req, res);
    if (pathOnly === "/api/prices/daily" && req.method === "GET") return handlePricesDaily(req, res);

    if (pathOnly === "/api/fins/statements" && req.method === "GET") return handleFinsStatements(req, res);
    if (pathOnly === "/api/screen/liquidity" && req.method === "GET") return handleScreenLiquidity(req, res);
    if (pathOnly === "/api/screen/basic" && req.method === "GET") return handleScreenBasic(req, res);

    res.statusCode = 404;
    res.end("Not Found");
  } catch (e) {
    safeJson(res, 500, { error: String(e.message || e) });
  }
}
