// api/index.js
// J-Quants JP Proxy (Screening) — full replacement
// 必須Env: PROXY_BEARER
// どちらか: (A) JQ_REFRESH_TOKEN  または  (B) JQ_MAIL + JQ_PASSWORD
// 任意Env: LOG_LEVEL=debug で簡易デバッグログ
//
// 実装の要点:
// - /token/auth_user (週1): refreshToken を取得してキャッシュ（メール/パスワードでの自動ブートストラップ）
// - /token/auth_refresh (24h): idToken を取得してキャッシュ
// - 日次株価は TurnoverValue を採用、信用残は Long/Short* の正式キーに対応
// - 市場は MarketCodeName（プライム/スタンダード/グロース）を採用
// - CORS 設定あり、プロキシ用 Bearer を各APIで要求

const JQ_BASE = "https://api.jquants.com/v1";
const VERSION = "1.0.9-full";

// ———————————————————————— ユーティリティ
const isDebug = () => (process.env.LOG_LEVEL || "").toLowerCase() === "debug";
const dlog = (...args) => { if (isDebug()) console.log("[DEBUG]", ...args); };

function json(res, code, obj) { res.status(code).json(obj); }
function now() { return Date.now(); }

function pick(v, ...keys) {
  for (const k of keys) {
    if (v != null && Object.prototype.hasOwnProperty.call(v, k) && v[k] != null) return v[k];
  }
  return undefined;
}
function toInt(x) { const n = Number(x); return Number.isFinite(n) ? Math.trunc(n) : null; }
function toNum(x) {
  if (x === "-" || x === "*" || x === "" || x == null) return null;
  const n = Number(x);
  return Number.isFinite(n) ? n : null;
}
function codeStr(x) { return String(x || "").padStart(4, "0"); }
function normDateStr(s) { return typeof s === "string" ? s : String(s || ""); }

// ———————————————————————— 認証（refreshToken / idToken キャッシュ）
let REFRESH_TOKEN = process.env.JQ_REFRESH_TOKEN || null;
let REFRESH_TOKEN_EXP_AT = REFRESH_TOKEN ? 0 : 0; // 環境変数の場合は期限不明(0=未知)
let ID_TOKEN = null;
let ID_TOKEN_EXP_AT = 0;

function msUntilExp() { return Math.max(0, (ID_TOKEN_EXP_AT || 0) - now()); }

function requireProxyAuth(req, res) {
  const header = req.headers["authorization"] || req.headers["Authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    json(res, 401, { error: "Missing Authorization: Bearer" });
    return false;
  }
  const token = header.slice("Bearer ".length).trim();
  if (!process.env.PROXY_BEARER || token !== process.env.PROXY_BEARER) {
    json(res, 401, { error: "Invalid bearer token" });
    return false;
  }
  return true;
}

// refreshToken をメール/パスワードから取得（週1回想定）
async function fetchRefreshTokenFromUserPass() {
  const mail = process.env.JQ_MAIL;
  const pass = process.env.JQ_PASSWORD;
  if (!mail || !pass) throw new Error("Missing JQ_MAIL / JQ_PASSWORD");

  const r = await fetch(`${JQ_BASE}/token/auth_user`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mailaddress: mail, password: pass }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.refreshToken) {
    throw new Error(`auth_user failed: ${r.status} ${JSON.stringify(j)}`);
  }
  // 1週間有効（安全側に -10分）
  REFRESH_TOKEN = j.refreshToken;
  REFRESH_TOKEN_EXP_AT = Date.now() + 7 * 24 * 60 * 60 * 1000 - 10 * 60 * 1000;
  dlog("refreshToken issued (masked)");
  return REFRESH_TOKEN;
}
function refreshTokenValid() {
  return !!REFRESH_TOKEN && (REFRESH_TOKEN_EXP_AT === 0 || REFRESH_TOKEN_EXP_AT > Date.now());
}
let inflightGetRT = null;
async function ensureRefreshToken() {
  if (refreshTokenValid()) return REFRESH_TOKEN;
  if (inflightGetRT) return inflightGetRT; // 同時実行デデュープ
  inflightGetRT = (async () => {
    if (process.env.JQ_REFRESH_TOKEN && !REFRESH_TOKEN) {
      // env に固定が入っている場合はそれを採用（期限は未知）
      REFRESH_TOKEN = process.env.JQ_REFRESH_TOKEN;
      REFRESH_TOKEN_EXP_AT = 0;
      return REFRESH_TOKEN;
    }
    return await fetchRefreshTokenFromUserPass();
  })();
  try { return await inflightGetRT; } finally { inflightGetRT = null; }
}

let inflightGetID = null;
async function refreshIdToken(maybeRefreshToken) {
  // 有効な refreshToken を確保
  const refreshToken = maybeRefreshToken || await ensureRefreshToken();

  const url = `${JQ_BASE}/token/auth_refresh?refreshtoken=${encodeURIComponent(refreshToken)}`;
  const r = await fetch(url, { method: "POST" });
  const t = await r.json().catch(() => ({}));

  if (!r.ok || !t.idToken) {
    // refreshToken が期限切れ/無効など → 再発行して再試行
    REFRESH_TOKEN = null; REFRESH_TOKEN_EXP_AT = 0;
    const rt2 = await ensureRefreshToken();
    const r2 = await fetch(`${JQ_BASE}/token/auth_refresh?refreshtoken=${encodeURIComponent(rt2)}`, { method: "POST" });
    const t2 = await r2.json().catch(() => ({}));
    if (!r2.ok || !t2.idToken) {
      throw new Error(`auth_refresh failed: ${r2.status} ${JSON.stringify(t2)}`);
    }
    ID_TOKEN = t2.idToken;
  } else {
    ID_TOKEN = t.idToken;
  }
  // 24h有効（安全側 -5分）
  ID_TOKEN_EXP_AT = Date.now() + 24 * 60 * 60 * 1000 - 5 * 60 * 1000;
  return { idToken: ID_TOKEN, expAt: ID_TOKEN_EXP_AT };
}
async function ensureIdToken() {
  if (ID_TOKEN && msUntilExp() > 0) return ID_TOKEN;
  if (inflightGetID) return inflightGetID; // 同時実行デデュープ
  inflightGetID = (async () => (await refreshIdToken()).idToken)();
  try { return await inflightGetID; } finally { inflightGetID = null; }
}

// 任意: クライアントが idToken を直接渡してくる場合に優先使用
function readIdTokenOverride(req) {
  const h = req.headers["x-id-token"] || req.headers["X-ID-TOKEN"];
  return typeof h === "string" && h.trim() ? h.trim() : null;
}

async function jqGET(pathWithQuery, idTokenOverride) {
  const idToken = idTokenOverride || await ensureIdToken();
  const url = `${JQ_BASE}${pathWithQuery}`;
  dlog("JQ GET", url);
  const r = await fetch(url, { headers: { Authorization: `Bearer ${idToken}` } });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = body && (body.message || body.error) ? ` ${JSON.stringify(body)}` : "";
    throw new Error(`JQ GET failed: ${r.status}${msg}`);
  }
  return body;
}

// ———————————————————————— JQ データマッピング
function mapDailyQuote(rec) {
  return {
    date: normDateStr(pick(rec, "Date", "date")),
    code: String(pick(rec, "Code", "code") || ""),
    close: toNum(pick(rec, "Close", "EndPrice", "close", "endPrice", "AdjustedClose", "adjusted_close")),
    turnover: toNum(pick(rec, "TurnoverValue", "turnoverValue", "trading_value"))
  };
}
function mapWeeklyMargin(rec) {
  const buy = toNum(pick(rec, "LongMarginTradeVolume", "long_margin_trade_volume", "buying"));
  const sell = toNum(pick(rec, "ShortMarginTradeVolume", "short_margin_trade_volume", "selling"));
  const buying = Number.isFinite(buy) ? buy : 0;
  const selling = Number.isFinite(sell) ? sell : 0;
  return {
    date: normDateStr(pick(rec, "Date", "date")),
    code: String(pick(rec, "Code", "code") || ""),
    buying, selling,
    net: (Number.isFinite(buying) && Number.isFinite(selling)) ? (buying - selling) : null,
    ratio: buying ? (selling / buying) : null
  };
}
function mapDailyPublic(rec) {
  const buy = toNum(pick(rec, "LongMarginOutstanding", "long_margin_outstanding", "buying_on_margin"));
  const sell = toNum(pick(rec, "ShortMarginOutstanding", "short_margin_outstanding", "selling_on_margin"));
  const r = toNum(pick(rec, "ShortLongRatio", "short_long_ratio", "MarginRate", "margin_rate"));
  return {
    date: normDateStr(pick(rec, "PublishedDate", "Date", "date")),
    code: String(pick(rec, "Code", "code") || ""),
    buying: Number.isFinite(buy) ? buy : 0,
    selling: Number.isFinite(sell) ? sell : 0,
    net: (Number.isFinite(buy) && Number.isFinite(sell)) ? (buy - sell) : null,
    margin_rate: (r != null ? (r > 1 ? r / 100 : r) : null) // ％で来た場合を 0-1 に正規化
  };
}

// ———————————————————————— 上場銘柄/営業日/株価ユーティリティ
async function getListedMap(idTokenOverride) {
  const j = await jqGET(`/listed/info`, idTokenOverride);
  const info = j.info || [];
  const m = new Map();
  for (const it of info) {
    m.set(codeStr(pick(it, "Code", "code")), {
      code: codeStr(pick(it, "Code", "code")),
      name: String(pick(it, "CompanyName", "name") || ""),
      marketJa: String(pick(it, "MarketCodeName", "Market", "market") || "")
    });
  }
  return m;
}
function marketMatch(marketParam, marketJa) {
  if (!marketParam || marketParam === "All") return true;
  const want = (marketParam || "").toLowerCase();
  const ja = (marketJa || "").toLowerCase();
  if (want === "prime")    return ja.includes("プライム");
  if (want === "standard") return ja.includes("スタンダード");
  if (want === "growth")   return ja.includes("グロース");
  return true;
}

async function getRecentTradingDates(nDays, idTokenOverride) {
  const today = new Date();
  const to = today.toISOString().slice(0, 10);
  const from = new Date(today.getTime() - 400 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const cal = await jqGET(`/markets/trading_calendar?from=${from}&to=${to}`, idTokenOverride);
  const list = (cal.trading_calendar || []).map(r => ({
    date: normDateStr(pick(r, "Date", "date")),
    hol: String(pick(r, "HolidayDivision", "holidayDivision", "Holiday") || "")
  }));
  const biz = list.filter(x => x.hol === "1" || x.hol === "2").map(x => x.date);
  const uniq = Array.from(new Set(biz)).sort(); // 昇順
  return uniq.slice(Math.max(0, uniq.length - nDays));
}
async function getLatestTradingDate(idTokenOverride) {
  const d = await getRecentTradingDates(1, idTokenOverride);
  return d[0];
}
async function fetchDailyQuotesByDate(dateStr, idTokenOverride) {
  const j = await jqGET(`/prices/daily_quotes?date=${encodeURIComponent(dateStr)}`, idTokenOverride);
  return (j.daily_quotes || []).map(mapDailyQuote);
}

// 直近N営業日の平均売買代金（TurnoverValue）＋最新終値
async function buildLiquidityAndClose(days = 20, idTokenOverride) {
  const dates = await getRecentTradingDates(days, idTokenOverride);
  if (dates.length === 0) return { avgTV: new Map(), latestClose: new Map() };

  const sumTV = new Map();
  let lastDayClose = new Map();

  for (let i = 0; i < dates.length; i++) {
    const dt = dates[i];
    const items = await fetchDailyQuotesByDate(dt, idTokenOverride);
    if (i === dates.length - 1) lastDayClose = new Map(items.map(it => [codeStr(it.code), it.close]));
    for (const it of items) {
      const code = codeStr(it.code);
      const v = it.turnover || 0;
      if (!Number.isFinite(v)) continue;
      sumTV.set(code, (sumTV.get(code) || 0) + v);
    }
  }
  const avgTV = new Map();
  for (const [code, total] of sumTV.entries()) avgTV.set(code, total / dates.length);
  return { avgTV, latestClose: lastDayClose };
}

// 3/6/12か月モメンタム（営業日ベースの近似）
async function buildMomentumSnapshots(idTokenOverride) {
  const dates = await getRecentTradingDates(260, idTokenOverride);
  if (dates.length === 0) return { d0: new Map() };
  const idx  = dates.length - 1;
  const idx3 = Math.max(0, dates.length - 63);
  const idx6 = Math.max(0, dates.length - 126);
  const idx12= Math.max(0, dates.length - 252);

  const [dq0, dq3, dq6, dq12] = await Promise.all([
    fetchDailyQuotesByDate(dates[idx], idTokenOverride),
    fetchDailyQuotesByDate(dates[idx3], idTokenOverride),
    fetchDailyQuotesByDate(dates[idx6], idTokenOverride),
    fetchDailyQuotesByDate(dates[idx12], idTokenOverride),
  ]);
  const toMap = (arr) => new Map(arr.map(it => [codeStr(it.code), it.close]));
  return { d0: toMap(dq0), d3: toMap(dq3), d6: toMap(dq6), d12: toMap(dq12),
           dates: { d0: dates[idx], d3: dates[idx3], d6: dates[idx6], d12: dates[idx12] } };
}
function calcReturn(nowClose, pastClose) {
  const a = toNum(nowClose), b = toNum(pastClose);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b === 0) return null;
  return a / b - 1;
}

// statements（EPS/BPS/DPS の簡易要約）
async function fetchFinsStatementsByCode(code, idTokenOverride) {
  const j = await jqGET(`/fins/statements?code=${encodeURIComponent(code)}`, idTokenOverride);
  return j.statements || [];
}
function summarizeFins(statements) {
  if (!Array.isArray(statements) || statements.length === 0) {
    return { eps_ttm: null, bps: null, dps: null, roe: null, roa: null };
  }
  const items = [...statements].sort((a, b) => {
    return normDateStr(pick(b, "DisclosedDate", "disclosedDate"))
         .localeCompare(normDateStr(pick(a, "DisclosedDate", "disclosedDate")));
  });

  const epsVals = [];
  for (const it of items) {
    const e = toNum(pick(it, "EarningsPerShare", "eps", "EPS"));
    if (e != null) epsVals.push(e);
    if (epsVals.length >= 4) break;
  }
  const eps_ttm = epsVals.length ? epsVals.reduce((x, y) => x + y, 0) : null;
  const bps = toNum(pick(items[0] || {}, "BookValuePerShare", "bps", "BPS")) ?? null;
  const dps = toNum(pick(items[0] || {}, "ResultDividendPerShareAnnual", "ForecastDividendPerShareAnnual", "dps", "DPS")) ?? null;
  const roe = toNum(pick(items[0] || {}, "ROE", "roe")); // 無い場合多い
  const roa = toNum(pick(items[0] || {}, "ROA", "roa"));
  return { eps_ttm, bps, dps, roe, roa };
}

// ———————————————————————— ルーター
export default async function handler(req, res) {
  try {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname.replace(/\/+$/, "");
    const method = req.method.toUpperCase();
    const idTokenOverride = readIdTokenOverride(req);

    // CORS
    if (method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-ID-TOKEN");
      return res.status(204).end();
    }
    res.setHeader("Access-Control-Allow-Origin", "*");

    // /api/health は無認可でOK
    if (path === "/api/health" && method === "GET") {
      return json(res, 200, {
        ok: true,
        ts: new Date().toISOString(),
        idToken_valid_ms: msUntilExp(),
        version: VERSION
      });
    }

    // それ以外はプロキシ用ベアラー必須
    if (!requireProxyAuth(req, res)) return;

    // idToken更新（内部キャッシュ）: POST
    if (path === "/api/auth/refresh" && method === "POST") {
      const body = typeof req.body === "object" ? req.body : {};
      const override = body?.refreshToken || body?.refreshtoken;
      const out = await refreshIdToken(override);
      return json(res, 200, out);
    }

    // 日次株価（JQのレスポンスをほぼ素通し）
    if (path === "/api/prices/daily" && method === "GET") {
      const code = url.searchParams.get("code");
      const from = url.searchParams.get("from");
      const to = url.searchParams.get("to");
      if (!code) return json(res, 400, { error: "code is required" });

      const q = new URLSearchParams({ code });
      if (from) q.set("from", from);
      if (to) q.set("to", to);
      const j = await jqGET(`/prices/daily_quotes?${q.toString()}`, idTokenOverride);
      return json(res, 200, j);
    }

    // 財務サマリ
    if (path === "/api/fins/statements" && method === "GET") {
      const code = url.searchParams.get("code");
      if (!code) return json(res, 400, { error: "code is required" });

      const stmts = await fetchFinsStatementsByCode(code, idTokenOverride);
      const sum = summarizeFins(stmts);

      const latestDate = await getLatestTradingDate(idTokenOverride);
      const dq = await fetchDailyQuotesByDate(latestDate, idTokenOverride);
      const me = dq.find(r => codeStr(r.code) === codeStr(code));
      const close = me?.close ?? null;

      let marketCap = null, per = null, pbr = null, dividend_yield = null;
      if (Number.isFinite(close)) {
        if (sum.eps_ttm != null && sum.eps_ttm !== 0) per = close / sum.eps_ttm;
        if (sum.bps != null && sum.bps !== 0) pbr = close / sum.bps;
        if (sum.dps != null && close !== 0) dividend_yield = sum.dps / close;
      }

      return json(res, 200, {
        summary: {
          code: codeStr(code),
          close,
          marketCap,
          eps_ttm: sum.eps_ttm,
          bps: sum.bps,
          dps: sum.dps,
          per,
          pbr,
          dividend_yield,
          roe: sum.roe,
          roa: sum.roa,
        },
        raw_count: stmts.length
      });
    }

    // 週次信用残
    if (path === "/api/credit/weekly" && method === "GET") {
      const code = url.searchParams.get("code");
      const weeks = Math.max(4, toInt(url.searchParams.get("weeks")) || 26);
      if (!code) return json(res, 400, { error: "code is required" });

      const j = await jqGET(`/markets/weekly_margin_interest?code=${encodeURIComponent(code)}`, idTokenOverride);
      let items = (j.weekly_margin_interest || []).map(mapWeeklyMargin);
      items.sort((a, b) => a.date.localeCompare(b.date));
      if (items.length > weeks) items = items.slice(items.length - weeks);

      const latest = items[items.length - 1] || {};
      const prev = items[items.length - 2] || {};
      const metrics = {
        code: codeStr(code),
        latest: latest.date ? latest : { date: null, buying: null, selling: null, net: null, ratio: null },
        wow_change: {
          buying: (latest.buying != null && prev.buying != null) ? latest.buying - prev.buying : null,
          selling: (latest.selling != null && prev.selling != null) ? latest.selling - prev.selling : null,
          net: (latest.net != null && prev.net != null) ? latest.net - prev.net : null,
        }
      };
      return json(res, 200, { code: codeStr(code), count: items.length, metrics, items });
    }

    // 日々公表信用残
    if (path === "/api/credit/daily_public" && method === "GET") {
      const code = url.searchParams.get("code");
      const days = Math.max(7, toInt(url.searchParams.get("days")) || 60);
      if (!code) return json(res, 400, { error: "code is required" });

      const today = new Date();
      const to = today.toISOString().slice(0, 10);
      const from = new Date(today.getTime() - (days + 20) * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

      const q = new URLSearchParams({ code, from, to });
      const j = await jqGET(`/markets/daily_margin_interest?${q.toString()}`, idTokenOverride);
      let items = (j.daily_margin_interest || []).map(mapDailyPublic);
      items.sort((a, b) => a.date.localeCompare(b.date));
      if (items.length > days) items = items.slice(items.length - days);
      return json(res, 200, { code: codeStr(code), count: items.length, items });
    }

    // 流動性プリフィルタ（平均売買代金）
    if (path === "/api/screen/liquidity" && method === "GET") {
      const market = url.searchParams.get("market") || "All";
      const minAvg = toInt(url.searchParams.get("min_avg_trading_value")) ?? 100_000_000;
      const days = toInt(url.searchParams.get("days")) ?? 20;

      const [listedMap, liq] = await Promise.all([getListedMap(idTokenOverride), buildLiquidityAndClose(days, idTokenOverride)]);
      const out = [];
      for (const [code, avg_trading_value] of liq.avgTV.entries()) {
        const meta = listedMap.get(code) || { name: "", marketJa: "" };
        if (!marketMatch(market, meta.marketJa)) continue;
        if (!Number.isFinite(avg_trading_value) || avg_trading_value < minAvg) continue;
        out.push({ code, name: meta.name, market: meta.marketJa, avg_trading_value: Math.round(avg_trading_value) });
      }
      out.sort((a, b) => b.avg_trading_value - a.avg_trading_value);
      return json(res, 200, { count: out.length, items: out });
    }

    // 総合スクリーナー
    if (path === "/api/screen/basic" && method === "GET") {
      const market = url.searchParams.get("market") || "All";
      const limit = Math.min(Math.max(toInt(url.searchParams.get("limit")) || 30, 1), 200);
      const liquidity_min = toInt(url.searchParams.get("liquidity_min")) ?? 100_000_000;
      const per_lt = url.searchParams.get("per_lt") != null ? Number(url.searchParams.get("per_lt")) : null;
      const pbr_lt = url.searchParams.get("pbr_lt") != null ? Number(url.searchParams.get("pbr_lt")) : null;
      const div_yield_gt = url.searchParams.get("div_yield_gt") != null ? Number(url.searchParams.get("div_yield_gt")) : null;
      const mom3m_gt = url.searchParams.get("mom3m_gt") != null ? Number(url.searchParams.get("mom3m_gt")) : null;

      const [listedMap, { avgTV, latestClose }, momSnaps] = await Promise.all([
        getListedMap(idTokenOverride),
        buildLiquidityAndClose(20, idTokenOverride),
        buildMomentumSnapshots(idTokenOverride),
      ]);

      const items = [];
      for (const [code, avg_trading_value] of avgTV.entries()) {
        const meta = listedMap.get(code) || { name: "", marketJa: "" };
        if (!marketMatch(market, meta.marketJa)) continue;
        if (!Number.isFinite(avg_trading_value) || avg_trading_value < liquidity_min) continue;

        const mom_3m = calcReturn(momSnaps.d0.get(code), momSnaps.d3.get(code));
        const mom_6m = calcReturn(momSnaps.d0.get(code), momSnaps.d6.get(code));
        const mom_12m = calcReturn(momSnaps.d0.get(code), momSnaps.d12.get(code));
        if (mom3m_gt != null && (mom_3m == null || mom_3m < mom3m_gt)) continue;

        // バリュー系（必要時だけ statements を呼ぶ）
        let per = null, pbr = null, dividend_yield = null;
        if (per_lt != null || pbr_lt != null || div_yield_gt != null) {
          try {
            const stmts = await fetchFinsStatementsByCode(code, idTokenOverride);
            const s = summarizeFins(stmts);
            const close = latestClose.get(code);
            if (Number.isFinite(close)) {
              if (s.eps_ttm != null && s.eps_ttm !== 0) per = close / s.eps_ttm;
              if (s.bps != null && s.bps !== 0) pbr = close / s.bps;
              if (s.dps != null && close !== 0) dividend_yield = s.dps / close;
            }
            if (per_lt != null && !(per != null && per < per_lt)) continue;
            if (pbr_lt != null && !(pbr != null && pbr < pbr_lt)) continue;
            if (div_yield_gt != null && !(dividend_yield != null && dividend_yield > div_yield_gt)) continue;
          } catch (e) {
            dlog("fins fetch failed for", code, e.message);
            continue;
          }
        }

        const liqScore = Math.log10(Math.max(1, avg_trading_value));
        const momScore = (mom_3m == null ? 0 : mom_3m * 100);
        const score = Math.round(10 * (liqScore + momScore));

        items.push({
          code,
          name: meta.name,
          per, pbr, dividend_yield,
          mom_3m, mom_6m, mom_12m,
          avg_trading_value: Math.round(avg_trading_value),
          score
        });
      }

      items.sort((a, b) => b.score - a.score);
      return json(res, 200, { count: Math.min(items.length, limit), items: items.slice(0, limit) });
    }

    // ポートフォリオ・サマリー
    if (path === "/api/portfolio/summary" && method === "GET") {
      const codesParam = url.searchParams.get("codes");
      const with_credit = toInt(url.searchParams.get("with_credit")) === 1;
      if (!codesParam) return json(res, 400, { error: "codes is required (comma-separated)" });

      const codes = codesParam.split(",").map(s => codeStr(s.trim())).filter(Boolean);
      const [listedMap, latestDate] = await Promise.all([getListedMap(idTokenOverride), getLatestTradingDate(idTokenOverride)]);
      const dq = await fetchDailyQuotesByDate(latestDate, idTokenOverride);
      const closeMap = new Map(dq.map(it => [codeStr(it.code), it.close]));

      const out = [];
      for (const code of codes) {
        let close = closeMap.get(code) ?? null;
        let per = null, pbr = null, dividend_yield = null, eps_ttm = null, bps = null, dps = null;
        let credit_latest = null;
        let error = null;

        try {
          const stmts = await fetchFinsStatementsByCode(code, idTokenOverride);
          const s = summarizeFins(stmts);
          eps_ttm = s.eps_ttm; bps = s.bps; dps = s.dps;
          if (Number.isFinite(close)) {
            if (s.eps_ttm != null && s.eps_ttm !== 0) per = close / s.eps_ttm;
            if (s.bps != null && s.bps !== 0) pbr = close / s.bps;
            if (s.dps != null && close !== 0) dividend_yield = s.dps / close;
          }
        } catch (e) { error = e.message; }

        if (with_credit) {
          try {
            const j = await jqGET(`/markets/weekly_margin_interest?code=${encodeURIComponent(code)}`, idTokenOverride);
            const arr = (j.weekly_margin_interest || []).map(mapWeeklyMargin).sort((a, b) => a.date.localeCompare(b.date));
            credit_latest = arr[arr.length - 1] || null;
          } catch (e) { error = (error ? error + "; " : "") + e.message; }
        }

        out.push({ code, close, per, pbr, dividend_yield, eps_ttm, bps, dps, credit_latest, error: error || null });
      }
      return json(res, 200, { count: out.length, items: out });
    }

    // 未対応
    return json(res, 404, { error: `No route for ${method} ${path}` });
  } catch (e) {
    console.error(e);
    return json(res, 500, { error: e.message || "Internal error" });
  }
}
