// api/index.js
// J-Quants Proxy (Screening) - full replacement
// Vercel Node.js (Edge ではなく Node.js) 用。必要に応じて runtime 設定は vercel.json/next.config.js 側で。
// Env 必須:
//   - PROXY_BEARER:     プロキシ利用時のベアラートークン（クライアント→このプロキシ）
//   - JQ_REFRESH_TOKEN: J-Quants の refreshToken（/token/auth_user かメニューから取得）
// 任意:
//   - LOG_LEVEL: debug にすると各種ログが少し出ます

const JQ_BASE = "https://api.jquants.com/v1";
const VERSION = "1.0.8-fix-keys";

const isDebug = () => (process.env.LOG_LEVEL || "").toLowerCase() === "debug";
const dlog = (...args) => { if (isDebug()) console.log("[DEBUG]", ...args); };

// ==============================
// 内部トークンキャッシュ
// ==============================
let ID_TOKEN = null;
let ID_TOKEN_EXP_AT = 0; // epoch ms

function json(res, code, obj) {
  res.status(code).json(obj);
}

function now() {
  return Date.now();
}

function msUntilExp() {
  return Math.max(0, (ID_TOKEN_EXP_AT || 0) - now());
}

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

async function refreshIdToken(maybeRefreshToken) {
  const refreshToken = maybeRefreshToken || process.env.JQ_REFRESH_TOKEN;
  if (!refreshToken) throw new Error("JQ_REFRESH_TOKEN is not set");

  const url = `${JQ_BASE}/token/auth_refresh?refreshtoken=${encodeURIComponent(refreshToken)}`;
  const r = await fetch(url, { method: "POST" });
  const t = await r.json().catch(() => ({}));

  if (!r.ok) {
    throw new Error(`auth_refresh failed: ${r.status} ${JSON.stringify(t)}`);
  }

  const idToken = t.idToken;
  if (!idToken) throw new Error("auth_refresh success but idToken missing");

  // JQのIDトークンは有効期間24h。安全側に -5分 の猶予。
  ID_TOKEN = idToken;
  ID_TOKEN_EXP_AT = now() + 24 * 60 * 60 * 1000 - 5 * 60 * 1000;

  return { idToken: ID_TOKEN, expAt: ID_TOKEN_EXP_AT };
}

async function ensureIdToken() {
  if (ID_TOKEN && msUntilExp() > 0) return ID_TOKEN;
  const { idToken } = await refreshIdToken();
  return idToken;
}

async function jqGET(pathWithQuery) {
  const idToken = await ensureIdToken();
  const url = `${JQ_BASE}${pathWithQuery}`;
  dlog("GET", url);
  const r = await fetch(url, { headers: { Authorization: `Bearer ${idToken}` } });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = body && (body.message || body.error) ? ` ${JSON.stringify(body)}` : "";
    throw new Error(`JQ GET failed: ${r.status}${msg}`);
  }
  return body;
}

function parseIntSafe(x) {
  const n = typeof x === "string" ? parseInt(x, 10) : Number(x);
  return Number.isFinite(n) ? n : null;
}
function parseFloatSafe(x) {
  if (x === "-" || x === "*" || x === "" || x == null) return null;
  const n = typeof x === "string" ? parseFloat(x) : Number(x);
  return Number.isFinite(n) ? n : null;
}

function pick(v, ...keys) {
  for (const k of keys) {
    if (v != null && Object.prototype.hasOwnProperty.call(v, k) && v[k] != null) return v[k];
  }
  return undefined;
}

function normalizeJQDateStr(s) {
  // "2024-09-01" も "20240901" も来るので一応文字列返し
  return typeof s === "string" ? s : String(s || "");
}

function mapDailyQuote(rec) {
  // J-Quantsのケーシング（先頭大文字）に対応、下位互換キーにもフォールバック
  const date = normalizeJQDateStr(pick(rec, "Date", "date"));
  const code = String(pick(rec, "Code", "code") || "");
  const close = parseFloatSafe(pick(rec, "Close", "close"));
  const turnover = parseFloatSafe(pick(rec, "TurnoverValue", "trading_value", "turnoverValue"));
  return { date, code, close, turnover };
}

function mapWeeklyMargin(rec) {
  // 週次信用残
  const date = normalizeJQDateStr(pick(rec, "Date", "date"));
  const code = String(pick(rec, "Code", "code") || "");
  const buying = parseFloatSafe(
    pick(
      rec,
      "LongMarginTradeVolume",
      "long_margin_trade_volume",
      "buying" // 万一自前計算の再入力にも備える
    )
  ) || 0;
  const selling = parseFloatSafe(
    pick(
      rec,
      "ShortMarginTradeVolume",
      "short_margin_trade_volume",
      "selling"
    )
  ) || 0;
  const net = Number.isFinite(buying) && Number.isFinite(selling) ? (buying - selling) : null;
  const ratio = buying ? (selling / buying) : null; // 比率（％ではなく倍率）
  return { date, code, buying, selling, net, ratio };
}

function mapDailyPublic(rec) {
  // 日々公表信用残
  const date = normalizeJQDateStr(pick(rec, "PublishedDate", "Date", "date"));
  const code = String(pick(rec, "Code", "code") || "");
  const buying = parseFloatSafe(pick(rec, "LongMarginOutstanding", "long_margin_outstanding")) || 0;
  const selling = parseFloatSafe(pick(rec, "ShortMarginOutstanding", "short_margin_outstanding")) || 0;
  const net = Number.isFinite(buying) && Number.isFinite(selling) ? (buying - selling) : null;
  const slrPct = parseFloatSafe(pick(rec, "ShortLongRatio", "short_long_ratio")); // 単位：％
  const margin_rate = slrPct != null ? slrPct / 100 : null; // スキーマは ratio 相当、0-1 に正規化
  return { date, code, buying, selling, net, margin_rate };
}

function codeStr(x) {
  return String(x || "").padStart(4, "0");
}

// 営業日（HolidayDivision 1:営業日 / 2:半日 も含める）
async function getRecentTradingDates(nDays) {
  const today = new Date();
  const to = today.toISOString().slice(0, 10);
  const fromDate = new Date(today.getTime() - 400 * 24 * 60 * 60 * 1000);
  const from = fromDate.toISOString().slice(0, 10);

  const cal = await jqGET(`/markets/trading_calendar?from=${from}&to=${to}`);
  const list = (cal.trading_calendar || []).map(r => ({
    date: normalizeJQDateStr(pick(r, "Date", "date")),
    holiday: String(pick(r, "HolidayDivision", "holidayDivision", "Holiday")) // 念のため
  }));

  const biz = list.filter(d => d.holiday === "1" || d.holiday === "2").map(d => d.date);
  // 後ろから nDays
  const uniq = Array.from(new Set(biz)).sort(); // 昇順
  const out = uniq.slice(Math.max(0, uniq.length - nDays));
  dlog("trading dates picked", out.length);
  return out;
}

// 最新の営業日
async function getLatestTradingDate() {
  const d = await getRecentTradingDates(1);
  return d[0];
}

// 上場一覧（市場・名称取り）
async function getListedMap() {
  const j = await jqGET(`/listed/info`);
  const info = j.info || [];
  const map = new Map();
  for (const r of info) {
    const code = codeStr(pick(r, "Code", "code"));
    const name = String(pick(r, "CompanyName", "name") || "");
    const marketJa = String(pick(r, "MarketCodeName", "market", "Market") || ""); // 例: プライム/スタンダード/グロース
    map.set(code, { code, name, marketJa });
  }
  return map;
}

function marketMatch(marketParam, marketJa) {
  if (!marketParam || marketParam === "All") return true;
  const m = marketParam.toLowerCase();
  const ja = (marketJa || "").toLowerCase();
  if (m === "prime") return ja.includes("プライム");
  if (m === "standard") return ja.includes("スタンダード");
  if (m === "growth") return ja.includes("グロース");
  return true;
}

// ある日付（営業日）1日の全銘柄 TurnoverValue 集計
async function fetchDailyQuotesByDate(dateStr) {
  const j = await jqGET(`/prices/daily_quotes?date=${encodeURIComponent(dateStr)}`);
  const items = (j.daily_quotes || []).map(mapDailyQuote);
  return items;
}

// 直近N営業日での平均売買代金（TurnoverValue平均）と最新終値
async function buildLiquidityAndClose(days = 20) {
  const dates = await getRecentTradingDates(days);
  if (dates.length === 0) return { avgTV: new Map(), latestClose: new Map() };

  const sumTV = new Map();
  let lastDayClose = new Map();

  for (let i = 0; i < dates.length; i++) {
    const dt = dates[i];
    const items = await fetchDailyQuotesByDate(dt);
    if (i === dates.length - 1) {
      lastDayClose = new Map(items.map(it => [codeStr(it.code), it.close]));
    }
    for (const it of items) {
      const code = codeStr(it.code);
      const v = it.turnover || 0;
      if (!Number.isFinite(v)) continue;
      sumTV.set(code, (sumTV.get(code) || 0) + v);
    }
  }
  const avgTV = new Map();
  for (const [code, total] of sumTV.entries()) {
    avgTV.set(code, total / dates.length);
  }
  return { avgTV, latestClose: lastDayClose };
}

// 3/6/12か月モメンタム（終値の比率 - 1）。基準日と過去営業日スナップショットだけで計算（全銘柄一括取得）
async function buildMomentumSnapshots() {
  const dates = await getRecentTradingDates(260); // 約1年ぶん
  if (dates.length === 0) return { d0: new Map() };

  const idx = dates.length - 1;                    // 最新
  const idx3m = Math.max(0, dates.length - 63);    // おおよそ3ヶ月（63営業日）
  const idx6m = Math.max(0, dates.length - 126);   // 約6ヶ月
  const idx12m = Math.max(0, dates.length - 252);  // 約12ヶ月

  const [dq0, dq3, dq6, dq12] = await Promise.all([
    fetchDailyQuotesByDate(dates[idx]),
    fetchDailyQuotesByDate(dates[idx3m]),
    fetchDailyQuotesByDate(dates[idx6m]),
    fetchDailyQuotesByDate(dates[idx12m]),
  ]);

  const toMap = (arr) => new Map(arr.map(it => [codeStr(it.code), it.close]));
  return {
    d0: toMap(dq0),
    d3: toMap(dq3),
    d6: toMap(dq6),
    d12: toMap(dq12),
    dates: { d0: dates[idx], d3: dates[idx3m], d6: dates[idx6m], d12: dates[idx12m] }
  };
}

function calcReturn(nowClose, pastClose) {
  const a = parseFloatSafe(nowClose);
  const b = parseFloatSafe(pastClose);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b === 0) return null;
  return a / b - 1;
}

// 直近4期 EPS/BPS/DPS の合成（TTM/最新推定）
function summarizeFins(statements) {
  if (!Array.isArray(statements) || statements.length === 0) {
    return { eps_ttm: null, bps: null, dps: null, roe: null, roa: null };
  }
  // 開示日降順でソート（念のため）
  const items = [...statements].sort((a, b) => {
    const da = normalizeJQDateStr(pick(a, "DisclosedDate", "disclosedDate"));
    const db = normalizeJQDateStr(pick(b, "DisclosedDate", "disclosedDate"));
    return db.localeCompare(da);
  });

  // EPSは四半期のEarningsPerShareを最大4つ合算（TTM）
  const epsVals = [];
  for (const it of items) {
    const e = parseFloatSafe(pick(it, "EarningsPerShare", "eps", "EPS"));
    if (e != null) epsVals.push(e);
    if (epsVals.length >= 4) break;
  }
  const eps_ttm = epsVals.length ? epsVals.reduce((a, b) => a + b, 0) : null;

  // BPS（BookValuePerShare）があれば最新を採用
  const bps = parseFloatSafe(pick(items[0] || {}, "BookValuePerShare", "bps", "BPS")) ?? null;

  // 配当は ResultDividendPerShareAnnual または ForecastDividendPerShareAnnual を優先
  const dps = parseFloatSafe(
    pick(items[0] || {},
      "ResultDividendPerShareAnnual",
      "ForecastDividendPerShareAnnual",
      "dps", "DPS")
  ) ?? null;

  // ROE/ROA（もし項目があれば単純取得。J-Quants statements には固定で項目が無い場合が多い。）
  const roe = parseFloatSafe(pick(items[0] || {}, "ROE", "roe"));
  const roa = parseFloatSafe(pick(items[0] || {}, "ROA", "roa"));

  return { eps_ttm, bps, dps, roe, roa };
}

async function fetchFinsStatementsByCode(code) {
  const j = await jqGET(`/fins/statements?code=${encodeURIComponent(code)}`);
  return j.statements || [];
}

// ==============================
// ルーティング
// ==============================
export default async function handler(req, res) {
  try {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname.replace(/\/+$/, "");
    dlog("path", path);

    // CORS (必要なら調整)
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      return res.status(204).end();
    }
    res.setHeader("Access-Control-Allow-Origin", "*");

    // /api/health は無認可でOK（稼働確認用）
    if (path === "/api/health") {
      return json(res, 200, {
        ok: true,
        ts: new Date().toISOString(),
        idToken_valid_ms: msUntilExp(),
        version: VERSION
      });
    }

    // それ以外はプロキシ用ベアラー必須
    if (!requireProxyAuth(req, res)) return;

    if (path === "/api/auth/refresh" && req.method === "POST") {
      const body = typeof req.body === "object" ? req.body : {};
      // 任意で body.refreshToken / body.refreshtoken を受け付け
      const override = body?.refreshToken || body?.refreshtoken;
      const out = await refreshIdToken(override);
      return json(res, 200, out);
    }

    if (path === "/api/prices/daily" && req.method === "GET") {
      const code = url.searchParams.get("code");
      const from = url.searchParams.get("from");
      const to = url.searchParams.get("to");
      if (!code) return json(res, 400, { error: "code is required" });

      const q = new URLSearchParams({ code });
      if (from) q.set("from", from);
      if (to) q.set("to", to);

      const j = await jqGET(`/prices/daily_quotes?${q.toString()}`);
      // そのまま返す（JQのキーを温存）
      return json(res, 200, j);
    }

    if (path === "/api/fins/statements" && req.method === "GET") {
      const code = url.searchParams.get("code");
      if (!code) return json(res, 400, { error: "code is required" });

      const stmts = await fetchFinsStatementsByCode(code);
      const sum = summarizeFins(stmts);

      // 終値・時価総額・PER/PBR/配当利回り 算出（可能な範囲）
      const latestDate = await getLatestTradingDate();
      const dq = await fetchDailyQuotesByDate(latestDate);
      const me = dq.find(r => codeStr(r.code) === codeStr(code));
      const close = me?.close ?? null;

      let marketCap = null, per = null, pbr = null, dividend_yield = null;
      // 発行株数が取れないので marketCap は不明（必要なら別API/自前保存）
      // PER/PBR/配当利回りは Close と EPS/BPS/DPS があれば単純算出
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

    if (path === "/api/credit/weekly" && req.method === "GET") {
      const code = url.searchParams.get("code");
      const weeks = parseIntSafe(url.searchParams.get("weeks")) || 26;
      if (!code) return json(res, 400, { error: "code is required" });

      const j = await jqGET(`/markets/weekly_margin_interest?code=${encodeURIComponent(code)}`);
      let items = (j.weekly_margin_interest || []).map(mapWeeklyMargin);
      // 昇順に整えて、末尾から weeks 件
      items.sort((a, b) => a.date.localeCompare(b.date));
      if (items.length > weeks) items = items.slice(items.length - weeks);

      const latest = items[items.length - 1] || {};
      const prev = items[items.length - 2] || {};
      const metrics = {
        code: codeStr(code),
        latest: latest.date ? latest : {
          date: null, buying: null, selling: null, net: null, ratio: null
        },
        wow_change: {
          buying: (latest.buying != null && prev.buying != null) ? latest.buying - prev.buying : null,
          selling: (latest.selling != null && prev.selling != null) ? latest.selling - prev.selling : null,
          net: (latest.net != null && prev.net != null) ? latest.net - prev.net : null,
        }
      };

      return json(res, 200, {
        code: codeStr(code),
        count: items.length,
        metrics,
        items
      });
    }

    if (path === "/api/credit/daily_public" && req.method === "GET") {
      const code = url.searchParams.get("code");
      const days = parseIntSafe(url.searchParams.get("days")) || 60;
      if (!code) return json(res, 400, { error: "code is required" });

      // from/to は日付で切って良い（営業日でなくてもAPI側で調整される）
      const today = new Date();
      const to = today.toISOString().slice(0, 10);
      const fromDate = new Date(today.getTime() - (days + 20) * 24 * 60 * 60 * 1000);
      const from = fromDate.toISOString().slice(0, 10);

      const q = new URLSearchParams({ code, from, to });
      const j = await jqGET(`/markets/daily_margin_interest?${q.toString()}`);
      let items = (j.daily_margin_interest || []).map(mapDailyPublic);
      items.sort((a, b) => a.date.localeCompare(b.date));
      if (items.length > days) items = items.slice(items.length - days);

      return json(res, 200, {
        code: codeStr(code),
        count: items.length,
        items
      });
    }

    if (path === "/api/screen/liquidity" && req.method === "GET") {
      const market = url.searchParams.get("market") || "All";
      const minAvg = parseIntSafe(url.searchParams.get("min_avg_trading_value")) ?? 100_000_000;
      const days = parseIntSafe(url.searchParams.get("days")) ?? 20;

      const [listedMap, liq] = await Promise.all([getListedMap(), buildLiquidityAndClose(days)]);
      const out = [];

      for (const [code, avg_trading_value] of liq.avgTV.entries()) {
        const meta = listedMap.get(code) || { name: "", marketJa: "" };
        if (!marketMatch(market, meta.marketJa)) continue;
        if (!Number.isFinite(avg_trading_value) || avg_trading_value < minAvg) continue;

        out.push({
          code,
          name: meta.name,
          market: meta.marketJa,
          avg_trading_value: Math.round(avg_trading_value)
        });
      }

      out.sort((a, b) => b.avg_trading_value - a.avg_trading_value);
      return json(res, 200, { count: out.length, items: out });
    }

    if (path === "/api/screen/basic" && req.method === "GET") {
      const market = url.searchParams.get("market") || "All";
      const limit = Math.min(Math.max(parseIntSafe(url.searchParams.get("limit")) || 30, 1), 200);
      const liquidity_min = parseIntSafe(url.searchParams.get("liquidity_min")) ?? 100_000_000;
      const per_lt = url.searchParams.get("per_lt") != null ? parseFloatSafe(url.searchParams.get("per_lt")) : null;
      const pbr_lt = url.searchParams.get("pbr_lt") != null ? parseFloatSafe(url.searchParams.get("pbr_lt")) : null;
      const div_yield_gt = url.searchParams.get("div_yield_gt") != null ? parseFloatSafe(url.searchParams.get("div_yield_gt")) : null;
      const mom3m_gt = url.searchParams.get("mom3m_gt") != null ? parseFloatSafe(url.searchParams.get("mom3m_gt")) : null;

      const [listedMap, { avgTV, latestClose }, momSnaps] = await Promise.all([
        getListedMap(),
        buildLiquidityAndClose(20),
        buildMomentumSnapshots()
      ]);

      const items = [];
      for (const [code, avg_trading_value] of avgTV.entries()) {
        const meta = listedMap.get(code) || { name: "", marketJa: "" };
        if (!marketMatch(market, meta.marketJa)) continue;
        if (!Number.isFinite(avg_trading_value) || avg_trading_value < liquidity_min) continue;

        // モメンタム計算
        const mom_3m = calcReturn(momSnaps.d0.get(code), momSnaps.d3.get(code));
        const mom_6m = calcReturn(momSnaps.d0.get(code), momSnaps.d6.get(code));
        const mom_12m = calcReturn(momSnaps.d0.get(code), momSnaps.d12.get(code));

        if (mom3m_gt != null && (mom_3m == null || mom_3m < mom3m_gt)) continue;

        // バリュー系（必要時のみ計算）—— per/pbr/yield 指定があれば statements 呼び
        let per = null, pbr = null, dividend_yield = null, eps_ttm = null, bps = null, dps = null;
        if (per_lt != null || pbr_lt != null || div_yield_gt != null) {
          try {
            const stmts = await fetchFinsStatementsByCode(code);
            const s = summarizeFins(stmts);
            eps_ttm = s.eps_ttm; bps = s.bps; dps = s.dps;
            const close = latestClose.get(code);
            if (Number.isFinite(close)) {
              if (s.eps_ttm != null && s.eps_ttm !== 0) per = close / s.eps_ttm;
              if (s.bps != null && s.bps !== 0) pbr = close / s.bps;
              if (s.dps != null && close !== 0) dividend_yield = s.dps / close;
            }
          } catch (e) {
            dlog("fins fetch failed for", code, e.message);
          }

          if (per_lt != null && !(per != null && per < per_lt)) continue;
          if (pbr_lt != null && !(pbr != null && pbr < pbr_lt)) continue;
          if (div_yield_gt != null && !(dividend_yield != null && dividend_yield > div_yield_gt)) continue;
        }

        // 簡易スコア（流動性 + 3mモメンタムを主軸）
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
      const sliced = items.slice(0, limit);
      return json(res, 200, { count: sliced.length, items: sliced });
    }

    if (path === "/api/portfolio/summary" && req.method === "GET") {
      const codesParam = url.searchParams.get("codes");
      const with_credit = parseIntSafe(url.searchParams.get("with_credit")) === 1;
      if (!codesParam) return json(res, 400, { error: "codes is required (comma-separated)" });

      const codes = codesParam.split(",").map(s => codeStr(s.trim())).filter(Boolean);
      const [listedMap, latestDate] = await Promise.all([getListedMap(), getLatestTradingDate()]);
      const dq = await fetchDailyQuotesByDate(latestDate);
      const closeMap = new Map(dq.map(it => [codeStr(it.code), it.close]));

      const out = [];
      for (const code of codes) {
        let close = closeMap.get(code) ?? null;
        let per = null, pbr = null, dividend_yield = null, eps_ttm = null, bps = null, dps = null;
        let credit_latest = null;
        let error = null;

        try {
          const stmts = await fetchFinsStatementsByCode(code);
          const s = summarizeFins(stmts);
          eps_ttm = s.eps_ttm; bps = s.bps; dps = s.dps;

          if (Number.isFinite(close)) {
            if (s.eps_ttm != null && s.eps_ttm !== 0) per = close / s.eps_ttm;
            if (s.bps != null && s.bps !== 0) pbr = close / s.bps;
            if (s.dps != null && close !== 0) dividend_yield = s.dps / close;
          }
        } catch (e) {
          error = e.message;
        }

        if (with_credit) {
          try {
            const j = await jqGET(`/markets/weekly_margin_interest?code=${encodeURIComponent(code)}`);
            const arr = (j.weekly_margin_interest || []).map(mapWeeklyMargin).sort((a, b) => a.date.localeCompare(b.date));
            credit_latest = arr[arr.length - 1] || null;
          } catch (e) {
            error = (error ? error + "; " : "") + e.message;
          }
        }

        out.push({
          code,
          close, per, pbr, dividend_yield,
          eps_ttm, bps, dps,
          credit_latest,
          error: error || null
        });
      }

      return json(res, 200, { count: out.length, items: out });
    }

    // 未対応
    return json(res, 404, { error: `No route for ${path}` });
  } catch (e) {
    console.error(e);
    return json(res, 500, { error: e.message || "Internal error" });
  }
}
