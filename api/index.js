// api/index.js
// J-Quants JP Proxy (Screening) — full replacement (paging + fast mode + codes[] fix)
// 必須Env: PROXY_BEARER
// どちらか: (A) JQ_REFRESH_TOKEN  または  (B) JQ_EMAIL + JQ_PASSWORD
// 任意Env: LOG_LEVEL=debug で簡易デバッグログ

const JQ_BASE = "https://api.jquants.com/v1";
const VERSION = "1.1.0-full-paging-fast";

const isDebug = () => (process.env.LOG_LEVEL || "").toLowerCase() === "debug";
const dlog = (...args) => { if (isDebug()) console.log("[DEBUG]", ...args); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function json(res, code, obj) { res.status(code).json(obj); }
function now() { return Date.now(); }
function readIdTokenOverride(req) {
  const h = req.headers["x-id-token"] || req.headers["X-ID-TOKEN"];
  return (typeof h === "string" && h.trim()) ? h.trim() : null;
}

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
// J-Quantsの日足は 5桁 (例: 67580)。銘柄の“本体コード”は先頭4桁なので統一する。
function codeStr(x) {
  const s = String(x || "").trim();
  // 先頭4桁が数字ならそれを採用（5桁の末尾セクター桁を落とす）
  const m = s.match(/^(\d{4})\d$/);
  if (m) return m[1];
  // 5桁以上だが先頭4桁が数字なら先頭4桁
  const n = s.match(/^(\d{4})/);
  if (n) return n[1];
  // それ以外はゼロ埋め4桁
  return s.padStart(4, "0");
}
function normDateStr(s) { return typeof s === "string" ? s : String(s || ""); }

// -------------------- 認証（refreshToken / idToken キャッシュ）
let REFRESH_TOKEN = process.env.JQ_REFRESH_TOKEN || null;
let REFRESH_TOKEN_EXP_AT = REFRESH_TOKEN ? 0 : 0; // env提供時は有効期限不明
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

// /token/auth_user（週1発行想定）
async function fetchRefreshTokenFromUserPass() {
  const mail = process.env.JQ_EMAIL;
  const pass = process.env.JQ_PASSWORD;
  if (!mail || !pass) throw new Error("Missing JQ_EMAIL / JQ_PASSWORD");

  const r = await fetch(`${JQ_BASE}/token/auth_user`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mailaddress: mail, password: pass }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.refreshToken) {
    throw new Error(`auth_user failed: ${r.status} ${JSON.stringify(j)}`);
  }
  REFRESH_TOKEN = j.refreshToken;
  REFRESH_TOKEN_EXP_AT = Date.now() + 7 * 24 * 60 * 60 * 1000 - 10 * 60 * 1000; // 1週間 -10分
  dlog("refreshToken issued");
  return REFRESH_TOKEN;
}
function refreshTokenValid() {
  return !!REFRESH_TOKEN && (REFRESH_TOKEN_EXP_AT === 0 || REFRESH_TOKEN_EXP_AT > Date.now());
}
let inflightGetRT = null;
async function ensureRefreshToken() {
  if (refreshTokenValid()) return REFRESH_TOKEN;
  if (inflightGetRT) return inflightGetRT;
  inflightGetRT = (async () => {
    if (process.env.JQ_REFRESH_TOKEN && !REFRESH_TOKEN) {
      REFRESH_TOKEN = process.env.JQ_REFRESH_TOKEN;
      REFRESH_TOKEN_EXP_AT = 0; // 不明
      return REFRESH_TOKEN;
    }
    return await fetchRefreshTokenFromUserPass();
  })();
  try { return await inflightGetRT; } finally { inflightGetRT = null; }
}

let inflightGetID = null;
async function refreshIdToken(maybeRefreshToken) {
  const refreshToken = maybeRefreshToken || await ensureRefreshToken();
  const url = `${JQ_BASE}/token/auth_refresh?refreshtoken=${encodeURIComponent(refreshToken)}`;
  const r = await fetch(url, { method: "POST" });
  const t = await r.json().catch(() => ({}));

  if (!r.ok || !t.idToken) {
    REFRESH_TOKEN = null; REFRESH_TOKEN_EXP_AT = 0;
    const rt2 = await ensureRefreshToken();
    const r2 = await fetch(`${JQ_BASE}/token/auth_refresh?refreshtoken=${encodeURIComponent(rt2)}`, { method: "POST" });
    const t2 = await r2.json().catch(() => ({}));
    if (!r2.ok || !t2.idToken) throw new Error(`auth_refresh failed: ${r2.status} ${JSON.stringify(t2)}`);
    ID_TOKEN = t2.idToken;
  } else {
    ID_TOKEN = t.idToken;
  }
  ID_TOKEN_EXP_AT = Date.now() + 24 * 60 * 60 * 1000 - 5 * 60 * 1000; // 24h -5分
  return { idToken: ID_TOKEN, expAt: ID_TOKEN_EXP_AT };
}
async function ensureIdToken() {
  if (ID_TOKEN && msUntilExp() > 0) return ID_TOKEN;
  if (inflightGetID) return inflightGetID;
  inflightGetID = (async () => (await refreshIdToken()).idToken)();
  try { return await inflightGetID; } finally { inflightGetID = null; }
}

// 任意：クライアントが直渡しする場合
async function jqGET(pathWithQuery, idTokenOverride) {
  const idToken = idTokenOverride || await ensureIdToken();
  const url = `${JQ_BASE}${pathWithQuery}`;
  let attempt = 0, lastErr;

  while (attempt < 3) {
    attempt++;
    try {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${idToken}` } });
      const body = await r.json().catch(() => ({}));
      if (r.ok) return body;

      // レート・一時障害はリトライ
      if ([429, 500, 502, 503, 504].includes(r.status)) {
        const backoff = 300 * Math.pow(2, attempt - 1); // 300, 600, 1200ms
        await sleep(backoff);
        continue;
      }
      // その他は即エラー
      const msg = body && (body.message || body.error) ? ` ${JSON.stringify(body)}` : "";
      throw new Error(`JQ GET failed: ${r.status}${msg}`);
    } catch (e) {
      lastErr = e;
      if (attempt >= 3) break;
      await sleep(300 * Math.pow(2, attempt - 1));
    }
  }
  throw lastErr || new Error("JQ GET failed");
}

// ★ ページングを最後まで取り切る共通ヘルパー
async function jqGETAll(path, idTokenOverride, opt = {}) {
  const maxPages = Number(opt.maxPages ?? 50);   // 上限
  const sleepMs  = Number(opt.sleepMs  ?? 120);  // ページ間の待機

  let out = [], next = null, pages = 0;
  do {
    const url = next ? `${path}&pagination_key=${encodeURIComponent(next)}` : path;
    const j = await jqGET(url, idTokenOverride);
    if (Array.isArray(j.daily_quotes)) out = out.concat(j.daily_quotes);
    next = j.pagination_key || null;
    pages++;
    if (next && pages < maxPages && sleepMs > 0) await sleep(sleepMs);
  } while (next && pages < maxPages);

  return out;
}

// -------------------- マッピング
function mapDailyQuote(rec) {
  return {
    date: normDateStr(pick(rec, "Date", "date")),
    code: codeStr(pick(rec, "Code", "code") || ""),
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
    code: codeStr(pick(rec, "Code", "code") || ""),
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
    code: codeStr(pick(rec, "Code", "code") || ""),
    buying: Number.isFinite(buy) ? buy : 0,
    selling: Number.isFinite(sell) ? sell : 0,
    net: (Number.isFinite(buy) && Number.isFinite(sell)) ? (buy - sell) : null,
    margin_rate: (r != null ? (r > 1 ? r / 100 : r) : null) // ％→0-1正規化
  };
}

// -------------------- 上場銘柄/営業日/株価ユーティリティ
async function getListedMap(idTokenOverride) {
  const j = await jqGET(`/listed/info`, idTokenOverride);
  const info = j.info || [];
  const m = new Map();
  for (const it of info) {
    const c = codeStr(pick(it, "Code", "code"));
    m.set(c, {
      code: c,
      name: String(pick(it, "CompanyName", "name") || ""),
      marketJa: String(pick(it, "MarketCodeName", "Market", "market") || "")
    });
  }
  return m;
}
function marketMatch(marketParam, marketNameRaw) {
  if (!marketParam || marketParam === "All") return true;

  const want = String(marketParam).trim().toLowerCase();
  const s = String(marketNameRaw || "").trim().toLowerCase();

  // 日本語・英語双方の代表語／略語に対応
  const PRIME = ["プライム", "prime", "tse prime", "prime market"];
  const STANDARD = ["スタンダード", "standard", "tse standard", "standard market"];
  const GROWTH = ["グロース", "growth", "tse growth", "growth market"];

  if (want === "prime")    return s === "" ? true : PRIME.some(k => s.includes(k));
  if (want === "standard") return s === "" ? true : STANDARD.some(k => s.includes(k));
  if (want === "growth")   return s === "" ? true : GROWTH.some(k => s.includes(k));

  // 未知指定は通す（落とし過ぎ防止）
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
async function fetchDailyQuotesByDate(dateStr, idTokenOverride, opt = {}) {
  const arr = await jqGETAll(`/prices/daily_quotes?date=${encodeURIComponent(dateStr)}`, idTokenOverride, opt);
  return arr.map(mapDailyQuote);
}

// 流動性（売買代金）の算出：
// mode="avg": 直近N営業日の平均（重い）
// mode="latest": 直近1日で近似（軽い・推奨）
async function buildLiquidityAndClose(days = 20, idTokenOverride, mode = "latest") {
  if (mode === "latest") {
    const dates = await getRecentTradingDates(1, idTokenOverride);
    if (dates.length === 0) return { avgTV: new Map(), latestClose: new Map() };
    const items = await fetchDailyQuotesByDate(dates[0], idTokenOverride);
    const latestClose = new Map(items.map(it => [codeStr(it.code), it.close]));
    const avgTV = new Map(items.map(it => [codeStr(it.code), Number(it.turnover) || 0]));
    return { avgTV, latestClose };
  }
  // 旧来: 平均モード（重いが精度高）
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

// 3/6/12か月モメンタム（営業日ベース近似）
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
// ---- 強化版：財務の値取得（キー揺れ対応 + あいまい一致） ----
function numFrom(obj, options) {
  // options: { aliases?: string[], regexKeys?: RegExp[], coerce?: (n)=>number|null }
  if (!obj || typeof obj !== "object") return null;
  const { aliases = [], regexKeys = [], coerce } = options || {};

  // 1) 厳密キー（大文字小文字＆スネーク/キャメル差吸収）
  const norm = s => String(s).toLowerCase().replace(/[^a-z0-9]/g, "");
  const normMap = new Map();
  for (const k of Object.keys(obj)) normMap.set(norm(k), k);

  for (const a of aliases) {
    const k = normMap.get(norm(a));
    if (k != null) {
      const v = obj[k];
      if (v !== "" && v !== "-" && v !== "*" && v != null && Number.isFinite(Number(v))) {
        const n = Number(v);
        return coerce ? coerce(n) : n;
      }
    }
  }

  // 2) 正規表現でキー名を走査（例：/book.*value.*per.*share/i）
  if (regexKeys.length) {
    for (const k of Object.keys(obj)) {
      for (const re of regexKeys) {
        if (re.test(k)) {
          const v = obj[k];
          if (v !== "" && v !== "-" && v !== "*" && v != null && Number.isFinite(Number(v))) {
            const n = Number(v);
            return coerce ? coerce(n) : n;
          }
        }
      }
    }
  }
  return null;
}

// BPS を Equity / Shares から算出（スケール異常に軽い補正ロジック付き）
function deriveBpsFromEquityShares(latest) {
  if (!latest) return null;

  // 純資産（親会社株主帰属）候補
  const equity = numFrom(latest, {
    aliases: [
      "Equity", "NetAssets", "TotalEquity", "EquityAttributableToOwnersOfParent"
    ],
    regexKeys: [
      /^(equity|net.?assets|total.?equity|equity.?attributable.*parent)$/i
    ]
  });

  // 期末発行株式数（自己株含む/含まない等いろいろ）
  let shares = numFrom(latest, {
    aliases: [
      "NumberOfIssuedAndOutstandingSharesAtEndOfFiscalYearIncludingTreasuryStock",
      "NumberOfIssuedAndOutstandingSharesAtEndOfFiscalYear",
      "IssuedShares",
      "CommonSharesOutstanding",
      "NumberOfShares"
    ],
    regexKeys: [
      /issued.*outstanding.*shares.*(fiscal|year|end)?/i,
      /common.*shares.*outstanding/i,
      /number.*of.*shares/i
    ]
  });

  if (equity == null || shares == null || shares <= 0) return null;

  // 一部データは「千株/百万株」単位のことがあるので、雑にスケール補正を試みる
  // 目安：日本の大型株で shares が 1e12 を超えることは稀 → 1e6, 1e3 で割るケースをチェック
  const tryScales = [1, 1e3, 1e6];
  let best = null;
  for (const s of tryScales) {
    const perShare = equity / (shares * s);
    if (Number.isFinite(perShare) && perShare > 0 && perShare < 1e7) {
      // ざっくり「1株純資産が1円〜1,000万円」の間を常識値として採用
      best = perShare;
      break;
    }
  }
  return best;
}

// ---- 置き換え版 summarizeFins（EPS/BPS/DPS/ROE/ROA を最大限埋める） ----
function summarizeFins(statements) {
  if (!Array.isArray(statements) || statements.length === 0) {
    return { eps_ttm: null, bps: null, dps: null, roe: null, roa: null };
  }

  // 開示日降順
  const items = [...statements].sort((a, b) => {
    const da = String(a.DisclosedDate || a.disclosedDate || "");
    const db = String(b.DisclosedDate || b.disclosedDate || "");
    return db.localeCompare(da);
  });

  const latest = items[0] || {};
  const prev   = items[1] || {};

  // EPS (TTM) … 直近4期合算
  const epsVals = [];
  for (let i = 0; i < Math.min(4, items.length); i++) {
    const e = numFrom(items[i], {
      aliases: ["EarningsPerShare", "EPS", "eps"],
      regexKeys: [/^eps$/i, /earnings.*per.*share/i]
    });
    if (e != null) epsVals.push(e);
  }
  const eps_ttm = epsVals.length ? epsVals.reduce((a, b) => a + b, 0) : null;

  // BPS … 1) 直接 per-share 値 → 2) Equity/Shares から算出
  let bps =
    numFrom(latest, {
      aliases: ["BookValuePerShare", "NetAssetsPerShare", "BPS", "bps", "EquityPerShare"],
      regexKeys: [/book.*value.*per.*share/i, /net.*assets.*per.*share/i, /\bbps\b/i, /equity.*per.*share/i]
    });
  if (bps == null) bps = deriveBpsFromEquityShares(latest);

  // DPS … 実績 > 予想。無ければ四半期の CashDividendsPaidPerShare を合算（年換算の代替）
  let dps = numFrom(latest, {
    aliases: [
      "ResultDividendPerShareAnnual",
      "ForecastDividendPerShareAnnual",
      "DividendPerShare", "DPS", "dps"
    ],
    regexKeys: [/dividend.*per.*share/i]
  });
  if (dps == null) {
    let sum = 0, seen = 0;
    for (let i = 0; i < Math.min(4, items.length); i++) {
      const q = numFrom(items[i], { aliases: ["CashDividendsPaidPerShare"], regexKeys: [/cash.*dividends.*per.*share/i] });
      if (q != null) { sum += q; seen++; }
    }
    if (seen > 0) dps = sum;
  }

  // ROE/ROA … 近似：TTM純利益 / ((期末 + 1期前末)/2)
  // TTM親会社株主利益
  let ni_ttm = null;
  let sumNI = 0, cnt = 0;
  for (let i = 0; i < Math.min(4, items.length); i++) {
    const ni = numFrom(items[i], {
      aliases: [
        "ProfitLossAttributableToOwnersOfParent",
        "NetIncome", "NetIncomeAttributableToOwnersOfParent"
      ],
      regexKeys: [/profit.*owners.*parent/i, /net.*income/i]
    });
    if (ni != null) { sumNI += ni; cnt++; }
  }
  if (cnt > 0) ni_ttm = sumNI;

  const eq_end = numFrom(latest, {
    aliases: ["Equity", "NetAssets", "TotalEquity", "EquityAttributableToOwnersOfParent"],
    regexKeys: [/^equity$/i, /net.?assets/i, /total.?equity/i, /equity.?attributable.*parent/i]
  });
  const eq_begin = numFrom(prev, {
    aliases: ["Equity", "NetAssets", "TotalEquity", "EquityAttributableToOwnersOfParent"],
    regexKeys: [/^equity$/i, /net.?assets/i, /total.?equity/i, /equity.?attributable.*parent/i]
  });

  const ta_end = numFrom(latest, { aliases: ["TotalAssets"], regexKeys: [/total.*assets/i] });
  const ta_begin = numFrom(prev,   { aliases: ["TotalAssets"], regexKeys: [/total.*assets/i] });

  const eq_avg = (eq_end != null && eq_begin != null) ? (eq_end + eq_begin) / 2 : null;
  const ta_avg = (ta_end != null && ta_begin != null) ? (ta_end + ta_begin) / 2 : null;

  let roe = null, roa = null;
  if (ni_ttm != null && eq_avg && eq_avg !== 0) roe = ni_ttm / eq_avg;
  if (ni_ttm != null && ta_avg && ta_avg !== 0) roa = ni_ttm / ta_avg;

  return { eps_ttm, bps, dps, roe, roa };
}

async function fetchFinsStatementsByCode(code, idTokenOverride) {
  const j = await jqGET(`/fins/statements?code=${encodeURIComponent(code)}`, idTokenOverride);
  return j.statements || [];
}

// -------------------- ルーター
export default async function handler(req, res) {
  try {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname.replace(/\/+$/, "");
    const method = req.method.toUpperCase();
    // /api/health は idToken 不要。先に health を返してから読む
    let idTokenOverride = null;

    // CORS
    if (method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-ID-TOKEN");
      return res.status(204).end();
    }
    res.setHeader("Access-Control-Allow-Origin", "*");

    // /api/health (no auth)
    if (path === "/api/health" && method === "GET") {
      return json(res, 200, {
        ok: true,
        ts: new Date().toISOString(),
        idToken_valid_ms: msUntilExp(),
        version: VERSION
      });
    }
    idTokenOverride = readIdTokenOverride(req);

    // それ以外はプロキシ用Bearer必須
    if (!requireProxyAuth(req, res)) return;

    // /api/auth/refresh
    if (path === "/api/auth/refresh" && method === "POST") {
      const body = typeof req.body === "object" ? req.body : {};
      const override = body?.refreshToken || body?.refreshtoken;
      const out = await refreshIdToken(override);
      return json(res, 200, out);
    }

    // /api/prices/daily
    if (path === "/api/prices/daily" && method === "GET") {
      const code = url.searchParams.get("code");
      const from = url.searchParams.get("from");
      const to = url.searchParams.get("to");
      if (!code) return json(res, 400, { error: "code is required" });

      const q = new URLSearchParams({ code });
      if (from) q.set("from", from);
      if (to) q.set("to", to);
      const j = await jqGET(`/prices/daily_quotes?${q.toString()}`, idTokenOverride);
      return json(res, 200, j); // JQの形式のまま返す
    }

    // /api/fins/statements
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

    // /api/credit/weekly
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

    // /api/credit/daily_public
    if (path === "/api/credit/daily_public" && method === "GET") {
      const code = url.searchParams.get("code");
      const days = Math.max(7, toInt(url.searchParams.get("days")) || 60);
      if (!code) return json(res, 400, { error: "code is required" });

      // ※対象銘柄でなければ空で返るのが正常。日付幅は広めに。
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

    // /api/universe: コードをページングで返す（軽量）
    if (path === "/api/universe" && method === "GET") {
      try {
        const market = url.searchParams.get("market") || "All";
        const liquidity_min = toInt(url.searchParams.get("liquidity_min")) ?? 100_000_000;
        const offset = Math.max(0, toInt(url.searchParams.get("offset")) ?? 0);
        const limit = Math.min(200, Math.max(1, toInt(url.searchParams.get("limit")) ?? 150));

        // 既定は軽量：直近1日
        const { avgTV } = await buildLiquidityAndClose(5, idTokenOverride, "latest");
        const listedMap = await getListedMap(idTokenOverride);

        // 市場＆流動性で母集団化 → TV降順
        const rows = [];
        for (const [code, tv] of avgTV.entries()) {
          if (!Number.isFinite(tv) || tv < liquidity_min) continue;
          const meta = listedMap.get(code) || { marketJa: "" };
          if (!marketMatch(market, meta.marketJa || "")) continue;
          rows.push([code, tv]);
        }
        rows.sort((a, b) => b[1] - a[1]);

        const page = rows.slice(offset, offset + limit).map(r => r[0]);
        return json(res, 200, {
          total: rows.length,
          offset,
          limit,
          codes: page
        });
      } catch (e) {
        return json(res, 200, { total: 0, offset: 0, limit: 0, codes: [], error: String(e && e.message || e) });
      }
    }

    // /api/screen/liquidity（fast=1 で軽量取得）
    if (path === "/api/screen/liquidity" && method === "GET") {
      const maxPages = toInt(url.searchParams.get("max_pages")) ?? undefined;
      const sleepMs  = toInt(url.searchParams.get("sleep_ms"))  ?? undefined;
      const jqAllOpt = { maxPages, sleepMs };
      const market = url.searchParams.get("market") || "All";
      const minAvg = toInt(url.searchParams.get("min_avg_trading_value")) ?? 100_000_000;
      const days = toInt(url.searchParams.get("days"));
      const fast = toInt(url.searchParams.get("fast")) === 1;
      const liqMode = (url.searchParams.get("liquidity_mode") || (fast ? "latest" : "latest")).toLowerCase(); // 既定=latest
      const daysEff = (days != null ? days : (fast ? 5 : 20));

      const [listedMap, liq] = await Promise.all([
        getListedMap(idTokenOverride),
        buildLiquidityAndClose(daysEff, idTokenOverride, liqMode)
      ]);

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

    // /api/screen/basic（軽量・段階フィルタ・時間予算・デバッグ）
    // ここ全体を置き換え
    if (path === "/api/screen/basic" && method === "GET") {
      // 常に {count, items} を 200 で返す（コネクタが {} に潰さないように）
      const safeReturn = (payload) => json(res, 200, Object.assign({ count: 0, items: [] }, payload));

      // パラメータ取るユーティリティ
      const numOrNull = (v) => (v == null ? null : (Number.isFinite(Number(v)) ? Number(v) : null));
      const intOrNull = (v) => (v == null ? null : (Number.isFinite(parseInt(v, 10)) ? parseInt(v, 10) : null));

      try {
        const market = url.searchParams.get("market") || "All";
        const limit = Math.min(Math.max(intOrNull(url.searchParams.get("limit")) || 30, 1), 200);
        const liquidity_min = intOrNull(url.searchParams.get("liquidity_min")) ?? 100_000_000;

        const per_lt = numOrNull(url.searchParams.get("per_lt"));
        const pbr_lt = numOrNull(url.searchParams.get("pbr_lt"));
        let div_yield_gt = numOrNull(url.searchParams.get("div_yield_gt"));
        // 2.5 → 0.025 のフォールバック（%指定対策）
        if (div_yield_gt != null && div_yield_gt > 1 && div_yield_gt <= 100) div_yield_gt = div_yield_gt / 100;

        const mom3m_gt = numOrNull(url.searchParams.get("mom3m_gt"));

        // 既定＝軽量
        const fastParam = (url.searchParams.get("fast") || "1").toLowerCase();
        const fast = (fastParam === "1" || fastParam === "true");

        // モメンタムは“条件がある時だけ”
        const needMomentum = (mom3m_gt != null);

        // 既定＝直近1日で流動性近似
        const liqMode = (url.searchParams.get("liquidity_mode") || "latest").toLowerCase();

        // デバッグ / 時間予算 / 走査上限
        const debug = (url.searchParams.get("debug") || "") === "1";
        const t0 = Date.now();
        const DBG = { phase: "start" };
        const budgetMs = intOrNull(url.searchParams.get("budget_ms")) ?? 25000;
        const deadline = t0 + Math.max(5000, budgetMs);
        const timeLeft = () => deadline - Date.now();

        // 財務API叩く銘柄数の上限（大きすぎると時間切れ）
        const MAX_SCAN = intOrNull(url.searchParams.get("max_scan")) ?? 500;

        // 対象銘柄の事前絞り込み（任意）
        const uniParam = url.searchParams.get("universe");
        const uniMulti = url.searchParams.getAll("universe");
        let allowSet = null;
        if (uniParam || (uniMulti && uniMulti.length > 1)) {
          const raw = [
            ...(uniParam ? uniParam.split(",") : []),
            ...((uniMulti.length > 1) ? uniMulti : [])
          ].map(s => codeStr(String(s).trim())).filter(Boolean);
          allowSet = new Set(raw);
          DBG.universe = raw.length;
        }

        // ===== 事前フェッチ（上場一覧 / 流動性 / モメンタム）=====
        const [listedMap, { avgTV, latestClose }, momSnaps] = await Promise.all([
          getListedMap(idTokenOverride).then(v => (DBG.listed = true, v)),
          buildLiquidityAndClose(fast ? 5 : 20, idTokenOverride, liqMode).then(v => (DBG.liq = true, v)),
          (needMomentum ? buildMomentumSnapshots(idTokenOverride) : Promise.resolve({ d0:new Map(), d3:new Map(), d6:new Map(), d12:new Map() }))
            .then(v => (DBG.mom = needMomentum, v)),
        ]);

        // 流動性候補が 0 なら即返す
        if (!avgTV || avgTV.size === 0) {
          if (debug) return safeReturn({ _debug: Object.assign(DBG, { reason: "no_liquidity", ms: Date.now() - t0 }) });
          return safeReturn({});
        }

        // ===== 第1段：母集団を作る（市場＋流動性のみ） =====
        // → これを “売買代金の大きい順” にソートしてから順に評価（上位で成立しやすい）
        const cands = [];
        for (const [code, tv] of avgTV.entries()) {
          if (allowSet && !allowSet.has(code)) continue;
          if (!Number.isFinite(tv) || tv < liquidity_min) continue;

          const meta = listedMap.get(code) || { name: "", marketJa: "" };
          const mname = meta.marketJa || ""; // 空は通す（落とし過ぎ防止）
          if (!marketMatch(market, mname)) continue;

          cands.push([code, tv]);
        }
        DBG.candidates = cands.length;

        if (cands.length === 0) {
          if (debug) return safeReturn({ _debug: Object.assign(DBG, { reason: "filtered_by_market_or_liq", ms: Date.now() - t0 }) });
          return safeReturn({});
        }

        // 売買代金の降順に並べて“重い順に優先的に”評価
        cands.sort((a, b) => b[1] - a[1]);

        // ===== 第2段：必要ならモメンタム判定 =====
        // mom3m_gt があるときだけ d0/d3 を使う（他は評価コスト無し）
        const items = [];
        let processed = 0, scanned = 0, kept = 0;

        for (const [code, tv] of cands) {
          processed++;
          if (timeLeft() <= 0) break;
          if (items.length >= limit) break;

          // モメンタム
          let mom_3m = null, mom_6m = null, mom_12m = null;
          if (needMomentum) {
            mom_3m = calcReturn(momSnaps.d0.get(code), momSnaps.d3.get(code));
            if (mom3m_gt != null && (mom_3m == null || mom_3m < mom3m_gt)) continue;
            // 3/6/12 は“返すときに見たい”方のために取る（条件未指定ならスコアには使わない）
            mom_6m = calcReturn(momSnaps.d0.get(code), momSnaps.d6.get(code));
            mom_12m = calcReturn(momSnaps.d0.get(code), momSnaps.d12.get(code));
          }

          // ===== 第3段：バリュー条件（ある場合のみ財務取得）=====
          let per = null, pbr = null, dividend_yield = null;
          if (per_lt != null || pbr_lt != null || div_yield_gt != null) {
            if (timeLeft() <= 0 || scanned >= MAX_SCAN) break;
            scanned++;

            try {
              const stmts = await fetchFinsStatementsByCode(code, idTokenOverride);
              const s = summarizeFins(stmts);
              const close = latestClose.get(code);

              if (Number.isFinite(close)) {
                if (s.eps_ttm != null && s.eps_ttm !== 0) per = close / s.eps_ttm;
                if (s.bps != null && s.bps !== 0) pbr = close / s.bps;
                if (s.dps != null && close !== 0) dividend_yield = s.dps / close;
              }

              // AND ロジック（両方指定時は両方満たす）
              if (per_lt != null && !(per != null && per < per_lt)) continue;
              if (pbr_lt != null && !(pbr != null && pbr < pbr_lt)) continue;
              if (div_yield_gt != null && !(dividend_yield != null && dividend_yield > div_yield_gt)) continue;
            } catch (_) {
              // 財務で失敗した銘柄はスキップ（全体は落とさない）
              continue;
            }
          }

          // スコア（軽量：流動性のみ／必要なら mom3m を加味）
          const liqScore = Math.log10(Math.max(1, tv));
          const momScore = (mom_3m == null ? 0 : mom_3m * 100);
          const score = Math.round(10 * (liqScore + momScore));

          const meta = listedMap.get(code) || { name: "" };
          items.push({
            code,
            name: meta.name,
            per, pbr, dividend_yield,
            mom_3m, mom_6m, mom_12m,
            avg_trading_value: Math.round(tv),
            score
          });
          kept++;
        }

        items.sort((a, b) => b.score - a.score);
        const payload = { count: Math.min(items.length, limit), items: items.slice(0, limit) };

        if (debug) payload._debug = Object.assign(DBG, {
          processed, kept, scanned,
          ms: Date.now() - t0, budget_ms: budgetMs
        });

        return safeReturn(payload);
      } catch (e) {
        return safeReturn({ error: String(e && e.message || e) });
      }
    }


    // /api/portfolio/summary（codes の explode/非explode 両対応）
    if (path === "/api/portfolio/summary" && method === "GET") {
      const codesParam = url.searchParams.get("codes");
      const codesMulti = url.searchParams.getAll("codes"); // explode=true 互換
      const with_credit = toInt(url.searchParams.get("with_credit")) === 1;

      const rawList = [
        ...(codesParam ? codesParam.split(",") : []),
        ...((codesMulti.length > 1) ? codesMulti : [])
      ].map(s => String(s).trim()).filter(Boolean);

      if (rawList.length === 0) return json(res, 400, { error: "codes is required" });
      const codes = rawList.map(codeStr);

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
