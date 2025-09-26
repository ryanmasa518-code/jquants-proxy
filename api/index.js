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
  // PROXY_BEARER 未設定ならスキップ
  if (!PROXY_BEARER) return true;

  try {
    // 1) Authorization: Bearer xx
    const h = (req.headers?.["authorization"] || "").toString();
    const bearer = h.startsWith("Bearer ") ? h.slice(7) : "";

    // 2) X-Proxy-Key: xx（開発用）
    const xkey = (req.headers?.["x-proxy-key"] || "").toString();

    // 3) ?key=xx（開発用：ブラウザ/簡易テスト向け）
    const url = safeParseURL(req);
    const qkey = (url.searchParams.get("key") || "").toString();

    const token = bearer || xkey || qkey;
    return !!token && token === PROXY_BEARER;
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
    const data = await jqFetch("/prices/daily_quotes", { code, from: rawFrom, to: rawTo }, idToken);

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
        daily = await jqFetch("/prices/daily_quotes", { code, from, to }, idToken);
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

// ===== A) /api/fins/statements =====
// 目的: 直近の財務データから TTM EPS / ROE / ROA / DPS / 配当利回り を算出して返す
// 使うAPI: GET /v1/fins/statements?code=XXXX
// 注意: J-Quantsのキー名は時期により揺れがあるため、緩めにパース

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}
function pick(obj, keys) {
  for (const k of keys) if (obj && obj[k] != null) return obj[k];
  return undefined;
}
// 直近(四半期/通期)の配列を新しい順に並べ替える補助（可能なら 'DisclosedDate' や 'FiscalYear'+'FiscalQuarter' を使う）
function sortRecent(a, b) {
  const da = pick(a, ["DisclosedDate", "disclosedDate", "date"]) || `${pick(a,["FiscalYear","fiscalYear","fy"]) || ""}${pick(a,["FiscalQuarter","fiscalQuarter","fq"]) || ""}`;
  const db = pick(b, ["DisclosedDate", "disclosedDate", "date"]) || `${pick(b,["FiscalYear","fiscalYear","fy"]) || ""}${pick(b,["FiscalQuarter","fiscalQuarter","fq"]) || ""}`;
  return String(db).localeCompare(String(da));
}

// 4本で簡易TTM（直近4四半期合計）を作る
function ttmFromQuarterly(rows, fields) {
  const q = rows.filter(r => (pick(r, ["Type","type"]) || "").toString().toLowerCase().includes("q")); // 四半期だけに絞る(なければ後で通期fallback)
  const recent4 = (q.length ? q : rows).slice(0, 4);
  const out = {};
  for (const [label, candidates] of Object.entries(fields)) {
    out[label] = recent4.reduce((acc, r) => acc + num(pick(r, candidates)), 0);
  }
  return out;
}

// BPS(EQUITY/SHARE)やDPS(dividend per share)の抽出（キー揺れ対応）
function extractPerShareLatest(rows) {
  // 新しい順に見て、単位がそれっぽいものを拾う
  for (const r of rows) {
    const eps = pick(r, ["EPS","EarningsPerShare","BasicEPS","basicEps","eps"]);
    const bps = pick(r, ["BPS","BookValuePerShare","bps"]);
    const dps = pick(r, ["DPS","DividendPerShare","dividend","dividendPerShare","dividendsPerShare"]);
    if (eps != null || bps != null || dps != null) {
      return { eps: num(eps), bps: num(bps), dps: num(dps) };
    }
  }
  return { eps: 0, bps: 0, dps: 0 };
}

async function fetchLatestClose(idToken, code) {
  // 直近60日から最後の終値を拾う
  const to = new Date();
  const from = new Date(to.getTime() - 90 * 24 * 60 * 60_000);
  const fmt = (d) => d.toISOString().slice(0,10).replace(/\D/g, "");
  const data = await jqFetch("/prices/daily_quotes", { code, from: fmt(from), to: fmt(to) }, idToken);
  const rows = Array.isArray(data) ? data : (data.daily_quotes || data.data || []);
  const last = rows[rows.length - 1] || {};
  const close = num(pick(last, ["Close","close","endPrice","AdjustedClose","adjusted_close"]));
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

    const rows = [...rows0].sort(sortRecent); // 新しい順

    // 直近の総資産、自己資本、当期純利益のTTM（四半期4本合計）
    const ttm = ttmFromQuarterly(rows, {
      revenue: ["NetSales","netSales","Revenue","revenue"],
      op:      ["OperatingIncome","operatingIncome"],
      ni:      ["NetIncome","netIncome","Profit","profit","ProfitAttributableToOwnersOfParent","netIncomeAttributableToOwnersOfParent"],
    });

    // 発行株式数（可能なら抽出）。見つからなければ EPS から逆算はしない（安全側）
    const sh = pick(rows[0], ["SharesOutstanding","sharesOutstanding","NumberOfIssuedAndOutstandingShares","issuedShares"]) || 0;
    const shares = num(sh);

    const perShare = extractPerShareLatest(rows); // EPS/BPS/DPS（最新の数値）
    // EPSをTTMで上書き（直近EPSが無い/古い場合に備え）
    const epsTTM = (shares > 0 && ttm.ni) ? (ttm.ni / shares) : perShare.eps;

    // 直近終値を取得
    const close = await fetchLatestClose(idToken, code);
    const mc = shares > 0 ? shares * close : 0;

    // PER/PBR/配当利回り
    const per = epsTTM > 0 ? (close / epsTTM) : null;
    const pbr = perShare.bps > 0 ? (close / perShare.bps) : null;
    const divYield = (perShare.dps > 0 && close > 0) ? (perShare.dps / close) : 0;

    // ROE/ROA（TTM純利益 / 期末自己資本/総資産 の近似）
    const equity = num(pick(rows[0], ["Equity","equity","TotalEquity","totalEquity","NetAssets","netAssets"]));
    const assets = num(pick(rows[0], ["TotalAssets","totalAssets","Assets","assets"]));
    const roe = (equity > 0 && ttm.ni) ? (ttm.ni / equity) : null;
    const roa = (assets > 0 && ttm.ni) ? (ttm.ni / assets) : null;

    // 要約
    const summary = {
      code,
      close,
      marketCap: mc,
      eps_ttm: epsTTM,
      bps: perShare.bps,
      dps: perShare.dps,
      per,
      pbr,
      dividend_yield: divYield, // 小数（0.03=3%）
      roe,
      roa,
    };

    safeJson(res, 200, { summary, raw_count: rows.length });
  } catch (e) {
    safeJson(res, 500, { error: String(e.message || e) });
  }
}

// ===== B) /api/screen/basic =====
// 入力例: ?market=Prime&limit=30&liquidity_min=100000000&per_lt=15&pbr_lt=1.2&div_yield_gt=0.03&mom3m_gt=0.05
// 出力: スコア降順で {code,name,per,pbr,div_yield,mom_3m,avg_trading_value,score}

async function calcAvgTradingValue(idToken, code, lookbackDays = 20) {
  const to = new Date();
  const from = new Date(to.getTime() - 90 * 24 * 60 * 60_000);
  const fmt = (d) => d.toISOString().slice(0,10).replace(/\D/g, "");
  const data = await jqFetch("/prices/daily_quotes", { code, from: fmt(from), to: fmt(to) }, idToken);
  const rows = Array.isArray(data) ? data : (data.daily_quotes || data.data || []);
  const recent = rows.slice(-lookbackDays);
  if (!recent.length) return 0;
  const avg = recent.reduce((a, r) => {
    const c = num(pick(r, ["Close","close","endPrice","AdjustedClose","adjusted_close"]));
    const v = num(pick(r, ["Volume","volume","turnoverVolume"]));
    return a + c * v;
  }, 0) / recent.length;
  return Math.round(avg);
}

function nthFromEnd(arr, n) {
  return arr[arr.length - 1 - n];
}
async function calcMomentum(idToken, code) {
  // 1/3/6/12ヶ月リターン（営業日≒暦で近似）
  const to = new Date();
  const from = new Date(to.getTime() - 400 * 24 * 60 * 60_000);
  const fmt = (d) => d.toISOString().slice(0,10).replace(/\D/g, "");
  const data = await jqFetch("/prices/daily_quotes", { code, from: fmt(from), to: fmt(to) }, idToken);
  const rows = Array.isArray(data) ? data : (data.daily_quotes || data.data || []);
  if (rows.length < 40) return { r1m: 0, r3m: 0, r6m: 0, r12m: 0 };

  const close = (r) => num(pick(r, ["Close","close","endPrice","AdjustedClose","adjusted_close"]));
  const last = close(rows[rows.length - 1]);

  const findAgo = (days) => {
    const idx = Math.max(rows.length - 1 - Math.round(days), 0);
    return close(rows[idx]);
  };
  const oneM = findAgo(21);
  const threeM = findAgo(63);
  const sixM = findAgo(126);
  const twelveM = findAgo(252);

  const ret = (cur, prev) => (prev > 0 ? (cur / prev - 1) : 0);
  return {
    r1m:  ret(last, oneM),
    r3m:  ret(last, threeM),
    r6m:  ret(last, sixM),
    r12m: ret(last, twelveM),
  };
}

function scoreRow(x) {
  // シンプル合成：流動性(20) + バリュー(30) + モメンタム(30) + 配当(20) = 100
  let s = 0;

  // 流動性：1億で10点、5億で満点（線形クリップ）
  const lv = Math.min(1, Math.max(0, (x.avg_trading_value - 1e8) / (5e8 - 1e8)));
  s += lv * 20;

  // バリュー：PER(15) + PBR(15) … 低いほど加点（PER 6〜15, PBR 0.6〜1.2で線形）
  if (x.per) {
    const perScore = Math.min(1, Math.max(0, (15 - x.per) / (15 - 6)));
    s += perScore * 15;
  }
  if (x.pbr) {
    const pbrScore = Math.min(1, Math.max(0, (1.2 - x.pbr) / (1.2 - 0.6)));
    s += pbrScore * 15;
  }

  // モメンタム：3M(15) + 6M(15) … -10%〜+20% でスケーリング
  const clip = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const scale = (v, lo, hi) => (clip(v, lo, hi) - lo) / (hi - lo);
  s += scale(x.mom_3m || 0, -0.10, 0.20) * 15;
  s += scale(x.mom_6m || 0, -0.10, 0.20) * 15;

  // 配当：0〜4%で0→満点（超過はクリップ）
  s += Math.min(1, (x.dividend_yield || 0) / 0.04) * 20;

  return Math.round(s);
}

async function handleScreenBasic(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    const url = safeParseURL(req);
    const market = (url.searchParams.get("market") || "All").trim();
    const limit  = Number(url.searchParams.get("limit") || "30");
    const liqMin = Number(url.searchParams.get("liquidity_min") || "100000000"); // 1億
    const perLt  = url.searchParams.get("per_lt");
    const pbrLt  = url.searchParams.get("pbr_lt");
    const divGt  = url.searchParams.get("div_yield_gt");
    const mom3Gt = url.searchParams.get("mom3m_gt");

    const idToken = await ensureIdToken();

    // universe取得
    const uni = await jqFetch("/listed/info", {}, idToken);
    let list = Array.isArray(uni) ? uni : (uni.info || uni.data || []);
    if (market && market !== "All") {
      const mkey = market.toLowerCase();
      list = list.filter(x => (x.market || x.market_code || "").toString().toLowerCase().includes(mkey));
    }

    // API負荷対策：まずは先頭から最大300でサンプリング（必要ならクエリで sample=N を追加）
    const sample = list.slice(0, Math.min(300, list.length));
    const out = [];

    for (const it of sample) {
      const code = it.code || it.Symbol || it.symbol || it.Code;
      const name = it.company_name || it.Name || it.companyName || "";
      if (!code) continue;

      try {
        // 流動性（平均売買代金）
        const avgVal = await calcAvgTradingValue(idToken, code, 20);
        if (avgVal < liqMin) continue;

        // 財務（EPS/BPS/DPS/利回り等）
        const fs = await jqFetch("/fins/statements", { code }, idToken);
        const rows0 = Array.isArray(fs) ? fs : (fs.statements || fs.data || []);
        if (!rows0.length) continue;
        const rows = [...rows0].sort(sortRecent);
        const perShare = extractPerShareLatest(rows);

        // 価格・モメンタム
        const lastClose = await fetchLatestClose(idToken, code);
        const mom = await calcMomentum(idToken, code);

        // PER/PBR/配当利回り
        const per = (perShare.eps > 0) ? (lastClose / perShare.eps) : null;
        const pbr = (perShare.bps > 0) ? (lastClose / perShare.bps) : null;
        const divYield = (perShare.dps > 0 && lastClose > 0) ? (perShare.dps / lastClose) : 0;

        // 事前フィルタ
        if (perLt && per != null && !(per < Number(perLt))) continue;
        if (pbrLt && pbr != null && !(pbr < Number(pbrLt))) continue;
        if (divGt && !(divYield >= Number(divGt))) continue;
        if (mom3Gt && !((mom.r3m || 0) >= Number(mom3Gt))) continue;

        const row = {
          code, name,
          per, pbr,
          dividend_yield: divYield,
          mom_3m: mom.r3m, mom_6m: mom.r6m, mom_12m: mom.r12m,
          avg_trading_value: avgVal,
        };
        row.score = scoreRow(row);
        out.push(row);
      } catch {
        continue; // 個別失敗はスキップ
      }
    }

    // スコア降順 → 上位limit件
    out.sort((a, b) => (b.score - a.score));
    safeJson(res, 200, { count: out.length, items: out.slice(0, limit) });
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

    if (pathOnly === "/api/debug" && req.method === "GET") return handleDebug(req, res);

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

async function handleDebug(req, res){
  const got = (req.headers?.["authorization"]||"").toString();
  const token = got.startsWith("Bearer ") ? got.slice(7) : "";
  const masked = token ? token.slice(0,3) + "***" + token.slice(-3) : "";
  const env = (process.env.PROXY_BEARER || "").toString();
  const envMasked = env ? env.slice(0,3) + "***" + env.slice(-3) : "";
  const match = !!env && env === token;
  safeJson(res, 200, {
    hasEnv: !!env,
    gotAuthHeader: !!got,
    headerMasked: masked,
    envMasked: envMasked,
    match
  });
}
