// api/index.js  — 2025-09-27 汎用版・最終形（ESM + patch）
// - ESM対応（export default）
// - 「7203デフォルト」禁止（code未指定は400）
// - codes=CSV / 複数クエリ両対応
// - キャッシュキー＝メソッド＋フルURL（クエリ含む）
// - idToken: refreshToken→失敗時は auth_user フォールバック
// - Market表記ゆれの正規化、上限フィルタでnullは通す、モメンタムnull対応

const JQ_BASE = 'https://api.jquants.com';
const VERSION = '2025-09-27.final-esm-patch1';

const cache = new Map(); // { key: { ts, ttl, body } }
const DEFAULT_TTL_MS = 5 * 60 * 1000;

// ============ Utils ============
const nowIso = () => new Date().toISOString();

function makeError(status, message) {
  const err = new Error(message || String(status));
  err.status = status;
  return err;
}

function safeJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(obj));
}

function getQuery(req) {
  const url = new URL(req.url, 'http://local');
  return url.searchParams;
}

// ※ デフォルトで code を埋めない。なければ 400。
function requireCode(q) {
  const code = (q.get('code') || '').trim();
  if (!code) throw makeError(400, 'code query is required');
  return code;
}

// codes=7203,6758,8035 と codes=7203&codes=6758 の両対応
function parseCodes(q) {
  const multi = q.getAll('codes');
  const base = multi.length ? multi : ((q.get('codes') || '').trim() ? [q.get('codes')] : []);
  const flat = base
    .flatMap(s => String(s).split(','))
    .map(s => s.trim())
    .filter(Boolean);
  if (!flat.length) throw makeError(400, 'codes query is required');
  return Array.from(new Set(flat));
}

// キャッシュキー：必ずクエリまで含む
function cacheKeyFromReq(req) {
  return req.method + ' ' + req.url;
}

function setCache(key, body, ttlMs) {
  cache.set(key, { ts: Date.now(), ttl: ttlMs ?? DEFAULT_TTL_MS, body });
}

function getCache(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.ts > hit.ttl) {
    cache.delete(key);
    return null;
  }
  return hit.body;
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const msg = `JQ ${res.status}: ${text || res.statusText}`;
    throw makeError(res.status, msg);
  }
  return res.json();
}

// ============ Market 正規化 ============
function normalizeMarketTag(raw) {
  const s = String(raw || '').toLowerCase();
  if (!s) return '';
  if (s.includes('prime') || s.includes('プライム')) return 'Prime';
  if (s.includes('standard') || s.includes('スタンダード')) return 'Standard';
  if (s.includes('growth') || s.includes('グロース')) return 'Growth';
  return s; // それ以外はそのまま（将来の拡張含む）
}

function matchMarket(itemMarket, wanted) {
  if (!wanted || wanted === 'All') return true;
  const m = normalizeMarketTag(itemMarket);
  return m === normalizeMarketTag(wanted);
}

// ============ Auth / idToken ============
const state = {
  idToken: '',
  idTokenExpAt: 0,
  refreshToken: (process.env.JQ_REFRESH_TOKEN || '').trim(),
};

function idTokenValidMs() {
  return Math.max(0, state.idTokenExpAt - Date.now());
}

async function jqAuthRefresh(refreshToken) {
  const u = `${JQ_BASE}/v1/token/auth_refresh?refreshtoken=${encodeURIComponent(refreshToken)}`;
  const j = await fetchJson(u, { method: 'POST' });
  const expMs = (j.expire ? Number(j.expire) * 1000 : Date.now() + 9 * 60 * 1000);
  return { idToken: j.idToken, expAt: expMs };
}

async function jqAuthUser(email, password) {
  const u = `${JQ_BASE}/v1/token/auth_user`;
  const j = await fetchJson(u, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mailaddress: email, password }),
  });
  return j.refreshToken;
}

async function ensureIdToken() {
  if (idTokenValidMs() > 15_000) return state.idToken;

  const rt = state.refreshToken || (process.env.JQ_REFRESH_TOKEN || '').trim();
  if (rt) {
    try {
      const { idToken, expAt } = await jqAuthRefresh(rt);
      state.idToken = idToken;
      state.idTokenExpAt = expAt;
      return idToken;
    } catch { /* fallback below */ }
  }

  const email = (process.env.JQ_EMAIL || '').trim();
  const password = (process.env.JQ_PASSWORD || '').trim();
  if (!email || !password) throw makeError(401, 'JQ auth failed: missing JQ_EMAIL/JQ_PASSWORD and invalid refreshToken');

  const newRt = await jqAuthUser(email, password);
  state.refreshToken = newRt;

  const { idToken, expAt } = await jqAuthRefresh(newRt);
  state.idToken = idToken;
  state.idTokenExpAt = expAt;
  return idToken;
}

async function jqGet(pathWithQuery) {
  const idToken = await ensureIdToken();
  const url = `${JQ_BASE}${pathWithQuery}`;
  return fetchJson(url, { headers: { Authorization: `Bearer ${idToken}` } });
}

// ============ Handlers ============
async function handleHealth(_req, res) {
  safeJson(res, 200, {
    ok: true,
    ts: nowIso(),
    version: VERSION,
    idToken_valid_ms: idTokenValidMs(),
  });
}

async function handleAuthRefresh(_req, res) {
  const idToken = await ensureIdToken();
  safeJson(res, 200, { idToken, expAt: state.idTokenExpAt });
}

async function handleUniverseListed(req, res) {
  const key = cacheKeyFromReq(req);
  const hit = getCache(key);
  if (hit) return safeJson(res, 200, hit);

  const data = await jqGet('/v1/listed/info');
  setCache(key, data, 24 * 60 * 60 * 1000); // 1日
  safeJson(res, 200, data);
}

async function handlePricesDaily(req, res) {
  const q = getQuery(req);
  const code = requireCode(q);
  const from = (q.get('from') || '').trim();
  const to = (q.get('to') || '').trim();

  const key = cacheKeyFromReq(req);
  const hit = getCache(key);
  if (hit) return safeJson(res, 200, hit);

  const sp = new URLSearchParams({ code });
  if (from) sp.set('from', from);
  if (to) sp.set('to', to);
  const data = await jqGet('/v1/prices/daily_quotes?' + sp.toString());
  setCache(key, data, 5 * 60 * 1000);
  safeJson(res, 200, data);
}

async function handleFinsStatements(req, res) {
  const q = getQuery(req);
  const code = requireCode(q);

  const key = cacheKeyFromReq(req);
  const hit = getCache(key);
  if (hit) return safeJson(res, 200, hit);

  const data = await jqGet('/v1/fins/statements?code=' + encodeURIComponent(code));
  const items = Array.isArray(data.statements) ? data.statements : [];
  items.sort((a, b) =>
    String(b.fiscal_year || '').localeCompare(String(a.fiscal_year || '')) ||
    String(b.fiscal_quarter || '').localeCompare(String(a.fiscal_quarter || ''))
  );
  const latest = items[0] || {};
  const summary = {
    code,
    close: null,
    marketCap: null,
    eps_ttm: latest.eps || latest.eps_ttm || null,
    bps: latest.bps || null,
    dps: latest.dps || latest.dividend || null,
    per: latest.per || null,
    pbr: latest.pbr || null,
    dividend_yield: latest.dividend_yield || null,
    roe: latest.roe || null,
    roa: latest.roa || null,
  };
  const payload = { summary, raw_count: items.length };
  setCache(key, payload, 60 * 60 * 1000);
  safeJson(res, 200, payload);
}

async function handleCreditWeekly(req, res) {
  const q = getQuery(req);
  const code = requireCode(q);
  const weeks = Math.max(4, Number(q.get('weeks') || 26));

  const key = cacheKeyFromReq(req);
  const hit = getCache(key);
  if (hit) return safeJson(res, 200, hit);

  const raw = await jqGet('/v1/credit/margin_balance?code=' + encodeURIComponent(code));
  const items = Array.isArray(raw.margin_balance) ? raw.margin_balance : [];
  const sliced = items.slice(-weeks);
  const latest = sliced[sliced.length - 1] || {};
  const prev = sliced[sliced.length - 2] || null;

  const metrics = {
    code,
    latest: {
      date: latest.date || null,
      buying: latest.margin_buying || latest.buying || null,
      selling: latest.margin_selling || latest.selling || null,
      net: (latest.margin_buying || latest.buying || 0) - (latest.margin_selling || latest.selling || 0),
      ratio: latest.ratio || null,
    },
    wow_change: prev ? {
      buying: (latest.margin_buying || latest.buying || 0) - (prev.margin_buying || prev.buying || 0),
      selling: (latest.margin_selling || latest.selling || 0) - (prev.margin_selling || prev.selling || 0),
      net: ((latest.margin_buying || latest.buying || 0) - (latest.margin_selling || latest.selling || 0))
         - ((prev.margin_buying || prev.buying || 0) - (prev.margin_selling || prev.selling || 0)),
    } : { buying: null, selling: null, net: null }
  };

  const payload = { code, count: sliced.length, metrics, items: sliced.map(x => ({
    date: x.date,
    buying: x.margin_buying || x.buying,
    selling: x.margin_selling || x.selling,
    net: (x.margin_buying || x.buying || 0) - (x.margin_selling || x.selling || 0),
    ratio: x.ratio ?? null,
  }))};

  setCache(key, payload, 10 * 60 * 1000);
  safeJson(res, 200, payload);
}

async function handleCreditDailyPublic(req, res) {
  const q = getQuery(req);
  const code = requireCode(q);
  const days = Math.max(7, Number(q.get('days') || 60));

  const key = cacheKeyFromReq(req);
  const hit = getCache(key);
  if (hit) return safeJson(res, 200, hit);

  const raw = await jqGet('/v1/credit/daily_margin_interest?code=' + encodeURIComponent(code));
  const items = Array.isArray(raw.daily_margin_interest) ? raw.daily_margin_interest : [];
  const sliced = items.slice(-days);

  const payload = {
    code,
    count: sliced.length,
    items: sliced.map(x => ({
      date: x.date,
      buying: x.margin_buying || x.buying,
      selling: x.margin_selling || x.selling,
      net: (x.margin_buying || x.buying || 0) - (x.margin_selling || x.selling || 0),
      margin_rate: x.margin_rate ?? null,
    }))
  };

  setCache(key, payload, 10 * 60 * 1000);
  safeJson(res, 200, payload);
}

// --- スクリーニング：流動性（内部処理） ---
async function handleScreenLiquidityInternal(market, minAvg, days, maxN) {
  const univ = await jqGet('/v1/listed/info');
  let list = Array.isArray(univ.info) ? univ.info : [];
  if (market !== 'All') {
    list = list.filter(x => matchMarket(x.market || x.Market, market));
  }
  if (maxN && list.length > maxN * 2) list = list.slice(0, maxN * 2);

  async function avgTradingValue(code) {
    const today = new Date();
    const from = new Date(today.getTime() - 120 * 24 * 60 * 60 * 1000);
    const fmt = (d) => d.toISOString().slice(0,10).replace(/-/g,'');
    const sp = new URLSearchParams({ code, from: fmt(from), to: fmt(today) });
    const j = await jqGet('/v1/prices/daily_quotes?' + sp.toString());
    const arr = Array.isArray(j.daily_quotes) ? j.daily_quotes.slice(-days) : [];
    if (!arr.length) return 0;
    const vals = arr.map(r => r.TurnoverValue ?? r.trading_value ?? r.TradingValue ?? 0);
    const avg = vals.reduce((a,b)=>a+Number(b||0),0) / arr.length;
    return Math.round(avg);
  }

  const out = [];
  let i = 0;
  const pool = 6;
  async function worker() {
    while (i < list.length) {
      const idx = i++;
      const it = list[idx];
      const code = String(it.Code || it.code || '').trim();
      if (!code) continue;
      const av = await avgTradingValue(code);
      if (av >= minAvg) out.push({
        code,
        name: it.Name || it.name || '',
        market: it.Market || it.market || '',
        avg_trading_value: av,
      });
    }
  }
  await Promise.all(Array.from({length: pool}, worker));
  return { count: out.length, items: out.sort((a,b)=>b.avg_trading_value - a.avg_trading_value).slice(0, maxN || out.length) };
}

async function handleScreenLiquidity(req, res) {
  const q = getQuery(req);
  const market = (q.get('market') || 'All').trim(); // All/Prime/Standard/Growth（日本語表記も可）
  const minAvg = Number(q.get('min_avg_trading_value') || 100_000_000);
  const days = Number(q.get('days') || 20);

  const key = cacheKeyFromReq(req);
  const hit = getCache(key);
  if (hit) return safeJson(res, 200, hit);

  const payload = await handleScreenLiquidityInternal(market, minAvg, days, 300);
  setCache(key, payload, 10 * 60 * 1000);
  safeJson(res, 200, payload);
}

// --- スクリーニング：複合 ---
async function handleScreenBasic(req, res) {
  const q = getQuery(req);
  const market = (q.get('market') || 'All').trim();
  const limit = Math.max(1, Math.min(200, Number(q.get('limit') || 30)));
  const liquidityMin = Number(q.get('liquidity_min') || 100_000_000);
  const perLt = q.get('per_lt') != null ? Number(q.get('per_lt')) : null;
  const pbrLt = q.get('pbr_lt') != null ? Number(q.get('pbr_lt')) : null;
  const dyGt = q.get('div_yield_gt') != null ? Number(q.get('div_yield_gt')) : null; // 0.03 = 3%
  const mom3Gt = q.get('mom3m_gt') != null ? Number(q.get('mom3m_gt')) : null;       // 0.05 = +5%

  const key = cacheKeyFromReq(req);
  const hit = getCache(key);
  if (hit) return safeJson(res, 200, hit);

  // 1) 流動性フィルター
  const liqResp = await handleScreenLiquidityInternal(market, liquidityMin, 20, 300);

  // 2) 財務・モメンタム
  const pool = 6;
  const out = [];
  let i = 0;
  async function finWorker() {
    while (i < liqResp.items.length) {
      const idx = i++;
      const it = liqResp.items[idx];
      const code = it.code;

      let per = null, pbr = null, dividend_yield = null, name = it.name;
      try {
        const fs = await jqGet('/v1/fins/statements?code=' + encodeURIComponent(code));
        const st = Array.isArray(fs.statements) ? fs.statements[0] : null;
        if (st) {
          per = (st.per ?? null);
          pbr = (st.pbr ?? null);
          dividend_yield = (st.dividend_yield ?? null);
          name = st.name || name;
        }
      } catch {}

      // 価格モメンタム（直近3/6/12ヶ月）
      let mom_3m = null, mom_6m = null, mom_12m = null;
      try {
        const today = new Date();
        const from = new Date(today.getTime() - 380 * 24 * 60 * 60 * 1000);
        const fmt = (d) => d.toISOString().slice(0,10).replace(/-/g,'');
        const prices = await jqGet('/v1/prices/daily_quotes?'+ new URLSearchParams({code, from: fmt(from), to: fmt(today)}).toString());
        const dq = Array.isArray(prices.daily_quotes) ? prices.daily_quotes : [];
        const closes = dq.map(r => Number(r.Close || r.close)).filter(v => Number.isFinite(v));
        if (closes.length > 0) {
          const last = closes[closes.length - 1];
          const idx3 = Math.max(0, closes.length - 63);
          const idx6 = Math.max(0, closes.length - 126);
          const idx12= Math.max(0, closes.length - 252);
          mom_3m = closes[idx3] ? (last - closes[idx3]) / closes[idx3] : null;
          mom_6m = closes[idx6] ? (last - closes[idx6]) / closes[idx6] : null;
          mom_12m= closes[idx12]? (last - closes[idx12]) / closes[idx12]: null;
        }
      } catch {}

      // 3) 条件（nullは通す：値がある時のみ比較）
      if (perLt != null && per != null && per > perLt) continue;
      if (pbrLt != null && pbr != null && pbr > pbrLt) continue;
      if (dyGt  != null && dividend_yield != null && dividend_yield < dyGt) continue;
      if (mom3Gt!= null && mom_3m != null && mom_3m < mom3Gt) continue;

      // 4) スコア（欠損は0寄与）
      const score = Math.round(
        (per != null ? (50 / Math.max(5, per)) : 0) +
        (pbr != null ? (50 / Math.max(0.5, pbr)) : 0) +
        (Math.max(0, mom_3m ?? 0) * 100) +
        (Math.max(0, dividend_yield ?? 0) * 300)
      );

      out.push({
        code, name,
        per, pbr, dividend_yield,
        mom_3m, mom_6m, mom_12m,
        avg_trading_value: it.avg_trading_value,
        score
      });
    }
  }
  await Promise.all(Array.from({length: pool}, finWorker));

  const items = out.sort((a,b)=>b.score - a.score).slice(0, limit);
  const payload = { count: items.length, items };
  setCache(key, payload, 5 * 60 * 1000);
  safeJson(res, 200, payload);
}

// --- ポートフォリオ要約 ---
async function handlePortfolioSummary(req, res) {
  const q = getQuery(req);
  const codes = parseCodes(q);
  const withCredit = (q.get('with_credit') || '0') === '1';

  const key = cacheKeyFromReq(req);
  const hit = getCache(key);
  if (hit) return safeJson(res, 200, hit);

  const out = [];
  const pool = 6;
  let i = 0;
  async function worker() {
    while (i < codes.length) {
      const idx = i++;
      const code = codes[idx];

      let close = null, per = null, pbr = null, dividend_yield = null, eps_ttm = null, bps = null, dps = null;
      try {
        const today = new Date();
        const from = new Date(today.getTime() - 70 * 24 * 60 * 60 * 1000);
        const fmt = (d) => d.toISOString().slice(0,10).replace(/-/g,'');
        const prices = await jqGet('/v1/prices/daily_quotes?'+ new URLSearchParams({code, from: fmt(from), to: fmt(today)}).toString());
        const dq = Array.isArray(prices.daily_quotes) ? prices.daily_quotes : [];
        if (dq.length) close = Number(dq[dq.length - 1].Close || dq[dq.length - 1].close || null);
      } catch {}

      try {
        const fs = await jqGet('/v1/fins/statements?code=' + encodeURIComponent(code));
        const st = Array.isArray(fs.statements) ? fs.statements[0] : null;
        if (st) {
          per = st.per ?? null;
          pbr = st.pbr ?? null;
          dividend_yield = st.dividend_yield ?? null;
          eps_ttm = st.eps_ttm ?? st.eps ?? null;
          bps = st.bps ?? null;
          dps = st.dps ?? st.dividend ?? null;
        }
      } catch {}

      let credit_latest = null;
      if (withCredit) {
        try {
          const raw = await jqGet('/v1/credit/margin_balance?code=' + encodeURIComponent(code));
          const items = Array.isArray(raw.margin_balance) ? raw.margin_balance : [];
          const last = items[items.length - 1];
          if (last) {
            credit_latest = {
              date: last.date || null,
              buying: last.margin_buying || last.buying || null,
              selling: last.margin_selling || last.selling || null,
              net: (last.margin_buying || last.buying || 0) - (last.margin_selling || last.selling || 0),
            };
          }
        } catch {}
      }

      out.push({ code, close, per, pbr, dividend_yield, eps_ttm, bps, dps, credit_latest, error: null });
    }
  }
  await Promise.all(Array.from({length: pool}, worker));

  const payload = { count: out.length, items: out };
  setCache(key, payload, 5 * 60 * 1000);
  safeJson(res, 200, payload);
}

// ============ Router ============
function requireBearer(req) {
  const hdr = req.headers['authorization'] || req.headers['Authorization'];
  const v = Array.isArray(hdr) ? hdr[0] : hdr;
  if (!v || !v.startsWith('Bearer ')) throw makeError(401, 'Unauthorized');
  const token = v.slice('Bearer '.length).trim();
  const expected = (process.env.PROXY_BEARER || '').trim();
  if (!expected || token !== expected) throw makeError(401, 'Unauthorized');
}

export default async function handler(req, res) {
  try {
    const url = new URL(req.url, 'http://local');
    const p = url.pathname;

    // 無認証
    if (req.method === 'GET' && p === '/api/health') return await handleHealth(req, res);

    // Bearer 必須
    requireBearer(req);

    if (req.method === 'POST' && p === '/api/auth/refresh') return await handleAuthRefresh(req, res);
    if (req.method === 'GET'  && p === '/api/universe/listed') return await handleUniverseListed(req, res);
    if (req.method === 'GET'  && p === '/api/prices/daily') return await handlePricesDaily(req, res);
    if (req.method === 'GET'  && p === '/api/fins/statements') return await handleFinsStatements(req, res);
    if (req.method === 'GET'  && p === '/api/credit/weekly') return await handleCreditWeekly(req, res);
    if (req.method === 'GET'  && p === '/api/credit/daily_public') return await handleCreditDailyPublic(req, res);
    if (req.method === 'GET'  && p === '/api/screen/liquidity') return await handleScreenLiquidity(req, res);
    if (req.method === 'GET'  && p === '/api/screen/basic') return await handleScreenBasic(req, res);
    if (req.method === 'GET'  && p === '/api/portfolio/summary') return await handlePortfolioSummary(req, res);

    throw makeError(404, 'Not Found');
  } catch (e) {
    const status = e.status || 500;
    safeJson(res, status, { error: e.message || 'Server Error' });
  }
}