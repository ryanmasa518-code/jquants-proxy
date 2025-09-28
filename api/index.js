// api/index.js — J-Quants proxy (PROD-hardened + credit + portfolio)
// 認証: Authorization: Bearer のみ（?key / X-Proxy-Key は無効）
// TTL: /listed=24h, /prices=10m, /fins=3d, /credit/weekly=24h, /credit/daily_public=6h, /portfolio/summary=3h
// 率制御: withLimit(MAX_CONCURRENCY=5) + リトライ(MAX_RETRIES=3, 基本待ち=400ms, 2倍指数)
// キー管理: auth_refresh失敗時は JQ_EMAIL/PASSWORD でrefreshToken再取得（ENV設定前提）

const JQ_BASE = "https://api.jquants.com/v1";

const {
  JQ_REFRESH_TOKEN: RAW_RT,
  JQ_EMAIL,
  JQ_PASSWORD,
  PROXY_BEARER,
  MAX_CONCURRENCY = "5",
  MAX_RETRIES = "3",
  BASE_BACKOFF_MS = "400",
} = process.env;

const ENV_REFRESH_TOKEN = (RAW_RT || "").trim();
const LIMIT = Math.max(1, Number(MAX_CONCURRENCY));
const RETRIES = Math.max(0, Number(MAX_RETRIES));
const BACKOFF0 = Math.max(50, Number(BASE_BACKOFF_MS));

// ===== state/cache =====
let cache = {
  idToken: null,
  idTokenExpAt: 0,
  refreshToken: ENV_REFRESH_TOKEN || null,
  resp: new Map(), // key -> {expAt,json}
};

// ===== utils =====
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nowIso = () => new Date().toISOString();
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
function num(v){ const n=Number(v); return Number.isFinite(n)?n:0; }
function pick(o, ks){ for(const k of ks) if(o && o[k]!=null) return o[k]; }

// 認可: Bearer のみ
function requireProxyBearer(req) {
  if (!PROXY_BEARER) return true; // env未設定時はスキップ（必要ならfalseに）
  const h = (req.headers?.["authorization"] || "").toString();
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  return !!token && token === PROXY_BEARER;
}

// ===== logging =====
function logInfo(evt, extra={}) { console.log(JSON.stringify({lvl:"info", ts:nowIso(), evt, ...extra})); }
function logWarn(evt, extra={}) { console.warn(JSON.stringify({lvl:"warn", ts:nowIso(), evt, ...extra})); }
function logError(evt, extra={}){ console.error(JSON.stringify({lvl:"error",ts:nowIso(), evt, ...extra})); }

// ===== concurrency limiter =====
let active = 0;
const waiters = [];
async function withLimit(fn) {
  if (active >= LIMIT) await new Promise(r => waiters.push(r));
  active++;
  try { return await fn(); }
  finally {
    active--;
    const n = waiters.shift();
    if (n) n();
  }
}

// ===== JQ fetch with retry/backoff =====
async function jqFetchRaw(url, headers) { return fetch(url, { headers }); }

async function jqFetch(path, params = {}, idToken) {
  const url = new URL(JQ_BASE + path);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  const headers = idToken ? { Authorization: `Bearer ${idToken}` } : {};
  const urlStr = url.toString();

  return withLimit(async () => {
    let attempt = 0, lastErrTxt = "";
    const t0 = Date.now();
    while (true) {
      try {
        const res = await jqFetchRaw(urlStr, headers);
        if (res.status === 429 && attempt < RETRIES) {
          const backoff = BACKOFF0 * Math.pow(2, attempt);
          logWarn("jq.rate_limited", { path, attempt, backoff_ms: backoff });
          await sleep(backoff); attempt++; continue;
        }
        if (!res.ok) {
          const txt = await res.text().catch(()=> ""); lastErrTxt = txt;
          if (res.status >= 500 && attempt < RETRIES) {
            const backoff = BACKOFF0 * Math.pow(2, attempt);
            logWarn("jq.server_error_retry", { path, status: res.status, attempt, backoff_ms: backoff, body: txt.slice(0,500) });
            await sleep(backoff); attempt++; continue;
          }
          logError("jq.error", { path, status: res.status, body: txt.slice(0,1000) });
          throw new Error(`JQ ${res.status}: ${txt || res.statusText}`);
        }
        const json = await res.json();
        const dt = Date.now() - t0;
        if (attempt>0) logInfo("jq.success_after_retry", { path, attempts: attempt+1, ms: dt });
        return json;
      } catch (e) {
        if (attempt < RETRIES) {
          const backoff = BACKOFF0 * Math.pow(2, attempt);
          logWarn("jq.fetch_retry", { path, attempt, backoff_ms: backoff, err: String(e).slice(0,300) });
          await sleep(backoff); attempt++; continue;
        }
        const dt = Date.now() - t0;
        logError("jq.fetch_fail", { path, attempts: attempt+1, ms: dt, lastErrTxt: lastErrTxt.slice(0,500) });
        throw e;
      }
    }
  });
}

// ===== auth =====
async function getRefreshTokenByPassword() {
  if (!JQ_EMAIL || !JQ_PASSWORD) throw new Error("Missing JQ_EMAIL/JQ_PASSWORD for refresh-token bootstrap.");
  const res = await fetch(`${JQ_BASE}/token/auth_user`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mailaddress: JQ_EMAIL, password: JQ_PASSWORD }),
  });
  if (!res.ok) {
    const txt = await res.text().catch(()=> "");
    logError("auth_user.fail", { status: res.status, body: txt.slice(0,1000) });
    throw new Error(`auth_user failed: ${res.status} ${txt}`);
  }
  const data = await res.json();
  if (!data.refreshToken) throw new Error("auth_user returned no refreshToken");
  logInfo("auth_user.ok");
  return String(data.refreshToken).trim();
}
async function getIdTokenByRefresh(refreshToken) {
  const qs = new URLSearchParams({ refreshtoken: refreshToken });
  const url = `${JQ_BASE}/token/auth_refresh?${qs.toString()}`;
  const res = await fetch(url, { method: "POST" });
  if (!res.ok) {
    const txt = await res.text().catch(()=> "");
    logWarn("auth_refresh.fail", { status: res.status, body: txt.slice(0,1000) });
    throw new Error(`auth_refresh failed: ${res.status} ${txt}`);
  }
  const data = await res.json();
  if (!data.idToken) throw new Error("auth_refresh returned no idToken");
  logInfo("auth_refresh.ok");
  return data.idToken;
}
async function ensureIdToken() {
  const now = Date.now();
  if (cache.idToken && cache.idTokenExpAt - now > 60_000) return cache.idToken;
  try {
    if (!cache.refreshToken) cache.refreshToken = ENV_REFRESH_TOKEN || (await getRefreshTokenByPassword());
    const idToken = await getIdTokenByRefresh(cache.refreshToken);
    cache.idToken = idToken; cache.idTokenExpAt = now + 24*60*60_000;
    return idToken;
  } catch (e) {
    if (JQ_EMAIL && JQ_PASSWORD) {
      logWarn("ensureIdToken.fallback_refreshToken_regen", { err: String(e).slice(0,300) });
      cache.refreshToken = await getRefreshTokenByPassword();
      const idToken = await getIdTokenByRefresh(cache.refreshToken);
      cache.idToken = idToken; cache.idTokenExpAt = Date.now() + 24*60*60_000;
      return idToken;
    }
    throw e;
  }
}

// ===== cache helpers =====
function getCached(key){ const hit=cache.resp.get(key); return hit && hit.expAt>Date.now()? hit.json : null; }
function setCached(key,jsonObj,ttlMs){ cache.resp.set(key,{expAt:Date.now()+ttlMs,json:jsonObj}); }

// ===== handlers =====
async function handleHealth(_req,res){
  safeJson(res,200,{ ok:true, ts:nowIso(), idToken_valid_ms:Math.max(0, cache.idTokenExpAt-Date.now()), concurrency:{limit:LIMIT, active} });
}
async function handleAuthRefresh(req,res){
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try { const idToken = await ensureIdToken(); safeJson(res,200,{ idToken, expAt: cache.idTokenExpAt }); }
  catch(e){ safeJson(res,500,{ error:String(e.message||e) }); }
}
// 置き換え：/api/universe/listed を軽量＆ページング対応に
async function handleUniverseListed(req, res) {
  const q = getQuery(req);
  const market = (q.get('market') || 'All').trim();     // All/Prime/Standard/Growth（日本語可）
  const limit  = Math.max(1, Math.min(500, Number(q.get('limit') || 200))); // デフォ200・最大500
  const offset = Math.max(0, Number(q.get('offset') || 0));
  const fieldsCsv = (q.get('fields') || 'code,name,market').trim();         // デフォ最小3項目
  const fields = new Set(fieldsCsv.split(',').map(s => s.trim()).filter(Boolean));
  const codesOnly = (q.get('codes_only') || '0') === '1';                   // 1 なら codes配列だけ返す
  const search = (q.get('q') || '').trim().toLowerCase();                   // 名前/コード部分一致

  // クエリ込みキャッシュキー（既存関数）
  const key = cacheKeyFromReq(req);
  const hit = getCache(key);
  if (hit) return safeJson(res, 200, hit);

  // 元データ取得
  const univ = await jqGet('/v1/listed/info');
  let list = Array.isArray(univ.info) ? univ.info : [];

  // 市場フィルタ（表記ゆれ吸収）
  if (market !== 'All') {
    list = list.filter(x => matchMarket(x.market || x.Market, market));
  }

  // フリーワード（コード or 名称）
  if (search) {
    list = list.filter(x => {
      const code = String(x.Code || x.code || '').toLowerCase();
      const name = String(x.Name || x.name || '').toLowerCase();
      return code.includes(search) || name.includes(search);
    });
  }

  const total = list.length;
  const page = list.slice(offset, offset + limit);

  if (codesOnly) {
    const codes = page.map(x => String(x.Code || x.code || '')).filter(Boolean);
    const payload = { count: codes.length, total, offset, limit, codes };
    setCache(key, payload, 24 * 60 * 60 * 1000); // 1日
    return safeJson(res, 200, payload);
  }

  // 必要フィールドだけ返す（* を含めれば全部）
  const mapped = page.map(x => {
    const obj = {};
    if (fields.has('*')) {
      // そのまま返すと肥大化するので注意。*は本当に必要な時だけ指定を想定。
      return Object.assign({}, x, {
        code: String(x.Code || x.code || ''),
        name: x.Name || x.name || '',
        market: x.Market || x.market || ''
      });
    }
    if (fields.has('code'))   obj.code   = String(x.Code || x.code || '');
    if (fields.has('name'))   obj.name   = x.Name || x.name || '';
    if (fields.has('market')) obj.market = x.Market || x.market || '';
    // 追加で取りたい項目があれば、必要に応じてここに列挙
    return obj;
  });

  const payload = { count: mapped.length, total, offset, limit, items: mapped };
  setCache(key, payload, 24 * 60 * 60 * 1000); // 1日
  safeJson(res, 200, payload);
}

async function handlePricesDaily(req,res){
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try{
    const url=safeParseURL(req);
    const code=(url.searchParams.get("code")||"").trim();
    if(!code) return safeJson(res,400,{error:"Missing code"});
    const digits=(s)=>(s||"").replace(/\D/g,"");
    let from=digits(url.searchParams.get("from"));
    let to=digits(url.searchParams.get("to"));
    if(!to) to=new Date().toISOString().slice(0,10).replace(/\D/g,"");
    if(!from){ const d=new Date(); d.setDate(d.getDate()-60); from=d.toISOString().slice(0,10).replace(/\D/g,""); }
    if(!/^\d{8}$/.test(from)||!/^\d{8}$/.test(to)) return safeJson(res,400,{error:"Invalid date format. Use YYYYMMDD."});
    if(Number(from)>Number(to)) return safeJson(res,400,{error:"`from` must be <= `to`"});

    const key=`prices:daily:${code}:${from}:${to}`; const hit=getCached(key); if(hit) return safeJson(res,200,hit);
    const idToken=await ensureIdToken();
    const data=await jqFetch("/prices/daily_quotes",{code,from,to},idToken);
    setCached(key,data,10*60_000);
    safeJson(res,200,data);
  }catch(e){ safeJson(res,500,{error:String(e.message||e)}); }
}

// ===== fins/statements =====
function sortRecent(a,b){
  const da = pick(a,["DisclosedDate","disclosedDate","date"]) || `${pick(a,["FiscalYear","fiscalYear","fy"])||""}${pick(a,["FiscalQuarter","fiscalQuarter","fq"])||""}`;
  const db = pick(b,["DisclosedDate","disclosedDate","date"]) || `${pick(b,["FiscalYear","fiscalYear","fy"])||""}${pick(b,["FiscalQuarter","fiscalQuarter","fq"])||""}`;
  return String(db).localeCompare(String(da));
}
function extractPerShareLatest(rows){
  for(const r of rows){
    const eps = pick(r,["EPS","EarningsPerShare","BasicEPS","basicEps","eps"]);
    const bps = pick(r,["BPS","BookValuePerShare","bps"]);
    const dps = pick(r,["DPS","DividendPerShare","dividend","dividendPerShare","dividendsPerShare"]);
    if (eps!=null || bps!=null || dps!=null) return { eps:num(eps), bps:num(bps), dps:num(dps) };
  }
  return { eps:0,bps:0,dps:0 };
}
function ttmFromQuarterly(rows, fields){
  const q = rows.filter(r => ((r.Type||r.type||"")+"").toLowerCase().includes("q"));
  const recent4 = (q.length ? q : rows).slice(0,4);
  const out={};
  for(const [label,cands] of Object.entries(fields)){
    let sum=0; for(const r of recent4){ for(const k of cands){ if(r[k]!=null){ sum += num(r[k]); break; } } }
    out[label]=sum;
  }
  return out;
}
async function fetchLatestClose(idToken, code){
  const to = new Date(); const from = new Date(to.getTime() - 90*24*60*60_000);
  const fmt=(d)=>d.toISOString().slice(0,10).replace(/\D/g,"");
  const data=await jqFetch("/prices/daily_quotes",{code,from:fmt(from),to:fmt(to)},idToken);
  const rows=Array.isArray(data)?data:(data.daily_quotes||data.data||[]);
  const last=rows[rows.length-1]||{};
  return num(pick(last,["Close","close","endPrice","AdjustedClose","adjusted_close"]));
}
async function handleFinsStatements(req,res){
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try{
    const url=safeParseURL(req);
    const code=(url.searchParams.get("code")||"").trim();
    if(!code) return safeJson(res,400,{error:"Missing code"});

    const key=`fins:${code}`; const hit=getCached(key); if(hit) return safeJson(res,200,hit);

    const idToken=await ensureIdToken();
    const resp=await jqFetch("/fins/statements",{code},idToken);
    const rows0=Array.isArray(resp)?resp:(resp.statements||resp.data||[]);
    if(!rows0.length) return safeJson(res,404,{error:"No statements"});
    const rows=[...rows0].sort(sortRecent);

    const ttm = ttmFromQuarterly(rows, {
      revenue:["NetSales","netSales","Revenue","revenue"],
      op:["OperatingIncome","operatingIncome"],
      ni:["NetIncome","netIncome","Profit","profit","ProfitAttributableToOwnersOfParent","netIncomeAttributableToOwnersOfParent"],
    });

    const shares = num(pick(rows[0],["SharesOutstanding","sharesOutstanding","NumberOfIssuedAndOutstandingShares","issuedShares"]));
    const perShare = extractPerShareLatest(rows);
    const epsTTM = (shares>0 && ttm.ni) ? (ttm.ni/shares) : perShare.eps;

    const close = await fetchLatestClose(idToken, code);
    const mc = shares>0 ? shares*close : 0;

    const per = epsTTM>0 ? (close/epsTTM) : null;
    const pbr = perShare.bps>0 ? (close/perShare.bps) : null;
    const divYield = (perShare.dps>0 && close>0) ? (perShare.dps/close) : 0;

    const equity = num(pick(rows[0],["Equity","equity","TotalEquity","totalEquity","NetAssets","netAssets"]));
    const assets = num(pick(rows[0],["TotalAssets","totalAssets","Assets","assets"]));
    const roe = (equity>0 && ttm.ni) ? (ttm.ni/equity) : null;
    const roa = (assets>0 && ttm.ni) ? (ttm.ni/assets) : null;

    const summary = { code, close, marketCap: mc, eps_ttm: epsTTM, bps: perShare.bps, dps: perShare.dps, per, pbr, dividend_yield: divYield, roe, roa };
    const payload = { summary, raw_count: rows.length };
    setCached(key, payload, 3*24*60*60_000);
    safeJson(res,200,payload);
  }catch(e){ safeJson(res,500,{error:String(e.message||e)}); }
}

// ===== credit: weekly margin interest =====
async function handleCreditWeekly(req,res){
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try{
    const url=safeParseURL(req);
    const code=(url.searchParams.get("code")||"").trim();
    const weeks=Math.max(4, Number(url.searchParams.get("weeks")||"26"));
    if(!code) return safeJson(res,400,{error:"Missing code"});

    const key=`credit:weekly:${code}:${weeks}`; const hit=getCached(key); if(hit) return safeJson(res,200,hit);

    const idToken=await ensureIdToken();
    const to=new Date(); const from=new Date(to.getTime()-370*24*60*60_000);
    const fmt=(d)=>d.toISOString().slice(0,10).replace(/\D/g,"");
    const raw=await jqFetch("/markets/weekly_margin_interest",{code,from:fmt(from),to:fmt(to)},idToken);

    const rows=Array.isArray(raw)?raw:(raw.weekly_margin_interest||raw.data||[]);
    rows.sort((a,b)=> String((b.Date||b.date||"")).localeCompare(String((a.Date||a.date||""))));
    const take=rows.slice(0,weeks);

    const n=(v)=>Number.isFinite(+v)?+v:0;
    const items=take.map(r=>{
      const buy=n(r.BuyingOnMargin||r.margin_buying||r.buying_on_margin);
      const sell=n(r.SellingOnMargin||r.margin_selling||r.selling_on_margin);
      return { date: r.Date||r.date, buying: buy, selling: sell, net: buy - sell, ratio: (buy>0? sell/buy : null) };
    });

    const cur=items[0]||{}, prev=items[1]||{};
    const pct=(a,b)=> (b && b!==0? (a/b - 1) : null);
    const metrics={ code, latest: cur, wow_change: { buying: pct(cur.buying,prev.buying), selling: pct(cur.selling,prev.selling), net: pct(cur.net,prev.net) } };

    const payload={ code, count: items.length, metrics, items };
    setCached(key,payload,24*60*60_000);
    safeJson(res,200,payload);
  }catch(e){ safeJson(res,500,{error:String(e.message||e)}); }
}

// ===== credit: daily public margin interest =====
async function handleCreditDailyPublic(req,res){
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try{
    const url=safeParseURL(req);
    const code=(url.searchParams.get("code")||"").trim();
    const days=Math.max(7, Number(url.searchParams.get("days")||"60"));
    if(!code) return safeJson(res,400,{error:"Missing code"});

    const key=`credit:daily_public:${code}:${days}`; const hit=getCached(key); if(hit) return safeJson(res,200,hit);

    const idToken=await ensureIdToken();
    const to=new Date(); const from=new Date(to.getTime()-(days+10)*24*60*60_000);
    const fmt=(d)=>d.toISOString().slice(0,10).replace(/\D/g,"");
    const raw=await jqFetch("/markets/daily_margin_interest",{code,from:fmt(from),to:fmt(to)},idToken);

    const rows=Array.isArray(raw)?raw:(raw.daily_margin_interest||raw.data||[]);
    rows.sort((a,b)=> String((a.Date||a.date||"")).localeCompare(String((b.Date||b.date||"")))); // 古→新
    const take=rows.slice(-days);

    const n=(v)=>Number.isFinite(+v)?+v:0;
    const items=take.map(r=>({
      date: r.Date||r.date,
      buying: n(r.BuyingOnMargin||r.buying_on_margin),
      selling: n(r.SellingOnMargin||r.selling_on_margin),
      net: n(r.BuyingOnMargin||r.buying_on_margin) - n(r.SellingOnMargin||r.selling_on_margin),
      margin_rate: r.MarginRate || r.margin_rate || null,
    }));

    const payload={ code, count: items.length, items };
    setCached(key,payload,6*60*60_000);
    safeJson(res,200,payload);
  }catch(e){ safeJson(res,500,{error:String(e.message||e)}); }
}

// ===== screen/liquidity (as before) =====
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

// ===== screen/basic =====
async function calcAvgTradingValue(idToken, code, lookbackDays = 20) {
  const to = new Date(); const from = new Date(to.getTime() - 90*24*60*60_000);
  const fmt=(d)=>d.toISOString().slice(0,10).replace(/\D/g,"");
  const data=await jqFetch("/prices/daily_quotes",{code,from:fmt(from),to:fmt(to)},idToken);
  const rows=Array.isArray(data)?data:(data.daily_quotes||data.data||[]);
  const recent=rows.slice(-lookbackDays); if(!recent.length) return 0;
  const avg=recent.reduce((a,r)=> a + num(pick(r,["Close","close","endPrice","AdjustedClose","adjusted_close"])) * num(pick(r,["Volume","volume","turnoverVolume"])), 0)/recent.length;
  return Math.round(avg);
}
async function calcMomentum(idToken, code) {
  const to=new Date(); const from=new Date(to.getTime() - 400*24*60*60_000);
  const fmt=(d)=>d.toISOString().slice(0,10).replace(/\D/g,"");
  const data=await jqFetch("/prices/daily_quotes",{code,from:fmt(from),to:fmt(to)},idToken);
  const rows=Array.isArray(data)?data:(data.daily_quotes||data.data||[]);
  if(rows.length<40) return { r1m:0,r3m:0,r6m:0,r12m:0 };
  const close=(r)=> num(pick(r,["Close","close","endPrice","AdjustedClose","adjusted_close"]));
  const last=close(rows[rows.length-1]);
  const findAgo=(days)=> close(rows[Math.max(rows.length - 1 - Math.round(days),0)]);
  const ret=(cur,prev)=> (prev>0? (cur/prev - 1) : 0);
  return { r1m:ret(last,findAgo(21)), r3m:ret(last,findAgo(63)), r6m:ret(last,findAgo(126)), r12m:ret(last,findAgo(252)) };
}
function scoreRow(x){
  let s=0;
  const lv=Math.min(1,Math.max(0,(x.avg_trading_value-1e8)/(5e8-1e8))); s += lv*20;
  if(x.per){ s += Math.min(1,Math.max(0,(15-x.per)/(15-6)))*15; }
  if(x.pbr){ s += Math.min(1,Math.max(0,(1.2-x.pbr)/(1.2-0.6)))*15; }
  const clip=(v,lo,hi)=>Math.min(hi,Math.max(lo,v));
  const scale=(v,lo,hi)=>(clip(v,lo,hi)-lo)/(hi-lo);
  s += scale(x.mom_3m||0, -0.10, 0.20) * 15;
  s += scale(x.mom_6m||0, -0.10, 0.20) * 15;
  s += Math.min(1,(x.dividend_yield||0)/0.04)*20;
  return Math.round(s);
}
async function handleScreenBasic(req,res){
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try{
    const url=safeParseURL(req);
    const market=(url.searchParams.get("market")||"All").trim();
    const limit=Number(url.searchParams.get("limit")||"30");
    const liqMin=Number(url.searchParams.get("liquidity_min")||"100000000");
    const perLt=url.searchParams.get("per_lt");
    const pbrLt=url.searchParams.get("pbr_lt");
    const divGt=url.searchParams.get("div_yield_gt");
    const mom3Gt=url.searchParams.get("mom3m_gt");

    const idToken=await ensureIdToken();
    const uni=await jqFetch("/listed/info",{},idToken);
    let list=Array.isArray(uni)?uni:(uni.info||uni.data||[]);
    if(market && market!=="All"){
      const mkey=market.toLowerCase();
      list=list.filter(x=>(x.market||x.market_code||"").toString().toLowerCase().includes(mkey));
    }
    const sample=list.slice(0,Math.min(300,list.length));
    const out=[];
    for(const it of sample){
      const code=it.code||it.Symbol||it.symbol||it.Code;
      const name=it.company_name||it.Name||it.companyName||"";
      if(!code) continue;
      try{
        const [avgVal, fs, lastClose, mom] = await Promise.all([
          calcAvgTradingValue(idToken, code, 20),
          jqFetch("/fins/statements",{code},idToken),
          fetchLatestClose(idToken, code),
          calcMomentum(idToken, code),
        ]);
        if(avgVal<liqMin) continue;
        const rows0=Array.isArray(fs)?fs:(fs.statements||fs.data||[]);
        if(!rows0.length) continue;
        const rows=[...rows0].sort(sortRecent);
        const perShare=extractPerShareLatest(rows);

        const per=(perShare.eps>0)?(lastClose/perShare.eps):null;
        const pbr=(perShare.bps>0)?(lastClose/perShare.bps):null;
        const divYield=(perShare.dps>0 && lastClose>0)?(perShare.dps/lastClose):0;

        if(perLt && per!=null && !(per<Number(perLt))) continue;
        if(pbrLt && pbr!=null && !(pbr<Number(pbrLt))) continue;
        if(divGt && !(divYield>=Number(divGt))) continue;
        if(mom3Gt && !((mom.r3m||0)>=Number(mom3Gt))) continue;

        const row={ code,name,per,pbr,dividend_yield:divYield,mom_3m:mom.r3m,mom_6m:mom.r6m,mom_12m:mom.r12m,avg_trading_value:avgVal };
        row.score=scoreRow(row);
        out.push(row);
      }catch(e){ logWarn("screen_basic.row_skip",{code,err:String(e).slice(0,300)}); continue; }
    }
    out.sort((a,b)=>b.score-a.score);
    safeJson(res,200,{ count: out.length, items: out.slice(0,limit) });
  }catch(e){ safeJson(res,500,{error:String(e.message||e)}); }
}

// ===== portfolio: summary (multi-codes) =====
async function handlePortfolioSummary(req, res) {
  if (!requireProxyBearer(req)) return safeJson(res, 401, { error: "Unauthorized" });
  try {
    const url = safeParseURL(req);
    const codesParam = (url.searchParams.get("codes") || "").trim();
    if (!codesParam) return safeJson(res, 400, { error: "Missing codes (comma-separated)" });
    const withCredit = (url.searchParams.get("with_credit") || "0") === "1";

    const codes = codesParam.split(",").map(s => s.trim()).filter(Boolean);
    if (!codes.length) return safeJson(res, 400, { error: "No valid codes" });

    const cacheKey = `portfolio:summary:${codes.slice().sort().join(",")}:${withCredit?"1":"0"}`;
    const hit = getCached(cacheKey);
    if (hit) return safeJson(res, 200, hit);

    const idToken = await ensureIdToken();

    const items = [];
    for (const code of codes) {
      try {
        const [fs, lastClose] = await Promise.all([
          jqFetch("/fins/statements", { code }, idToken),
          fetchLatestClose(idToken, code),
        ]);
        const rows0 = Array.isArray(fs) ? fs : (fs.statements || fs.data || []);
        if (!rows0.length) { items.push({ code, error: "No statements" }); continue; }
        const rows = [...rows0].sort(sortRecent);

        const ttm = ttmFromQuarterly(rows, {
          ni: ["NetIncome","netIncome","Profit","profit","ProfitAttributableToOwnersOfParent","netIncomeAttributableToOwnersOfParent"],
        });
        const shares = num(pick(rows[0], ["SharesOutstanding","sharesOutstanding","NumberOfIssuedAndOutstandingShares","issuedShares"]));
        const perShare = extractPerShareLatest(rows);
        const epsTTM = (shares > 0 && ttm.ni) ? (ttm.ni / shares) : perShare.eps;

        const per  = epsTTM > 0 ? (lastClose / epsTTM) : null;
        const pbr  = perShare.bps > 0 ? (lastClose / perShare.bps) : null;
        const yld  = (perShare.dps > 0 && lastClose > 0) ? (perShare.dps / lastClose) : 0;

        const base = { code, close: lastClose, per, pbr, dividend_yield: yld, eps_ttm: epsTTM, bps: perShare.bps, dps: perShare.dps };

        if (!withCredit) { items.push(base); continue; }

        // 週次信用の最新だけ添付（軽量）
        let credit = null;
        try {
          const raw = await jqFetch("/markets/weekly_margin_interest", { code }, idToken);
          const rowsC = Array.isArray(raw) ? raw : (raw.weekly_margin_interest || raw.data || []);
          rowsC.sort((a,b)=> String((b.Date||b.date||"")).localeCompare(String((a.Date||a.date||""))));
          const r0 = rowsC[0];
          if (r0) {
            const buy  = num(r0.BuyingOnMargin || r0.margin_buying || r0.buying_on_margin);
            const sell = num(r0.SellingOnMargin || r0.margin_selling || r0.selling_on_margin);
            credit = { date: r0.Date || r0.date, buying: buy, selling: sell, net: buy - sell };
          }
        } catch (_) {}
        items.push({ ...base, credit_latest: credit });
      } catch (e) {
        logWarn("portfolio.summary.row_skip", { code, err: String(e).slice(0,300) });
        items.push({ code, error: "fetch_failed" });
      }
    }

    const payload = { count: items.length, items };
    setCached(cacheKey, payload, 3 * 60 * 60_000);
    safeJson(res, 200, payload);
  } catch (e) {
    safeJson(res, 500, { error: String(e.message || e) });
  }
}

// ===== router =====
export default async function handler(req,res){
  try{
    const raw = typeof req?.url === "string" ? req.url : "/";
    const pathOnly = raw.split("?")[0].replace(/\/+$/, "");

    if (pathOnly === "/api/health") return handleHealth(req,res);

    if (pathOnly === "/api/auth/refresh" && (req.method==="POST"||req.method==="GET")) return handleAuthRefresh(req,res);
    if (pathOnly === "/api/universe/listed" && req.method==="GET") return handleUniverseListed(req,res);
    if (pathOnly === "/api/prices/daily" && req.method==="GET") return handlePricesDaily(req,res);

    if (pathOnly === "/api/fins/statements" && req.method==="GET") return handleFinsStatements(req,res);

    if (pathOnly === "/api/credit/weekly" && req.method==="GET") return handleCreditWeekly(req,res);
    if (pathOnly === "/api/credit/daily_public" && req.method==="GET") return handleCreditDailyPublic(req,res);

    if (pathOnly === "/api/screen/liquidity" && req.method==="GET") return handleScreenLiquidity(req,res);
    if (pathOnly === "/api/screen/basic" && req.method==="GET") return handleScreenBasic(req,res);

    if (pathOnly === "/api/portfolio/summary" && req.method==="GET") return handlePortfolioSummary(req,res);

    res.statusCode=404; res.end("Not Found");
  }catch(e){ safeJson(res,500,{error:String(e.message||e)}); }
}
