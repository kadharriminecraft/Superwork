/* =====================================================================
   RELAY SUPER WORKER — a dedicated Cloudflare Worker for the Relay
   proxy browser. Deploy on YOUR Cloudflare account (free tier is fine):

     1. dash.cloudflare.com → Workers & Pages → Create worker
     2. Name it (e.g. relay-super) → Edit code → paste this whole file
     3. Deploy → copy the URL (https://relay-super.YOU.workers.dev)
     4. Relay → Settings → Network → Super Worker → paste the URL → Save

   Why this unlocks "the absolute most" (vs generic CORS proxies):
     - Follows redirects server-side and reports the FINAL URL
       (X-Relay-Final-Url) so Relay's address bar is always correct
     - Streams binary bodies untouched (images, video, downloads)
     - FORCED DOWNLOADS: append &rl-dl=1&rl-fn=name to any proxied URL and
       the worker replies with Content-Disposition: attachment — the
       phone's real download manager takes over, so saved files actually
       appear in Downloads (blob: tricks often vanish on mobile).
       v2.0: EVERY failure on a download route (rl-dl, /__relay/file,
       /__relay/hls, early errors) ALSO answers as an attachment (with
       x-relay-dl-error / x-relay-file-miss markers) — so Relay can trigger
       downloads with a TOP-LEVEL anchor click, which is the one path mobile
       Chrome never blocks. (Hidden-iframe downloads are silently dropped
       by the ad-download heuristic — "the saver never pops up".)
       v2.1: the SPA location patch now also rewrites BARE location.href
       (etc.) tokens, not just (window|document).location.X — VitePress
       sites (fmhy.net) and most Vue SPAs boot their router from the bare
       form and otherwise render their own 404 page inside the sandbox.
     - FILE RELAY for client-side files: POST bytes to /__relay/put
       (X-Relay-Fn + X-Relay-Ct headers), get back {id}, then open
       /__relay/file/<id> — the worker serves YOUR bytes back as a real
       attachment download. Sites that build files in JavaScript (audio
       converters, exports) become reliably savable on Android/iOS.
       NOTE: Cloudflare routes each request independently, so the file
       relay works best on the same connection — Relay verifies the file
       before every click and falls back to its local-save ladder when an
       isolate boundary loses the bytes.
     - STATELESS HLS DOWNLOADS: GET /__relay/hls?url=<m3u8>&fn=<name> —
       the worker resolves the playlist (master -> best mobile variant ->
       init + segments), assembles the video and streams it back as a
       Content-Disposition attachment in ONE request. No stored state, any
       isolate, real download manager. (Steam trailers, any HLS CDN.)
     - Accepts POST/PUT/DELETE with body passthrough (form submits — search
       boxes, logins, and POST-then-file download endpoints like soundcloak's
       /_/download/<artist>/<track> — the mp3 comes straight back through
       the worker with its Content-Disposition filename intact)
     - Custom upstream headers via X-Relay-Headers (a JSON object: {"x-youtube-client-name":"3"})
       for API spoofing, plus X-Relay-UA for the fetch User-Agent
     - X-Relay-Cookie (v2.3): cookies written by the page's own JS inside
       the sandbox (consent banners, challenge tokens, session ids) ride
       back through the proxy and replay upstream — the per-isolate jar
       can't do that, so this closes the loop for cookie-based sites
     - v2.3: /__relay/hls muxes the separate AUDIO rendition into the saved
       MP4 (Steam + most modern CDNs ship video-only + audio-only HLS; the
       old assembler produced silent files)
     - Keeps a per-site cookie jar so LOGINS survive across requests
       (cookies are stored in the worker, scoped to the target host — they
       never leak to the browser or to other sites)
     - Forwards Range requests (media seeking works)
     - Strips CSP / X-Frame-Options / HSTS so nothing blocks rendering
     - Caches static assets on Cloudflare's edge (images load instantly
       the second time); X-Relay-NoCache: 1 skips the cache on demand
     - No shared rate limits — it is YOUR worker on YOUR quota
     - /__relay/health endpoint so Relay can auto-verify the connection
     - v2.7: /__relay/apl — the APLMate (Apple Music) flow runs INSIDE one
       invocation: session cookie + no-Turnstile JWT + track list + direct
       cdndl mp3 links, all from one isolate so the site's ip+ua+session
       binding stays consistent (separate invocations get different
       Cloudflare egress IPs and the site rejects them)

   URL shapes accepted (all equivalent):
     https://YOUR.WORKER/?url=https://example.com/      (encoded or raw)
     https://YOUR.WORKER/?https://example.com/          (Zibri style)
     https://YOUR.WORKER/https://example.com/           (path style)
   ===================================================================== */

const VERSION = '2.7';
const UA_DESKTOP = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const UA_MOBILE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const HOP_LIMIT = 10;
const FETCH_TIMEOUT_MS = 40000;

/* Headers we never forward back to the browser (they break rendering or
   are meaningless through a proxy) */
const STRIP_RESPONSE = new Set([
  'content-security-policy', 'content-security-policy-report-only',
  'x-frame-options', 'strict-transport-security', 'report-to', 'nel',
  'set-cookie', 'set-cookie2', 'alt-svc', 'cross-origin-opener-policy',
  'cross-origin-embedder-policy', 'cross-origin-resource-policy',
  'content-encoding', 'content-length', 'transfer-encoding',
  'permissions-policy', 'feature-policy', 'x-content-type-options',
  'cf-ray', 'cf-cache-status', 'server', 'reporting-endpoints'
]);
/* Request headers worth forwarding upstream */
const FORWARD_REQUEST = new Set([
  'accept', 'accept-language', 'range', 'if-none-match', 'if-modified-since',
  'content-type', 'authorization', 'x-requested-with', 'referer', 'x-relay-referer'
]);

addEventListener('fetch', (event) => {
  event.respondWith(handle(event.request, event));
});

/* ---- per-host cookie jar (best-effort, per isolate lifetime) ----
   Login/session cookies set by the target site are captured here and
   replayed on later requests to the same host. They are NEVER sent to the
   browser (that would put them on the worker's own domain — wrong scope). */
const JAR = new Map(); /* hostname -> Map(name -> { v, exp }) */
const JAR_MAX_HOSTS = 60, JAR_MAX_PER_HOST = 40;

/* ---- file-relay store (client bytes → real downloads) ---- */
const FILES = new Map(); /* id -> { buf, ct, fn, exp } */
const MAX_FILES = 12, MAX_FILE_BYTES = 150 * 1024 * 1024, FILE_TTL_MS = 10 * 60 * 1000;

function evictFiles() {
  const now = Date.now();
  for (const [k, v] of FILES) { if (v.exp < now) FILES.delete(k); }
}
function cors204(req) {
  return new Response(null, {
    status: 204,
    headers: {
      'access-control-allow-origin': (req.headers.get('origin') || '*'),
      'access-control-allow-methods': 'POST, GET, OPTIONS',
      'access-control-allow-headers': 'Content-Type, X-Relay-Fn, X-Relay-Ct',
      'access-control-max-age': '86400'
    }
  });
}
/* dl-mode failure as a 200 attachment — never a rendered page.
   x-relay-dl-error lets Relay's pre-click fetch() probe tell a dead link
   (falls back to the blob/Share ladder) from a healthy download, without
   ever letting the failure render as a page. */
function dlError(status, note) {
  return new Response('Relay download failed\n\n' + String(note || 'unknown error') + '\n\nThe file may be gone, or its host is blocking the proxy. Try the Share\nbutton (top of the page) or open the link directly.\n', {
    status: status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'content-disposition': 'attachment; filename="relay-download-failed.txt"',
      'x-relay-dl-error': '1',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*'
    }
  });
}

function readJar(host) {
  const m = JAR.get(host);
  if (!m) return [];
  const now = Date.now(), out = [];
  for (const [k, c] of m) {
    if (c.exp && c.exp < now) { m.delete(k); continue; }
    out.push(c.v);
  }
  return out;
}
function writeJar(host, setCookies) {
  if (!setCookies || !setCookies.length) return 0;
  let m = JAR.get(host);
  if (!m) {
    if (JAR.size >= JAR_MAX_HOSTS) return 0;
    m = new Map(); JAR.set(host, m);
  }
  let added = 0;
  for (const raw of setCookies) {
    const parts = String(raw).split(';');
    const pair = parts[0];
    const eq = pair.indexOf('=');
    if (eq < 1) continue;
    const name = pair.slice(0, eq).trim();
    if (!name || !/^[\w!#$%&'*+\-.^`|~]+$/.test(name)) continue;
    if (m.size >= JAR_MAX_PER_HOST && !m.has(name)) continue;
    let exp = 0;
    for (const p of parts.slice(1)) {
      const pm = /^\s*(max-age|expires)\s*=\s*(.*?)\s*$/i.exec(p);
      if (pm) {
        if (/^max-age$/i.test(pm[1])) { const s = parseInt(pm[2], 10); exp = isNaN(s) ? 0 : Date.now() + s * 1000; }
        else { const d = Date.parse(pm[2]); exp = isNaN(d) ? 0 : d; }
      }
    }
    if (exp && exp < Date.now()) { m.delete(name); continue; } /* expired cookie: drop */
    m.set(name, { v: pair.trim(), exp: exp });
    added++;
  }
  return added;
}
/* Set-Cookie split: headers.getSetCookie() when the runtime provides it,
   otherwise split the combined header on commas that start a new cookie
   (commas inside Expires dates don't match the lookahead). */
function getSetCookies(headers) {
  try {
    if (typeof headers.getSetCookie === 'function') {
      const arr = headers.getSetCookie();
      if (arr && arr.length) return arr;
    }
  } catch (e) {}
  const combined = headers.get('set-cookie');
  if (!combined) return [];
  return combined.split(/,(?=\s*[^\s=;,]+\s*=)/).map(s => s.trim()).filter(Boolean);
}
function mergeCookies(clientCookie, jarList) {
  const seen = new Set();
  const out = [];
  const add = (str) => {
    if (!str) return;
    for (const part of String(str).split(';')) {
      const p = part.trim();
      if (!p) continue;
      const eq = p.indexOf('=');
      const name = eq > 0 ? p.slice(0, eq).trim() : p;
      if (seen.has(name)) continue;
      seen.add(name); out.push(p);
    }
  };
  add(clientCookie);
  jarList.forEach(add);
  return out.join('; ');
}

/* ================= CMAF/fMP4 remux (v2.3) =================
   Split-rendition HLS (Steam and most modern CDNs) needs the video-only
   variant AND a separate audio rendition merged into ONE file. The pieces
   are self-contained CMAF fragments, so a real merge is possible without
   ffmpeg: build one init segment declaring BOTH tracks (video moov + the
   audio trak with a rewritten track id), then interleave the fragments,
   rewriting each audio fragment's tfhd track id to match. Every step is
   validated; anything unexpected returns null and the caller falls back
   to the old video-only assembly (with an honest note). */
function rlU32(u8, off){ return (u8[off] << 24 | u8[off + 1] << 16 | u8[off + 2] << 8 | u8[off + 3]) >>> 0; }
function rlSetU32(u8, off, v){ u8[off] = (v >>> 24) & 255; u8[off + 1] = (v >>> 16) & 255; u8[off + 2] = (v >>> 8) & 255; u8[off + 3] = v & 255; }
/* iterate top-level ISO-BMFF boxes in u8[start,end) */
function rlBoxes(u8, start, end){
  const out = [];
  let p = start;
  while (p + 8 <= end){
    let size = rlU32(u8, p);
    let head = 8;
    if (size === 1){
      if (p + 16 > end) break;
      const hi = rlU32(u8, p + 8), lo = rlU32(u8, p + 12);
      size = hi * 4294967296 + lo;
      head = 16;
    } else if (size === 0){
      size = end - p;
    }
    if (size < head || p + size > end) break;
    const type = String.fromCharCode(u8[p + 4], u8[p + 5], u8[p + 6], u8[p + 7]);
    out.push({ type: type, start: p, head: head, size: size, end: p + size });
    p += size;
  }
  return out;
}
function rlConcat(parts){
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts){ out.set(p, o); o += p.length; }
  return out;
}
/* read a single box's payload bytes */
function rlPayload(u8, box){ return u8.subarray(box.start + box.head, box.end); }
/* track id inside trex/tfhd (fullbox: 4 bytes ver/flags, then the id) */
function rlTrackId(u8, box){
  const pay = box.start + box.head;
  return rlU32(u8, pay + 4);
}
/* track id inside tkhd — layout depends on the version byte:
   v0: ver/flags(4) created(4) modified(4) track_ID(4)  -> payload+12
   v1: ver/flags(4) created(8) modified(8) track_ID(4) -> payload+20 */
function rlTkhdTrackId(u8, box){
  const p = box.start + box.head;
  const ver = u8[p];           /* FullBox version = first byte */
  return rlU32(u8, p + (ver === 1 ? 20 : 12));
}
/* merge the video init + audio init into one two-track init */
function rlMergeCmafInit(vBuf, aBuf){
  try{
    const v = new Uint8Array(vBuf), a = new Uint8Array(aBuf);
    const vTop = rlBoxes(v, 0, v.length);
    const aTop = rlBoxes(a, 0, a.length);
    const vFtyp = vTop.find(b => b.type === 'ftyp');
    const vMoovB = vTop.find(b => b.type === 'moov');
    const aMoovB = aTop.find(b => b.type === 'moov');
    if (!vMoovB || !aMoovB) return null;
    const vMoov = rlBoxes(v, vMoovB.start + vMoovB.head, vMoovB.end);
    const aMoov = rlBoxes(a, aMoovB.start + aMoovB.head, aMoovB.end);
    const vMvhd = vMoov.find(b => b.type === 'mvhd');
    const vTrak = vMoov.filter(b => b.type === 'trak');
    const vMvexB = vMoov.find(b => b.type === 'mvex');
    const aTrak = aMoov.filter(b => b.type === 'trak');
    const aMvexB = aMoov.find(b => b.type === 'mvex');
    if (!vMvhd || vTrak.length !== 1 || !vMvexB || aTrak.length !== 1 || !aMvexB) return null;
    /* trex boxes carry per-track fragment defaults */
    const vMvex = rlBoxes(v, vMvexB.start + vMvexB.head, vMvexB.end);
    const aMvex = rlBoxes(a, aMvexB.start + aMvexB.head, aMvexB.end);
    const vTrex = vMvex.find(b => b.type === 'trex');
    const aTrex = aMvex.filter(b => b.type === 'trex');
    if (!vTrex || aTrex.length !== 1) return null;
    const vTkhd = rlBoxes(v, vTrak[0].start + vTrak[0].head, vTrak[0].end).find(b => b.type === 'tkhd');
    const aTkhd = rlBoxes(a, aTrak[0].start + aTrak[0].head, aTrak[0].end).find(b => b.type === 'tkhd');
    if (!vTkhd || !aTkhd) return null;
    const vid = rlTkhdTrackId(v, vTkhd);
    let aid = rlTkhdTrackId(a, aTkhd);
    const aTrexId = rlTrackId(a, aTrex[0]);
    if (aid !== aTrexId) return null;      /* trak/trex disagree — bail */
    let newAid = aid;
    if (newAid === vid){
      newAid = vid + 1;
      if (newAid > 0xffff) return null;
    }
    /* patch the audio trak + trex track ids (4-byte in-place writes) */
    const aTrakPatched = new Uint8Array(rlPayload(a, aTrak[0]));
    {
      const kids = rlBoxes(aTrakPatched, 0, aTrakPatched.length);
      const tkhd = kids.find(b => b.type === 'tkhd');
      if (!tkhd) return null;
      const ver = aTrakPatched[tkhd.start + tkhd.head];
      rlSetU32(aTrakPatched, tkhd.start + tkhd.head + (ver === 1 ? 20 : 12), newAid);
    }
    const aTrexPatched = new Uint8Array(rlPayload(a, aTrex[0]));
    rlSetU32(aTrexPatched, 4, newAid);
    /* mvhd next_track_id (v0 layout: ver/flags, created, modified, timescale,
       duration, .. 22 bytes rate+volume+reserved+matrix .., next_track_id at
       offset 100 of the payload; v1 differs — bump only when the layout is v0) */
    const vMvhdPayload = new Uint8Array(rlPayload(v, vMvhd));
    if (vMvhdPayload.length >= 104 && vMvhdPayload[0] === 0){
      if (rlU32(vMvhdPayload, 100) <= newAid) rlSetU32(vMvhdPayload, 100, newAid + 1);
    }
    /* rebuild moov: mvhd, video trak, audio trak, mvex(trex, trex).
       NOTE: mvex children are FULL boxes (8-byte headers + payload) —
       concatenating bare trex payloads produces garbage the demuxer reads
       as a size-0 box and every fragment after it fails to resolve its
       track (the exact bug ffprobe surfaced on Steam's streams). */
    const vTrakPayload = new Uint8Array(rlPayload(v, vTrak[0]));
    const mkBox = (type, body) => {
      const out = new Uint8Array(8 + body.length);
      rlSetU32(out, 0, out.length);
      out[4] = type.charCodeAt(0); out[5] = type.charCodeAt(1); out[6] = type.charCodeAt(2); out[7] = type.charCodeAt(3);
      out.set(body, 8);
      return out;
    };
    const trexVFull = new Uint8Array(v.subarray(vTrex.start, vTrex.end));
    const trexAFull = mkBox('trex', aTrexPatched);
    let mvexBody = new Uint8Array(0);
    {
      const keep = [];
      for (const b of vMvex){
        if (b.type === 'trex') continue;   /* replaced by the two trex below */
        keep.push(new Uint8Array(v.subarray(b.start, b.end)));
      }
      keep.push(trexVFull);
      keep.push(trexAFull);
      mvexBody = rlConcat(keep);
    }
    const mk = (type, body) => {
      const out = new Uint8Array(8 + body.length);
      rlSetU32(out, 0, out.length);
      out[4] = type.charCodeAt(0); out[5] = type.charCodeAt(1); out[6] = type.charCodeAt(2); out[7] = type.charCodeAt(3);
      out.set(body, 8);
      return out;
    };
    const moovParts = [
      mk('mvhd', vMvhdPayload),
      mk('trak', vTrakPayload),
      mk('trak', aTrakPatched),
      mk('mvex', mvexBody)
    ];
    const moov = mk('moov', rlConcat(moovParts));
    const ftyp = vFtyp ? new Uint8Array(rlPayload(v, vFtyp)) : null;
    const parts = [];
    if (ftyp) parts.push(mk('ftyp', ftyp));
    parts.push(moov);
    return rlConcat(parts);
  } catch (eMI){ return null; }
}
/* rewrite a fragment's tfhd track ids (audio segs keep their own ids in
   the source file; when they equal oldId they become newId) and drop
   sidx/styp boxes so interleaving cannot leave stale indexes around */
function rlRetagCmafSeg(segBuf, oldId, newId){
  try{
    const u8 = new Uint8Array(segBuf);
    const top = rlBoxes(u8, 0, u8.length);
    if (!top.length) return null;
    let moof = null;
    const keep = [];
    for (const b of top){
      if (b.type === 'sidx' || b.type === 'styp') continue;
      keep.push(b);
      if (b.type === 'moof') moof = b;
    }
    if (!moof) return null;
    if (oldId !== newId){
      const moofKids = rlBoxes(u8, moof.start + moof.head, moof.end);
      for (const mb of moofKids){
        if (mb.type !== 'traf') continue;
        const trafs = rlBoxes(u8, mb.start + mb.head, mb.end);
        for (const tb of trafs){
          if (tb.type !== 'tfhd') continue;
          const at = tb.start + tb.head + 4;
          if (rlU32(u8, at) === oldId) rlSetU32(u8, at, newId);
        }
      }
    }
    const parts = keep.map(b => new Uint8Array(u8.subarray(b.start, b.end)));
    return rlConcat(parts);
  } catch (eRS){ return null; }
}

/* ---- APLMate flow (single invocation) ----------------------------------
   Every helper here is LOCAL to one request: cookie string, UA, Referer all
   thread through the chain inside the same invocation (see the route doc
   above for why that binding matters). */
const APL_UA = UA_MOBILE;
function aplCookieFrom(res, prev) {
  try {
    let scs = [];
    if (typeof res.headers.getSetCookie === 'function') scs = res.headers.getSetCookie() || [];
    if (!scs.length) { const c = res.headers.get('set-cookie'); if (c) scs = [c]; }
    if (!scs.length) return prev || '';
    let jar = {};
    String(prev || '').split(/;\s*/).filter(Boolean).forEach(function (p) {
      const eq = p.indexOf('=');
      if (eq > 0) jar[p.slice(0, eq)] = p.slice(eq + 1);
    });
    scs.forEach(function (raw) {
      const kv = String(raw).split(';')[0];
      const eq = kv.indexOf('=');
      if (eq > 0) {
        const k = kv.slice(0, eq);
        const v = kv.slice(eq + 1);
        if (v === '' || /^(deleted|)$/i.test(v)) delete jar[k]; /* expired */
        else jar[k] = v;
      }
    });
    return Object.keys(jar).map(function (k) { return k + '=' + jar[k]; }).join('; ');
  } catch (eC) { return prev || ''; }
}
async function aplFetch(url, init, cookie) {
  /* one upstream call with the site's session + referer + UA, following
     redirects manually so Set-Cookie is captured at every hop.
     Returns {res, cookie} — the caller keeps threading the jar. */
  let next = url;
  let res = null;
  for (let hop = 0; hop <= 4; hop++) {
    const headers = Object.assign({}, init.headers || {});
    if (cookie) headers['cookie'] = cookie;
    res = await fetch(next, Object.assign({}, init, { headers: headers, redirect: 'manual' }));
    cookie = aplCookieFrom(res, cookie);
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) break;
      try { next = new URL(loc, next).href; } catch (eL) { break; }
      try { if (res.body) await res.body.cancel(); } catch (eB) {}
      continue;
    }
    break;
  }
  return { res: res, cookie: cookie };
}
async function aplHandle(u) {
  const url = (u.searchParams.get('url') || '').trim();
  const trackIdx = parseInt(u.searchParams.get('track') || '-1', 10);
  const maxEager = Math.max(1, Math.min(40, parseInt(u.searchParams.get('max') || '10', 10) || 10));
  if (!/^https?:\/\/(music\.apple\.com|amp\.music\.apple\.com|embed\.music\.apple\.com)\//i.test(url)) {
    return json(400, { ok: false, error: 'Not an Apple Music link — paste a music.apple.com URL' });
  }
  const B = 'https://aplmate.com';
  let cookie = '';

  /* 1. warmup — establish the session cookie */
  let rr = await aplFetch(B + '/', { headers: { 'user-agent': APL_UA, accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'accept-language': 'en-US,en;q=0.9' } }, cookie);
  cookie = rr.cookie;
  if (!/session_data=/.test(cookie)) {
    /* one retry — occasional 429/5xx blips at the edge */
    await new Promise(function (res) { setTimeout(res, 600); });
    rr = await aplFetch(B + '/', { headers: { 'user-agent': APL_UA, accept: 'text/html', 'accept-language': 'en-US,en;q=0.9' } }, cookie);
    cookie = rr.cookie;
    if (!/session_data=/.test(cookie)) return json(502, { ok: false, error: 'APLMate did not start a session (edge hiccup) — try again' });
  }

  /* 2. userverify — the no-Turnstile JWT mint */
  let token = '';
  for (let a = 0; a < 2 && !token; a++) {
    if (a) await new Promise(function (res) { setTimeout(res, 700); });
    rr = await aplFetch(B + '/action/userverify', {
      method: 'POST',
      headers: { 'user-agent': APL_UA, referer: B + '/', 'x-requested-with': 'XMLHttpRequest', 'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', accept: '*/*' },
      body: 'url=' + encodeURIComponent(url)
    }, cookie);
    cookie = rr.cookie;
    try { token = (JSON.parse(await rr.res.text()) || {}).token || ''; } catch (eT) { token = ''; }
  }
  if (!token) return json(502, { ok: false, error: 'APLMate token mint failed — try again in a minute' });

  /* 3. /action — the track list (multipart, exactly like the site's FormData XHR) */
  let html = '', errMsg = '';
  for (let a = 0; a < 2 && !html; a++) {
    if (a) await new Promise(function (res) { setTimeout(res, 700); });
    const fd = new FormData();
    fd.append('url', url);
    fd.append('cf-turnstile-response', token);
    rr = await aplFetch(B + '/action', {
      method: 'POST',
      headers: { 'user-agent': APL_UA, referer: B + '/', accept: '*/*' },
      body: fd
    }, cookie);
    cookie = rr.cookie;
    try {
      const j = JSON.parse(await rr.res.text());
      if (j && j.html) html = String(j.html);
      else if (j && j.message) errMsg = String(j.message);
    } catch (eA) {}
  }
  if (!html) return json(502, { ok: false, error: errMsg || 'APLMate could not read that link' });

  /* 4. parse the album header + every track form */
  const tracks = [];
  const formRe = /<form\s+name="submitapurl"[^>]*>([\s\S]*?)<\/form>/g;
  let fm2;
  while ((fm2 = formRe.exec(html)) !== null) {
    const f = fm2[1];
    const gv = function (n) {
      const m = new RegExp('name="' + n + '" value=\'([^\']*)\'').exec(f);
      return m ? m[1] : '';
    };
    let meta = {};
    try { meta = JSON.parse(atob(gv('data'))) || {}; } catch (eD) {}
    tracks.push({
      i: tracks.length,
      data: gv('data'), base: gv('base'), token: gv('token'),
      name: String(meta.name || 'Track ' + (tracks.length + 1)).slice(0, 120),
      artist: String(meta.artist || '').slice(0, 120),
      album: String(meta.album || '').slice(0, 120),
      cover: String(meta.cover || '').slice(0, 400),
      duration: String(meta.duration || '').slice(0, 12),
      mp3: ''
    });
  }
  if (!tracks.length) return json(200, { ok: true, version: VERSION, album: { title: '', artist: '', cover: '' }, tracks: [], note: 'No downloadable tracks on that page' });
  const headerTitle = (/<h3[^>]*itemprop="name"[^>]*>\s*<[^>]*title="([^"]+)"/.exec(html) || [])[1] || tracks[0].album || '';
  const headerArtist = (/<p><span>([^<]+)\s*·/.exec(html) || [])[1] || tracks[0].artist || '';
  const headerCover = (/(<img[^>]+class="[^"]*"[^>]*src=")(https:[^"]+)"/.exec(html) || [])[2] || tracks[0].cover || '';

  /* 5. resolve track mp3 links — eager for the first N, or exactly the one asked for */
  const want = trackIdx >= 0 ? [trackIdx] : tracks.map(function (t, i) { return i; }).slice(0, maxEager);
  let deadStreak = 0;
  for (const idx of want) {
    if (idx >= tracks.length) continue;
    const t = tracks[idx];
    let got = false;
    for (let a = 0; a < 2 && !got; a++) {
      if (a) await new Promise(function (res) { setTimeout(res, 800); });
      try {
        const fd = new FormData();
        fd.append('data', t.data);
        fd.append('base', t.base);
        fd.append('token', t.token);
        rr = await aplFetch(B + '/action/track', {
          method: 'POST',
          headers: { 'user-agent': APL_UA, referer: B + '/', accept: '*/*' },
          body: fd
        }, cookie);
        cookie = rr.cookie;
        const j = JSON.parse(await rr.res.text());
        if (j && j.data) {
          const dl = String(j.data);
          t.mp3 = (/href="(https:\/\/cdndl\.aplmate\.com\/mp3\?token=[^"]+)"/.exec(dl) || [])[1] || '';
          got = !!t.mp3;
        }
      } catch (eTR) {}
    }
    deadStreak = got ? 0 : deadStreak + 1;
    if (deadStreak >= 2) break; /* the site throttled this run — ship what we have */
    await new Promise(function (res) { setTimeout(res, 350); }); /* polite spacing */
  }
  return json(200, {
    ok: true,
    version: VERSION,
    album: { title: headerTitle.slice(0, 140), artist: headerArtist.slice(0, 140), cover: headerCover.slice(0, 400) },
    tracks: tracks,
    lazy: tracks.filter(function (t) { return !t.mp3; }).length
  });
}

async function handle(req, event) {
  const u = new URL(req.url);

  /* ---- health / detection endpoint ---- */
  if (u.pathname === '/__relay/health' || u.pathname === '/healthz') {
    return new Response('relay-super-ok/' + VERSION, {
      status: 200,
      headers: {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
        'access-control-allow-origin': '*',
        'x-relay-version': VERSION
      }
    });
  }

  /* ---- Apple Music grabber: GET /__relay/apl?url=<music.apple.com link>[&track=N][&max=M]
     APLMate (aplmate.com) converts Apple Music links to mp3, but its flow is
     session-BOUND: the token it issues embeds the requester's ip + user-agent
     + session cookie, and every step must present all three CONSISTENTLY.
     From the browser those steps would exit through different proxy IPs
     (each netFetch races its own proxy), and even two calls to this worker
     can land on different isolates with different egress IPs — so the only
     reliable shape is the whole chain INSIDE ONE invocation, where the
     isolate, the cookie, the UA and the egress IP all stay fixed. The
     Turnstile front-gate is bypassed entirely: the site's own fallback
     endpoint (/action/userverify) mints a signed JWT with no human-check
     (it exists for browsers where Turnstile fails to load). Steps: warmup
     (session cookie) -> userverify (JWT) -> /action (multipart, like the
     site's FormData XHR; returns the track list) -> /action/track per song
     (multipart; returns cdndl.aplmate.com/mp3?token= direct links, which are
     URL-authenticated and work from ANY IP for 10h). The app then downloads
     the mp3 through this worker's normal proxy path. Eager track resolution
     is capped (subrequest limit ~50/invocation); the rest resolve lazily
     via &track=N (which re-runs the cheap steps + one track call). */
  if (u.pathname === '/__relay/apl') {
    if (req.method === 'OPTIONS') return cors204(req);
    try { return await aplHandle(u); } catch (eApl) {
      return json(502, { ok: false, error: 'apl flow failed: ' + String((eApl && eApl.message) || eApl).slice(0, 160) });
    }
  }

  /* ---- file relay: client-side bytes → real download ----
     JS-generated files (blob:/data: from converters, export buttons) can't
     be handed to the mobile download manager reliably from a page — but the
     worker can serve them back as a genuine Content-Disposition attachment.
     POST /__relay/put (body = bytes, X-Relay-Fn/X-Relay-Ct headers) → {id}
     GET  /__relay/file/<id>[?rl-fn=name] → the bytes as a download.
     Stored per-isolate in memory: max 12 files, 64MB total, 10-minute TTL. */
  if (u.pathname === '/__relay/put') {
    if (req.method !== 'POST' && req.method !== 'OPTIONS') return json(405, { error: 'POST only' });
    if (req.method === 'OPTIONS') return cors204(req);
    const ctl = req.headers.get('content-length');
    if (ctl && parseInt(ctl, 10) > MAX_FILE_BYTES) return json(413, { error: 'file too large (max 80MB)' });
    let buf;
    try { buf = await req.arrayBuffer(); }
    catch (eBuf) { return json(400, { error: 'unreadable body' }); }
    if (buf.byteLength === 0) return json(400, { error: 'empty body' });
    if (buf.byteLength > MAX_FILE_BYTES) return json(413, { error: 'file too large (max 80MB)' });
    try { evictFiles(); } catch (eEv) {}
    if (FILES.size >= MAX_FILES) {
      const oldest = FILES.keys().next().value;
      FILES.delete(oldest);
    }
    const id = 'f' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
    FILES.set(id, {
      buf: buf,
      ct: (req.headers.get('x-relay-ct') || 'application/octet-stream').split(';')[0].slice(0, 100),
      fn: String(req.headers.get('x-relay-fn') || 'download').slice(0, 120),
      exp: Date.now() + FILE_TTL_MS
    });
    return json(200, { id: id, url: '/__relay/file/' + id, expires_in: FILE_TTL_MS });
  }
  const fm = /^\/__relay\/file\/([A-Za-z0-9]+)$/.exec(u.pathname);
  if (fm) {
    const rec = FILES.get(fm[1]);
    if (!rec || rec.exp < Date.now()) {
      if (rec) FILES.delete(fm[1]);
      /* 200 + attachment + miss marker — NEVER a plain 404 JSON: Relay now
         clicks these URLs with a top-level anchor (the only download path
         mobile Chrome never blocks), so a miss must not render as a page.
         Relay's pre-click probe reads x-relay-file-miss and falls back to
         its Blob/Share ladder instead of saving this notice. */
      return new Response('Relay file relay missed — the worker instance that held these bytes is gone.\nUse Share from the page, or download the file again.\n', {
        status: 200,
        headers: {
          'content-type': 'text/plain; charset=utf-8',
          'content-disposition': 'attachment; filename="relay-file-missed.txt"',
          'x-relay-file-miss': '1',
          'cache-control': 'no-store',
          'access-control-allow-origin': '*',
          'x-relay-version': VERSION
        }
      });
    }
    const fn = (u.searchParams.get('rl-fn') || rec.fn || 'download').replace(/[\r\n"\\/]/g, '_');
    const safe = fn.replace(/[^\x20-\x7e]/g, '_').slice(0, 120) || 'download';
    const enc = encodeURIComponent(fn).replace(/['()]/g, function (c) { return '%' + c.charCodeAt(0).toString(16).toUpperCase(); });
    const out = new Headers({
      'content-type': rec.ct || 'application/octet-stream',
      'content-disposition': "attachment; filename=\"" + safe + "\"; filename*=UTF-8''" + enc,
      'cache-control': 'no-store',
      'access-control-allow-origin': '*',
      'x-relay-version': VERSION
    });
    return new Response(rec.buf, { status: 200, headers: out });
  }

  /* ---- STATELESS HLS download: GET /__relay/hls?url=<playlist>&fn=<name>&maxh=<720>
     A .m3u8 is a text playlist, not the video — the browser-side app can
     resolve and reassemble it, but handing the BYTES back to the user was
     the unreliable part (the in-memory file relay breaks when Cloudflare
     routes the follow-up GET to a different isolate). THIS endpoint does the
     whole job inside ONE request: fetch the master playlist, pick the best
     mobile-friendly variant (height <= maxh, default 720; else the lowest
     bandwidth), fetch its media playlist, pull the init (#EXT-X-MAP) plus
     every segment — AND, when the master declares a separate AUDIO
     rendition (Steam and most modern CDNs), fetch the audio playlist too
     and MUX both tracks into one MP4 via the CMAF remuxer above, so the
     saved file is not silent. No stored state, so any isolate can serve it.
     Limits (Workers free tier): ~50 subrequests per invocation — playlists
     (up to 3) plus at most 42 pieces; over that the response is a 422 with
     a clear message so the app can fall back to its client-side assembler. */
  if (u.pathname === '/__relay/hls') {
    if (req.method === 'OPTIONS') return cors204(req);
    const plUrl = u.searchParams.get('url') || '';
    const fnRaw = (u.searchParams.get('fn') || 'video').replace(/\.m3u8$/i, '').slice(0, 120);
    const maxH = Math.max(240, Math.min(2160, parseInt(u.searchParams.get('maxh') || '720', 10) || 720));
    const probeOnly = u.searchParams.get('probe') === '1';
    /* every failure is an ATTACHMENT (v2.0): the download click is a
       top-level anchor, and a text error body must never render as a page */
    const hlsNote = (msg, status) => new Response('Relay HLS download failed\n\n' + msg + '\n', {
      status: status || 502,
      headers: {
        'content-type': 'text/plain; charset=utf-8',
        'content-disposition': 'attachment; filename="relay-hls-failed.txt"',
        'x-relay-dl-error': '1',
        'cache-control': 'no-store',
        'access-control-allow-origin': '*',
        'x-relay-version': VERSION
      }
    });
    if (!/^https?:\/\//i.test(plUrl)) return hlsNote('missing or invalid playlist url', 400);
    const hlsFetch = async (urlStr) => {
      for (let a = 0; a < 3; a++) {
        try {
          const r = await fetch(urlStr, {
            headers: { 'user-agent': UA_MOBILE, 'accept': '*/*' },
            redirect: 'follow', credentials: 'omit'
          });
          if ([403, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524].includes(r.status) && a < 2) { continue; }
          if (!r.ok) throw new Error('http ' + r.status + ' fetching ' + urlStr.split('/').pop());
          return r;
        } catch (e) {
          if (a >= 2) throw e;
          await new Promise((rr) => setTimeout(rr, 350 + a * 450));
        }
      }
    };
    /* playlist parser: master variants + audio-rendition declaration +
       media playlist segments + the CMAF init (#EXT-X-MAP) */
    const parsePl = (txt) => {
      const lines = String(txt).split(/\r?\n/);
      const out = { master: false, mapUri: '', segs: [], variants: [], audioUri: '' };
      let bw = 0, h = 0;
      const audioCands = [];
      for (const raw of lines) {
        const ln = raw.trim();
        if (!ln) continue;
        if (ln[0] === '#') {
          if (/^#EXT-X-STREAM-INF/i.test(ln)) {
            out.master = true;
            bw = parseInt((/BANDWIDTH=(\d+)/i.exec(ln) || [0, 0])[1], 10) || 0;
            const mr = /RESOLUTION=(\d+)x(\d+)/i.exec(ln);
            h = mr ? parseInt(mr[2], 10) : 0;
          } else if (/^#EXT-X-MEDIA/i.test(ln) && /TYPE\s*=\s*"?AUDIO"?/i.test(ln)) {
            const um = /URI\s*=\s*"([^"]+)"/i.exec(ln);
            if (um) audioCands.push({ uri: um[1], def: /DEFAULT\s*=\s*YES/i.test(ln) });
          } else {
            const mm = /^#EXT-X-MAP:.*URI="([^"]+)"/i.exec(ln);
            if (mm) out.mapUri = mm[1];
          }
          continue;
        }
        if (out.master && (bw || h)) { out.variants.push({ uri: ln, bw, h }); bw = 0; h = 0; }
        else if (!out.master) out.segs.push(ln);
      }
      /* preferred audio rendition: DEFAULT=YES first, else the first declared */
      const pref = audioCands.filter(a => a.def)[0] || audioCands[0];
      if (pref) out.audioUri = pref.uri;
      return out;
    };
    const absU = (rel, base) => { try { return new URL(rel, base).href; } catch (e) { return null; } };

    try {
      const masterRes = await hlsFetch(plUrl);
      const masterTxt = await masterRes.text();
      if (!/^#EXTM3U/i.test(masterTxt.trim())) throw new Error('the url did not return an HLS playlist');
      let pl = parsePl(masterTxt);
      let chosen = plUrl;
      let audioPlUrl = pl.audioUri ? absU(pl.audioUri, plUrl) : '';
      if (pl.master) {
        let pool = pl.variants.filter((v) => v.h && v.h <= maxH);
        if (!pool.length) pool = pl.variants.slice().sort((a, b) => (a.bw || 0) - (a.bw || 0)).slice(0, 1);
        if (!pool.length) throw new Error('no variants in the master playlist');
        const best = pool.reduce((a, b) => ((b.bw || 0) > (a.bw || 0) ? b : a));
        chosen = absU(best.uri, plUrl);
        if (!chosen) throw new Error('bad variant url');
        const varRes = await hlsFetch(chosen);
        pl = parsePl(await varRes.text());
        if (pl.master) throw new Error('nested master playlists');
      }
      /* video pieces: [init?] + segments */
      const videoPieces = [];
      if (pl.mapUri){ const mi = absU(pl.mapUri, chosen); if (mi) videoPieces.push(mi); }
      for (const s of pl.segs){ const su = absU(s, chosen); if (su) videoPieces.push(su); }
      if (!videoPieces.length) throw new Error('no media segments in the playlist');

      /* ---- audio rendition (split-track CDNs: Steam etc.) ---- */
      let audioPieces = [];
      let audioPl = null;
      if (audioPlUrl){
        try{
          const aRes = await hlsFetch(audioPlUrl);
          const aTxt = await aRes.text();
          if (/^#EXTM3U/i.test(String(aTxt).trim())){
            const ap = parsePl(aTxt);
            if (!ap.master){
              if (ap.mapUri){ const mi = absU(ap.mapUri, audioPlUrl); if (mi) audioPieces.push(mi); }
              for (const s of ap.segs){ const su = absU(s, audioPlUrl); if (su) audioPieces.push(su); }
              audioPl = { hasInit: !!ap.mapUri, nSegs: ap.segs.length };
            }
          }
        }catch(eAudio){ audioPieces = []; audioPl = null; }
      }
      /* mux is only possible when BOTH playlists carry a CMAF init */
      const canMux = !!(pl.mapUri && audioPl && audioPl.hasInit && audioPieces.length);
      const totalPieces = videoPieces.length + audioPieces.length;
      if (probeOnly) return json(200, { ok: 1, pieces: totalPieces, audio_split: (audioPieces.length && !canMux) ? 1 : 0, audio_mux: canMux ? 1 : 0, version: VERSION });
      if (totalPieces > 42) return hlsNote('this stream has ' + totalPieces + ' segments — over the per-request subrequest limit. The app will assemble it client-side instead.', 422);

      const capBytes = 150 * 1024 * 1024;
      let total = 0;
      const grab = async (pu) => {
        const r = await hlsFetch(pu);
        const buf = await r.arrayBuffer();
        if (!buf || buf.byteLength === 0) throw new Error('empty segment ' + pu.split('/').pop());
        total += buf.byteLength;
        if (total > capBytes) throw new Error('the assembled video exceeds the 150MB worker limit — use Copy link');
        return buf;
      };
      /* fetch the video track once — reused by both the muxed and the
         video-only fallback answer */
      const vParts = [];
      for (const pu of videoPieces) vParts.push(await grab(pu));

      if (canMux){
        try{
          const aParts = [];
          for (const au of audioPieces) aParts.push(await grab(au));
          const vInit = vParts[0], aInit = aParts[0];
          const vSegs = vParts.slice(1), aSegs = aParts.slice(1);
          const merged = rlMergeCmafInit(vInit, aInit);
          if (merged){
            /* track ids: read each init's single trak; retag audio fragments
               when the ids collide with the video track */
            const trackIdOf = (buf) => {
              try{
                const u8 = new Uint8Array(buf);
                const moov = rlBoxes(u8, 0, u8.length).find(b => b.type === 'moov');
                if (!moov) return 0;
                const trak = rlBoxes(u8, moov.start + moov.head, moov.end).find(b => b.type === 'trak');
                if (!trak) return 0;
                const tkhd = rlBoxes(u8, trak.start + trak.head, trak.end).find(b => b.type === 'tkhd');
                if (!tkhd) return 0;
                return rlTrackId(u8, tkhd);
              }catch(eT){ return 0; }
            };
            const vid = trackIdOf(vInit) || 1;
            const aid = trackIdOf(aInit) || 1;
            const newAid = (aid === vid) ? (vid + 1) : aid;
            const outParts = [merged];
            const n = Math.max(vSegs.length, aSegs.length);
            for (let i = 0; i < n; i++){
              /* video fragments pass through the retagger too: identical ids,
                 but it strips styp/sidx — a stale sidx would point at the
                 PRE-interleave offsets and corrupt parsing */
              if (i < vSegs.length){
                const vr = rlRetagCmafSeg(vSegs[i], vid, vid);
                outParts.push(vr ? vr : vSegs[i]);
              }
              if (i < aSegs.length){
                const ret = rlRetagCmafSeg(aSegs[i], aid, newAid);
                outParts.push(ret ? ret : aSegs[i]);
              }
            }
            const fn2 = (fnRaw + (/\.mp4$/i.test(fnRaw) ? '' : '.mp4'));
            const safe2 = fn2.replace(/[\r\n"\\/]/g, '_').replace(/[^\x20-\x7e]/g, '_').slice(0, 120) || 'video.mp4';
            const enc2 = encodeURIComponent(fn2).replace(/['()]/g, function (c) { return '%' + c.charCodeAt(0).toString(16).toUpperCase(); });
            const out2 = new Headers({
              'content-type': 'video/mp4',
              'content-disposition': "attachment; filename=\"" + safe2 + "\"; filename*=UTF-8''" + enc2,
              'cache-control': 'no-store',
              'access-control-allow-origin': '*',
              'x-relay-hls-pieces': String(totalPieces),
              'x-relay-audio-mux': '1',
              'x-relay-version': VERSION
            });
            const joined2 = new ReadableStream({
              start(c) {
                try { for (const p of outParts) c.enqueue(new Uint8Array(p)); c.close(); }
                catch (eSt2) { try { c.close(); } catch (eCl2) {} }
              }
            });
            return new Response(outParts.length === 1 ? outParts[0] : joined2, { status: 200, headers: out2 });
          }
          /* merge refused (unexpected box layout) — video-only below */
        }catch(eMux){ /* audio fetch failed mid-way — video-only below */ }
      }

      /* ---- video-only answer (no audio rendition, or the mux bailed) ---- */
      const fn = (fnRaw + (/\.mp4$/i.test(fnRaw) ? '' : '.mp4'));
      const safe = fn.replace(/[\r\n"\\/]/g, '_').replace(/[^\x20-\x7e]/g, '_').slice(0, 120) || 'video.mp4';
      const enc = encodeURIComponent(fn).replace(/['()]/g, function (c) { return '%' + c.charCodeAt(0).toString(16).toUpperCase(); });
      const out = new Headers({
        'content-type': 'video/mp4',
        'content-disposition': "attachment; filename=\"" + safe + "\"; filename*=UTF-8''" + enc,
        'cache-control': 'no-store',
        'access-control-allow-origin': '*',
        'x-relay-hls-pieces': String(totalPieces),
        'x-relay-audio-split': audioPieces.length ? '1' : '0',
        'x-relay-version': VERSION
      });
      /* v2.2: stream the parts back one by one instead of materializing a
         second contiguous copy (Blob -> arrayBuffer doubled peak isolate
         memory — what killed assemblies approaching the 100MB ceiling) */
      const joined = new ReadableStream({
        start(c) {
          try { for (const p of vParts) c.enqueue(new Uint8Array(p)); c.close(); }
          catch (eSt) { try { c.close(); } catch (eCl) {} }
        }
      });
      return new Response(vParts.length === 1 ? vParts[0] : joined, { status: 200, headers: out });
    } catch (eH) {
      return hlsNote(String((eH && eH.message) || eH));
    }
  }
  /* ---- forced-download mode ----
     &rl-dl=1 turns ANY proxied URL into a file download: the response gets
     Content-Disposition: attachment, so the browser hands it to its real
     download manager (Android: the file lands in Downloads and shows in the
     notification shade). &rl-fn= supplies the filename. These params are
     stripped from the search BEFORE the target URL is assembled, so they
     work in every URL shape (path-style, ?url=, ?<target>). */
  let dlMode = false, dlName = '';
  try {
    if (u.searchParams.get('rl-dl') === '1') {
      dlMode = true;
      dlName = u.searchParams.get('rl-fn') || '';
      u.searchParams.delete('rl-dl');
      u.searchParams.delete('rl-fn');
    }
  } catch (eDl) {}
  const noCache = (req.headers.get('x-relay-nocache') === '1');

  /* ---- resolve the target URL ---- */
  let target = null;
  const qp = u.searchParams.get('url') || u.searchParams.get('u') || u.searchParams.get('q');
  if (qp && /^https?:\/\//i.test(qp)) target = qp;
  if (!target && u.search.length > 1) {
    const raw = u.search.slice(1);
    if (/^https?%3A%2F%2F/i.test(raw)) {
      try { target = decodeURIComponent(raw); } catch (e) { target = null; }
    } else if (/^https?:\/\//i.test(raw)) {
      target = raw;
    }
  }
  if (!target && /^\/https?:\/\//i.test(u.pathname)) {
    target = u.pathname.slice(1) + u.search;
  }
  /* workerd collapses "//" in the path, so /https://x also arrives as
     /https:/x — normalize any slash count after the scheme */
  if (!target) {
    const pm = /^\/(https?:)\/+(.+)$/i.exec(u.pathname);
    if (pm) target = pm[1] + '//' + pm[2] + u.search;
  }
  if (!target) {
    /* ---- targetless path request: module-graph repair (v2.1) ----
       ES modules resolve "/assets/x.js" specifiers against the importing
       module's OWN ORIGIN — and every module Relay serves comes from THIS
       worker, so Vite/VitePress-style import("/assets/page.js") arrives
       here as a bare /assets/... path with NO target (previously: 400,
       the page-data load dies, the SPA renders its own 404 — fmhy.net).
       Import maps cannot fix this (cross-origin modules bypass the
       document's map), so the worker remembers, in the edge cache, which
       site's asset tree each served path belonged to ("path marker"),
       and redirects the targetless request back to the mapped URL. */
    if (req.method === 'GET' && !/^\/(__relay|healthz|favicon)/i.test(u.pathname)) {
      try {
        const marker = await caches.default.match(stripRange(req));
        if (marker) {
          const site = (await marker.text()).trim();
          if (/^https?:\/\/[a-z0-9.-]+/i.test(site)) {
            const dest = u.origin + '/' + site + u.pathname + u.search;
            return new Response(null, {
              status: 302,
              headers: {
                'location': dest,
                'access-control-allow-origin': (req.headers.get('origin') || '*'),
                'access-control-allow-methods': 'GET, HEAD, OPTIONS',
                'access-control-allow-headers': 'Content-Type, Range',
                'cache-control': 'no-store',
                'x-relay-path-redirect': '1',
                'x-relay-version': VERSION
              }
            });
          }
        }
      } catch (eMark) {}
    }
    /* dl-mode hardening: a clicked download URL must never answer a page */
    if (dlMode) return dlError(200, 'missing target url');
    return json(400, {
      error: 'missing target',
      usage: 'Append the URL: ?url=https://example.com/  ·  ?https://example.com/  ·  /https://example.com/',
      health: '/__relay/health'
    });
  }

  /* ---- SSRF guard: refuse private/loopback targets ---- */
  let tu;
  try { tu = new URL(target); } catch (e) { return dlMode ? dlError(200, 'invalid target url') : json(400, { error: 'invalid target url' }); }
  if (!/^https?:$/.test(tu.protocol)) return dlMode ? dlError(200, 'only http/https targets are supported') : json(400, { error: 'only http/https targets are supported' });
  const host = tu.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') ||
      /^\d+\.\d+\.\d+\.\d+$/.test(host) && /^(10\.|127\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) ||
      host === '::1' || host === '[::1]' || host === 'metadata.google.internal') {
    return dlMode ? dlError(200, 'private addresses are blocked') : json(403, { error: 'private addresses are blocked' });
  }

  /* ---- build the upstream request ---- */
  const headers = new Headers();
  for (const name of FORWARD_REQUEST) {
    const v = req.headers.get(name);
    if (v) headers.set(name, v);
  }
  /* extra upstream headers as JSON — lets the client fully impersonate an
     app API call (innertube clients etc.) without the browser ever sending
     a non-simple header. Refuse the handful that would break the proxy. */
  try {
    const extraRaw = req.headers.get('x-relay-headers');
    if (extraRaw) {
      const extra = JSON.parse(extraRaw);
      let n = 0;
      for (const k in extra) {
        const lk = String(k).toLowerCase();
        if (lk === 'cookie' || lk === 'host' || lk === 'content-length' ||
            lk === 'connection' || lk === 'transfer-encoding' || lk === 'x-relay-headers') continue;
        const val = String(extra[k]);
        if (!val || (n++ > 12)) continue;
        headers.set(k, val);
      }
    }
  } catch (eHdr) {}
  /* explicit UA control — Relay sends this for desktop-site mode */
  const uaOverride = req.headers.get('x-relay-ua');
  headers.set('User-Agent', uaOverride || UA_MOBILE);
  const accept = headers.get('accept');
  if (!accept) headers.set('accept', '*/*');
  /* ---- bot-score hygiene ----
     (1) Referer: only same-host referers survive. A referer pointing at
         some other origin (the hosting app, a proxy dashboard) is a glaring
         bot tell — anti-bot systems like Walmart's PerimeterX score it.
     (2) Fetch hints: Relay marks document loads vs XHRs with X-Relay-Hint;
         translate into the Sec-Fetch-* set a real browser would send, so
         upstreams see a consistent navigation fingerprint. */
  const ref = headers.get('referer');
  if (ref){
    let drop = true;
    try { drop = new URL(ref).hostname.toLowerCase() !== host; } catch (eRef) {}
    if (drop) headers.delete('referer');
  }
  /* X-Relay-Referer: Relay's fetch relay states the REAL page URL the request
     is being made from (the sandboxed frame can't set Referer itself).
     Some backends REQUIRE a same-site referer before they will serve media
     or API payloads (audio-stream proxies, image CDNs) — with the referer
     dropped those requests 403. Only a valid http(s) URL is honored; it
     overrides the browser referer. */
  try {
    const rr = req.headers.get('x-relay-referer');
    if (rr && /^https?:\/\//i.test(rr) && !/^https?:\/\/[.\d]+(:\d+)?/.test(rr)) {
      headers.set('Referer', rr);
      headers.delete('x-relay-referer');
    }
  } catch (eRR) {}
  const hint = (req.headers.get('x-relay-hint') || '').toLowerCase();
  if (hint === 'doc'){
    headers.set('sec-fetch-dest', 'document');
    headers.set('sec-fetch-mode', 'navigate');
    headers.set('sec-fetch-site', 'none');
    headers.set('sec-fetch-user', '?1');
    headers.set('upgrade-insecure-requests', '1');
  } else if (hint === 'xhr'){
    headers.set('sec-fetch-dest', 'empty');
    headers.set('sec-fetch-mode', 'cors');
    headers.set('sec-fetch-site', 'same-origin');
  }
  try{ headers.delete('x-relay-hint'); }catch(eH){}
  if (!headers.get('accept-language')) headers.set('accept-language', 'en-US,en;q=0.9');
  /* session cookies: replay the per-host jar + anything the client sent,
     merged by name (client wins, jar fills the gaps — logins stick).
     X-Relay-Cookie (v2.3): the browser cannot set the real Cookie header
     on a cross-origin fetch (it is a forbidden header name), so pages
     running inside Relay's sandbox forward the cookies their JS wrote
     (document.cookie) through this custom header instead. It merges with
     the same client-wins rule, so consent banners, challenge tokens and
     JS-built sessions survive across isolates AND page loads. */
  const clientCookie = req.headers.get('cookie') || req.headers.get('x-relay-cookie') || '';
  const jarList = readJar(host);
  const cookieHeader = mergeCookies(clientCookie, jarList);
  if (cookieHeader) headers.set('Cookie', cookieHeader);

  const method = req.method;
  const init = {
    method: (method === 'OPTIONS') ? 'GET' : method,
    headers: headers,
    redirect: 'manual',
    credentials: 'omit'
  };
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    init.body = req.body;
    init.duplex = 'half';
  }

  /* ---- fetch with manual redirect following ---- */
  /* transient upstream failures (CDN burst 403/429, 5xx blips, workerd
     connection resets) killed whole pages when ONE chunk hit one — browsers
     report webpack ChunkLoadError and React bails. Retry the hostile
     statuses a couple of times with a small delay (GET/HEAD only — a
     streamed POST body cannot be replayed). */
  /* 520-524 are Cloudflare origin-connect failures — workers.dev targets
     throw transient 521s under load; one retry turns a dead search into a
     result set. */
  const RETRY_STATUS = new Set([403, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524]);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  async function robustFetch(urlStr) {
    let res = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        res = await fetch(urlStr, Object.assign({}, init, { signal: ctrl.signal }));
      } catch (eNet) {
        if (attempt < 2 && (method === 'GET' || method === 'HEAD')) { await sleep(300 + attempt * 400); continue; }
        throw eNet;
      }
      if (attempt < 2 && (method === 'GET' || method === 'HEAD') && RETRY_STATUS.has(res.status)) {
        if (res.body) { try { res.body.cancel(); } catch (eC) {} }
        await sleep(400 + attempt * 600);
        continue;
      }
      return res;
    }
    return res;
  }
  let res = null, finalUrl = target, hops = 0;
  /* v2.4: every hop's Set-Cookie pairs are also RELAYED to the client in
     X-Relay-Set-Cookie ("host|=|k=v; k=v" entries joined by "||") — the
     app persists them per-site, so server-set state (geo / consent /
     session cookies the worker's per-isolate jar would silently eat)
     survives across isolates AND page reloads. Client-JS cookies still
     win on the next request via the X-Relay-Cookie merge. */
  const scRelay = [];
  const ctrl = new AbortController();
  const timer = setTimeout(() => { try { ctrl.abort(); } catch (e) {} }, FETCH_TIMEOUT_MS);
  try {
    let next = target;
    while (hops <= HOP_LIMIT) {
      res = await robustFetch(next);
      /* harvest cookies at EVERY hop into that hop's host jar + the client relay */
      try {
        const hopHost = new URL(next).hostname;
        const scs = getSetCookies(res.headers);
        writeJar(hopHost, scs);
        if (scs && scs.length) {
          const kv = scs.map((sc) => String(sc).split(';')[0]).filter(Boolean).join('; ');
          if (kv) scRelay.push(hopHost + '|=|' + kv);
        }
      } catch (eJ) {}
      const status = res.status;
      if (status >= 300 && status < 400) {
        const loc = res.headers.get('location');
        if (loc) {
          try { finalUrl = new URL(loc, next).href; } catch (e) { break; }
          /* redirect re-issues should be GET for 301/302/303 */
          if (status === 301 || status === 302 || status === 303) { init.method = 'GET'; delete init.body; }
          next = finalUrl;
          hops++;
          continue;
        }
      }
      finalUrl = next;
      break;
    }
    if (hops > HOP_LIMIT) { clearTimeout(timer); return dlMode ? dlError(200, 'too many redirects (' + hops + ' hops)') : json(508, { error: 'too many redirects', hops: hops }); }
  } catch (err) {
    clearTimeout(timer);
    /* dl-mode safety: Chrome RENDERS 4xx/5xx bodies as pages even when
       Content-Disposition is set — a failed download must never navigate the
       app away. Serve the failure as a 200 attachment (a tiny .txt) instead. */
    if (dlMode) return dlError(200, 'fetch failed: ' + String(err && err.message || err));
    return json(502, { error: 'upstream fetch failed', detail: String(err && err.message || err) });
  }
  clearTimeout(timer);
  /* upstream answered with an error while in dl-mode — same rule: never let
     the browser turn it into a navigation */
  if (dlMode && res.status >= 400) { clearTimeout(timer); return dlError(200, 'upstream ' + res.status + ' for this file — the link may be dead or the host blocks the proxy'); }

  /* ---- burst-shield: stale-if-error for scripts/styles ----
     Bursty CDN edge nodes (nginx rate limiters, cheap shared hosts)
     randomly 403 when 3-4 module scripts are fetched in parallel, and
     one dead module kills the whole SPA graph. If a js/css GET just
     failed upstream but the edge cache holds ANY earlier copy of the
     same URL, serve it instead — a slightly stale bundle beats a dead
     app (Vite chunk hashes change only on deploys, so stale almost
     never differs). */
  let staleHit = false;
  if (method === 'GET' && (res.status === 403 || res.status === 429 || res.status >= 500) && !dlMode) {
    const ctb = (res.headers.get('content-type') || '').toLowerCase();
    const isJsOrCss = /javascript|ecmascript|css/.test(ctb) || /\.(m?js|css)(\?|$)/i.test(new URL(finalUrl).pathname);
    if (isJsOrCss) {
      try {
        /* v2.5: versioned asset key first; the plain stripRange() key stays
           as a second lookup because TARGETLESS path requests use that same
           key space for their site markers */
        let cached = await caches.default.match(assetCacheKey(req));
        if (!cached) cached = await caches.default.match(stripRange(req));
        if (cached) { clearTimeout(timer); res = cached; finalUrl = cached.headers.get('x-relay-final-url') || finalUrl; staleHit = true; }
      } catch (eStale) {}
    }
  }

  /* ---- SPA router unlock: patch location tokens in served JS ----
     Relay renders pages in a sandboxed frame whose location is frozen at
     about:srcdoc (window.location is [Unforgeable] — pathname cannot be
     redefined, real history.pushState even THROWS there). Every
     pathname-routed SPA reads window.location.pathname after its router
     pushes state and then renders the wrong route, so in-page navigation
     dies while the shell renders fine. Rewrite TWO token families to route
     through window.__rlLoc() — a fake location Relay's runtime installs
     that tracks the real page URL + every shimmed pushState. Without the
     runtime present the expression falls back to the real location
     unchanged, so this is a strict no-op for everyone else.
       1. (window|document).location.<member>
       2. BARE location.<member>  — added v2.1. VitePress (fmhy.net and
          thousands of docs sites) is the canonical victim: its router
          computes the initial route from `location.href`, which inside the
          sandbox is "about:srcdoc" → normalized to "srcdoc.html" → no
          route matches → the site's own styled 404 page replaces the
          content. Minified bundles almost never keep a parameter or local
          named `location` (minifiers rename them), so the bare form is
          safe to wrap; the `(?<![.\w$:])` lookbehind keeps member-access
          chains (Yg.document.location.href) raw AND stops the patch from
          re-matching its own output (…:location) on a second pass. */
  if (method === 'GET' && res.status === 200 && !dlMode) {
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    const isJs = /javascript|ecmascript/.test(ct) || /\.mjs$/i.test(new URL(finalUrl).pathname);
    if (isJs && !res.headers.get('x-relay-js-patch')) {
      try {
        /* NOTE: reading text() disturbs res.body — the response is ALWAYS
           rebuilt below (patched or not), never the drained original. */
        const txt = await res.text();
        if (txt && txt.length < 6 * 1024 * 1024) {
          let patched = txt;
          if (txt.indexOf('location') >= 0) {
            patched = txt.replace(
              /* (?<![.\w$]) — the match must not be a MEMBER ACCESS: sentry-style
                 aliases like `Yg.document.location.href` would otherwise become
                 `Yg.(window.__rlLoc?...)` — a syntax error that kills the whole
                 bundle. Aliased reads stay raw (they only feed telemetry). */
              /(?<![.\w$])((?:window|document)\.location)(\.(?:pathname|href|origin|hostname|hash|search|port|protocol|assign|replace|reload|toString)\b)/g,
              '(window.__rlLoc?window.__rlLoc():$1)$2'
            ).replace(
              /* bare global `location.X` — see the comment above. The extra `:`
                 exclusion prevents re-matching the patched output itself. */
              /(?<![.\w$:])location(\.(?:pathname|href|origin|hostname|hash|search|port|protocol|toString)\b)/g,
              '(window.__rlLoc?window.__rlLoc():location)$1'
            ).replace(
              /* v2.6: BARE (window|document).location captured as a VALUE — no
                 member access follows, so the two rules above never fire.
                 history v4/v5 (react-router's engine, in Spotify's vendor
                 bundle) computes the app's INITIAL route exactly this way:
                   var o = window.location, s = o.pathname + o.search + o.hash
                 Inside the sandbox that reads about:srcdoc — no route
                 matches — pathname-routed apps render their no-match
                 fallback forever (Spotify's mobile web player showed the
                 home feed on /search and never mounted the search view).
                 Wrap the bare capture in the same __rlLoc fallback so the
                 fake location — which tracks the real page URL and every
                 shimmed pushState — is what routers capture. Exclusions:
                 `.` member (rule 1's territory), identifier chars, `(`, and
                 arithmetic/assignment ops (never a value read); the `:`
                 lookbehind stops this rule from re-wrapping rule 1's own
                 output (`…:window.location)`). */
              /(?<![.\w$:])(?:window|document)\.location(?![.\w$(=+\-*%\[])/g,
              '(window.__rlLoc?window.__rlLoc():window.location)'
            );
          }
          /* always rebuild: text() drained the original body */
          {
            const hdrs = new Headers();
            res.headers.forEach((v, k) => { hdrs.set(k, v); });
            hdrs.delete('content-length');
            if (patched !== txt) hdrs.set('x-relay-js-patch', '1');
            res = new Response(patched, { status: res.status, statusText: res.statusText, headers: hdrs });
          }
        } else {
          /* empty / oversized body — rebuild from the drained text as-is */
          const hdrs0 = new Headers();
          res.headers.forEach((v, k) => { hdrs0.set(k, v); });
          hdrs0.delete('content-length');
          res = new Response(txt || '', { status: res.status, statusText: res.statusText, headers: hdrs0 });
        }
      } catch (eJs) { /* body unreadable — serve as-is */ }
    }
  }

  /* ---- cache static assets on the edge (downloads and no-cache opt-outs
         are excluded) ---- */
  let hit = false;
  if (method === 'GET' && res.status === 200 && !dlMode && !noCache) {
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (/^(image\/|font\/|audio\/|video\/)/.test(ct) || /\/(javascript|css)$/.test(ct)) {
      try {
        const cache = caches.default;
        const cached = await cache.match(assetCacheKey(req));
        if (cached) { clearTimeout(timer); hit = true; res = cached; finalUrl = cached.headers.get('x-relay-final-url') || finalUrl; }
        else { eventPut(cache, req, res, finalUrl, event); }
      } catch (e) { /* cache API unavailable — fine */ }
    }
  }

  /* ---- path-marker write: remember site → bare path (v2.1) ----
     Whenever a site's JS/CSS is served, record that this PATH belongs to
     that site's asset tree, so the targetless "/assets/..." module
     requests above can be redirected back to the right URL. Key = the
     exact targetless request URL; value = the site origin; TTL 30 min. **/
  let markerDebug = 'none';
  if (method === 'GET' && res.status === 200 && !dlMode) {
    try {
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      const isAsset = /^(text\/css|application\/javascript|text\/javascript)/.test(ct) || /\/(javascript|css)$/.test(ct);
      if (isAsset && /^\/https?:\/+/i.test(u.pathname)) {
        markerDebug = 'asset ' + ct.slice(0, 25);
        const tp = new URL(finalUrl);
        const markerKey = new Request(u.origin + tp.pathname, { method: 'GET' });
        const markerVal = new Response(tp.origin, {
          headers: { 'cache-control': 'max-age=1800' }
        });
        const putP = caches.default.put(markerKey, markerVal).then(() => { markerDebug = 'wrote ' + tp.pathname; }, () => { markerDebug = 'putfail'; });
        if (event && event.waitUntil) { try { event.waitUntil(putP); } catch (eW) {} }
      }
    } catch (eMW) { markerDebug = 'err ' + String(eMW); }
  }

  /* ---- rebuild response headers ---- */
  const out = new Headers();
  res.headers.forEach((value, name) => {
    if (!STRIP_RESPONSE.has(name.toLowerCase())) out.set(name, value);
  });
  const origin = req.headers.get('origin') || '*';
  out.set('Access-Control-Allow-Origin', origin);
  out.set('Access-Control-Allow-Methods', 'GET, HEAD, POST, PUT, DELETE, OPTIONS');
  out.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Range, X-Relay-UA, X-Relay-Hint, X-Relay-Headers, X-Relay-NoCache, X-Relay-Referer, X-Relay-Cookie, Accept, Accept-Language, Cookie');
  out.set('Access-Control-Expose-Headers', 'X-Relay-Final-Url, X-Relay-Status, X-Relay-Hops, X-Relay-Cache, X-Relay-Version, X-Relay-Jar, X-Relay-Set-Cookie');
  out.set('X-Relay-Final-Url', finalUrl);
  out.set('X-Relay-Status', String(res.status));
  out.set('X-Relay-Hops', String(hops));
  out.set('X-Relay-Cache', (hit || staleHit) ? 'HIT' : 'MISS');
  out.set('X-Relay-Version', VERSION);
  out.set('X-Relay-Jar', String(readJar(tu.hostname).length));
  try { out.set('X-Relay-Marker-Debug', markerDebug); } catch (eDb) {}
  /* v2.4: server-set cookies relayed to the client (see scRelay above).
     Header values must be printable ASCII — sanitize hard, cap the payload. */
  try {
    if (scRelay.length) {
      const scVal = scRelay.join('||').replace(/[\x00-\x1f\x7f]/g, '').replace(/[^\x20-\x7e]/g, '_').slice(0, 3000);
      if (scVal) out.set('X-Relay-Set-Cookie', scVal);
    }
  } catch (eSC) {}
  if (dlMode) {
    /* a quoted ASCII fallback + an RFC 5987 UTF-8 name covers every browser */
    const safe = String(dlName || fileNameFromUrl(finalUrl) || 'download')
      .replace(/[\r\n"\\]/g, '').replace(/[^\x20-\x7e]/g, '_').slice(0, 120) || 'download';
    const enc = encodeURIComponent(String(dlName || safe)).replace(/['()]/g, function (c) { return '%' + c.charCodeAt(0).toString(16).toUpperCase(); });
    out.set('Content-Disposition', "attachment; filename=\"" + safe + "\"; filename*=UTF-8''" + enc);
    out.set('Cache-Control', 'no-store');
  } else if (!out.has('cache-control')) {
    out.set('cache-control', 'public, max-age=600');
  }

  /* OPTIONS preflight */
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: out });

  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: out });
}

/* fire-and-forget cache write (stream-safe: clone, put in background).
   v2.5 CRITICAL FIX: the old code built `new Response(res.clone(), …)` — a
   Response object is NOT a valid BodyInit, so the runtime stringified it to
   the literal text "[object Response]" (17 bytes) and cached THAT as the
   body. Every asset served from the edge cache was 17 bytes of junk with the
   origin's own content-type — the "site looks bare-bones / CSS missing /
   blank page" bug (jackbox.tv, tesla.com, intermittent everywhere). The
   cached copy is now built from the CLONE'S BODY STREAM (a legal BodyInit)
   so real bytes land in the cache. A version tag in the key orphans every
   entry the old code poisoned (some origins sent year-long max-ages, so
   stale junk could otherwise outlive the fix). */
const CACHE_KEY_VER = 'rl2';
function eventPut(cache, req, res, finalUrl, event) {
  try {
    const cl = res.clone ? res.clone() : null;
    const hdrs = new Headers(res.headers);
    hdrs.set('x-relay-final-url', finalUrl);
    const copy = new Response(cl ? cl.body : res.body, {
      status: res.status, statusText: res.statusText, headers: hdrs
    });
    const p = cache.put(assetCacheKey(req), copy).catch(() => {});
    if (event && event.waitUntil) { try { event.waitUntil(p); } catch (eW) {} }
  } catch (e) { /* ignore */ }
}
/* asset-cache key: ignores Range AND carries a version tag — the marker
   cache (targetless /assets/... lookups) keeps using plain stripRange()
   keys, so the two key spaces never collide. */
function assetCacheKey(req) {
  const u = new URL(req.url);
  const key = u.origin + u.pathname + u.search + (u.search ? '&' : '?') + CACHE_KEY_VER;
  return new Request(key, { method: 'GET' });
}
/* cache key ignores Range so a full copy can serve range requests */
function stripRange(req) {
  const u = new URL(req.url);
  const clean = new Request(u.href, { method: 'GET' });
  return clean;
}

function json(status, obj) {
  return new Response(JSON.stringify(obj, null, 2), {
    status: status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'cache-control': 'no-store'
    }
  });
}
/* best filename guess from the final URL path (used when rl-fn is absent) */
function fileNameFromUrl(uStr) {
  try {
    const p = new URL(uStr).pathname.split('/').filter(Boolean);
    return decodeURIComponent(p[p.length - 1] || '').slice(0, 120);
  } catch (e) { return ''; }
}
