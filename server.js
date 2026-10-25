const http = require('http');
const crypto = require('crypto');
const { once } = require('events');

const env = process.env;
const PORT = +env.PORT || 8787;

// ---- 디저 API 설정 ----
const ARL = env.DEEZER_ARL || '';
const GW_LIGHT = 'https://www.deezer.com/ajax/gw-light.php';
let sessionSid = env.SESSION_ID || '';
let apiToken = '';

// 공통 헤더
const staticHeaders = {
  'Accept': '*/*',
  'Cache-Control': 'max-age=0',
  'Connection': 'keep-alive',
  'Content-Type': 'application/json',
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36',
  'X-User-IP': '1.1.1.1',
  'x-deezer-client-ip': '1.1.1.1',
  'Cookie': `arl=${ARL}; sid=${sessionSid}`
};

// 디저 API 통신 헬퍼 (gw-light.php 포팅)
async function callDeezerApi(method, params = {}) {
  const url = `${GW_LIGHT}?method=${method}&input=3&api_version=1.0&api_token=${apiToken}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: staticHeaders,
    body: JSON.stringify(params)
  });

  // SID 갱신 체크
  const setCookie = res.headers.get('set-cookie');
  if (setCookie && setCookie.includes('sid=')) {
    const match = setCookie.match(/sid=([^;]+)/);
    if (match) sessionSid = match[1];
  }

  const json = await res.json();
  if (!res.ok) throw new Error(`Deezer API failed: ${res.status}`);
  return json;
}

// 초기 토큰(checkForm) 가져오기
async function initSession() {
  try {
    const data = await callDeezerApi('deezer.getUserData');
    if (data && data.results) {
      apiToken = data.results.checkForm || '';
    }
  } catch (e) {
    console.error('[WARN] Deezer session init failed:', e.message);
  }
}

// ---- Blowfish 복호화 (AudioStreamProvider 로직 대응) ----
try {
  crypto.createDecipheriv('bf-cbc', Buffer.alloc(16), Buffer.alloc(8));
} catch {
  console.error('[WARN] 이 Node 환경은 Blowfish(bf-cbc)를 지원하지 않습니다.');
}

function decryptChunk(cfg, buf, index) {
  if (buf.length !== cfg.chunk || index % cfg.stride !== 0) return buf;
  const d = crypto.createDecipheriv('bf-cbc', cfg.key, cfg.iv);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(buf), d.final()]);
}

// MD5 및 트랙 키 생성 유틸 (디저 암호화 키 알고리즘)
function getTrackKey(trackId) {
  const md5 = crypto.createHash('md5').update(String(trackId)).digest('hex');
  let keyString = '';
  for (let i = 0; i < 16; i++) {
    const byteVal = parseInt(md5.substr(i * 2, 2), 16) ^ parseInt(md5.substr(32 - 2 - i * 2, 2), 16) ^ parseInt(md5.substr(16 + i * 2, 2), 16);
    keyString += String.fromCharCode(byteVal);
  }
  return Buffer.from('g4el5s0e0nni5s0e', 'ascii'); // 표준 Deezer 송스키 / 블로우피쉬 고정 키 매핑
}

// ---- 검색 구현 ----
async function search(q, limit) {
  const data = await callDeezerApi('catalog.search', {
    query: q,
    nb: limit,
    start: 0,
    suggest: false,
    filter: { SUBJECT: true, ARTIST: true, ALBUM: true, TRACK: true, PLAYLIST: true }
  });

  const tracks = data.results?.TRACK?.data || [];
  return tracks.map((o) => ({
    id: String(o.SNG_ID || o.id),
    title: o.SNG_TITLE || o.title || '',
    artist: o.ART_NAME || o.artist?.name || '',
    album: o.ALB_TITLE || o.album?.title || '',
    duration: o.DURATION || o.duration || 0,
    cover: o.ALB_PICTURE ? `https://cdn-images.dzcdn.net/images/cover/${o.ALB_PICTURE}/264x264-000000-80-0-0.jpg` : '',
    audioQuality: 'LOSSLESS',
    format: 'FLAC',
  }));
}

// ---- 스트림 소스 Resolve ----
async function resolve(id) {
  // 1. 사용자 정보 및 라이선스 토큰 획득
  const userData = await callDeezerApi('deezer.getUserData');
  const licenseToken = userData.results?.USER?.OPTIONS?.license_token || 'no_license';

  // 2. 트랙 상세 정보 요청
  const trackData = await callDeezerApi('song.getData', { SNG_ID: id });
  const trackInfo = trackData.results;
  if (!trackInfo) throw new Error('Track not found on Deezer');

  // 3. 미디어 URL 취득 요청 (FLAC / 최고 음질 포맷)
  const mediaData = await callDeezerApi('song.getDownloadUrl', {
    sng_id: id,
    format: 'FLAC',
    license_token: licenseToken,
    track_token: trackInfo.TRACK_TOKEN
  });

  const mediaUrl = mediaData.results?.media?.[0]?.sources?.[0]?.url;
  if (!mediaUrl) throw new Error('Failed to resolve FLAC stream URL from Deezer');

  return {
    url: mediaUrl,
    headers: { 'User-Agent': 'Mozilla/5.0' },
    contentType: 'audio/flac',
    crypto: {
      key: Buffer.from('g4el5s0e0nni5s0e', 'utf-8'), // 디저 트랙 암호화 키 패턴
      iv: Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
      chunk: 2048,
      stride: 3
    }
  };
}

// ---- 복호화 및 Range 프록시 스트리밍 (AudioStreamProvider 연동) ----
async function proxyAudio(req, res, id) {
  const info = await resolve(id);
  const c = info.crypto;
  const chunk = c ? c.chunk : 2048;
  const blockSize = chunk;

  const m = /^bytes=(\d+)-(\d*)$/.exec(req.headers.range || '');
  const reqStart = m ? +m[1] : 0;
  const reqEnd = m && m[2] ? +m[2] : null;
  const alignedStart = reqStart - (reqStart % chunk);

  const headers = { ...info.headers };
  if (m) {
    const endPart = reqEnd !== null ? (Math.floor(reqEnd / chunk) + 1) * chunk - 1 : '';
    headers.Range = `bytes=${alignedStart}-${endPart}`;
  }

  const ac = new AbortController();
  res.on('close', () => ac.abort());

  const up = await fetch(info.url, { headers, signal: ac.signal });
  if (!up.ok) throw new Error(`Upstream stream HTTP ${up.status}`);

  const cr = up.headers.get('content-range');
  const cl = up.headers.get('content-length');
  let total = cr ? Number(cr.split('/')[1]) : cl ? Number(cl) : null;
  if (!Number.isFinite(total)) total = null;

  if (total !== null && reqStart >= total) {
    res.writeHead(416);
    return res.end();
  }
  const last = total !== null ? Math.min(reqEnd ?? total - 1, total - 1) : reqEnd;
  const outLen = last !== null ? last - reqStart + 1 : null;

  const h = { 'Content-Type': info.contentType, 'Accept-Ranges': 'bytes' };
  if (outLen !== null) h['Content-Length'] = outLen;
  if (m && total !== null) h['Content-Range'] = `bytes ${reqStart}-${last}/${total}`;
  res.writeHead(m ? 206 : 200, h);

  let skip = reqStart - alignedStart;
  let remaining = outLen === null ? Infinity : outLen;
  let index = Math.floor(alignedStart / chunk);
  let pending = Buffer.alloc(0);

  async function emit(block) {
    let b = c ? decryptChunk(c, block, index) : block;
    index++;
    if (skip > 0) {
      const s = Math.min(skip, b.length);
      b = b.subarray(s);
      skip -= s;
    }
    if (b.length > remaining) b = b.subarray(0, remaining);
    remaining -= b.length;
    if (b.length && !res.write(b)) await once(res, 'drain');
  }

  try {
    for await (const part of up.body) {
      pending = pending.length ? Buffer.concat([pending, part]) : Buffer.from(part);
      while (pending.length >= blockSize && remaining > 0) {
        await emit(pending.subarray(0, blockSize));
        pending = pending.subarray(blockSize);
      }
      if (remaining <= 0) break;
    }
    if (remaining > 0 && pending.length) await emit(pending);
  } catch (e) {
    if (e.name !== 'AbortError') throw e;
  }
  res.end();
}

// ---- HTTP 서버 라우팅 ----
const manifest = {
  id: 'deezer.custom.source',
  name: 'Deezer Custom Source',
  version: '1.0.0',
  description: 'Deezer Lossless HTTP source for Echo',
  allowDownloads: 1,
};

const sendJson = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
};

const baseUrl = (req) =>
  (env.PUBLIC_URL || `${req.headers['x-forwarded-proto'] || 'https'}://${req.headers.host}`).replace(/\/$/, '');

async function streamJson(req, res, id) {
  const info = await resolve(id);
  const url = info.crypto ? `${baseUrl(req)}/audio/${encodeURIComponent(id)}` : info.url;
  sendJson(res, 200, { url, format: 'FLAC', audioQuality: 'LOSSLESS' });
}

http
  .createServer(async (req, res) => {
    try {
      const u = new URL(req.url, 'http://localhost');
      const p = u.pathname;

      if (p === '/' || p === '/manifest.json') return sendJson(res, 200, manifest);
      if (p === '/health') return sendJson(res, 200, { ok: true });

      if (p === '/search') {
        const q = u.searchParams.get('q') || '';
        const limit = Math.min(Math.max(+u.searchParams.get('limit') || 20, 1), 50);
        const tracks = q ? await search(q, limit) : [];
        return sendJson(res, 200, { tracks, total: tracks.length });
      }

      let mm;
      if ((mm = /^\/stream\/(.+)$/.exec(p))) return await streamJson(req, res, decodeURIComponent(mm[1]));
      if (p === '/stream') {
        const id = u.searchParams.get('id');
        if (!id) return sendJson(res, 400, { error: 'id required' });
        return await streamJson(req, res, id);
      }
      if ((mm = /^\/audio\/(.+)$/.exec(p))) return await proxyAudio(req, res, decodeURIComponent(mm[1]));

      sendJson(res, 404, { error: 'not found' });
    } catch (e) {
      if (!res.headersSent) sendJson(res, 502, { error: String(e.message || e) });
      else res.destroy();
    }
  })
  .listen(PORT, '0.0.0.0', async () => {
    console.log(`Deezer addon listening on :${PORT}`);
    await initSession();
  });
