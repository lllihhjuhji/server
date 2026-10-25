cat > server.js <<'EOF'
const http = require('http');
const crypto = require('crypto');
const { once } = require('events');

const env = process.env;
const PORT = +env.PORT || 8787;
const SOURCE_BASE = (env.SOURCE_BASE || 'https://api.example.com').replace(/\/$/, '');

// ---- 세션 / 인증 헤더 주입 (Interceptor 역할) ----
const store = { token: env.AUTH_TOKEN || '', sessionId: env.SESSION_ID || '', extra: {} };

async function refreshSession() {
  throw new Error('session refresh not implemented'); // 401 시 재발급 로직을 여기에
}

async function api(url, opts = {}, retry = true) {
  const headers = {
    ...(opts.headers || {}),
    Authorization: `Bearer ${store.token}`,
    'X-Session-Id': store.sessionId,
    ...store.extra,
  };
  const res = await fetch(url, { ...opts, headers });
  if (res.status === 401 && retry) {
    Object.assign(store, await refreshSession());
    return api(url, opts, false);
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res;
}

// ---- Blowfish 스트라이프 복호화 ----
try {
  crypto.createDecipheriv('bf-cbc', Buffer.alloc(16), Buffer.alloc(8));
} catch {
  console.error('[WARN] 이 Node는 Blowfish(bf-cbc)를 지원하지 않음. run.sh의 --openssl-legacy-provider 확인');
}

function decryptChunk(cfg, buf, index) {
  if (buf.length !== cfg.chunk || index % cfg.stride !== 0) return buf;
  const d = crypto.createDecipheriv('bf-cbc', cfg.key, cfg.iv); // 청크마다 IV 리셋
  d.setAutoPadding(false);
  return Buffer.concat([d.update(buf), d.final()]);
}

// ---- 소스 연동부: 서비스에 맞게 수정 ----
async function search(q, limit) {
  const res = await api(`${SOURCE_BASE}/search?q=${encodeURIComponent(q)}&limit=${limit}`);
  const j = await res.json();
  return (j.data || []).map((o) => ({
    id: String(o.id),
    title: o.title || '',
    artist: o.artist || '',
    album: o.album,
    duration: o.duration,
    cover: o.cover,
    audioQuality: 'LOSSLESS',
    format: 'FLAC',
  }));
}

async function resolve(id) {
  const res = await api(`${SOURCE_BASE}/tracks/${encodeURIComponent(id)}`);
  const o = await res.json();
  if (!o.stream_url) throw new Error('stream_url missing');
  let cfg = null;
  if (o.encrypted) {
    if (!env.STREAM_KEY_HEX || !env.STREAM_IV_HEX) throw new Error('STREAM_KEY_HEX / STREAM_IV_HEX not set');
    cfg = {
      key: Buffer.from(env.STREAM_KEY_HEX, 'hex'),
      iv: Buffer.from(env.STREAM_IV_HEX, 'hex'),
      chunk: +env.STREAM_CHUNK || 2048,
      stride: +env.STREAM_STRIDE || 3,
    };
    if (cfg.iv.length !== 8 || cfg.chunk % 8 !== 0) throw new Error('bad IV/chunk config');
  }
  return { url: o.stream_url, headers: {}, contentType: 'audio/flac', crypto: cfg };
}

// ---- 복호화 프록시 (Range 지원) ----
async function proxyAudio(req, res, id) {
  const info = await resolve(id);
  const c = info.crypto;
  const chunk = c ? c.chunk : 1;
  const blockSize = c ? c.chunk : 65536;

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
  if (!up.ok) throw new Error(`upstream HTTP ${up.status}`);
  if (m && up.status !== 206) throw new Error('upstream ignored Range');

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

// ---- HTTP 서버 ----
const manifest = {
  id: 'custom.source',
  name: 'Custom Source',
  version: '1.0.0',
  description: 'Custom HTTP source addon',
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
  .listen(PORT, '0.0.0.0', () => console.log(`addon listening on :${PORT}`));
EOF
