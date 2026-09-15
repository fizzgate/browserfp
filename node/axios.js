// axios adapter —— **独立**用 axios 的 wire 出网（不是 bun fetch wire）。
//
// 为什么不复用 fetch.js:
//   fetch.js 走的是 bun 内置 fetch 的 wire（auto-inject UA/Accept、AE="gzip, deflate, br"、
//   Host 在最前、Connection: close）。axios 的 wire 完全不同——app 头保调用方原序、尾组
//   固定 Content-Length → Accept-Encoding → Host → Connection、AE="gzip, compress, deflate, br"、
//   Connection: keep-alive（CC 2.1.266+）。混用就是矛盾指纹,风控立判。
//
// 权威 spec: resty/lua/fizz/proxy/fp_http.lua 的 `build_request_axios`（见函数注释头,
// 里面有本机 axios@1.15.2 跑在 bun 1.4.0 里裸 TCP 抓包的实测记录）。
//
// 用法（自带 axios-shaped 客户端,不依赖 npm 上的 axios 包）:
//   const bfp = require('@fizzgate/browserfp');
//   const axios = bfp.axios({ profile: bfp.getProfileById('bun:nhttps-tls13-pq') });
//   const res = await axios.get('https://api.anthropic.com/api/oauth/profile', {
//     headers: {
//       Accept: 'application/json, text/plain, */*',
//       'User-Agent': 'axios/1.15.2',
//       Authorization: 'Bearer ' + token,
//     },
//   });
//   res.data / res.status / res.headers  // 与 axios 兼容
//
// 或接管现有 axios 实例:
//   const inst = require('axios').create();
//   inst.defaults.adapter = bfp.axiosAdapter({ profile });
//
// 差异（都是有意的）:
//   1. 不做 cookie 管理（伪装场景外部塞 cookie 更常见）
//   2. 自动跟随重定向（默认 20 次;maxRedirects: 0 关掉）
//   3. Response.data 按 responseType 决定形态（json/text/arraybuffer）
//   4. **HTTP/2 直接拒绝** —— axios wire 只在 h1 有意义。profile 若 ALPN 谈成 h2 会 fail-close。
//      要 h2 请用真浏览器 profile 走 fetch。

'use strict';

const url = require('url');
const zlib = require('zlib');
const browserfp = require('./browserfp.js');
const tls13 = require('./tls13.js');
const http1 = require('./http1.js');

// axios wire 的默认 profile —— CC CLI cli.js 里 $o = axios,底层走 node:https,
// 对应 profile 是 bun:nhttps-tls13-pq（alpn=[],不申明 ALPN 走 h1;对齐 resty
// `is_axios ? "bun:nhttps-tls13-pq" : "bun:sdk-tls13-pq"`）。
const DEFAULT_PROFILE_ID = 'bun:nhttps-tls13-pq';

// axios wire 尾组的 4 头 —— 顺序固定 Content-Length → Accept-Encoding → Host → Connection,
// 无论调用方给不给,都由本模块按固定序追加到尾部,值缺省走 axios 默认。
const TAIL_HEADERS = new Set(['host', 'connection', 'accept-encoding', 'content-length']);

// -----------------------------------------------------------------------------
// 头拼装 —— 权威 spec: resty fp_http.lua:143 build_request_axios
// -----------------------------------------------------------------------------

/**
 * 组装 HTTP/1.1 header list（保序 [[k,v],...]）,严格按 axios 真实 wire。
 *
 * 参数:
 *   userHeadersRaw  调用方给的 [[k,v],...]（保序,含 Accept/UA/Auth/... 之类的 app 头;
 *                   若显式给了 Host/Connection/AE/CL,值会被采用但位置会挪到尾组固定序）
 *   host, port      用于填缺省 Host 头
 *   bodyBuf         Buffer | undefined,决定要不要发 Content-Length（GET 一律不发）
 *
 * 返回: [[k,v],...] 可直接喂 http1.request。
 */
function composeAxiosH1Headers({ userHeadersRaw, host, port, bodyBuf }) {
  const hostValue = host + (port === 443 ? '' : ':' + port);
  const bodyLen = bodyBuf && bodyBuf.length > 0 ? bodyBuf.length : 0;
  const app = [];
  const explicit = Object.create(null); // lc → value（调用方显式给的尾组值,采用但会挪到尾组）
  for (const [k, v] of userHeadersRaw) {
    const lc = String(k).toLowerCase();
    if (TAIL_HEADERS.has(lc)) {
      explicit[lc] = v;
    } else {
      app.push([k, v]);
    }
  }
  const tail = [];
  // Content-Length 只在有 body 时才发（GET/HEAD/无 body 一律不发,与 axios 实测一致）
  const clExplicit = explicit['content-length'];
  if (clExplicit !== undefined) {
    tail.push(['Content-Length', String(clExplicit)]);
  } else if (bodyLen > 0) {
    tail.push(['Content-Length', String(bodyLen)]);
  }
  tail.push(['Accept-Encoding', explicit['accept-encoding'] || 'gzip, compress, deflate, br']);
  tail.push(['Host', explicit['host'] || hostValue]);
  // CC 2.1.266+ 实测 axios 全是 keep-alive（16/16 请求）;2.1.241 时全是 close（1105/1105）;
  // 随 CC 版本走,当前默认取 keep-alive。调用方可覆盖。
  tail.push(['Connection', explicit['connection'] || 'keep-alive']);
  return app.concat(tail);
}

// -----------------------------------------------------------------------------
// 响应处理
// -----------------------------------------------------------------------------

function decompress(headers, body) {
  // headers: [[k,v],...]
  let ce = '';
  for (const [k, v] of headers) {
    if (k.toLowerCase() === 'content-encoding') { ce = String(v).toLowerCase(); break; }
  }
  if (!ce || ce === 'identity') return body;
  try {
    if (ce === 'gzip') return zlib.gunzipSync(body);
    if (ce === 'deflate') return zlib.inflateSync(body);
    if (ce === 'br') return zlib.brotliDecompressSync(body);
    if (ce === 'zstd' && typeof zlib.zstdDecompressSync === 'function') {
      return zlib.zstdDecompressSync(body);
    }
  } catch (e) {
    if (ce === 'gzip' || ce === 'deflate') {
      try { return zlib.inflateRawSync(body); } catch (_) {}
    }
  }
  return body;
}

function pickHeader(headers, name) {
  const lc = name.toLowerCase();
  for (const [k, v] of headers) if (k.toLowerCase() === lc) return v;
  return null;
}

// -----------------------------------------------------------------------------
// URL / config 工具
// -----------------------------------------------------------------------------

// axios.proxy 配置 → HTTP CONNECT URL 字串
function axiosProxyToUrl(p) {
  if (!p || typeof p !== 'object') return undefined;
  const proto = p.protocol || 'http';
  const auth = p.auth && p.auth.username
    ? encodeURIComponent(p.auth.username) + ':' + encodeURIComponent(p.auth.password || '') + '@'
    : '';
  return `${proto}://${auth}${p.host}:${p.port}`;
}

// axios config.headers 可能是 object / 数组 / AxiosHeaders 实例,统一转 [[k,v],...] 保序
function normalizeHeaders(h) {
  if (!h) return [];
  if (Array.isArray(h)) {
    return h.filter(([k, v]) => v !== undefined && v !== null).map(([k, v]) => [String(k), String(v)]);
  }
  if (typeof h === 'object') {
    const out = [];
    // Object.keys 对字符串键按插入序 —— ES2015+ 保证
    for (const k of Object.keys(h)) {
      const v = h[k];
      if (v !== undefined && v !== null) out.push([String(k), String(v)]);
    }
    return out;
  }
  return [];
}

// axios config → { method, url, headersRaw, body }
function configToRequest(config) {
  // 拼 URL（含 baseURL + params）
  let u = config.url || '';
  if (config.baseURL && !/^https?:\/\//i.test(u)) {
    u = config.baseURL.replace(/\/+$/, '') + '/' + u.replace(/^\/+/, '');
  }
  if (config.params && typeof config.params === 'object') {
    const qs = new URLSearchParams();
    for (const k of Object.keys(config.params)) {
      const v = config.params[k];
      if (Array.isArray(v)) for (const vv of v) qs.append(k, vv);
      else if (v !== undefined && v !== null) qs.append(k, v);
    }
    const q = qs.toString();
    if (q) u += (u.includes('?') ? '&' : '?') + q;
  }
  const method = (config.method || 'get').toUpperCase();

  // headers 保序转 [[k,v],...]。若 body 是对象且未指定 Content-Type,补上 application/json。
  let headersRaw = normalizeHeaders(config.headers);
  let body;
  if (config.data !== undefined && config.data !== null && method !== 'GET' && method !== 'HEAD') {
    if (typeof config.data === 'string' || Buffer.isBuffer(config.data)) {
      body = Buffer.isBuffer(config.data) ? config.data : Buffer.from(config.data);
    } else if (config.data instanceof URLSearchParams) {
      body = Buffer.from(config.data.toString());
      if (!headersRaw.some(([k]) => k.toLowerCase() === 'content-type')) {
        headersRaw = [['Content-Type', 'application/x-www-form-urlencoded;charset=utf-8'], ...headersRaw];
      }
    } else {
      body = Buffer.from(JSON.stringify(config.data));
      if (!headersRaw.some(([k]) => k.toLowerCase() === 'content-type')) {
        headersRaw = [['Content-Type', 'application/json'], ...headersRaw];
      }
    }
  }
  return { method, url: u, headersRaw, body };
}

// -----------------------------------------------------------------------------
// 主体 —— 一次 axios 请求（含跟随重定向）
// -----------------------------------------------------------------------------

async function doRequest({ method, url: currentUrl, headersRaw, body, profile, proxy, timeout, redirect, maxRedirects }) {
  browserfp.load();
  let hops = 0;
  let current = currentUrl;
  let redirected = false;
  let curMethod = method;
  let curBody = body;
  let curHeaders = headersRaw;

  for (;;) {
    const u = new url.URL(current);
    if (u.protocol !== 'https:') throw new Error(`只支持 https（当前 ${u.protocol}）`);
    const host = u.hostname;
    const port = u.port ? parseInt(u.port, 10) : 443;
    const pathAndQuery = u.pathname + (u.search || '');

    // ⚠ 不覆盖 opts.alpn —— profile 里 ALPN 保原样(如 nhttps-* 系无 ALPN,是 bun 1.4.1 node:https
    //   node:tls.ts:494 `ALPNProtocols=undefined` 的真实行为)。风控最严的地方是 TLS 指纹保真,
    //   我们**必须字节级对齐** bun 1.4.1 原始 ClientHello,不能为了绕 h2 硬加 ALPN。
    //   若上游因缺 ALPN 谈成 h2 → 是本地环境走了不同的 CDN 边缘(真实 CC 用同 profile 也会遇到,
    //   代表 anthropic 侧那条链路本来就选 h1 或者用别的手段区分)。fail-close 不硬发。
    const conn = await tls13.connect({ host, port, profile, timeout, proxy });
    let res;
    try {
      if (conn.alpn === 'h2') {
        throw new Error(
          `axios wire 需要 HTTP/1.1（当前 ALPN=h2）—— ` +
          `profile.id=${profile && profile.id} 上游谈成了 h2。`
        );
      }
      const h1Headers = composeAxiosH1Headers({
        userHeadersRaw: curHeaders,
        host, port, bodyBuf: curBody,
      });
      res = await http1.request({
        stream: conn.stream, method: curMethod,
        path: pathAndQuery, headers: h1Headers, body: curBody, timeout,
      });
    } finally {
      conn.close();
    }

    // 重定向
    const location = pickHeader(res.headers, 'location');
    const isRedirect = [301, 302, 303, 307, 308].includes(res.status) && location;
    if (isRedirect && redirect === 'follow') {
      if (hops >= maxRedirects) throw new Error(`重定向超过 ${maxRedirects} 次`);
      hops++;
      redirected = true;
      current = new url.URL(location, current).toString();
      if (res.status === 303 || res.status === 301 || res.status === 302) {
        if (curMethod !== 'GET' && curMethod !== 'HEAD') {
          curMethod = 'GET';
          curBody = undefined;
        }
      }
      continue;
    }
    if (isRedirect && redirect === 'error') {
      throw new Error(`不允许重定向:status=${res.status} location=${location}`);
    }

    const finalBody = decompress(res.headers, res.body);
    return {
      status: res.status,
      statusText: res.statusText || '',
      headers: res.headers,
      body: finalBody,
      url: current,
      redirected,
    };
  }
}

// -----------------------------------------------------------------------------
// axios adapter fn —— 接受 axios config,返回 axios response 形态
// -----------------------------------------------------------------------------

async function _adapterFn(config) {
  const profile = config._bfp_profile
    || (config._bfp_ua ? browserfp.selectUA(config._bfp_ua) : browserfp.getProfileById(DEFAULT_PROFILE_ID));
  if (!profile) throw new Error(`browserfp profile 找不到（默认 ${DEFAULT_PROFILE_ID}）——libbrowserfp 需含此 profile`);
  const proxy = config._bfp_proxy
    || (config.proxy ? axiosProxyToUrl(config.proxy) : undefined);
  const timeout = config.timeout || 30000;
  const redirect = config.maxRedirects === 0 ? 'manual' : 'follow';
  const maxRedirects = config.maxRedirects === 0 ? 0 : (config.maxRedirects || 20);

  const req = configToRequest(config);
  const res = await doRequest({
    method: req.method, url: req.url, headersRaw: req.headersRaw, body: req.body,
    profile, proxy, timeout, redirect, maxRedirects,
  });

  const buf = Buffer.isBuffer(res.body) ? res.body : Buffer.from(res.body || '');
  // 响应头 → axios 形态（对象,大小写不敏感就交给 axios 侧包一层;这里 lower-case + 逗号合并）
  const headers = {};
  for (const [k, v] of res.headers) {
    const lc = k.toLowerCase();
    headers[lc] = headers[lc] !== undefined ? headers[lc] + ', ' + v : v;
  }
  const rt = config.responseType || 'json';
  let data;
  const text = buf.toString('utf8');
  if (rt === 'arraybuffer') {
    data = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  } else if (rt === 'stream') {
    throw new Error('axios responseType=stream 暂不支持');
  } else if (rt === 'text') {
    data = text;
  } else {
    try { data = JSON.parse(text); } catch (_) { data = text; }
  }
  return {
    data,
    status: res.status,
    statusText: res.statusText,
    headers,
    config,
    request: null,
  };
}

// -----------------------------------------------------------------------------
// 公开 API
// -----------------------------------------------------------------------------

/**
 * axiosAdapter({ profile?, ua?, proxy? })
 *
 * 返回一个 axios 兼容的 adapter 函数。传给 axios.create({ adapter }) 或 instance.defaults.adapter。
 * 默认 profile = bun:nhttps-tls13-pq（axios wire 唯一合法选择,别让 selectUA 给个 chrome）。
 */
function axiosAdapter(defaults = {}) {
  return async function browserfpAxiosAdapter(config) {
    config._bfp_ua = config._bfp_ua || defaults.ua;
    config._bfp_profile = config._bfp_profile || defaults.profile;
    config._bfp_proxy = config._bfp_proxy || defaults.proxy;
    return _adapterFn(config);
  };
}

/**
 * createAxios({ profile?, ua?, proxy?, headers?, baseURL?, timeout? })
 *
 * 返回一个"用起来像 axios"的极简对象:get / post / put / delete / patch / request / head。
 * 不依赖 npm 上的 axios 包 —— 自己实现最小 API,直接走 bun:nhttps-tls13-pq wire。
 *
 * 也可以用 axios 官方包 + 我们的 adapter:
 *   const axios = require('axios').create({ adapter: bfp.axiosAdapter({ profile }) })
 * 这样能拿到 axios 全套（interceptors、cancel token 等）。
 */
function createAxios(defaults = {}) {
  const inst = {
    defaults: { ...defaults },
    async request(config) {
      const merged = {
        ...defaults,
        ...config,
        headers: { ...(defaults.headers || {}), ...(config.headers || {}) },
        _bfp_ua: config._bfp_ua || defaults.ua,
        _bfp_profile: config._bfp_profile || defaults.profile,
        _bfp_proxy: config._bfp_proxy || defaults.proxy,
      };
      return _adapterFn(merged);
    },
    get(u, config = {}) { return inst.request({ ...config, method: 'GET', url: u }); },
    delete(u, config = {}) { return inst.request({ ...config, method: 'DELETE', url: u }); },
    head(u, config = {}) { return inst.request({ ...config, method: 'HEAD', url: u }); },
    options(u, config = {}) { return inst.request({ ...config, method: 'OPTIONS', url: u }); },
    post(u, data, config = {}) { return inst.request({ ...config, method: 'POST', url: u, data }); },
    put(u, data, config = {}) { return inst.request({ ...config, method: 'PUT', url: u, data }); },
    patch(u, data, config = {}) { return inst.request({ ...config, method: 'PATCH', url: u, data }); },
  };
  return inst;
}

module.exports = {
  createAxios,
  axiosAdapter,
  // 内部方便单测导出（不视为公开 API）
  _composeAxiosH1Headers: composeAxiosH1Headers,
  _adapterFn,
  DEFAULT_PROFILE_ID,
};
