// test-axios-wire.js —— axios wire 字节级 golden 测试
//
// 两层验证:
//   1. **纯函数字节 golden**:_composeAxiosH1Headers 输入 [[k,v],...] + host/port/body,
//      byte-diff 期望的 wire。不碰网络。
//   2. **端到端真实 socket**:起本地 raw TCP echo server,直接调 http1.request 走 axios wire
//      产的 header list,抓 server 收到的全部字节,byte-diff 期望。证明 wire 从 client 拼装
//      到发到线上是同一份字节。
//
// 权威 spec: resty/lua/fizz/proxy/fp_http.lua 的 `build_request_axios`。
//
// 不测 TLS 层 —— TLS 是 tls13.js 的地盘,这里只测 h1 wire。

'use strict';

const assert = require('assert');
const net = require('net');
const http1 = require('./http1.js');
const { _composeAxiosH1Headers } = require('./axios.js');

let pass = 0, fail = 0;
async function t(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
    pass++;
  } catch (e) {
    console.error(`  FAIL ${name}\n       ${e.stack || e.message || e}`);
    fail++;
  }
}

// -----------------------------------------------------------------------------
// helper: [[k,v],...] → 字节序列化的 header block（不含 request line,不含末尾双 CRLF）
// -----------------------------------------------------------------------------
function serialize(headers) {
  return headers.map(([k, v]) => `${k}: ${v}`).join('\r\n');
}

// -----------------------------------------------------------------------------
// 1. 纯函数 golden 测试
// -----------------------------------------------------------------------------

(async () => {

  // ========== axios POST /v1/oauth/token (对齐 CC CLI cli.js 2.1.266 $o.post) ==========
  await t('POST 有 body:CL→AE→Host→Connection 尾组,AE=axios 默认,Connection=keep-alive', () => {
    const bodyBuf = Buffer.from('{"grant_type":"authorization_code","code":"abc"}');
    const headers = _composeAxiosH1Headers({
      userHeadersRaw: [
        ['Accept', 'application/json, text/plain, */*'],
        ['Content-Type', 'application/json'],
        ['User-Agent', 'axios/1.15.2'],
      ],
      host: 'platform.claude.com',
      port: 443,
      bodyBuf,
    });
    const expected =
      'Accept: application/json, text/plain, */*\r\n' +
      'Content-Type: application/json\r\n' +
      'User-Agent: axios/1.15.2\r\n' +
      'Content-Length: ' + bodyBuf.length + '\r\n' +
      'Accept-Encoding: gzip, compress, deflate, br\r\n' +
      'Host: platform.claude.com\r\n' +
      'Connection: keep-alive';
    assert.strictEqual(serialize(headers), expected);
  });

  // ========== axios GET /api/oauth/profile (对齐 CC CLI cli.js a7t) ==========
  await t('GET 无 body:不发 Content-Length,尾组 AE→Host→Connection', () => {
    const headers = _composeAxiosH1Headers({
      userHeadersRaw: [
        ['Accept', 'application/json, text/plain, */*'],
        ['Content-Type', 'application/json'],
        ['Authorization', 'Bearer sk-ant-xxx'],
        ['Cache-Control', 'no-cache'],
        ['User-Agent', 'axios/1.15.2'],
      ],
      host: 'api.anthropic.com',
      port: 443,
      bodyBuf: undefined,
    });
    const expected =
      'Accept: application/json, text/plain, */*\r\n' +
      'Content-Type: application/json\r\n' +
      'Authorization: Bearer sk-ant-xxx\r\n' +
      'Cache-Control: no-cache\r\n' +
      'User-Agent: axios/1.15.2\r\n' +
      'Accept-Encoding: gzip, compress, deflate, br\r\n' +
      'Host: api.anthropic.com\r\n' +
      'Connection: keep-alive';
    assert.strictEqual(serialize(headers), expected);
  });

  // ========== first_token_date 形 (claude-cli UA,带 anthropic-beta,无 Content-Type) ==========
  await t('GET claude-cli UA:app 头保调用方原序,anthropic-beta 尾组前落位', () => {
    const headers = _composeAxiosH1Headers({
      userHeadersRaw: [
        ['Accept', 'application/json, text/plain, */*'],
        ['User-Agent', 'claude-cli/2.1.263 (external, cli)'],
        ['Authorization', 'Bearer sk-ant-xxx'],
        ['anthropic-beta', 'oauth-2025-04-20'],
      ],
      host: 'api.anthropic.com',
      port: 443,
      bodyBuf: undefined,
    });
    const expected =
      'Accept: application/json, text/plain, */*\r\n' +
      'User-Agent: claude-cli/2.1.263 (external, cli)\r\n' +
      'Authorization: Bearer sk-ant-xxx\r\n' +
      'anthropic-beta: oauth-2025-04-20\r\n' +
      'Accept-Encoding: gzip, compress, deflate, br\r\n' +
      'Host: api.anthropic.com\r\n' +
      'Connection: keep-alive';
    assert.strictEqual(serialize(headers), expected);
  });

  // ========== 调用方显式给了 Host / Connection / AE —— 值采用,位置挪到尾组固定序 ==========
  await t('caller 显式给尾组头:值被采用,位置强制挪到尾组固定序', () => {
    const headers = _composeAxiosH1Headers({
      userHeadersRaw: [
        ['Host', 'proxy.internal:8080'],           // caller 给了,但会挪到尾组
        ['Accept', '*/*'],
        ['Connection', 'close'],                    // caller 给了 close,采用
        ['User-Agent', 'axios/1.15.2'],
        ['Accept-Encoding', 'identity'],            // caller 给了 identity,采用
      ],
      host: 'example.com',
      port: 443,
      bodyBuf: undefined,
    });
    const expected =
      'Accept: */*\r\n' +
      'User-Agent: axios/1.15.2\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Host: proxy.internal:8080\r\n' +
      'Connection: close';
    assert.strictEqual(serialize(headers), expected);
  });

  // ========== 非 443 端口:Host 带 :port ==========
  await t('非 443 端口:Host 带 :port', () => {
    const headers = _composeAxiosH1Headers({
      userHeadersRaw: [['Accept', '*/*']],
      host: 'localhost',
      port: 8443,
      bodyBuf: undefined,
    });
    assert.ok(serialize(headers).includes('Host: localhost:8443'));
  });

  // ========== bodyBuf.length 上到 Content-Length ==========
  await t('bodyBuf.length 精确写入 Content-Length', () => {
    const bodyBuf = Buffer.from([0x00, 0x01, 0x02, 0xff]); // 4 字节含非 ASCII
    const headers = _composeAxiosH1Headers({
      userHeadersRaw: [['Content-Type', 'application/octet-stream']],
      host: 'example.com',
      port: 443,
      bodyBuf,
    });
    const s = serialize(headers);
    assert.ok(s.includes('Content-Length: 4'), 's=' + s);
  });

  // ========== 空 app 头(极端):只有尾组 ==========
  await t('空 app 头:只有尾组 AE→Host→Connection', () => {
    const headers = _composeAxiosH1Headers({
      userHeadersRaw: [],
      host: 'example.com',
      port: 443,
      bodyBuf: undefined,
    });
    const expected =
      'Accept-Encoding: gzip, compress, deflate, br\r\n' +
      'Host: example.com\r\n' +
      'Connection: keep-alive';
    assert.strictEqual(serialize(headers), expected);
  });

  // ---------------------------------------------------------------------------
  // 2. 端到端 socket 测试:验证 http1.request 走这批 headers 发出去的字节
  // ---------------------------------------------------------------------------

  await t('端到端:http1.request 拿到 composeAxiosH1Headers 的头,server 收到字节与 golden 一致', async () => {
    // 起本地 TCP echo:client 发过来什么就存起来,然后回一个最小 200 OK
    const captured = [];
    const server = net.createServer((sock) => {
      sock.on('data', (chunk) => {
        captured.push(chunk);
        const full = Buffer.concat(captured).toString('latin1');
        // 等 header 完整（\r\n\r\n）就回 response,忽略 body
        if (full.includes('\r\n\r\n')) {
          const respBody = '{"ok":true}';
          sock.end(
            'HTTP/1.1 200 OK\r\n' +
            'Content-Type: application/json\r\n' +
            'Content-Length: ' + respBody.length + '\r\n' +
            'Connection: close\r\n\r\n' +
            respBody
          );
        }
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;

    try {
      // 拨号 raw TCP
      const socket = net.connect({ host: '127.0.0.1', port });
      await new Promise((r, j) => { socket.once('connect', r); socket.once('error', j); });

      const bodyBuf = Buffer.from('{"a":1}');
      const h1Headers = _composeAxiosH1Headers({
        userHeadersRaw: [
          ['Accept', 'application/json, text/plain, */*'],
          ['Content-Type', 'application/json'],
          ['User-Agent', 'axios/1.15.2'],
        ],
        host: '127.0.0.1',
        port,
        bodyBuf,
      });

      const res = await http1.request({
        stream: socket, method: 'POST',
        path: '/v1/oauth/token', headers: h1Headers, body: bodyBuf, timeout: 5000,
      });

      assert.strictEqual(res.status, 200);
      // socket 已被 http1 read 完并关掉,captured 里就是 client 完整发出的字节
      const wire = Buffer.concat(captured).toString('latin1');

      // 期望 wire = request line + headers + \r\n\r\n + body
      const expectedHeaderBlock =
        'POST /v1/oauth/token HTTP/1.1\r\n' +
        'Accept: application/json, text/plain, */*\r\n' +
        'Content-Type: application/json\r\n' +
        'User-Agent: axios/1.15.2\r\n' +
        'Content-Length: ' + bodyBuf.length + '\r\n' +
        'Accept-Encoding: gzip, compress, deflate, br\r\n' +
        'Host: 127.0.0.1:' + port + '\r\n' +
        'Connection: keep-alive\r\n\r\n';
      const expectedBody = bodyBuf.toString('latin1');
      const expected = expectedHeaderBlock + expectedBody;
      assert.strictEqual(wire, expected, '\nGOT:\n' + wire + '\n\nEXPECTED:\n' + expected);
    } finally {
      server.close();
    }
  });

  await t('端到端:GET 无 body,server 收到无 Content-Length', async () => {
    const captured = [];
    const server = net.createServer((sock) => {
      sock.on('data', (chunk) => {
        captured.push(chunk);
        const full = Buffer.concat(captured).toString('latin1');
        if (full.includes('\r\n\r\n')) {
          sock.end('HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
        }
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;

    try {
      const socket = net.connect({ host: '127.0.0.1', port });
      await new Promise((r, j) => { socket.once('connect', r); socket.once('error', j); });

      const h1Headers = _composeAxiosH1Headers({
        userHeadersRaw: [
          ['Accept', 'application/json, text/plain, */*'],
          ['User-Agent', 'claude-cli/2.1.263 (external, cli)'],
          ['Authorization', 'Bearer sk-ant-x'],
          ['anthropic-beta', 'oauth-2025-04-20'],
        ],
        host: '127.0.0.1',
        port,
        bodyBuf: undefined,
      });

      await http1.request({
        stream: socket, method: 'GET',
        path: '/api/oauth/profile', headers: h1Headers, body: undefined, timeout: 5000,
      });

      const wire = Buffer.concat(captured).toString('latin1');
      const expected =
        'GET /api/oauth/profile HTTP/1.1\r\n' +
        'Accept: application/json, text/plain, */*\r\n' +
        'User-Agent: claude-cli/2.1.263 (external, cli)\r\n' +
        'Authorization: Bearer sk-ant-x\r\n' +
        'anthropic-beta: oauth-2025-04-20\r\n' +
        'Accept-Encoding: gzip, compress, deflate, br\r\n' +
        'Host: 127.0.0.1:' + port + '\r\n' +
        'Connection: keep-alive\r\n\r\n';
      assert.strictEqual(wire, expected, '\nGOT:\n' + wire + '\n\nEXPECTED:\n' + expected);
      // 关键断言:GET 请求绝对不发 Content-Length
      assert.ok(!wire.toLowerCase().includes('content-length'), 'GET 不应有 Content-Length');
    } finally {
      server.close();
    }
  });

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
