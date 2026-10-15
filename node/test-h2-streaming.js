/**
 * http2.request 的流式响应（SSE）支持 —— 回归锁。
 *
 * ## 为什么加这个能力
 * codex 的 `/backend-api/codex/responses` 走 HTTP 时是 SSE 长流，一轮可能几分钟。
 * 原实现把 DATA 帧全攒进 respBodyChunks、END_STREAM 才 resolve，且 `timeout`
 * 是**总超时**（默认 30s）—— 对 SSE 两条都不成立。
 *
 * ## 关键不变量
 * **不传 `onBodyChunk` 时行为必须逐字节不变** —— 生产 resty / lua / go 绑定都在
 * 用同一份实现，这里只新增可选能力。
 */
const assert = require('assert');
const { EventEmitter } = require('events');
const http2 = require('./http2.js');
const hpack = require('./hpack.js');
const zlib = require('zlib');
const { createStreamingDecompressor, createStreamSink } = require('./fetch.js');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  ok  ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n       ' + e.message); fail++; }
}
async function ta(name, fn) {
  try { await fn(); console.log('  ok  ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n       ' + e.message); fail++; }
}

/** 一个最小的双向 stream 替身：记录我方写出的字节，并能把服务端帧喂进来。 */
function fakeStream() {
  const ee = new EventEmitter();
  ee.written = [];
  ee.write = (buf) => { ee.written.push(buf); return true; };
  ee.feed = (buf) => ee.emit('data', buf);
  // http2.js 用 stream.off(...) 解绑
  ee.off = ee.removeListener.bind(ee);
  return ee;
}

const FRAME_DATA = 0x0, FRAME_HEADERS = 0x1, FRAME_SETTINGS = 0x4, FRAME_CONTINUATION = 0x9;
const F_END_STREAM = 0x1, F_END_HEADERS = 0x4;

function serverHeaders(status, extra = []) {
  return http2.writeFrame(
    FRAME_HEADERS, F_END_HEADERS, 1,
    hpack.encodeHeaderBlock([[':status', String(status)], ...extra]),
  );
}
function serverData(text, end) {
  return http2.writeFrame(FRAME_DATA, end ? F_END_STREAM : 0, 1, Buffer.from(text));
}

function startRequest(stream, opts = {}) {
  return http2.request({
    stream,
    prefaceBytes: Buffer.alloc(0),
    pseudoOrder: 'm,a,s,p',
    method: 'POST',
    scheme: 'https',
    authority: 'chatgpt.com',
    path: '/backend-api/codex/responses',
    headers: [['content-type', 'application/json']],
    body: Buffer.from('{}'),
    ...opts,
  });
}

(async () => {
  console.log('http2 流式响应：');

  await ta('⭐ 传 onBodyChunk → 每个 DATA 帧即时回调，不等 END_STREAM', async () => {
    const s = fakeStream();
    const chunks = [];
    let headerStatus = null;
    const p = startRequest(s, {
      onBodyChunk: (c) => chunks.push(c.toString('utf8')),
      onHeaders: (status) => { headerStatus = status; },
    });
    s.feed(http2.writeFrame(FRAME_SETTINGS, 0, 0, Buffer.alloc(0)));
    s.feed(serverHeaders(200, [['content-type', 'text/event-stream']]));
    // 头一到就该交出去（早于任何 body）
    assert.strictEqual(headerStatus, 200, 'onHeaders 应在 body 之前回调');
    s.feed(serverData('event: a\ndata: 1\n\n', false));
    assert.deepStrictEqual(chunks, ['event: a\ndata: 1\n\n'], '第一帧应已回调');
    s.feed(serverData('event: b\ndata: 2\n\n', false));
    assert.strictEqual(chunks.length, 2, '第二帧应已回调');
    s.feed(serverData('', true));
    const res = await p;
    assert.strictEqual(res.status, 200);
    // 流式下不再在内存里攒整份 body
    assert.strictEqual(res.body.length, 0, '流式模式不应累积 body');
  });

  await ta('⛔ 不传 onBodyChunk → 仍是「攒齐再 resolve」，body 完整（既有调用方不受影响）', async () => {
    const s = fakeStream();
    const p = startRequest(s);
    s.feed(http2.writeFrame(FRAME_SETTINGS, 0, 0, Buffer.alloc(0)));
    s.feed(serverHeaders(200));
    s.feed(serverData('hello ', false));
    s.feed(serverData('world', true));
    const res = await p;
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.toString('utf8'), 'hello world', 'body 必须完整');
    assert.ok(res.headers.every(([k]) => !k.startsWith(':')), 'pseudo-header 应被过滤');
  });

  await ta('流式下 timeout 是**空闲**超时：持续收帧不会被掐', async () => {
    const s = fakeStream();
    const chunks = [];
    const p = startRequest(s, {
      timeout: 120,
      onBodyChunk: (c) => chunks.push(c),
    });
    s.feed(http2.writeFrame(FRAME_SETTINGS, 0, 0, Buffer.alloc(0)));
    s.feed(serverHeaders(200));
    // 每 60ms 喂一帧，总时长 300ms > timeout(120ms)，但每帧都重置空闲计时
    for (let i = 0; i < 5; i++) {
      await new Promise((r) => setTimeout(r, 60));
      s.feed(serverData('d' + i, false));
    }
    s.feed(serverData('', true));
    const res = await p;
    assert.strictEqual(res.status, 200);
    assert.strictEqual(chunks.length, 5, '五帧都应收到，不该因总时长超 timeout 被掐');
  });

  await ta('流式下真正空闲超过 timeout → 报空闲超时（不是静默挂住）', async () => {
    const s = fakeStream();
    const p = startRequest(s, { timeout: 80, onBodyChunk: () => {} });
    s.feed(http2.writeFrame(FRAME_SETTINGS, 0, 0, Buffer.alloc(0)));
    s.feed(serverHeaders(200));
    let msg = '';
    try { await p; } catch (e) { msg = e.message; }
    assert.ok(/空闲超时/.test(msg), '应报空闲超时，实际: ' + msg);
  });

  await ta('⭐⛔ 响应头跨 HEADERS+CONTINUATION → onHeaders 仍必须触发（曾漏）', async () => {
    const st = fakeStream();
    let sawStatus = null;
    const chunks = [];
    const p = startRequest(st, {
      onHeaders: (status) => { sawStatus = status; },
      onBodyChunk: (c) => chunks.push(c),
    });
    st.feed(http2.writeFrame(FRAME_SETTINGS, 0, 0, Buffer.alloc(0)));
    // 把 header block 切成两半：HEADERS(不带 END_HEADERS) + CONTINUATION(带)
    const block = hpack.encodeHeaderBlock([
      [':status', '200'],
      ['content-type', 'text/event-stream'],
      ['x-filler', 'y'.repeat(200)],
    ]);
    const cut = Math.floor(block.length / 2);
    st.feed(http2.writeFrame(FRAME_HEADERS, 0, 1, block.subarray(0, cut)));
    assert.strictEqual(sawStatus, null, 'header 未收齐时不该交付');
    st.feed(http2.writeFrame(FRAME_CONTINUATION, F_END_HEADERS, 1, block.subarray(cut)));
    assert.strictEqual(sawStatus, 200, 'CONTINUATION 收齐后必须交付 onHeaders');
    st.feed(serverData('data: 1\n\n', true));
    const res = await p;
    assert.strictEqual(res.status, 200);
    assert.strictEqual(chunks.length, 1);
  });

  await ta('跨帧 header + gzip body → 调用方拿到的仍是明文（端到端串起来）', async () => {
    const st = fakeStream();
    const original = 'event: x\ndata: 42\n\n';
    const gz = zlib.gzipSync(Buffer.from(original));
    // 用 fetch 的 sink 把 http2 的回调接起来，复刻真实链路
    const got = [];
    const sink = createStreamSink({ onChunk: (c) => got.push(c) }, true);
    const hooks = sink.h2Hooks();
    const p = startRequest(st, hooks);
    st.feed(http2.writeFrame(FRAME_SETTINGS, 0, 0, Buffer.alloc(0)));
    const block = hpack.encodeHeaderBlock([
      [':status', '200'],
      ['content-encoding', 'gzip'],
      ['x-filler', 'z'.repeat(200)],
    ]);
    const cut = Math.floor(block.length / 2);
    st.feed(http2.writeFrame(FRAME_HEADERS, 0, 1, block.subarray(0, cut)));
    st.feed(http2.writeFrame(FRAME_CONTINUATION, F_END_HEADERS, 1, block.subarray(cut)));
    // ⚠ 必须直接喂 Buffer：gzip 是二进制，经 toString('binary') + Buffer.from(utf8)
    // 会被破坏（第一版测试就栽在这里，源码没问题）。
    st.feed(http2.writeFrame(FRAME_DATA, 0, 1, gz.subarray(0, 8)));
    st.feed(http2.writeFrame(FRAME_DATA, F_END_STREAM, 1, gz.subarray(8)));
    await p;
    sink.finish();
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(Buffer.concat(got).toString('utf8'), original);
  });

  // --- fetch.js 的增量解压器 -------------------------------------------------
  console.log('\nfetch 增量解压：');
  await ta('gzip：分两段喂进去，解出完整原文（SSE 不能用整份 sync 解压）', async () => {
    const original = 'event: a\ndata: 1\n\nevent: b\ndata: 2\n\n';
    const gz = zlib.gzipSync(Buffer.from(original));
    const inf = createStreamingDecompressor('gzip');
    assert.ok(inf, 'gzip 应得到解压器');
    const out = [];
    inf.on('data', (c) => out.push(c));
    const done = new Promise((r) => inf.on('end', r));
    inf.write(gz.subarray(0, Math.floor(gz.length / 2)));
    inf.write(gz.subarray(Math.floor(gz.length / 2)));
    inf.end();
    await done;
    assert.strictEqual(Buffer.concat(out).toString('utf8'), original);
  });

  t('identity / 空 / 未知编码 → null（直接透传，与 decompress() 口径一致）', () => {
    assert.strictEqual(createStreamingDecompressor(''), null);
    assert.strictEqual(createStreamingDecompressor('identity'), null);
    assert.strictEqual(createStreamingDecompressor('x-weird'), null);
    assert.strictEqual(createStreamingDecompressor(undefined), null);
  });

  t('br / deflate 有解压器', () => {
    assert.ok(createStreamingDecompressor('br'));
    assert.ok(createStreamingDecompressor('deflate'));
    assert.ok(createStreamingDecompressor('GZIP'), '大小写不敏感');
  });


  // --- fetch.js 的流式 sink 接线（真正的集成点） ---------------------------
  console.log('\nfetch 流式 sink：');

  t('没给 onChunk → sink 为 null（调用方走"攒齐"老路）', () => {
    assert.strictEqual(createStreamSink({}, true), null);
    assert.strictEqual(createStreamSink(null, true), null);
    assert.strictEqual(createStreamSink({ onChunk: 'nope' }, true), null);
  });

  t('未压缩响应 → chunk 原样透传', () => {
    const got = [];
    const sink = createStreamSink({ onChunk: (c) => got.push(c.toString('utf8')) }, true);
    const h = sink.h2Hooks();
    h.onHeaders(200, [['content-type', 'text/event-stream']]);
    h.onBodyChunk(Buffer.from('data: 1\n\n'));
    h.onBodyChunk(Buffer.from('data: 2\n\n'));
    sink.finish();
    assert.deepStrictEqual(got, ['data: 1\n\n', 'data: 2\n\n']);
  });

  await ta('⭐ gzip 响应 → 先建解压器再喂 body，调用方拿到的是明文 SSE', async () => {
    const original = 'event: a\ndata: {"x":1}\n\nevent: b\ndata: {"x":2}\n\n';
    const gz = zlib.gzipSync(Buffer.from(original));
    const got = [];
    const sink = createStreamSink({ onChunk: (c) => got.push(c) }, true);
    const h = sink.h2Hooks();
    // 关键顺序：onHeaders 必须先到，否则解压器建不起来
    h.onHeaders(200, [['content-type', 'text/event-stream'], ['content-encoding', 'gzip']]);
    h.onBodyChunk(gz.subarray(0, 10));
    h.onBodyChunk(gz.subarray(10));
    sink.finish();
    await new Promise((r) => setTimeout(r, 30));  // 让 zlib 的 data 事件跑完
    assert.strictEqual(Buffer.concat(got).toString('utf8'), original);
  });

  t('decompress:false → 即使 content-encoding 是 gzip 也不解（尊重调用方）', () => {
    const got = [];
    const sink = createStreamSink({ onChunk: (c) => got.push(c) }, /*decompressResp*/ false);
    const h = sink.h2Hooks();
    h.onHeaders(200, [['content-encoding', 'gzip']]);
    const raw = Buffer.from([1, 2, 3]);
    h.onBodyChunk(raw);
    assert.deepStrictEqual(Buffer.concat(got), raw, '应原样给出压缩字节');
  });

  t('onResponseHeaders 被转发，且 onChunk 抛异常不会炸传输', () => {
    let seen = null;
    const sink = createStreamSink({
      onChunk: () => { throw new Error('调用方自己的 bug'); },
      onResponseHeaders: (status, headers) => { seen = { status, headers }; },
    }, true);
    const h = sink.h2Hooks();
    h.onHeaders(201, [['x-a', 'b']]);
    assert.strictEqual(seen.status, 201);
    assert.deepStrictEqual(seen.headers, [['x-a', 'b']]);
    // onChunk 抛错必须被吞掉 —— 否则一个调用方 bug 会掐断整条连接
    assert.doesNotThrow(() => h.onBodyChunk(Buffer.from('x')));
  });

  t('⛔ 源码门禁：h1 + onChunk 必须明确报错，不许静默退回"攒齐"', () => {
    const src = require('fs').readFileSync(__dirname + '/fetch.js', 'utf8');
    assert.ok(/onChunk（流式响应）目前只支持 HTTP\/2/.test(src), '缺少 h1 流式的明确报错');
    assert.ok(/redirect === 'follow' && !streamSink/.test(src), '流式下必须跳过 redirect follow');
  });

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
