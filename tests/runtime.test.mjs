import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import aws4 from 'aws4';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

test('Workers runtime forwards S3 bodies, rejects redirects, and preserves 304', async () => {
    const root = fileURLToPath(new URL('../', import.meta.url));
    const output = await mkdtemp(path.join(root, '.wrangler/runtime-test-'));
    let mf;
    try {
        execFileSync(process.execPath, [path.join(root, 'node_modules/wrangler/bin/wrangler.js'), 'pages', 'functions', 'build', 'functions', '--outdir', output], {
            cwd: root, env: { ...process.env, WRANGLER_SEND_METRICS: 'false', WRANGLER_LOG_PATH: path.join(root, '.wrangler/logs') }, stdio: 'pipe',
        });
        const credentials = { accessKeyId: 'runtime-test-key', secretAccessKey: 'runtime-test-secret-not-real' };
        const calls = [];
        let upstreamStatus = 200;
        mf = new Miniflare(convertV4MiniflareOptions({ workers: [{
            name: 'proxy', modules: true, script: await readFile(path.join(output, 'index.js'), 'utf8'), compatibilityDate: '2024-12-30',
            bindings: { B2_BUCKET_NAME: 'memo-assets', B2_ENDPOINT: 's3.us-west-002.backblazeb2.com', B2_ACCESS_KEY_ID: credentials.accessKeyId, B2_SECRET_ACCESS_KEY: credentials.secretAccessKey },
            outboundService: async request => {
                const url = new URL(request.url);
                calls.push({ url: request.url, method: request.method, body: await request.text() });
                assert.equal(url.hostname, 's3.us-west-002.backblazeb2.com');
                assert.equal(url.pathname, '/memo-assets/runtime.txt');
                return new Response(request.method === 'HEAD' || upstreamStatus === 304 ? null : 'saved', {
                    status: upstreamStatus, headers: upstreamStatus >= 300 && upstreamStatus !== 304 ? { Location: 'https://must-not-contact.invalid/private' } : {},
                });
            },
        }] }));
        async function call(method) {
            const body = method === 'PUT' ? 'synthetic attachment 内容' : undefined;
            const signed = aws4.sign({ host: 'proxy.example.com', path: '/memo-assets/runtime.txt', method, service: 's3', region: 'us-west-002', body,
                headers: { 'content-type': 'text/plain', 'x-amz-content-sha256': createHash('sha256').update(body || '').digest('hex') },
            }, credentials);
            return mf.dispatchFetch('https://proxy.example.com' + signed.path, { method, headers: signed.headers, body });
        }
        for (const method of ['PUT', 'GET', 'HEAD', 'DELETE']) {
            const response = await call(method);
            assert.equal(response.status, 200, await response.clone().text());
            assert.equal(response.headers.get('x-proxy'), 'b2-pages-verified');
            assert.equal(response.headers.get('cache-control'), 'private, no-store');
            assert.equal(await response.text(), method === 'HEAD' ? '' : 'saved');
            assert.equal(calls.at(-1).body, method === 'PUT' ? 'synthetic attachment 内容' : '');
        }
        for (const status of [301, 302, 303, 307, 308]) {
            upstreamStatus = status;
            const before = calls.length;
            const response = await call('GET');
            assert.equal(response.status, 502);
            assert.deepEqual(await response.json(), { error: 'Upstream request failed' });
            assert.equal(response.headers.get('location'), null);
            assert.equal(calls.length, before + 1, 'must never follow redirects');
        }
        upstreamStatus = 304;
        const response = await call('GET');
        assert.equal(response.status, 304);
        assert.equal(await response.text(), '');
    } finally {
        await mf?.dispose();
        await rm(output, { recursive: true, force: true });
    }
});
