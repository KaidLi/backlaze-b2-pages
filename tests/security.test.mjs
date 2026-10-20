import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import aws4 from 'aws4';
import { AuthenticationError, signRequest, verifyRequest } from '../src/sigv4.ts';
import { onRequest } from '../functions/[[path]].ts';

// Synthetic credentials: never point this test suite at a real B2 account.
const credentials = { accessKeyId: 'test-key-id', secretAccessKey: 'test-secret-not-a-real-key' };
const env = { B2_BUCKET_NAME: 'memo-assets', B2_ENDPOINT: 's3.us-west-004.backblazeb2.com', B2_ACCESS_KEY_ID: credentials.accessKeyId, B2_SECRET_ACCESS_KEY: credentials.secretAccessKey };
const fixed = new Date('2026-10-20T12:00:00Z');
const amzDate = date => date.toISOString().replace(/[:-]|\.\d{3}/g, '');
const sha256 = value => createHash('sha256').update(value).digest('hex');

test('malformed endpoint is a configuration error and never contacts B2', async t => {
    t.mock.method(globalThis, 'fetch', () => { throw new Error('must not fetch'); });
    const response = await onRequest({ request: new Request('https://proxy.example.com/'), env: { ...env, B2_ENDPOINT: 'https://' } });
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { error: 'Proxy configuration error' });
    assert.equal(globalThis.fetch.mock.callCount(), 0);
});

test('configured proxy rejects anonymous requests before contacting B2', async t => {
    t.mock.method(globalThis, 'fetch', () => { throw new Error('must not fetch'); });
    const response = await onRequest({ request: new Request('https://proxy.example.com/'), env });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: 'Authentication failed' });
    assert.equal(globalThis.fetch.mock.callCount(), 0);
});

function signed({ method = 'GET', path = '/memo-assets/image.png', date = fixed, headers = {}, body, presigned = false, expires = '60', keys = credentials } = {}) {
    if (presigned) path += (path.includes('?') ? '&' : '?') + `X-Amz-Date=${amzDate(date)}&X-Amz-Expires=${expires}`;
    const request = aws4.sign({ host: 'proxy.example.com', path, service: 's3', region: 'us-west-004', method, headers: presigned ? { ...headers } : { 'X-Amz-Date': amzDate(date), ...headers }, body, signQuery: presigned, extraHeadersToInclude: { range: true } }, keys);
    return new Request('https://' + request.host + request.path, { method, headers: request.headers, body });
}

async function rejected(request, now = fixed.getTime()) {
    await assert.rejects(verifyRequest(request, credentials, now), AuthenticationError);
}

test('matches AWS published GET Object signature, independent of our signer', async () => {
    // AWS S3 SigV4 documentation, 2013-05-24 example credentials and signature.
    const example = { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' };
    const request = new Request('https://examplebucket.s3.amazonaws.com/test.txt', { headers: {
        range: 'bytes=0-9', 'x-amz-date': '20130524T000000Z', 'x-amz-content-sha256': sha256(''),
        authorization: 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41',
    } });
    await verifyRequest(request, example, Date.parse('2013-05-24T00:00:00Z'));
});

for (const method of ['GET', 'HEAD', 'PUT', 'POST', 'DELETE']) {
    test(`accepts independently signed ${method}`, async () => {
        await verifyRequest(signed({ method, body: ['PUT', 'POST'].includes(method) ? '附件内容' : undefined }), credentials, fixed.getTime());
    });
}

for (const path of ['/memo-assets/%E4%B8%AD%E6%96%87%20a%2Bb%21.png', '/memo-assets/a//b.txt', '/memo-assets/%252F.txt', '/memo-assets?list-type=2&prefix=%E5%9B%BE%2F&max-keys=10', '/memo-assets?uploads=']) {
    test(`canonicalizes S3 path/query ${path}`, async () => {
        await verifyRequest(signed({ path }), credentials, fixed.getTime());
    });
}

test('accepts header-authenticated unsigned payload without consuming the stream', async () => {
    const request = signed({ method: 'PUT', body: 'stream', headers: { 'X-Amz-Content-Sha256': 'UNSIGNED-PAYLOAD' } });
    assert.equal((await verifyRequest(request, credentials, fixed.getTime())).payloadHash, 'UNSIGNED-PAYLOAD');
    assert.equal(request.bodyUsed, false);
});

for (const method of ['GET', 'PUT']) {
    test(`accepts independent presigned ${method}`, async () => {
        await verifyRequest(signed({ method, presigned: true }), credentials, fixed.getTime() + 30_000);
    });
}

test('rejects right key ID with wrong secret (original authentication bypass)', async () => {
    await rejected(signed({ keys: { ...credentials, secretAccessKey: 'wrong-secret' } }));
});

test('rejects missing, malformed and zero-filled signatures', async () => {
    await rejected(new Request('https://proxy.example.com/memo-assets/file'));
    const request = signed();
    request.headers.set('authorization', request.headers.get('authorization').replace(/Signature=.*/, 'Signature=' + '0'.repeat(64)));
    await rejected(request);
    request.headers.set('authorization', 'AWS4-HMAC-SHA256 nonsense');
    await rejected(request);
});

for (const mutation of ['host', 'path', 'query', 'method', 'signed-header', 'payload-hash', 'service', 'scope-date', 'algorithm', 'signed-headers-order']) {
    test(`rejects tampered ${mutation}`, async () => {
        const original = signed({ headers: { Range: 'bytes=0-9' } });
        const headers = new Headers(original.headers);
        let url = original.url;
        let method = original.method;
        if (mutation === 'host') url = url.replace('proxy.example.com', 'other.example.com');
        if (mutation === 'path') url = url.replace('image.png', 'private.txt');
        if (mutation === 'query') url += '?versionId=other';
        if (mutation === 'method') method = 'DELETE';
        if (mutation === 'signed-header') headers.set('Range', 'bytes=100-200');
        if (mutation === 'payload-hash') headers.set('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
        if (mutation === 'service') headers.set('authorization', headers.get('authorization').replace('/s3/', '/iam/'));
        if (mutation === 'scope-date') headers.set('authorization', headers.get('authorization').replace('/20261020/', '/20261019/'));
        if (mutation === 'algorithm') headers.set('authorization', headers.get('authorization').replace('AWS4-HMAC-SHA256', 'AWS4-HMAC-SHA1'));
        if (mutation === 'signed-headers-order') headers.set('authorization', headers.get('authorization').replace('host;range;', 'range;host;'));
        await rejected(new Request(url, { method, headers }));
    });
}

test('rejects stale header requests and timestamps too far in the future', async () => {
    await rejected(signed(), fixed.getTime() + 16 * 60_000);
    await rejected(signed(), fixed.getTime() - 6 * 60_000);
});

for (const expires of ['0', '-1', '604801', 'NaN', 'Infinity']) {
    test(`rejects invalid presigned expiry ${expires}`, async () => {
        await rejected(signed({ presigned: true, expires }));
    });
}

test('rejects expired presigned URLs and attempts to extend their expiry', async () => {
    const request = signed({ presigned: true });
    await rejected(request, fixed.getTime() + 60_000);
    const url = new URL(request.url);
    url.searchParams.set('X-Amz-Expires', '600');
    await rejected(new Request(url, { headers: request.headers }));
});

test('rejects duplicate credentials, mixed authentication and unsigned x-amz operation headers', async () => {
    const query = signed({ presigned: true });
    await rejected(new Request(query.url + '&X-Amz-Signature=' + '0'.repeat(64), { headers: query.headers }));
    await rejected(new Request(query.url + '&x-amz-signature=' + '0'.repeat(64), { headers: query.headers }));
    const header = signed();
    await rejected(new Request(query.url, { headers: header.headers }));
    header.headers.set('x-amz-copy-source', '/another-bucket/file');
    await rejected(header);
});

test('signs upstream requests using the regional B2 endpoint, verified with aws4', async () => {
    const url = new URL('https://s3.us-west-004.backblazeb2.com/memo-assets/%E5%9B%BE%20a%2Bb.png?partNumber=1&uploadId=x%2By');
    const headers = await signRequest('PUT', url, new Headers({ 'content-type': 'image/png' }), sha256('png'), credentials, 'us-west-004', fixed);
    const independent = new aws4.RequestSigner({ host: url.host, path: url.pathname + url.search, service: 's3', region: 'us-west-004', method: 'PUT', headers: Object.fromEntries(headers), extraHeadersToIgnore: { 'content-length': true }, extraHeadersToInclude: { range: true } }, credentials);
    independent.prepareRequest();
    assert.equal(headers.get('authorization').split('Signature=')[1], independent.signature());
});

test('invalid auth never reaches B2 and does not disclose key ID or secret', async t => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not fetch'); });
    const wrong = signed({ date: new Date(), keys: { accessKeyId: 'unknown-key', secretAccessKey: 'wrong' } });
    const response = await onRequest({ request: wrong, env });
    assert.equal(response.status, 403);
    const text = await response.text();
    assert.equal(text, '{"error":"Authentication failed"}');
    assert.ok(!text.includes(credentials.accessKeyId) && !text.includes(credentials.secretAccessKey));
    assert.equal(fetch.mock.callCount(), 0);
});

test('handler streams hashed uploads and preserves S3 multipart parameters', async t => {
    const content = '中文附件';
    const request = signed({ date: new Date(), method: 'PUT', path: '/memo-assets/image.txt?partNumber=1&uploadId=test%2Bupload', body: content });
    const fetch = t.mock.method(globalThis, 'fetch', async (url, options) => {
        assert.equal(url.pathname, '/memo-assets/image.txt');
        assert.equal(url.searchParams.get('uploadId'), 'test+upload');
        assert.equal(options.headers.get('x-amz-content-sha256'), sha256(content));
        assert.equal(await new Response(options.body).text(), content);
        const independent = new aws4.RequestSigner({ host: url.host, path: url.pathname + url.search, service: 's3', region: 'us-west-004', method: options.method, headers: Object.fromEntries(options.headers), extraHeadersToIgnore: { 'content-length': true }, extraHeadersToInclude: { range: true } }, credentials);
        independent.prepareRequest();
        assert.equal(options.headers.get('authorization').split('Signature=')[1], independent.signature());
        assert.equal(options.redirect, 'manual');
        assert.deepEqual(options.cf, { cacheEverything: false, cacheTtl: 0 });
        return new Response('saved', { status: 200, headers: { 'Cache-Control': 'public, max-age=86400' } });
    });
    const response = await onRequest({ request, env });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), 'saved');
    assert.equal(response.headers.get('cache-control'), 'private, no-store');
    assert.equal(fetch.mock.callCount(), 1);
});

test('handler strips client query credentials before re-signing upstream', async t => {
    const request = signed({ date: new Date(), presigned: true });
    t.mock.method(globalThis, 'fetch', async (url, options) => {
        assert.equal(url.search, '');
        assert.match(options.headers.get('authorization'), /us-west-004\/s3\/aws4_request/);
        return new Response('image');
    });
    assert.equal((await onRequest({ request, env })).status, 200);
});

for (const path of ['/memo-assets-other/file', '/virtual-folder/file', '/memo-assets/file']) {
    test(`keeps bucket routing inside configured bucket: ${path}`, async t => {
        t.mock.method(globalThis, 'fetch', async url => {
            const expected = path.startsWith('/memo-assets/') ? path : '/memo-assets' + path;
            assert.equal(url.pathname, expected);
            return new Response('ok');
        });
        assert.equal((await onRequest({ request: signed({ path, date: new Date() }), env })).status, 200);
    });
}

for (const method of ['GET', 'HEAD', 'PUT', 'DELETE']) {
    test(`handler rejects forged ${method} before any upstream side effect`, async t => {
        const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not fetch'); });
        const request = signed({ method, date: new Date(), keys: { ...credentials, secretAccessKey: 'wrong-secret' } });
        assert.equal((await onRequest({ request, env })).status, 403);
        assert.equal(fetch.mock.callCount(), 0);
    });
}

test('handler does not log signed URLs or return upstream exception details', async t => {
    const sensitive = 'fake-secret-that-must-not-be-logged';
    const logs = [];
    t.mock.method(console, 'error', (...args) => logs.push(args.join(' ')));
    t.mock.method(globalThis, 'fetch', async () => { throw new Error(sensitive); });
    const response = await onRequest({ request: signed({ presigned: true, date: new Date() }), env });
    assert.equal(response.status, 502);
    assert.equal(await response.text(), '{"error":"Upstream request failed"}');
    assert.deepEqual(logs, ['B2 proxy request failed']);
});

for (const alias of ['/%6Demo-assets/image.png', '/memo-assets%2Fimage.png']) {
    test(`equivalent signed path cannot select a different upstream object: ${alias}`, async t => {
        const original = signed({ date: new Date() });
        t.mock.method(globalThis, 'fetch', async url => {
            assert.equal(url.pathname, '/memo-assets/image.png');
            return new Response('same object');
        });
        assert.equal((await onRequest({ request: new Request('https://proxy.example.com' + alias, { headers: original.headers }), env })).status, 200);
    });
}

test('rejects ambiguous duplicate S3 operation parameters', async () => {
    await rejected(signed({ path: '/memo-assets/image.png?versionId=one&versionId=two' }));
});
