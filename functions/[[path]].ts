import { AuthenticationError, AUTH_QUERY_PARAMETERS, canonicalS3Path, signRequest, verifyRequest } from '../src/sigv4.ts';

export interface Env {
    B2_BUCKET_NAME: string;
    B2_ENDPOINT: string;
    B2_ACCESS_KEY_ID: string;
    B2_SECRET_ACCESS_KEY: string;
}

const FORWARDED_HEADERS = new Set([
    'content-type', 'content-length', 'content-disposition', 'content-encoding', 'content-md5',
    'cache-control', 'range', 'if-match', 'if-none-match', 'if-modified-since', 'if-unmodified-since',
    'x-amz-copy-source', 'x-amz-copy-source-if-match', 'x-amz-copy-source-if-none-match',
    'x-amz-copy-source-if-modified-since', 'x-amz-copy-source-if-unmodified-since',
    'x-amz-metadata-directive', 'x-amz-tagging-directive', 'x-amz-storage-class',
    'x-amz-acl', 'x-amz-grant-read', 'x-amz-grant-write', 'x-amz-grant-read-acp',
    'x-amz-grant-write-acp', 'x-amz-grant-full-control',
    'x-amz-sdk-checksum-algorithm', 'x-amz-checksum-crc32', 'x-amz-checksum-crc32c',
    'x-amz-checksum-sha1', 'x-amz-checksum-sha256',
]);

function errorResponse(status: number, error: string): Response {
    return Response.json({ error }, { status, headers: { 'Cache-Control': 'no-store' } });
}

export const onRequest: PagesFunction<Env> = async ({ request, env }) => {
    try {
        if (!env.B2_ACCESS_KEY_ID || !env.B2_SECRET_ACCESS_KEY || !env.B2_ENDPOINT || !/^[A-Za-z0-9][A-Za-z0-9.-]{1,61}[A-Za-z0-9]$/.test(env.B2_BUCKET_NAME || '')) {
            return errorResponse(500, 'Proxy configuration error');
        }
        let endpoint: URL;
        try {
            endpoint = new URL(env.B2_ENDPOINT.includes('://') ? env.B2_ENDPOINT : 'https://' + env.B2_ENDPOINT);
        } catch {
            return errorResponse(500, 'Proxy configuration error');
        }
        const region = /^s3\.([a-z0-9-]+)\.backblazeb2\.com$/.exec(endpoint.hostname)?.[1];
        if (!region || endpoint.protocol !== 'https:' || endpoint.port || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== '/') {
            return errorResponse(500, 'Proxy configuration error');
        }
        if (!['GET', 'HEAD', 'PUT', 'POST', 'DELETE'].includes(request.method)) return errorResponse(405, 'Method not allowed');

        const credentials = { accessKeyId: env.B2_ACCESS_KEY_ID, secretAccessKey: env.B2_SECRET_ACCESS_KEY };
        // Authenticate the original request BEFORE rewriting or fetching it.
        const { payloadHash } = await verifyRequest(request, credentials);
        const incoming = new URL(request.url);
        // Route exactly the same S3 path that was authenticated. Percent-encoded
        // bucket/slash aliases must not select a different directory upstream.
        const incomingPath = canonicalS3Path(incoming);
        const bucketPrefix = '/' + env.B2_BUCKET_NAME;
        const path = incomingPath === bucketPrefix || incomingPath.startsWith(bucketPrefix + '/')
            ? incomingPath : bucketPrefix + incomingPath;
        const upstream = new URL(endpoint.origin + path);
        for (const [key, value] of incoming.searchParams) {
            if (!AUTH_QUERY_PARAMETERS.has(key.toLowerCase())) upstream.searchParams.append(key, value);
        }
        const headers = new Headers();
        for (const [name, value] of request.headers) {
            if (FORWARDED_HEADERS.has(name) || name.startsWith('x-amz-meta-')) headers.set(name, value);
        }
        // B2 checks streamed bytes against this authenticated content hash.
        // Never silently downgrade a hashed body to UNSIGNED-PAYLOAD.
        await signRequest(request.method, upstream, headers, payloadHash, credentials, region);
        const options: RequestInit = {
            method: request.method,
            headers,
            body: request.body,
            // Workers supports only follow/manual. Never forward signed
            // credentials to a redirect target supplied by the upstream.
            redirect: 'manual',
            cf: { cacheEverything: false, cacheTtl: 0 },
        };
        const response = await fetch(upstream, options);
        if ([301, 302, 303, 307, 308].includes(response.status)) {
            await response.body?.cancel();
            return errorResponse(502, 'Upstream request failed');
        }
        const responseHeaders = new Headers(response.headers);
        responseHeaders.set('Cache-Control', 'private, no-store');
        responseHeaders.set('X-Proxy', 'b2-pages-verified');
        responseHeaders.delete('x-amz-request-id');
        responseHeaders.delete('x-amz-id-2');
        return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });
    } catch (error) {
        if (error instanceof AuthenticationError) return errorResponse(error.status, 'Authentication failed');
        // Do not log URLs, signed queries, credential scopes or expected key IDs.
        console.error('B2 proxy request failed');
        return errorResponse(502, 'Upstream request failed');
    }
};
