/** S3 Signature V4 using Web Crypto, compatible with the Workers runtime. */
export interface Credentials {
    accessKeyId: string;
    secretAccessKey: string;
}

export class AuthenticationError extends Error {
    readonly status: number;
    constructor(status = 403) {
        super('Authentication failed');
        this.status = status;
    }
}

const ALGORITHM = 'AWS4-HMAC-SHA256';
const EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const HEADER_MAX_AGE_MS = 15 * 60 * 1000;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const encoder = new TextEncoder();

export const AUTH_QUERY_PARAMETERS = new Set([
    'x-amz-algorithm', 'x-amz-credential', 'x-amz-date', 'x-amz-expires',
    'x-amz-signedheaders', 'x-amz-signature', 'x-amz-security-token',
]);

function reject(): never { throw new AuthenticationError(); }

function hex(bytes: ArrayBuffer): string {
    return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}

async function hash(value: string): Promise<string> {
    return hex(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}

async function hmac(key: BufferSource, value: string): Promise<ArrayBuffer> {
    const imported = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return crypto.subtle.sign('HMAC', imported, encoder.encode(value));
}

async function signingKey(secret: string, date: string, region: string): Promise<ArrayBuffer> {
    const day = await hmac(encoder.encode('AWS4' + secret), date);
    const regional = await hmac(day, region);
    return hmac(await hmac(regional, 's3'), 'aws4_request');
}

function encode(value: string): string {
    return encodeURIComponent(value).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

export function canonicalS3Path(url: URL): string {
    // Decode exactly once; preserve repeated slashes in S3 object keys.
    try {
        return url.pathname.split('/').map(part => encode(decodeURIComponent(part))).join('/').replace(/%2F/g, '/');
    } catch { return reject(); }
}

function canonicalQuery(url: URL, presigned: boolean): string {
    return Array.from(url.searchParams)
        .filter(([key]) => !(presigned && key === 'X-Amz-Signature'))
        .map(([key, value]) => [encode(key), encode(value)])
        .sort(([ak, av], [bk, bv]) => ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0)
        .map(([key, value]) => key + '=' + value).join('&');
}

function canonicalHeaders(url: URL, headers: Headers, names: string[]): string {
    return names.map(name => {
        const value = name === 'host' ? url.host : headers.get(name);
        if (value === null) reject();
        return name + ':' + value.trim().replace(/\s+/g, ' ') + '\n';
    }).join('');
}

function canonicalRequest(method: string, url: URL, headers: Headers, names: string[], payloadHash: string, presigned: boolean): string {
    return [method, canonicalS3Path(url), canonicalQuery(url, presigned), canonicalHeaders(url, headers, names), names.join(';'), payloadHash].join('\n');
}

function parseDate(value: string): number {
    if (!/^\d{8}T\d{6}Z$/.test(value)) reject();
    const formatted = `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(9, 11)}:${value.slice(11, 13)}:${value.slice(13, 15)}Z`;
    const result = Date.parse(formatted);
    if (!Number.isFinite(result) || new Date(result).toISOString().replace(/[:-]|\.\d{3}/g, '') !== value) reject();
    return result;
}

function signedHeaderNames(value: string): string[] {
    const names = value.split(';');
    if (!names.includes('host') || names.some(name => !/^[a-z0-9-]+$/.test(name))) reject();
    if (names.join(';') !== [...new Set(names)].sort().join(';')) reject();
    return names;
}

function payloadHashFor(request: Request, presigned: boolean): string {
    const value = request.headers.get('x-amz-content-sha256') || (presigned ? 'UNSIGNED-PAYLOAD' : EMPTY_HASH);
    // Chunk-signed/trailer payloads cannot be transparently re-signed.
    if (value !== 'UNSIGNED-PAYLOAD' && !/^[a-f0-9]{64}$/.test(value)) reject();
    if (!presigned && request.body !== null && !request.headers.has('x-amz-content-sha256')) reject();
    return value;
}

export async function verifyRequest(request: Request, credentials: Credentials, now = Date.now()): Promise<{ payloadHash: string }> {
    const url = new URL(request.url);
    const authorization = request.headers.get('authorization');
    const presigned = url.searchParams.has('X-Amz-Signature');
    if (!authorization && !presigned) throw new AuthenticationError(401);

    // Reject duplicate/case-confusable credentials and mixed auth schemes.
    const seen = new Set<string>();
    const queryNames = new Set<string>();
    for (const [name] of url.searchParams) {
        // S3 operation parameters are single-valued here. Do not let a client
        // reorder duplicate versionId/uploadId values after canonical signing.
        if (queryNames.has(name)) reject();
        queryNames.add(name);
        if (AUTH_QUERY_PARAMETERS.has(name.toLowerCase())) {
            if (seen.has(name.toLowerCase())) reject();
            seen.add(name.toLowerCase());
            if (!/^X-Amz-(Algorithm|Credential|Date|Expires|SignedHeaders|Signature|Security-Token)$/.test(name)) reject();
        }
    }
    if ((authorization && seen.size > 0) || request.headers.has('x-amz-security-token') || seen.has('x-amz-security-token')) reject();

    let credential: string;
    let signature: string;
    let date: string;
    let names: string[];
    if (presigned) {
        const required = (name: string): string => url.searchParams.get(name) || reject();
        if (required('X-Amz-Algorithm') !== ALGORITHM) reject();
        credential = required('X-Amz-Credential');
        signature = required('X-Amz-Signature');
        date = required('X-Amz-Date');
        names = signedHeaderNames(required('X-Amz-SignedHeaders'));
        const expires = required('X-Amz-Expires');
        if (!/^[1-9]\d*$/.test(expires) || Number(expires) > 604800) reject();
        const time = parseDate(date);
        if (now < time - FUTURE_SKEW_MS || now >= time + Number(expires) * 1000) reject();
    } else {
        if (!authorization?.startsWith(ALGORITHM + ' ')) reject();
        const fields = new Map<string, string>();
        for (const field of authorization.slice(ALGORITHM.length + 1).split(',')) {
            const match = /^\s*(Credential|SignedHeaders|Signature)=([^\s,]+)\s*$/.exec(field);
            if (!match || fields.has(match[1])) reject();
            fields.set(match[1], match[2]);
        }
        if (fields.size !== 3) reject();
        credential = fields.get('Credential')!;
        signature = fields.get('Signature')!;
        names = signedHeaderNames(fields.get('SignedHeaders')!);
        if (!names.includes('x-amz-date')) reject();
        date = request.headers.get('x-amz-date') || reject();
        const time = parseDate(date);
        if (now < time - FUTURE_SKEW_MS || now - time > HEADER_MAX_AGE_MS) reject();
    }

    const scope = /^([^/]+)\/(\d{8})\/([a-z0-9-]+)\/s3\/aws4_request$/.exec(credential);
    if (!scope || scope[1] !== credentials.accessKeyId || scope[2] !== date.slice(0, 8) || !/^[a-f0-9]{64}$/.test(signature)) reject();
    if (request.headers.has('content-md5') && !names.includes('content-md5')) reject();
    for (const [name] of request.headers) {
        if (name.startsWith('x-amz-') && name !== 'x-amz-content-sha256' && name !== 'x-amz-user-agent' && !names.includes(name)) reject();
    }
    const payloadHash = payloadHashFor(request, presigned);
    const canonical = canonicalRequest(request.method, url, request.headers, names, payloadHash, presigned);
    const stringToSign = [ALGORITHM, date, credential.slice(credential.indexOf('/') + 1), await hash(canonical)].join('\n');
    const key = await crypto.subtle.importKey('raw', await signingKey(credentials.secretAccessKey, scope[2], scope[3]), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const bytes = Uint8Array.from(signature.match(/../g)!, value => parseInt(value, 16));
    if (!await crypto.subtle.verify('HMAC', key, bytes, encoder.encode(stringToSign))) reject();
    return { payloadHash };
}

export async function signRequest(method: string, url: URL, headers: Headers, payloadHash: string, credentials: Credentials, region: string, now = new Date()): Promise<Headers> {
    const date = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    headers.set('host', url.host);
    headers.set('x-amz-date', date);
    headers.set('x-amz-content-sha256', payloadHash);
    const names = Array.from(headers.keys()).filter(name => name !== 'authorization' && name !== 'content-length').sort();
    const scope = `${date.slice(0, 8)}/${region}/s3/aws4_request`;
    const canonical = canonicalRequest(method, url, headers, names, payloadHash, false);
    const message = [ALGORITHM, date, scope, await hash(canonical)].join('\n');
    const signature = hex(await hmac(await signingKey(credentials.secretAccessKey, date.slice(0, 8), region), message));
    headers.set('authorization', `${ALGORITHM} Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}`);
    return headers;
}
