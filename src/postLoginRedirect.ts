import crypto from 'node:crypto';

/**
 * Default lifetime of the signed OAuth state that carries the post-login
 * return URL. Ten minutes is enough for a browser to complete the login and
 * keeps a stolen/replayed state from being usable indefinitely.
 */
export const RETURN_STATE_TTL_MS = 10 * 60 * 1000;

/**
 * Parse a comma-separated or JSON-array configuration value into a list of
 * trimmed, non-empty strings.
 */
export function parseList(value: string | undefined, fallback: string[] = []): string[] {
    if (!value) {
        return fallback;
    }

    try {
        const parsed = JSON.parse(value);
        if (Array.isArray(parsed)) {
            return parsed.map(String).map(item => item.trim()).filter(Boolean);
        }
    }
    catch {
        // Also accept a comma-separated value for easier deployment configuration.
    }

    return value.split(',').map(item => item.trim()).filter(Boolean);
}

/**
 * Decide where a user should be sent after a successful login.
 *
 * The frontend may rely on the proxy being mounted at a different origin than
 * the one it is served from (staging, development). Such an origin has to be
 * explicitly allow-listed, otherwise the login endpoint would become an open
 * redirect. Relative URLs are resolved against the proxy origin and are always
 * allowed.
 *
 * @returns an absolute URL when the target is allowed, otherwise `/`.
 */
export function resolveReturnUrl(
    rawReturnUrl: string | undefined,
    requestOrigin: string,
    allowedOrigins: string[],
): string {
    if (!rawReturnUrl) {
        return '/';
    }

    let parsed: URL;
    try {
        parsed = new URL(rawReturnUrl, requestOrigin);
    }
    catch {
        return '/';
    }

    if (parsed.origin !== requestOrigin && !allowedOrigins.includes(parsed.origin)) {
        return '/';
    }

    return parsed.toString();
}

const b64urlEncode = (value: string) => Buffer.from(value, 'utf8').toString('base64url');
const b64urlDecode = (value: string) => Buffer.from(value, 'base64url').toString('utf8');

const sign = (payload: string, secret: string) =>
    crypto.createHmac('sha256', secret).update(payload).digest('base64url');

/**
 * Encode the post-login return URL into a signed, self-contained OAuth `state`.
 *
 * Carrying the return URL in `state` (instead of relying on a cookie) makes
 * the login flow work for frontends on a different registrable domain, where
 * the proxy's cookie is rejected by the browser, and across proxy replicas
 * that do not share session storage.
 */
export function createReturnState(
    returnUrl: string,
    secret: string,
    now: number = Date.now(),
): string {
    const payload = b64urlEncode(JSON.stringify({ r: returnUrl, t: now }));
    return `${payload}.${sign(payload, secret)}`;
}

/**
 * Verify a signed state and return the return URL it carries.
 *
 * @returns the return URL, or `undefined` when the state is missing, tampered
 *          with or expired.
 */
export function readReturnState(
    state: unknown,
    secret: string,
    now: number = Date.now(),
): string | undefined {
    if (typeof state !== 'string' || !state.includes('.')) {
        return undefined;
    }

    const separator = state.lastIndexOf('.');
    const payload = state.slice(0, separator);
    const signature = state.slice(separator + 1);
    const expected = sign(payload, secret);

    const signatureBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expected);
    if (signatureBuffer.length !== expectedBuffer.length
        || !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
        return undefined;
    }

    let parsed: { r?: unknown; t?: unknown };
    try {
        parsed = JSON.parse(b64urlDecode(payload));
    }
    catch {
        return undefined;
    }

    if (typeof parsed.r !== 'string' || typeof parsed.t !== 'number') {
        return undefined;
    }

    if (now - parsed.t > RETURN_STATE_TTL_MS) {
        return undefined;
    }

    return parsed.r;
}
