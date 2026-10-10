import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto';

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

export function toBase64Url(input: Buffer | Uint8Array): string {
    return Buffer.from(input).toString('base64url');
}

/**
 * Decode a canonical base64url string. Returns null for anything that is not a
 * well-formed, canonical base64url value so callers can reject malformed input
 * instead of silently accepting garbage.
 */
export function fromBase64Url(value: unknown): Buffer | null {
    if (typeof value !== 'string' || value.length === 0 || !BASE64URL_RE.test(value)) {
        return null;
    }

    const decoded = Buffer.from(value, 'base64url');
    if (decoded.toString('base64url') !== value) {
        return null;
    }

    return decoded;
}

export function byteLength(value: unknown): number | null {
    const decoded = fromBase64Url(value);
    return decoded ? decoded.length : null;
}

export function sha256(input: Buffer | Uint8Array | string): Buffer {
    return createHash('sha256').update(input).digest();
}

export function randomBytes(length: number): Buffer {
    return nodeRandomBytes(length);
}
