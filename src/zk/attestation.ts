import { createPublicKey } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { fromBase64Url, sha256, toBase64Url } from './base64.ts';
import type { UserIdentityClaims, UserKeysRecord } from './types.ts';

const ATTESTATION_AUDIENCE = 'openai-proxy-zk-key';
const ATTESTATION_PURPOSE = 'zk-key-identity-attestation';
const ATTESTATION_TTL_SECONDS = 24 * 60 * 60;
const FINGERPRINT_DOMAIN = 'openai-proxy-user-key-v1\0';

/**
 * Signs identity-to-key statements with a proxy-specific asymmetric
 * signing key. The JWT bearer token is never stored or returned.
 */
export class KeyAttestor {
    private readonly privateKey: string;
    private readonly issuer: string;
    private readonly keyId: string;
    private readonly verificationJwk: Record<string, unknown>;

    constructor(privateKey: string, issuer: string, keyId: string) {
        const publicKey = createPublicKey(privateKey);
        if (publicKey.asymmetricKeyType !== 'rsa'
            || (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
            throw new Error('ZK attestation signing key must be an RSA key of at least 2048 bits');
        }

        const jwk = publicKey.export({ format: 'jwk' });
        this.verificationJwk = {
            ...jwk,
            kid: keyId,
            use: 'sig',
            alg: 'RS256',
            key_ops: ['verify'],
        };
        this.privateKey = privateKey;
        this.issuer = issuer;
        this.keyId = keyId;
    }

    static fromEnvironment(env: NodeJS.ProcessEnv = process.env): KeyAttestor | null {
        const configuredKey = env.ZK_ATTESTATION_PRIVATE_KEY;
        const issuer = env.ZK_ATTESTATION_ISSUER;
        if (!configuredKey && !issuer) return null;
        if (!configuredKey || !issuer) {
            throw new Error('ZK_ATTESTATION_PRIVATE_KEY and ZK_ATTESTATION_ISSUER must be configured together');
        }

        return new KeyAttestor(
            configuredKey.replace(/\\n/g, '\n'),
            issuer,
            env.ZK_ATTESTATION_KEY_ID || 'zk-attestation-1',
        );
    }

    jwks(): { keys: Record<string, unknown>[] } {
        return { keys: [{ ...this.verificationJwk }] };
    }

    issue(record: UserKeysRecord, identityIssuer?: string): string | null {
        const identity = record.identity ?? (identityIssuer
            ? { issuer: identityIssuer, subject: record.userId }
            : null);
        if (!identity || identity.subject !== record.userId) return null;

        return jwt.sign({
            purpose: ATTESTATION_PURPOSE,
            identity,
            key: {
                algorithm: record.publicKeyAlgorithm,
                fingerprint: userKeyFingerprint(record.publicKeyAlgorithm, record.publicKey),
            },
        }, this.privateKey, {
            algorithm: 'RS256',
            keyid: this.keyId,
            issuer: this.issuer,
            subject: identity.subject,
            audience: ATTESTATION_AUDIENCE,
            expiresIn: ATTESTATION_TTL_SECONDS,
            header: { typ: 'zk-key-attestation+jwt' },
        });
    }
}

/** SHA-256 fingerprint already used by the ZK key verification protocol. */
export function userKeyFingerprint(algorithm: string, publicKey: string): string {
    const decodedKey = fromBase64Url(publicKey);
    if (!decodedKey) {
        throw new Error('Cannot fingerprint an invalid base64url public key');
    }

    return toBase64Url(sha256(Buffer.concat([
        Buffer.from(FINGERPRINT_DOMAIN, 'utf8'),
        Buffer.from(algorithm, 'utf8'),
        Buffer.from([0]),
        decodedKey,
    ])));
}

export function identityClaimsFromRequest(
    requestUser: Record<string, unknown> | undefined,
    userId: string,
    fallbackIssuer?: string,
    includeProfile = false,
): UserIdentityClaims | null {
    const issuer = typeof requestUser?.iss === 'string' ? requestUser.iss : fallbackIssuer;
    if (!issuer) return null;

    const identity: UserIdentityClaims = {
        issuer,
        subject: userId,
        observedAt: new Date().toISOString(),
    };
    const copyString = (
        claim: string,
        property: 'name' | 'email' | 'preferredUsername',
        maxLength: number,
    ) => {
        const value = requestUser?.[claim];
        if (typeof value === 'string' && value.length > 0) {
            identity[property] = value.slice(0, maxLength);
        }
    };

    if (includeProfile) {
        copyString('name', 'name', 256);
        copyString('email', 'email', 320);
        copyString('preferred_username', 'preferredUsername', 128);
        if (typeof requestUser?.email_verified === 'boolean') {
            identity.emailVerified = requestUser.email_verified;
        }
    }

    return identity;
}
