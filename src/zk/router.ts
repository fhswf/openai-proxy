import express from 'express';
import rateLimit from 'express-rate-limit';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { byteLength, randomBytes, sha256, toBase64Url } from './base64.ts';
import { identityClaimsFromRequest, KeyAttestor } from './attestation.ts';
import type { GroupChatEpochEnvelope, GroupChatMemberRecord, EnvelopeAlgorithm, UserKeyAlgorithm, ZkStore } from './types.ts';
import { verifyAssertion } from './webauthn.ts';
import type { WebAuthnConfig } from './webauthn.ts';
import type { GroupChatEventBus } from './groupChatEventBus.ts';

const CHALLENGE_BYTES = 32;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const ASSERTION_TTL_MS = 15 * 60 * 1000;

const MAX_CIPHERTEXT_BYTES = 5 * 1024 * 1024;
const MAX_GROUP_CATALOG_BYTES = 2 * 1024 * 1024;
const MAX_GROUP_EVENT_BYTES = 256 * 1024;
const MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024;
const MAX_METADATA_BYTES = 64 * 1024;
// Retain envelopes from the previous RSA-OAEP-4096 client (512 bytes).
const MAX_WRAPPED_KEY_BYTES = 1024;
const MAX_IV_BYTES = 16;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const MAX_PUBLIC_KEY_BYTES = 2048;
// Wrapped PKCS#8 private keys can exceed 2 KiB for RSA-4096 keys.
const MAX_ENCRYPTED_SK_BYTES = 16 * 1024;
const MAX_CREDENTIAL_NAME_LENGTH = 80;
const MAX_ID_LENGTH = 128;
const MAX_GROUP_MEMBERS = 100;
const CHAT_SHARE_LINK_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Error type carrying the HTTP status and machine-readable code from the
 * documented error format so handlers can throw instead of returning early.
 */
class ZkError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(
        status: number,
        code: string,
        message: string,
    ) {
        super(message);
        this.name = 'ZkError';
        this.status = status;
        this.code = code;
    }
}

const sendError = (res: express.Response, status: number, code: string, message: string) => {
    res.status(status).json({ error: { code, message } });
};

const getUserId = (req: express.Request): string => {
    const userId = req['user']?.sub;
    if (!userId || typeof userId !== 'string') {
        throw new ZkError(401, 'unauthenticated', 'Missing authenticated user');
    }

    return userId;
};

/**
 * Validate an opaque base64url field. Callers never see plaintext, so the
 * server only enforces bounds and well-formedness, not cryptographic content.
 */
function requireBase64(
    value: unknown,
    field: string,
    options: { min?: number; max?: number } = {},
): string {
    const length = byteLength(value);
    if (length === null) {
        throw new ZkError(400, 'invalid_payload', `${field} must be a base64url string`);
    }

    if (options.min != null && length < options.min) {
        throw new ZkError(400, 'invalid_payload', `${field} is too short`);
    }

    if (options.max != null && length > options.max) {
        throw new ZkError(413, 'payload_too_large', `${field} is too long`);
    }

    return value as string;
}

function requireOptionalBase64(
    value: unknown,
    field: string,
    options: { min?: number; max?: number } = {},
): string | null {
    if (value == null) {
        return null;
    }

    return requireBase64(value, field, options);
}

function requireUserKeyAlgorithm(
    value: unknown,
    defaultValue: UserKeyAlgorithm = 'RSA-OAEP-SHA256',
): UserKeyAlgorithm {
    if (value == null) return defaultValue;
    if (value === 'RSA-OAEP-SHA256' || value === 'ECDH-P256') return value;
    throw new ZkError(400, 'invalid_payload', 'publicKeyAlgorithm is unsupported');
}

function requireCredentialName(value: unknown): string {
    if (value == null) return 'Passkey';
    if (typeof value !== 'string') {
        throw new ZkError(400, 'invalid_payload', 'credentialName must be a string');
    }

    const name = value.trim();
    if (!name || name.length > MAX_CREDENTIAL_NAME_LENGTH || /[\u0000-\u001f\u007f]/.test(name)) {
        throw new ZkError(400, 'invalid_payload', `credentialName must be 1-${MAX_CREDENTIAL_NAME_LENGTH} printable characters`);
    }

    return name;
}

function requireIdentityProfileDisclosure(value: unknown): boolean {
    if (value == null || value === 'subject') return false;
    if (value === 'profile') return true;
    throw new ZkError(400, 'invalid_payload', 'identityDisclosure must be subject or profile');
}

function requireEnvelopeAlgorithm(value: unknown): EnvelopeAlgorithm {
    // Omitted algorithms identify envelopes written before algorithm metadata
    // was added; those used direct RSA-OAEP wrapping.
    if (value == null || value === 'RSA-OAEP-SHA256') return 'RSA-OAEP-SHA256';
    if (value === 'ECDH-P256-HKDF-SHA256-AES-256-GCM') return value;
    throw new ZkError(400, 'invalid_payload', 'envelopeAlgorithm is unsupported');
}

function requireEnvelope(body: Record<string, unknown>, field: string) {
    const envelopeAlgorithm = requireEnvelopeAlgorithm(body.envelopeAlgorithm);
    const wrappedKey = requireBase64(body.wrappedKey, `${field}.wrappedKey`, {
        min: envelopeAlgorithm === 'ECDH-P256-HKDF-SHA256-AES-256-GCM' ? 48 : 1,
        max: MAX_WRAPPED_KEY_BYTES,
    });

    if (envelopeAlgorithm === 'ECDH-P256-HKDF-SHA256-AES-256-GCM') {
        if (byteLength(wrappedKey) !== 48) {
            throw new ZkError(400, 'invalid_payload', `${field}.wrappedKey must contain a 32-byte AES-GCM key and tag`);
        }

        return {
            envelopeAlgorithm,
            wrappedKey,
            wrappedKeyIv: requireBase64(body.wrappedKeyIv, `${field}.wrappedKeyIv`, { min: 12, max: 12 }),
            ephemeralPublicKey: requireBase64(body.ephemeralPublicKey, `${field}.ephemeralPublicKey`, {
                min: 1,
                max: MAX_PUBLIC_KEY_BYTES,
            }),
        };
    }

    if (body.ephemeralPublicKey != null) {
        throw new ZkError(400, 'invalid_payload', `${field}.ephemeralPublicKey is only valid for ECDH envelopes`);
    }

    return {
        envelopeAlgorithm,
        wrappedKey,
        wrappedKeyIv: requireOptionalBase64(body.wrappedKeyIv, `${field}.wrappedKeyIv`, { max: MAX_IV_BYTES }),
        ephemeralPublicKey: null,
    };
}

function envelopeAlgorithmForKey(algorithm: UserKeyAlgorithm): EnvelopeAlgorithm {
    return algorithm === 'ECDH-P256'
        ? 'ECDH-P256-HKDF-SHA256-AES-256-GCM'
        : 'RSA-OAEP-SHA256';
}

function requireId(value: unknown, field: string): string {
    if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID_LENGTH) {
        throw new ZkError(400, 'invalid_payload', `${field} must be a non-empty string`);
    }

    if (/[\u0000-\u001f]/.test(value)) {
        throw new ZkError(400, 'invalid_payload', `${field} contains invalid characters`);
    }

    return value;
}

export interface ZkRouterOptions {
    store: ZkStore;
    webauthn: WebAuthnConfig;
    /** Optional proxy signing key for identity-to-public-key attestations. */
    attestor?: KeyAttestor | null;
    /** Configured OIDC issuer used for existing key records without saved claims. */
    identityIssuer?: string;
    /** Rate limit for write endpoints, per authenticated user. */
    writeRateLimit?: { windowMs: number; max: number };
    groupChatEventBus?: GroupChatEventBus;
}

export function createZkRouter(options: ZkRouterOptions): express.Router {
    const { store, webauthn } = options;
    const groupChatEventBus = options.groupChatEventBus;
    const router = express.Router();

    const route = (handler: (req: express.Request, res: express.Response) => Promise<void> | void) =>
        (req: express.Request, res: express.Response, next: express.NextFunction) => {
            Promise.resolve()
                .then(() => handler(req, res))
                .catch((err) => {
                    if (err instanceof ZkError) {
                        sendError(res, err.status, err.code, err.message);
                        return;
                    }

                    next(err);
                });
        };

    const writeLimiter = rateLimit({
        windowMs: options.writeRateLimit?.windowMs ?? 60 * 1000,
        max: options.writeRateLimit?.max ?? 120,
        keyGenerator: (req) => req['user']?.sub || req.ip,
        standardHeaders: 'draft-8',
        handler: (_req, res) => sendError(res, 429, 'rate_limited', 'Too many requests'),
    });

    const lookupLimiter = rateLimit({
        windowMs: 10 * 60 * 1000,
        max: 20,
        keyGenerator: (req) => req['user']?.sub || req.ip,
        standardHeaders: 'draft-8',
        handler: (_req, res) => sendError(res, 429, 'rate_limited', 'Too many requests'),
    });

    const shareRedeemLimiter = rateLimit({
        windowMs: 60 * 1000,
        max: 60,
        standardHeaders: 'draft-8',
        handler: (_req, res) => sendError(res, 429, 'rate_limited', 'Too many requests'),
    });

    const now = () => new Date();

    const requireShareTokenHash = (value: unknown): string => {
        const token = requireBase64(value, 'token', { min: 32, max: 32 });
        return sha256(Buffer.from(token, 'base64url')).toString('hex');
    };

    const resolveShareLink = async (tokenHash: string) => {
        const link = await store.getChatShareLink(tokenHash);
        if (!link || link.expiresAt.getTime() <= Date.now()) return null;
        if (await store.getGroupChat(link.chatId)) return null;
        const chat = await store.getChat(link.chatId);
        if (!chat) return null;
        return { link, chat };
    };

    const issueChallenge = async (
        kind: 'registration' | 'assertion',
        credentialId: string | null,
        userId: string | null,
    ): Promise<string> => {
        const challenge = toBase64Url(randomBytes(CHALLENGE_BYTES));
        await store.saveChallenge({
            challenge,
            kind,
            credentialId,
            userId,
            expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
        });
        return challenge;
    };

    // --- User keys -------------------------------------------------------

    router.post('/keys/registration-challenge', writeLimiter, route(async (_req, res) => {
        const challenge = await issueChallenge('registration', null, null);
        res.json({ challenge });
    }));

    router.post('/keys', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const body = req.body ?? {};
        const includeIdentityProfile = requireIdentityProfileDisclosure(body.identityDisclosure);
        const credentialName = requireCredentialName(body.credentialName);

        const credentialId = requireBase64(body.credentialId, 'credentialId', { min: 1, max: MAX_CREDENTIAL_ID_BYTES });
        const credentialPublicKey = requireBase64(body.credentialPublicKey, 'credentialPublicKey', { min: 1, max: MAX_PUBLIC_KEY_BYTES });
        const publicKeyAlgorithm = requireUserKeyAlgorithm(body.publicKeyAlgorithm);
        const publicKey = requireBase64(body.publicKey, 'publicKey', { min: 1, max: MAX_PUBLIC_KEY_BYTES });
        const encryptedSk = requireBase64(body.encryptedSk, 'encryptedSk', { min: 1, max: MAX_ENCRYPTED_SK_BYTES });
        const encryptedSkIv = requireBase64(body.encryptedSkIv, 'encryptedSkIv', { min: 1, max: MAX_IV_BYTES });
        const challenge = requireBase64(body.challenge, 'challenge', { min: 1 });

        const pending = await store.takeChallenge(challenge);
        if (!pending || pending.kind !== 'registration') {
            throw new ZkError(400, 'invalid_payload', 'Invalid or expired challenge');
        }

        const credentialOwner = await store.getUserCredentialById(credentialId);
        if (credentialOwner && credentialOwner.userKeys.userId !== userId) {
            throw new ZkError(409, 'conflict', 'Credential already registered');
        }

        const existing = await store.getUserKeysByUserId(userId);
        if (existing && (existing.publicKeyAlgorithm !== publicKeyAlgorithm || existing.publicKey !== publicKey)) {
            throw new ZkError(409, 'key_mismatch', 'Adding a passkey must keep the existing user public key; use key rotation to replace it');
        }
        const existingCredential = existing?.credentials.find(item => item.credentialId === credentialId);
        const timestamp = now();
        const credential = {
            credentialId,
            name: credentialName,
            credentialPublicKey,
            encryptedSk,
            encryptedSkIv,
            assertedAt: existingCredential?.assertedAt ?? null,
            createdAt: existingCredential?.createdAt ?? timestamp,
            updatedAt: timestamp,
        };
        const record = {
            userId,
            publicKeyAlgorithm,
            publicKey,
            identity: options.attestor
                ? identityClaimsFromRequest(req['user'], userId, options.identityIssuer, includeIdentityProfile)
                : null,
            credentials: [
                ...(existing?.credentials.filter(item => item.credentialId !== credentialId) ?? []),
                credential,
            ],
            createdAt: existing?.createdAt ?? timestamp,
            updatedAt: timestamp,
        };
        await store.upsertUserKeys(record);

        res.status(201).json({
            userId,
            credentialId,
            credentialName,
            createdAt: record.createdAt.toISOString(),
        });
    }));

    router.post('/keys/assertion-challenge', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const body = req.body ?? {};
        const credentialId = requireBase64(body.credentialId, 'credentialId', { min: 1, max: MAX_CREDENTIAL_ID_BYTES });

        const registeredCredential = await store.getUserCredentialById(credentialId);
        if (!registeredCredential || registeredCredential.userKeys.userId !== userId) {
            throw new ZkError(404, 'not_found', 'Unknown credential');
        }

        const challenge = await issueChallenge('assertion', credentialId, userId);
        res.json({ challenge });
    }));

    router.post('/keys/assertion', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const body = req.body ?? {};

        const credentialId = requireBase64(body.credentialId, 'credentialId', { min: 1, max: MAX_CREDENTIAL_ID_BYTES });
        const challenge = requireBase64(body.challenge, 'challenge', { min: 1 });
        const authenticatorData = requireBase64(body.authenticatorData, 'authenticatorData', { min: 37 });
        const clientDataJSON = requireBase64(body.clientDataJSON, 'clientDataJSON', { min: 1 });
        const signature = requireBase64(body.signature, 'signature', { min: 1 });

        const pending = await store.takeChallenge(challenge);
        if (!pending || pending.kind !== 'assertion' || pending.userId !== userId) {
            throw new ZkError(400, 'invalid_payload', 'Invalid or expired challenge');
        }

        if (pending.credentialId !== credentialId) {
            throw new ZkError(400, 'invalid_payload', 'Challenge is bound to a different credential');
        }

        const registeredCredential = await store.getUserCredentialById(credentialId);
        if (!registeredCredential || registeredCredential.userKeys.userId !== userId) {
            throw new ZkError(404, 'not_found', 'No registered keys for this user');
        }

        const verdict = verifyAssertion(
            { credentialId, authenticatorData, clientDataJSON, signature },
            challenge,
            registeredCredential.credential.credentialPublicKey,
            webauthn,
        );

        if (!verdict.ok) {
            throw new ZkError(401, 'unauthenticated', `Assertion rejected: ${verdict.reason}`);
        }

        await store.markAsserted(userId, credentialId, now());
        res.status(204).end();
    }));

    router.get('/keys/me', route(async (req, res) => {
        const userId = getUserId(req);
        const record = await store.getUserKeysByUserId(userId);
        if (!record) {
            throw new ZkError(404, 'not_found', 'No keys registered for this user');
        }

        // Credential IDs and names bootstrap credential selection on a new
        // device. Only the wrapped private key for the most recently asserted
        // credential is released, and only for a short time.
        const timestamp = Date.now();
        const recentlyAsserted = record.credentials
            .filter(credential => credential.assertedAt && timestamp - credential.assertedAt.getTime() <= ASSERTION_TTL_MS)
            .sort((a, b) => (b.assertedAt?.getTime() ?? 0) - (a.assertedAt?.getTime() ?? 0))[0];
        const selectedCredential = recentlyAsserted ?? record.credentials[0];

        res.json({
            userId: record.userId,
            credentialId: selectedCredential?.credentialId ?? null,
            credentialName: selectedCredential?.name ?? null,
            credentials: record.credentials.map(credential => ({
                credentialId: credential.credentialId,
                name: credential.name,
                createdAt: credential.createdAt.toISOString(),
            })),
            publicKeyAlgorithm: record.publicKeyAlgorithm,
            publicKey: record.publicKey,
            identityDisclosure: record.identity?.email ? 'profile' : 'subject',
            identityAttestation: options.attestor?.issue(record, options.identityIssuer) ?? null,
            ...(recentlyAsserted ? {
                encryptedSk: recentlyAsserted.encryptedSk,
                encryptedSkIv: recentlyAsserted.encryptedSkIv,
            } : {}),
        });
    }));

    router.delete('/keys/me', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        await store.deleteUserKeys(userId);
        res.status(204).end();
    }));

    router.patch('/keys/me/identity-disclosure', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const record = await store.getUserKeysByUserId(userId);
        if (!record) throw new ZkError(404, 'not_found', 'No keys registered for this user');

        const includeProfile = requireIdentityProfileDisclosure(req.body?.identityDisclosure);
        const identity = identityClaimsFromRequest(
            req['user'],
            userId,
            options.identityIssuer,
            includeProfile,
        );
        if (!identity) {
            throw new ZkError(503, 'identity_unavailable', 'The identity provider did not supply an issuer');
        }
        await store.updateUserIdentity(userId, identity);
        res.json({ identityDisclosure: includeProfile ? 'profile' : 'subject' });
    }));

    router.patch('/keys/me/credentials/:credentialId', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const credentialId = requireBase64(req.params.credentialId, 'credentialId', { min: 1, max: MAX_CREDENTIAL_ID_BYTES });
        if (req.body?.credentialName == null) {
            throw new ZkError(400, 'invalid_payload', 'credentialName is required');
        }
        const credentialName = requireCredentialName(req.body?.credentialName);
        const record = await store.getUserKeysByUserId(userId);
        if (!record?.credentials.some(item => item.credentialId === credentialId)) {
            throw new ZkError(404, 'not_found', 'Unknown credential');
        }

        await store.renameUserCredential(userId, credentialId, credentialName, now());
        res.json({ credentialId, credentialName });
    }));

    router.delete('/keys/me/credentials/:credentialId', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const credentialId = requireBase64(req.params.credentialId, 'credentialId', { min: 1, max: MAX_CREDENTIAL_ID_BYTES });
        const record = await store.getUserKeysByUserId(userId);
        const credential = record?.credentials.find(item => item.credentialId === credentialId);
        if (!record || !credential) {
            throw new ZkError(404, 'not_found', 'Unknown credential');
        }
        if (record.credentials.length <= 1) {
            throw new ZkError(409, 'last_credential', 'Cannot remove the last passkey; delete the key account instead');
        }

        await store.deleteUserCredential(userId, credentialId);
        res.status(204).end();
    }));

    router.get('/keys/attestation-jwks', route(async (_req, res) => {
        if (!options.attestor) {
            throw new ZkError(503, 'attestation_unavailable', 'Key identity attestations are not configured');
        }

        res.set('Cache-Control', 'public, max-age=300');
        res.json(options.attestor.jwks());
    }));

    router.get('/keys/:userId/public-key', route(async (req, res) => {
        const userId = requireId(req.params.userId, 'userId');
        const record = await store.getUserKeysByUserId(userId);
        if (!record) {
            throw new ZkError(404, 'not_found', 'Unknown user');
        }

        res.json({
            userId: record.userId,
            publicKeyAlgorithm: record.publicKeyAlgorithm,
            publicKey: record.publicKey,
            identityAttestation: options.attestor?.issue(record, options.identityIssuer) ?? null,
        });
    }));

    router.get('/keys/lookup', lookupLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        if (!(await store.getUserKeysByUserId(userId))) {
            throw new ZkError(403, 'forbidden', 'Encrypted chat storage is not enabled');
        }
        const requester = req['user'];
        const email = typeof req.query.email === 'string'
            ? req.query.email.trim().toLowerCase()
            : '';
        if (!email || email.length > 320 || !/^[^@\s]+@[^@\s]+$/.test(email)) {
            throw new ZkError(400, 'invalid_payload', 'email must be a valid email address');
        }

        // Keep lookups within the authenticated user's verified email domain.
        // Returning the same 404 for every miss prevents account enumeration.
        const requesterEmail = typeof requester?.email === 'string' ? requester.email : '';
        const requesterDomain = requesterEmail.split('@').at(-1)?.toLowerCase();
        const requestedDomain = email.split('@').at(-1);
        if (
            requester?.email_verified !== true ||
            !requesterDomain ||
            requesterDomain !== requestedDomain
        ) {
            throw new ZkError(404, 'not_found', 'No discoverable recipient was found');
        }

        const recipient = await store.findUserKeysByEmail(email);
        if (!recipient || recipient.userId === userId) {
            throw new ZkError(404, 'not_found', 'No discoverable recipient was found');
        }
        res.json({
            userId: recipient.userId,
            publicKeyAlgorithm: recipient.publicKeyAlgorithm,
            publicKey: recipient.publicKey,
        });
    }));

    // --- Chats -----------------------------------------------------------

    router.get('/group-catalog', route(async (req, res) => {
        const userId = getUserId(req);
        const catalog = await store.getGroupCatalog(userId);
        if (!catalog) throw new ZkError(404, 'not_found', 'No saved group catalog');
        res.json({
            ciphertext: catalog.ciphertext,
            iv: catalog.iv,
            selfEnvelope: {
                recipientId: userId,
                envelopeAlgorithm: catalog.envelope.envelope_algorithm,
                ephemeralPublicKey: catalog.envelope.ephemeral_public_key,
                wrappedKey: catalog.envelope.wrapped_key,
                wrappedKeyIv: catalog.envelope.wrapped_key_iv,
            },
            rev: catalog.rev,
            updatedAt: catalog.updatedAt.toISOString(),
        });
    }));

    router.put('/group-catalog', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const userKeys = await store.getUserKeysByUserId(userId);
        if (!userKeys) throw new ZkError(403, 'forbidden', 'Encrypted chat storage is not enabled');

        const body = req.body ?? {};
        const ciphertext = requireBase64(body.ciphertext, 'ciphertext', { min: 1, max: MAX_GROUP_CATALOG_BYTES });
        const iv = requireBase64(body.iv, 'iv', { min: 12, max: 12 });
        if (!body.selfEnvelope || typeof body.selfEnvelope !== 'object') {
            throw new ZkError(400, 'invalid_payload', 'selfEnvelope is required');
        }
        if (body.selfEnvelope.recipientId !== userId) {
            throw new ZkError(400, 'invalid_payload', 'selfEnvelope recipientId must match the caller');
        }
        const envelope = requireEnvelope(body.selfEnvelope, 'selfEnvelope');
        if (envelope.envelopeAlgorithm !== envelopeAlgorithmForKey(userKeys.publicKeyAlgorithm)) {
            throw new ZkError(400, 'invalid_payload', 'selfEnvelope algorithm does not match the registered public key');
        }
        const baseRev = body.baseRev == null ? null : Number(body.baseRev);
        if (baseRev != null && (!Number.isSafeInteger(baseRev) || baseRev < 0)) {
            throw new ZkError(400, 'invalid_payload', 'baseRev must be a non-negative integer');
        }

        const result = await store.putGroupCatalog({
            userId,
            ciphertext,
            iv,
            envelope: {
                envelope_algorithm: envelope.envelopeAlgorithm,
                ephemeral_public_key: envelope.ephemeralPublicKey,
                wrapped_key: envelope.wrappedKey,
                wrapped_key_iv: envelope.wrappedKeyIv,
            },
            rev: 0,
            updatedAt: now(),
        }, baseRev);
        if (result === 'conflict') {
            res.status(409).json({ error: { code: 'conflict', message: 'Group catalog changed on another device' } });
            return;
        }
        const saved = await store.getGroupCatalog(userId);
        res.status(result === 'created' ? 201 : 200).json({ rev: saved?.rev ?? 1 });
    }));

    router.post('/chats/:id/group', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const chatId = requireId(req.params.id, 'id');
        const chat = await store.getChat(chatId);
        if (!chat) throw new ZkError(404, 'not_found', 'Chat not found');
        if (chat.ownerId !== userId) throw new ZkError(403, 'forbidden', 'Only the owner can create a group chat');
        if (await store.getGroupChat(chatId)) throw new ZkError(409, 'conflict', 'Chat is already a group chat');

        const body = req.body ?? {};
        const memberIds = body.members;
        if (!Array.isArray(memberIds) || memberIds.length < 2 || memberIds.length > MAX_GROUP_MEMBERS) {
            throw new ZkError(400, 'invalid_payload', `members must contain 2-${MAX_GROUP_MEMBERS} users`);
        }
        const ids = memberIds.map((value, index) => requireId(value, `members[${index}]`));
        if (new Set(ids).size !== ids.length || !ids.includes(userId)) {
            throw new ZkError(400, 'invalid_payload', 'members must be unique and include the chat owner');
        }
        if (!Array.isArray(body.envelopes) || body.envelopes.length !== ids.length) {
            throw new ZkError(400, 'invalid_payload', 'An epoch 1 envelope is required for every member');
        }

        const envelopes: GroupChatEpochEnvelope[] = [];
        const recipients = new Set<string>();
        for (const [index, raw] of body.envelopes.entries()) {
            if (!raw || typeof raw !== 'object') {
                throw new ZkError(400, 'invalid_payload', `envelopes[${index}] must be an object`);
            }
            const recipientId = requireId(raw.recipientId, `envelopes[${index}].recipientId`);
            if (!ids.includes(recipientId) || recipients.has(recipientId)) {
                throw new ZkError(400, 'invalid_payload', 'Each member must have exactly one envelope');
            }
            const recipient = await store.getUserKeysByUserId(recipientId);
            if (!recipient) throw new ZkError(404, 'not_found', `Group member ${recipientId} has no registered keys`);
            const envelope = requireEnvelope(raw, `envelopes[${index}]`);
            if (envelope.envelopeAlgorithm !== envelopeAlgorithmForKey(recipient.publicKeyAlgorithm)) {
                throw new ZkError(400, 'invalid_payload', `Envelope algorithm does not match member ${recipientId}'s key`);
            }
            recipients.add(recipientId);
            envelopes.push({
                recipientId,
                epoch: 1,
                envelope_algorithm: envelope.envelopeAlgorithm,
                ephemeral_public_key: envelope.ephemeralPublicKey,
                wrapped_key: envelope.wrappedKey,
                wrapped_key_iv: envelope.wrappedKeyIv,
                created_at: now(),
            });
        }

        const timestamp = now();
        const record = {
            chatId,
            ownerId: userId,
            currentEpoch: 1,
            committedSequence: 0,
            members: ids.map((memberId): GroupChatMemberRecord => ({
                userId: memberId,
                role: memberId === userId ? 'owner' : 'member',
            })),
            envelopes,
            createdAt: timestamp,
            updatedAt: timestamp,
        };
        const result = await store.createGroupChat(record);
        if (result === 'not_found') throw new ZkError(404, 'not_found', 'Chat not found');
        if (result === 'forbidden') throw new ZkError(403, 'forbidden', 'Only the owner can create a group chat');
        if (result === 'exists') throw new ZkError(409, 'conflict', 'Chat is already a group chat');
        // A capability link created before conversion must not outlive the
        // transition to member-controlled access.
        await store.deleteChatShareLinksForChat(chatId);
        res.status(201).json({ chatId, ownerId: userId, currentEpoch: 1, members: ids });
    }));

    router.get('/chats/:id/group', route(async (req, res) => {
        const userId = getUserId(req);
        const chatId = requireId(req.params.id, 'id');
        const group = await store.getGroupChat(chatId);
        if (!group) throw new ZkError(404, 'not_found', 'Group chat not found');
        if (!group.members.some(member => member.userId === userId)) {
            throw new ZkError(403, 'forbidden', 'No access to this group chat');
        }
        res.json({
            chatId,
            ownerId: group.ownerId,
            currentEpoch: group.currentEpoch,
            cursor: group.committedSequence,
            members: group.members,
            envelopes: group.envelopes
                .filter(envelope => envelope.recipientId === userId)
                .map(envelope => ({
                    epoch: envelope.epoch,
                    envelopeAlgorithm: envelope.envelope_algorithm,
                    ephemeralPublicKey: envelope.ephemeral_public_key,
                    wrappedKey: envelope.wrapped_key,
                    wrappedKeyIv: envelope.wrapped_key_iv,
                })),
        });
    }));

    router.put('/chats/:id/group/membership', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const chatId = requireId(req.params.id, 'id');
        const current = await store.getGroupChat(chatId);
        if (!current) throw new ZkError(404, 'not_found', 'Group chat not found');
        if (current.ownerId !== userId) throw new ZkError(403, 'forbidden', 'Only the owner can change group membership');

        const body = req.body ?? {};
        const baseEpoch = Number(body.baseEpoch);
        if (!Number.isSafeInteger(baseEpoch) || baseEpoch < 1) {
            throw new ZkError(400, 'invalid_payload', 'baseEpoch must be a positive integer');
        }
        if (baseEpoch !== current.currentEpoch) {
            res.status(409).json({ currentEpoch: current.currentEpoch });
            return;
        }
        if (baseEpoch >= Number.MAX_SAFE_INTEGER) {
            throw new ZkError(409, 'conflict', 'Group key epoch limit reached');
        }

        const rawMembers = body.members;
        if (!Array.isArray(rawMembers) || rawMembers.length < 1 || rawMembers.length > MAX_GROUP_MEMBERS) {
            throw new ZkError(400, 'invalid_payload', `members must contain 1-${MAX_GROUP_MEMBERS} users`);
        }
        const memberIds = rawMembers.map((value, index) => requireId(value, `members[${index}]`));
        if (new Set(memberIds).size !== memberIds.length || !memberIds.includes(current.ownerId)) {
            throw new ZkError(400, 'invalid_payload', 'members must be unique and retain the chat owner');
        }
        if (!Array.isArray(body.envelopes)) {
            throw new ZkError(400, 'invalid_payload', 'envelopes must be an array');
        }

        const nextEpoch = baseEpoch + 1;
        const parsed: GroupChatEpochEnvelope[] = [];
        const seen = new Set<string>();
        const hasNextEpochEnvelope = new Set<string>();
        for (const [index, raw] of body.envelopes.entries()) {
            if (!raw || typeof raw !== 'object') {
                throw new ZkError(400, 'invalid_payload', `envelopes[${index}] must be an object`);
            }
            const recipientId = requireId(raw.recipientId, `envelopes[${index}].recipientId`);
            const epoch = Number(raw.epoch);
            if (!memberIds.includes(recipientId)) {
                throw new ZkError(400, 'invalid_payload', 'Envelopes may only be supplied for active members');
            }
            if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > nextEpoch) {
                throw new ZkError(400, 'invalid_payload', 'Envelope epoch is invalid');
            }
            const key = `${recipientId}\u0000${epoch}`;
            if (seen.has(key)) throw new ZkError(400, 'invalid_payload', 'Duplicate member epoch envelope');
            const recipient = await store.getUserKeysByUserId(recipientId);
            if (!recipient) throw new ZkError(404, 'not_found', `Group member ${recipientId} has no registered keys`);
            const envelope = requireEnvelope(raw, `envelopes[${index}]`);
            if (envelope.envelopeAlgorithm !== envelopeAlgorithmForKey(recipient.publicKeyAlgorithm)) {
                throw new ZkError(400, 'invalid_payload', `Envelope algorithm does not match member ${recipientId}'s key`);
            }
            seen.add(key);
            if (epoch === nextEpoch) hasNextEpochEnvelope.add(recipientId);
            parsed.push({
                recipientId,
                epoch,
                envelope_algorithm: envelope.envelopeAlgorithm,
                ephemeral_public_key: envelope.ephemeralPublicKey,
                wrapped_key: envelope.wrappedKey,
                wrapped_key_iv: envelope.wrappedKeyIv,
                created_at: now(),
            });
        }
        if (memberIds.some(memberId => !hasNextEpochEnvelope.has(memberId))) {
            throw new ZkError(400, 'invalid_payload', 'A new epoch envelope is required for every active member');
        }

        const envelopeMap = new Map(current.envelopes.map(envelope => [
            `${envelope.recipientId}\u0000${envelope.epoch}`,
            envelope,
        ]));
        for (const envelope of parsed) {
            envelopeMap.set(`${envelope.recipientId}\u0000${envelope.epoch}`, envelope);
        }
        const timestamp = now();
        const record = {
            ...current,
            currentEpoch: nextEpoch,
            members: memberIds.map((memberId): GroupChatMemberRecord => ({
                userId: memberId,
                role: memberId === current.ownerId ? 'owner' : 'member',
            })),
            envelopes: [...envelopeMap.values()],
            updatedAt: timestamp,
        };
        const result = await store.replaceGroupChatMembership(chatId, userId, baseEpoch, record);
        if (result === 'not_found') throw new ZkError(404, 'not_found', 'Group chat not found');
        if (result === 'forbidden') throw new ZkError(403, 'forbidden', 'Only the owner can change group membership');
        if (result === 'conflict') {
            const latest = await store.getGroupChat(chatId);
            res.status(409).json({ currentEpoch: latest?.currentEpoch ?? null });
            return;
        }
        res.json({ chatId, currentEpoch: nextEpoch, members: memberIds });
    }));

    router.get('/chats/:id/events', route(async (req, res) => {
        const userId = getUserId(req);
        const chatId = requireId(req.params.id, 'id');
        const after = req.query.after == null ? 0 : Number(req.query.after);
        const limit = req.query.limit == null ? 20 : Number(req.query.limit);
        if (!Number.isSafeInteger(after) || after < 0) {
            throw new ZkError(400, 'invalid_payload', 'after must be a non-negative integer cursor');
        }
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 20) {
            throw new ZkError(400, 'invalid_payload', 'limit must be an integer from 1 to 20');
        }
        const events = await store.listGroupChatEvents(chatId, userId, after, limit);
        if (events === null) {
            if (!(await store.getGroupChat(chatId))) throw new ZkError(404, 'not_found', 'Group chat not found');
            throw new ZkError(403, 'forbidden', 'No access to this group chat');
        }
        res.json({ events: events.map(event => ({
            chatId: event.chatId,
            sequence: event.sequence,
            eventId: event.eventId,
            actorId: event.actorId,
            epoch: event.epoch,
            ciphertext: event.ciphertext,
            iv: event.iv,
            createdAt: event.createdAt.toISOString(),
        })), nextCursor: events.at(-1)?.sequence ?? after, hasMore: events.length === limit });
    }));

    router.post('/chats/:id/events', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const chatId = requireId(req.params.id, 'id');
        const body = req.body ?? {};
        const eventId = requireId(body.eventId, 'eventId');
        const epoch = Number(body.epoch);
        if (!Number.isSafeInteger(epoch) || epoch < 1) {
            throw new ZkError(400, 'invalid_payload', 'epoch must be a positive integer');
        }
        const ciphertext = requireBase64(body.ciphertext, 'ciphertext', { min: 1, max: MAX_GROUP_EVENT_BYTES });
        const iv = requireBase64(body.iv, 'iv', { min: 12, max: 12 });
        const result = await store.appendGroupChatEvent({
            chatId,
            eventId,
            actorId: userId,
            epoch,
            ciphertext,
            iv,
            createdAt: now(),
        });
        if (result.status === 'not_found') throw new ZkError(404, 'not_found', 'Group chat not found');
        if (result.status === 'forbidden') throw new ZkError(403, 'forbidden', 'No access to this group chat');
        if (result.status === 'conflict') {
            throw new ZkError(409, 'conflict', 'Group membership or key epoch changed');
        }
        groupChatEventBus?.publish(result.event);
        res.status(result.status === 'created' ? 201 : 200).json({
            chatId,
            eventId,
            sequence: result.event.sequence,
            duplicate: result.status === 'existing',
            createdAt: result.event.createdAt.toISOString(),
        });
    }));

    // A link token is a revocable, seven-day capability. Store only its hash;
    // the client keeps the decryption key in the URL fragment, which browsers
    // never send to this server.
    router.post('/chats/:id/share-link', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        if (await store.getGroupChat(id)) {
            throw new ZkError(409, 'conflict', 'Group chats use member invitations instead of share links');
        }
        const chat = await store.getChat(id);
        if (!chat) throw new ZkError(404, 'not_found', 'Chat not found');
        if (chat.ownerId !== userId) {
            throw new ZkError(403, 'forbidden', 'Only the owner can create a share link');
        }
        if (!(await store.getUserKeysByUserId(userId))) {
            throw new ZkError(403, 'forbidden', 'Encrypted chat storage is not enabled');
        }

        const token = toBase64Url(randomBytes(32));
        const createdAt = now();
        const expiresAt = new Date(createdAt.getTime() + CHAT_SHARE_LINK_TTL_MS);
        const tokenHash = sha256(Buffer.from(token, 'base64url')).toString('hex');
        await store.saveChatShareLink({ tokenHash, chatId: id, ownerId: userId, createdAt, expiresAt });
        res.status(201).json({ token, expiresAt: expiresAt.toISOString() });
    }));

    router.post('/chats/:id/share-link/revoke', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        if (await store.getGroupChat(id)) {
            throw new ZkError(409, 'conflict', 'Group chats do not support share links');
        }
        const tokenHash = requireShareTokenHash((req.body ?? {}).token);
        const chat = await store.getChat(id);
        if (!chat) throw new ZkError(404, 'not_found', 'Chat not found');
        if (chat.ownerId !== userId) {
            throw new ZkError(403, 'forbidden', 'Only the owner can revoke a share link');
        }
        const link = await store.getChatShareLink(tokenHash);
        if (link?.chatId === id && link.ownerId === userId) {
            await store.deleteChatShareLink(tokenHash);
        }
        res.status(204).end();
    }));

    router.post('/public-shares/redeem', shareRedeemLimiter, route(async (req, res) => {
        const tokenHash = requireShareTokenHash((req.body ?? {}).token);
        const resolved = await resolveShareLink(tokenHash);
        if (!resolved) throw new ZkError(404, 'not_found', 'This share link is invalid or expired');
        const { chat } = resolved;
        res.set('Cache-Control', 'no-store').json({
            id: chat.id,
            rev: chat.rev,
            ciphertext: chat.ciphertext,
            iv: chat.iv,
            metadataCt: chat.metadataCt,
            metadataIv: chat.metadataIv,
        });
    }));

    router.post('/public-shares/redeem-attachment', shareRedeemLimiter, route(async (req, res) => {
        const body = req.body ?? {};
        const tokenHash = requireShareTokenHash(body.token);
        const resolved = await resolveShareLink(tokenHash);
        if (!resolved) throw new ZkError(404, 'not_found', 'This share link is invalid or expired');
        const attachmentId = requireId(body.attachmentId, 'attachmentId');
        const attachment = await store.getAttachment(resolved.chat.id, attachmentId);
        if (!attachment) throw new ZkError(404, 'not_found', 'Attachment not found');
        res.status(200)
            .type('application/octet-stream')
            .set('Cache-Control', 'no-store')
            .set('Content-Length', String(attachment.size));
        await pipeline(attachment.stream, res);
    }));

    router.get('/chats', route(async (req, res) => {
        const userId = getUserId(req);
        const chats = await store.listChatsForRecipient(userId);
        res.json(chats.map(chat => ({
            id: chat.id,
            ownerId: chat.ownerId,
            updatedAt: chat.updatedAt.toISOString(),
            rev: chat.rev,
        })));
    }));

    router.get('/chats/:id', route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');

        const chat = await store.getChat(id);
        if (!chat) {
            throw new ZkError(404, 'not_found', 'Chat not found');
        }

        if (!(await store.hasEnvelope(id, userId))) {
            throw new ZkError(403, 'forbidden', 'No access to this chat');
        }

        const group = await store.getGroupChat(id);
        const envelopes = await store.listEnvelopes(id);
        res.json({
            id: chat.id,
            ownerId: chat.ownerId,
            rev: chat.rev,
            ciphertext: chat.ciphertext,
            iv: chat.iv,
            metadataCt: chat.metadataCt,
            metadataIv: chat.metadataIv,
            envelopes: envelopes
                .filter(envelope => !group || envelope.recipient_id === userId)
                .map(envelope => ({
                    recipientId: envelope.recipient_id,
                    envelopeAlgorithm: envelope.envelope_algorithm,
                    ephemeralPublicKey: envelope.ephemeral_public_key,
                    wrappedKey: envelope.wrapped_key,
                    wrappedKeyIv: envelope.wrapped_key_iv,
                    ...(envelope.epoch == null ? {} : { epoch: envelope.epoch }),
                })),
        });
    }));

    router.get('/chats/:id/attachments/:attachmentId', route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        const attachmentId = requireId(req.params.attachmentId, 'attachmentId');
        if (!(await store.hasEnvelope(id, userId))) {
            throw new ZkError(403, 'forbidden', 'No access to this chat');
        }

        const attachment = await store.getAttachment(id, attachmentId);
        if (!attachment) {
            throw new ZkError(404, 'not_found', 'Attachment not found');
        }

        res.status(200)
            .type('application/octet-stream')
            .set('Content-Length', String(attachment.size));
        await pipeline(attachment.stream, res);
    }));

    router.head('/chats/:id/attachments/:attachmentId', route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        const attachmentId = requireId(req.params.attachmentId, 'attachmentId');
        if (!(await store.hasEnvelope(id, userId))) {
            throw new ZkError(403, 'forbidden', 'No access to this chat');
        }
        if (!(await store.hasAttachment(id, attachmentId))) {
            throw new ZkError(404, 'not_found', 'Attachment not found');
        }
        res.status(204).end();
    }));

    router.put('/chats/:id/attachments/:attachmentId', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        const attachmentId = requireId(req.params.attachmentId, 'attachmentId');
        const chat = await store.getChat(id);
        if (!chat) {
            throw new ZkError(404, 'not_found', 'Chat not found');
        }
        const isGroupMember = await store.hasGroupChatMembership(id, userId);
        if (chat.ownerId !== userId && !isGroupMember) {
            throw new ZkError(403, 'forbidden', 'Only the owner can upload attachments');
        }
        if (!req.is('application/octet-stream')) {
            throw new ZkError(415, 'invalid_content_type', 'Attachment data must be application/octet-stream');
        }

        let bytes = 0;
        const limit = new Transform({
            transform(chunk: Buffer, _encoding, callback) {
                bytes += chunk.length;
                if (bytes > MAX_ATTACHMENT_BYTES) {
                    callback(new ZkError(413, 'payload_too_large', 'Attachment is too large'));
                    return;
                }
                callback(null, chunk);
            },
            flush(callback) {
                if (bytes < 28) {
                    callback(new ZkError(400, 'invalid_payload', 'Encrypted attachment is incomplete'));
                    return;
                }
                callback();
            },
        });
        await store.putAttachment(id, attachmentId, req.pipe(limit));
        res.status(204).end();
    }));

    router.delete('/chats/:id/attachments/:attachmentId', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        const attachmentId = requireId(req.params.attachmentId, 'attachmentId');
        const chat = await store.getChat(id);
        if (!chat) {
            throw new ZkError(404, 'not_found', 'Chat not found');
        }
        const isGroupMember = await store.hasGroupChatMembership(id, userId);
        if (chat.ownerId !== userId && !isGroupMember) {
            throw new ZkError(403, 'forbidden', 'Only the owner can delete attachments');
        }

        await store.deleteAttachment(id, attachmentId);
        res.status(204).end();
    }));

    router.put('/chats/:id', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        if (await store.getGroupChat(id)) {
            throw new ZkError(409, 'conflict', 'Use the encrypted group event API to update this chat');
        }
        const body = req.body ?? {};

        const ciphertext = requireBase64(body.ciphertext, 'ciphertext', { min: 1, max: MAX_CIPHERTEXT_BYTES });
        const iv = requireBase64(body.iv, 'iv', { min: 1, max: MAX_IV_BYTES });
        const metadataCt = requireOptionalBase64(body.metadataCt, 'metadataCt', { max: MAX_METADATA_BYTES });
        const metadataIv = requireOptionalBase64(body.metadataIv, 'metadataIv', { max: MAX_IV_BYTES });

        const selfEnvelope = body.selfEnvelope;
        if (!selfEnvelope || typeof selfEnvelope !== 'object') {
            throw new ZkError(400, 'invalid_payload', 'selfEnvelope is required');
        }

        const parsedSelfEnvelope = requireEnvelope(selfEnvelope, 'selfEnvelope');
        const userKeys = await store.getUserKeysByUserId(userId);
        if (userKeys && parsedSelfEnvelope.envelopeAlgorithm !== envelopeAlgorithmForKey(userKeys.publicKeyAlgorithm)) {
            throw new ZkError(400, 'invalid_payload', 'selfEnvelope algorithm does not match the registered public key');
        }

        const baseRev = body.baseRev == null ? null : Number(body.baseRev);
        if (baseRev != null && (!Number.isInteger(baseRev) || baseRev < 0)) {
            throw new ZkError(400, 'invalid_payload', 'baseRev must be a non-negative integer');
        }

        const existing = await store.getChat(id);
        if (existing && existing.ownerId !== userId) {
            throw new ZkError(403, 'forbidden', 'Only the owner can overwrite a chat');
        }

        const timestamp = now();
        const selfEnvelopeRecord = {
            chat_id: id,
            recipient_id: userId,
            envelope_algorithm: parsedSelfEnvelope.envelopeAlgorithm,
            ephemeral_public_key: parsedSelfEnvelope.ephemeralPublicKey,
            wrapped_key: parsedSelfEnvelope.wrappedKey,
            wrapped_key_iv: parsedSelfEnvelope.wrappedKeyIv,
            is_owner: true,
            created_at: timestamp,
        };

        const outcome = await store.upsertChat(
            {
                id,
                ownerId: existing?.ownerId ?? userId,
                ciphertext,
                iv,
                metadataCt,
                metadataIv,
                rev: existing?.rev ?? 1,
                createdAt: existing?.createdAt ?? timestamp,
                updatedAt: timestamp,
            },
            selfEnvelopeRecord,
            baseRev,
        );

        if (outcome === 'conflict') {
            const current = await store.getChat(id);
            res.status(409).json({ currentRev: current?.rev ?? null });
            return;
        }

        res.status(outcome === 'created' ? 201 : 200).json({
            id,
            rev: outcome === 'created' ? 1 : (await store.getChat(id))?.rev ?? 1,
        });
    }));

    router.post('/chats/:id/share', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        if (await store.getGroupChat(id)) {
            throw new ZkError(409, 'conflict', 'Use the group membership endpoint to share a group chat');
        }
        const body = req.body ?? {};

        const recipientId = requireId(body.recipientId, 'recipientId');
        const parsedEnvelope = requireEnvelope(body, 'body');

        if (!(await store.hasEnvelope(id, userId))) {
            throw new ZkError(403, 'forbidden', 'Caller has no key for this chat');
        }

        const recipient = await store.getUserKeysByUserId(recipientId);
        if (!recipient) {
            throw new ZkError(404, 'not_found', 'Recipient has no registered keys');
        }
        if (parsedEnvelope.envelopeAlgorithm !== envelopeAlgorithmForKey(recipient.publicKeyAlgorithm)) {
            throw new ZkError(400, 'invalid_payload', 'Envelope algorithm does not match the recipient public key');
        }

        const chat = await store.getChat(id);
        if (!chat) {
            throw new ZkError(404, 'not_found', 'Chat not found');
        }

        await store.upsertEnvelope({
            chat_id: id,
            recipient_id: recipientId,
            envelope_algorithm: parsedEnvelope.envelopeAlgorithm,
            ephemeral_public_key: parsedEnvelope.ephemeralPublicKey,
            wrapped_key: parsedEnvelope.wrappedKey,
            wrapped_key_iv: parsedEnvelope.wrappedKeyIv,
            is_owner: recipientId === chat.ownerId,
            created_at: now(),
        });

        res.status(201).json({ recipientId });
    }));

    router.post('/chats/:id/revoke', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        if (await store.getGroupChat(id)) {
            throw new ZkError(409, 'conflict', 'Use the group membership endpoint to revoke group chat access');
        }
        const recipientId = requireId((req.body ?? {}).recipientId, 'recipientId');

        const chat = await store.getChat(id);
        if (!chat) {
            throw new ZkError(404, 'not_found', 'Chat not found');
        }

        if (chat.ownerId !== userId) {
            throw new ZkError(403, 'forbidden', 'Only the owner can revoke access');
        }

        if (recipientId === chat.ownerId) {
            throw new ZkError(400, 'invalid_payload', 'Owner cannot revoke their own access');
        }

        await store.deleteEnvelope(id, recipientId);
        res.status(204).end();
    }));

    router.delete('/chats/:id', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');

        const chat = await store.getChat(id);
        if (!chat) {
            throw new ZkError(404, 'not_found', 'Chat not found');
        }

        if (chat.ownerId !== userId) {
            throw new ZkError(403, 'forbidden', 'Only the owner can delete a chat');
        }

        await store.deleteChat(id);
        res.status(204).end();
    }));

    // --- Rotation --------------------------------------------------------

    router.post('/keys/rotate', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const body = req.body ?? {};
        const includeIdentityProfile = requireIdentityProfileDisclosure(body.identityDisclosure);
        const credentialName = requireCredentialName(body.credentialName);

        const credentialId = requireBase64(body.credentialId, 'credentialId', { min: 1, max: MAX_CREDENTIAL_ID_BYTES });
        const credentialPublicKey = requireBase64(body.credentialPublicKey, 'credentialPublicKey', { min: 1, max: MAX_PUBLIC_KEY_BYTES });
        const publicKey = requireBase64(body.publicKey, 'publicKey', { min: 1, max: MAX_PUBLIC_KEY_BYTES });
        const encryptedSk = requireBase64(body.encryptedSk, 'encryptedSk', { min: 1, max: MAX_ENCRYPTED_SK_BYTES });
        const encryptedSkIv = requireBase64(body.encryptedSkIv, 'encryptedSkIv', { min: 1, max: MAX_IV_BYTES });
        const challenge = requireBase64(body.challenge, 'challenge', { min: 1 });

        const pending = await store.takeChallenge(challenge);
        if (!pending || pending.kind !== 'registration') {
            throw new ZkError(400, 'invalid_payload', 'Invalid or expired challenge');
        }

        const existing = await store.getUserKeysByUserId(userId);
        if (!existing) {
            throw new ZkError(404, 'not_found', 'No keys registered for this user');
        }
        const publicKeyAlgorithm = requireUserKeyAlgorithm(body.publicKeyAlgorithm, existing.publicKeyAlgorithm);

        const credentialOwner = await store.getUserCredentialById(credentialId);
        if (credentialOwner && credentialOwner.userKeys.userId !== userId) {
            throw new ZkError(409, 'conflict', 'Credential already registered');
        }

        await store.upsertUserKeys({
            ...existing,
            publicKeyAlgorithm,
            publicKey,
            identity: options.attestor
                ? identityClaimsFromRequest(req['user'], userId, options.identityIssuer, includeIdentityProfile)
                : null,
            // Rotation replaces the user's key and therefore starts with one
            // credential wrapper for the new key material.
            credentials: [{
                credentialId,
                name: credentialName,
                credentialPublicKey,
                encryptedSk,
                encryptedSkIv,
                assertedAt: null,
                createdAt: now(),
                updatedAt: now(),
            }],
            updatedAt: now(),
        });

        res.status(204).end();
    }));

    return router;
}

export { ZkError };
