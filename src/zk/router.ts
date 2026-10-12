import express from 'express';
import rateLimit from 'express-rate-limit';
import { byteLength, randomBytes, toBase64Url } from './base64.ts';
import type { ZkStore } from './types.ts';
import { verifyAssertion } from './webauthn.ts';
import type { WebAuthnConfig } from './webauthn.ts';

const CHALLENGE_BYTES = 32;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const ASSERTION_TTL_MS = 15 * 60 * 1000;

const MAX_CIPHERTEXT_BYTES = 5 * 1024 * 1024;
const MAX_METADATA_BYTES = 64 * 1024;
const MAX_WRAPPED_KEY_BYTES = 256;
const MAX_IV_BYTES = 16;
const MAX_CREDENTIAL_ID_BYTES = 1024;
const MAX_PUBLIC_KEY_BYTES = 2048;
const MAX_ENCRYPTED_SK_BYTES = 2048;
const MAX_ID_LENGTH = 128;

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
    /** Rate limit for write endpoints, per authenticated user. */
    writeRateLimit?: { windowMs: number; max: number };
}

export function createZkRouter(options: ZkRouterOptions): express.Router {
    const { store, webauthn } = options;
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

    const now = () => new Date();

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

        const credentialOwner = await store.getUserKeysByCredentialId(credentialId);
        if (credentialOwner && credentialOwner.userId !== userId) {
            throw new ZkError(409, 'conflict', 'Credential already registered');
        }

        const existing = await store.getUserKeysByUserId(userId);
        await store.upsertUserKeys({
            userId,
            credentialId,
            credentialPublicKey,
            publicKey,
            encryptedSk,
            encryptedSkIv,
            // Registration alone never unlocks encryptedSk; a WebAuthn
            // assertion is required before the wrapped key can be fetched.
            assertedAt:
                existing?.credentialId === credentialId
                    ? existing.assertedAt
                    : null,
            createdAt: existing?.createdAt ?? now(),
            updatedAt: now(),
        });

        res.status(201).json({ userId, createdAt: (existing?.createdAt ?? now()).toISOString() });
    }));

    router.post('/keys/assertion-challenge', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const body = req.body ?? {};
        const credentialId = requireBase64(body.credentialId, 'credentialId', { min: 1, max: MAX_CREDENTIAL_ID_BYTES });

        const record = await store.getUserKeysByCredentialId(credentialId);
        if (!record || record.userId !== userId) {
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

        const record = await store.getUserKeysByUserId(userId);
        if (!record || record.credentialId !== credentialId) {
            throw new ZkError(404, 'not_found', 'No registered keys for this user');
        }

        const verdict = verifyAssertion(
            { credentialId, authenticatorData, clientDataJSON, signature },
            challenge,
            record.credentialPublicKey,
            webauthn,
        );

        if (!verdict.ok) {
            throw new ZkError(401, 'unauthenticated', `Assertion rejected: ${verdict.reason}`);
        }

        await store.markAsserted(userId, now());
        res.status(204).end();
    }));

    router.get('/keys/me', route(async (req, res) => {
        const userId = getUserId(req);
        const record = await store.getUserKeysByUserId(userId);
        if (!record) {
            throw new ZkError(404, 'not_found', 'No keys registered for this user');
        }

        // credentialId and publicKey are needed to bootstrap an assertion on a
        // new device. The wrapped private key, however, is only released after a
        // recent WebAuthn assertion; otherwise it could be fetched and attacked
        // offline.
        const assertedAt = record.assertedAt?.getTime() ?? 0;
        const unlocked = Date.now() - assertedAt <= ASSERTION_TTL_MS;

        res.json({
            userId: record.userId,
            credentialId: record.credentialId,
            publicKey: record.publicKey,
            ...(unlocked ? {
                encryptedSk: record.encryptedSk,
                encryptedSkIv: record.encryptedSkIv,
            } : {}),
        });
    }));

    router.delete('/keys/me', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        await store.deleteUserKeys(userId);
        res.status(204).end();
    }));

    router.get('/keys/:userId/public-key', route(async (req, res) => {
        const userId = requireId(req.params.userId, 'userId');
        const record = await store.getUserKeysByUserId(userId);
        if (!record) {
            throw new ZkError(404, 'not_found', 'Unknown user');
        }

        res.json({ userId: record.userId, publicKey: record.publicKey });
    }));

    // --- Chats -----------------------------------------------------------

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

        const envelopes = await store.listEnvelopes(id);
        res.json({
            id: chat.id,
            ownerId: chat.ownerId,
            rev: chat.rev,
            ciphertext: chat.ciphertext,
            iv: chat.iv,
            metadataCt: chat.metadataCt,
            metadataIv: chat.metadataIv,
            envelopes: envelopes.map(envelope => ({
                recipientId: envelope.recipient_id,
                wrappedKey: envelope.wrapped_key,
                wrappedKeyIv: envelope.wrapped_key_iv,
            })),
        });
    }));

    router.put('/chats/:id', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        const body = req.body ?? {};

        const ciphertext = requireBase64(body.ciphertext, 'ciphertext', { min: 1, max: MAX_CIPHERTEXT_BYTES });
        const iv = requireBase64(body.iv, 'iv', { min: 1, max: MAX_IV_BYTES });
        const metadataCt = requireOptionalBase64(body.metadataCt, 'metadataCt', { max: MAX_METADATA_BYTES });
        const metadataIv = requireOptionalBase64(body.metadataIv, 'metadataIv', { max: MAX_IV_BYTES });

        const selfEnvelope = body.selfEnvelope;
        if (!selfEnvelope || typeof selfEnvelope !== 'object') {
            throw new ZkError(400, 'invalid_payload', 'selfEnvelope is required');
        }

        const wrappedKey = requireBase64(selfEnvelope.wrappedKey, 'selfEnvelope.wrappedKey', { min: 1, max: MAX_WRAPPED_KEY_BYTES });
        const wrappedKeyIv = requireOptionalBase64(selfEnvelope.wrappedKeyIv, 'selfEnvelope.wrappedKeyIv', { max: MAX_IV_BYTES });

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
            wrapped_key: wrappedKey,
            wrapped_key_iv: wrappedKeyIv,
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
        const body = req.body ?? {};

        const recipientId = requireId(body.recipientId, 'recipientId');
        const wrappedKey = requireBase64(body.wrappedKey, 'wrappedKey', { min: 1, max: MAX_WRAPPED_KEY_BYTES });
        const wrappedKeyIv = requireOptionalBase64(body.wrappedKeyIv, 'wrappedKeyIv', { max: MAX_IV_BYTES });

        if (!(await store.hasEnvelope(id, userId))) {
            throw new ZkError(403, 'forbidden', 'Caller has no key for this chat');
        }

        const recipient = await store.getUserKeysByUserId(recipientId);
        if (!recipient) {
            throw new ZkError(404, 'not_found', 'Recipient has no registered keys');
        }

        const chat = await store.getChat(id);
        if (!chat) {
            throw new ZkError(404, 'not_found', 'Chat not found');
        }

        await store.upsertEnvelope({
            chat_id: id,
            recipient_id: recipientId,
            wrapped_key: wrappedKey,
            wrapped_key_iv: wrappedKeyIv,
            is_owner: recipientId === chat.ownerId,
            created_at: now(),
        });

        res.status(201).json({ recipientId });
    }));

    router.post('/chats/:id/revoke', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
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

        const credentialOwner = await store.getUserKeysByCredentialId(credentialId);
        if (credentialOwner && credentialOwner.userId !== userId) {
            throw new ZkError(409, 'conflict', 'Credential already registered');
        }

        await store.upsertUserKeys({
            ...existing,
            credentialId,
            credentialPublicKey,
            publicKey,
            encryptedSk,
            encryptedSkIv,
            assertedAt: null,
            updatedAt: now(),
        });

        res.status(204).end();
    }));

    return router;
}

export { ZkError };
