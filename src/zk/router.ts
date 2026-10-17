import express from 'express';
import rateLimit from 'express-rate-limit';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { byteLength, randomBytes, toBase64Url } from './base64.ts';
import { identityClaimsFromRequest, KeyAttestor } from './attestation.ts';
import type { EnvelopeAlgorithm, UserKeyAlgorithm, ZkStore } from './types.ts';
import { verifyAssertion } from './webauthn.ts';
import type { WebAuthnConfig } from './webauthn.ts';

const CHALLENGE_BYTES = 32;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const ASSERTION_TTL_MS = 15 * 60 * 1000;

const MAX_CIPHERTEXT_BYTES = 5 * 1024 * 1024;
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
                envelopeAlgorithm: envelope.envelope_algorithm,
                ephemeralPublicKey: envelope.ephemeral_public_key,
                wrappedKey: envelope.wrapped_key,
                wrappedKeyIv: envelope.wrapped_key_iv,
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

    router.put('/chats/:id/attachments/:attachmentId', writeLimiter, route(async (req, res) => {
        const userId = getUserId(req);
        const id = requireId(req.params.id, 'id');
        const attachmentId = requireId(req.params.attachmentId, 'attachmentId');
        const chat = await store.getChat(id);
        if (!chat) {
            throw new ZkError(404, 'not_found', 'Chat not found');
        }
        if (chat.ownerId !== userId) {
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
        if (chat.ownerId !== userId) {
            throw new ZkError(403, 'forbidden', 'Only the owner can delete attachments');
        }

        await store.deleteAttachment(id, attachmentId);
        res.status(204).end();
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
