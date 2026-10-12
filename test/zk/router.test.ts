import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import http from 'node:http';
import express from 'express';
import { createZkRouter } from '../../src/zk/router.ts';
import { MemoryZkStore } from '../../src/zk/memoryStore.ts';
import { createAssertion, createCredential, fakeCiphertext } from './helpers.ts';

const RP_ID = 'vault.example.org';
const ORIGIN = 'https://app.example.org';

// Credential ids must be canonical base64url, matching what a browser produces.
const credId = (value: string) => Buffer.from(value, 'utf8').toString('base64url');

interface TestServer {
    url: string;
    close: () => Promise<void>;
}

function startServer(asUser: (req: express.Request) => string | null): Promise<TestServer> {
    const app = express();
    app.use(express.json({ limit: '10mb' }));
    app.use((req, _res, next) => {
        const user = asUser(req);
        if (user) {
            req['user'] = { sub: user };
        }
        next();
    });
    app.use('/api/zk', createZkRouter({
        store: new MemoryZkStore(),
        webauthn: { rpId: RP_ID, origins: [ORIGIN] },
        writeRateLimit: { windowMs: 60_000, max: 10_000 },
    }));
    app.use((err, _req, res, _next) => {
        res.status(500).json({ error: { code: 'internal', message: String(err) } });
    });

    // Route the authenticated user from a header so tests can switch identity.
    const server = http.createServer(app);
    return new Promise((resolve) => {
        server.listen(0, () => {
            const address = server.address();
            const port = typeof address === 'object' && address ? address.port : 0;
            resolve({
                url: `http://127.0.0.1:${port}`,
                close: () => new Promise<void>((done) => server.close(() => done())),
            });
        });
    });
}

let server: TestServer;

before(async () => {
    server = await startServer((req) => (req.headers['x-test-user'] as string) || null);
});

after(async () => {
    await server.close();
});

async function call(
    method: string,
    path: string,
    options: { user?: string; body?: unknown } = {},
): Promise<{ status: number; body: any }> {
    const headers: Record<string, string> = {};
    if (options.user) {
        headers['x-test-user'] = options.user;
    }
    if (options.body !== undefined) {
        headers['content-type'] = 'application/json';
    }

    const response = await fetch(`${server.url}${path}`, {
        method,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });

    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function registerUser(user: string, credentialId: string) {
    const credential = createCredential();
    const challengeResponse = await call('POST', '/api/zk/keys/registration-challenge', { user });
    assert.equal(challengeResponse.status, 200);

    const registration = await call('POST', '/api/zk/keys', {
        user,
        body: {
            credentialId,
            publicKey: credential.publicKey,
            encryptedSk: fakeCiphertext(128),
            encryptedSkIv: fakeCiphertext(12),
            challenge: challengeResponse.body.challenge,
        },
    });
    assert.equal(registration.status, 201);
    return credential;
}

async function assertUser(user: string, credentialId: string, credential: ReturnType<typeof createCredential>) {
    const challengeResponse = await call('POST', '/api/zk/keys/assertion-challenge', {
        user,
        body: { credentialId },
    });
    assert.equal(challengeResponse.status, 200);

    const assertion = createAssertion({
        credentialId,
        challenge: challengeResponse.body.challenge,
        rpId: RP_ID,
        origin: ORIGIN,
        privateKey: credential.privateKey,
    });

    return call('POST', '/api/zk/keys/assertion', {
        user,
        body: { ...assertion, challenge: challengeResponse.body.challenge },
    });
}

const chatBody = () => ({
    ciphertext: fakeCiphertext(256),
    iv: fakeCiphertext(12),
    metadataCt: fakeCiphertext(48),
    metadataIv: fakeCiphertext(12),
    selfEnvelope: { wrappedKey: fakeCiphertext(256), wrappedKeyIv: fakeCiphertext(12) },
});

describe('zk router', () => {
    it('requires authentication', async () => {
        const response = await call('GET', '/api/zk/chats');
        assert.equal(response.status, 401);
        assert.equal(response.body.error.code, 'unauthenticated');
    });

    it('registers keys and releases the wrapped SK only after an assertion', async () => {
        const credential = await registerUser('alice', credId('cred-alice'));

        const before = await call('GET', '/api/zk/keys/me', { user: 'alice' });
        assert.equal(before.status, 200, 'metadata is available to bootstrap a new device');
        assert.equal(before.body.credentialId, credId('cred-alice'));
        assert.equal(before.body.encryptedSk, undefined, 'wrapped SK is locked before an assertion');

        const assertion = await assertUser('alice', credId('cred-alice'), credential);
        assert.equal(assertion.status, 204);

        const after = await call('GET', '/api/zk/keys/me', { user: 'alice' });
        assert.equal(after.status, 200);
        assert.equal(after.body.encryptedSk, fakeCiphertext(128));
        assert.equal(after.body.encryptedSkIv, fakeCiphertext(12));

        const publicKey = await call('GET', '/api/zk/keys/alice/public-key', { user: 'bob' });
        assert.equal(publicKey.status, 200);
        assert.equal(publicKey.body.publicKey, credential.publicKey);
        assert.equal(publicKey.body.encryptedSk, undefined);
    });

    it('rejects a replayed or mismatched assertion challenge', async () => {
        const credential = await registerUser('replay-user', credId('cred-replay'));

        const challengeResponse = await call('POST', '/api/zk/keys/assertion-challenge', {
            user: 'replay-user',
            body: { credentialId: credId('cred-replay') },
        });
        const assertion = createAssertion({
            credentialId: credId('cred-replay'),
            challenge: challengeResponse.body.challenge,
            rpId: RP_ID,
            origin: ORIGIN,
            privateKey: credential.privateKey,
        });

        const body = { ...assertion, challenge: challengeResponse.body.challenge };
        const first = await call('POST', '/api/zk/keys/assertion', { user: 'replay-user', body });
        assert.equal(first.status, 204);

        const second = await call('POST', '/api/zk/keys/assertion', { user: 'replay-user', body });
        assert.equal(second.status, 400, 'challenges are single-use');
    });

    it('rejects an assertion signed for a wrong origin or rp id', async () => {
        const credential = await registerUser('tamper-user', credId('cred-tamper'));

        const badOriginChallenge = await call('POST', '/api/zk/keys/assertion-challenge', {
            user: 'tamper-user',
            body: { credentialId: credId('cred-tamper') },
        });
        const badOrigin = createAssertion({
            credentialId: credId('cred-tamper'),
            challenge: badOriginChallenge.body.challenge,
            rpId: RP_ID,
            origin: 'https://evil.example.org',
            privateKey: credential.privateKey,
        });
        const originResult = await call('POST', '/api/zk/keys/assertion', {
            user: 'tamper-user',
            body: { ...badOrigin, challenge: badOriginChallenge.body.challenge },
        });
        assert.equal(originResult.status, 401);

        const badRpChallenge = await call('POST', '/api/zk/keys/assertion-challenge', {
            user: 'tamper-user',
            body: { credentialId: credId('cred-tamper') },
        });
        // Sign over a different rpIdHash than the server expects.
        const wrongRp = createAssertion({
            credentialId: credId('cred-tamper'),
            challenge: badRpChallenge.body.challenge,
            rpId: 'other.example.org',
            origin: ORIGIN,
            privateKey: credential.privateKey,
        });
        const rpResult = await call('POST', '/api/zk/keys/assertion', {
            user: 'tamper-user',
            body: { ...wrongRp, challenge: badRpChallenge.body.challenge },
        });
        assert.equal(rpResult.status, 401);
    });

    it('stores, lists, restores and versions a chat', async () => {
        await registerUser('owner', credId('cred-owner'));

        const create = await call('PUT', '/api/zk/chats/chat-1', {
            user: 'owner',
            body: chatBody(),
        });
        assert.equal(create.status, 201);
        assert.equal(create.body.rev, 1);

        const list = await call('GET', '/api/zk/chats', { user: 'owner' });
        assert.equal(list.body.length, 1);
        assert.equal(list.body[0].id, 'chat-1');
        assert.equal(list.body[0].ciphertext, undefined, 'list omits ciphertext');

        const get = await call('GET', '/api/zk/chats/chat-1', { user: 'owner' });
        assert.equal(get.status, 200);
        assert.equal(get.body.ciphertext, chatBody().ciphertext);
        assert.equal(get.body.envelopes.length, 1);
        assert.equal(get.body.envelopes[0].recipientId, 'owner');

        const update = await call('PUT', '/api/zk/chats/chat-1', {
            user: 'owner',
            body: { ...chatBody(), baseRev: 1 },
        });
        assert.equal(update.status, 200);
        assert.equal(update.body.rev, 2);

        const conflict = await call('PUT', '/api/zk/chats/chat-1', {
            user: 'owner',
            body: { ...chatBody(), baseRev: 1 },
        });
        assert.equal(conflict.status, 409);
        assert.equal(conflict.body.currentRev, 2);
    });

    it('shares a chat and enforces access control', async () => {
        const ownerCred = await registerUser('owner2', credId('cred-owner2'));
        await registerUser('bob', credId('cred-bob'));

        await call('PUT', '/api/zk/chats/chat-share', { user: 'owner2', body: chatBody() });

        // Bob cannot read before sharing.
        const denied = await call('GET', '/api/zk/chats/chat-share', { user: 'bob' });
        assert.equal(denied.status, 403);

        const share = await call('POST', '/api/zk/chats/chat-share/share', {
            user: 'owner2',
            body: {
                recipientId: 'bob',
                wrappedKey: fakeCiphertext(256),
                wrappedKeyIv: fakeCiphertext(12),
            },
        });
        assert.equal(share.status, 201);

        const bobGet = await call('GET', '/api/zk/chats/chat-share', { user: 'bob' });
        assert.equal(bobGet.status, 200);
        assert.equal(bobGet.body.envelopes.length, 2);

        // A user without an envelope cannot share.
        await registerUser('mallory', credId('cred-mallory'));
        const malloryShare = await call('POST', '/api/zk/chats/chat-share/share', {
            user: 'mallory',
            body: {
                recipientId: 'bob',
                wrappedKey: fakeCiphertext(256),
                wrappedKeyIv: fakeCiphertext(12),
            },
        });
        assert.equal(malloryShare.status, 403);

        // Revoke removes Bob's access.
        const revoke = await call('POST', '/api/zk/chats/chat-share/revoke', {
            user: 'owner2',
            body: { recipientId: 'bob' },
        });
        assert.equal(revoke.status, 204);
        const afterRevoke = await call('GET', '/api/zk/chats/chat-share', { user: 'bob' });
        assert.equal(afterRevoke.status, 403);

        // Only the owner may delete.
        const bobDelete = await call('DELETE', '/api/zk/chats/chat-share', { user: 'bob' });
        assert.equal(bobDelete.status, 403);
        const ownerDelete = await call('DELETE', '/api/zk/chats/chat-share', { user: 'owner2' });
        assert.equal(ownerDelete.status, 204);
        assert.ok(ownerCred.publicKey);
    });

    it('returns 413 for oversized ciphertext and 400 for malformed payloads', async () => {
        await registerUser('sizelord', credId('cred-size'));

        const tooLarge = await call('PUT', '/api/zk/chats/chat-big', {
            user: 'sizelord',
            body: { ...chatBody(), ciphertext: Buffer.alloc(6 * 1024 * 1024).toString('base64url') },
        });
        assert.equal(tooLarge.status, 413);
        assert.equal(tooLarge.body.error.code, 'payload_too_large');

        const malformed = await call('PUT', '/api/zk/chats/chat-bad', {
            user: 'sizelord',
            body: { ...chatBody(), iv: 'not base64!' },
        });
        assert.equal(malformed.status, 400);
        assert.equal(malformed.body.error.code, 'invalid_payload');
    });

    it('rotates keys without invalidating existing chats', async () => {
        const credential = await registerUser('rotator', credId('cred-rotate'));
        await call('PUT', '/api/zk/chats/chat-rotate', { user: 'rotator', body: chatBody() });

        const newCredential = createCredential();
        const challengeResponse = await call('POST', '/api/zk/keys/registration-challenge', { user: 'rotator' });
        const rotation = await call('POST', '/api/zk/keys/rotate', {
            user: 'rotator',
            body: {
                credentialId: credId('cred-rotate-2'),
                publicKey: newCredential.publicKey,
                encryptedSk: fakeCiphertext(128),
                encryptedSkIv: fakeCiphertext(12),
                challenge: challengeResponse.body.challenge,
            },
        });
        assert.equal(rotation.status, 204);

        const me = await call('GET', '/api/zk/keys/me', { user: 'rotator' });
        // Rotation installs a new credential; the wrapped SK is locked until the
        // new credential asserts.
        assert.equal(me.status, 200);
        assert.equal(me.body.credentialId, credId('cred-rotate-2'));
        assert.equal(me.body.encryptedSk, undefined);

        const challengeResponse2 = await call('POST', '/api/zk/keys/assertion-challenge', {
            user: 'rotator',
            body: { credentialId: credId('cred-rotate-2') },
        });
        const assertion = createAssertion({
            credentialId: credId('cred-rotate-2'),
            challenge: challengeResponse2.body.challenge,
            rpId: RP_ID,
            origin: ORIGIN,
            privateKey: newCredential.privateKey,
        });
        await call('POST', '/api/zk/keys/assertion', {
            user: 'rotator',
            body: { ...assertion, challenge: challengeResponse2.body.challenge },
        });

        const get = await call('GET', '/api/zk/chats/chat-rotate', { user: 'rotator' });
        assert.equal(get.status, 200);
        assert.ok(credential.publicKey);
    });
});
