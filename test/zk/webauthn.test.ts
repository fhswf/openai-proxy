import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { hasPrfExtensionFlag, verifyAssertion } from '../../src/zk/webauthn.ts';
import { sha256, toBase64Url } from '../../src/zk/base64.ts';
import { createAssertion, createCredential } from './helpers.ts';

const RP_ID = 'vault.example.org';
const ORIGIN = 'https://app.example.org';
const CONFIG = { rpId: RP_ID, origins: [ORIGIN] };

describe('webauthn', () => {
    it('reports PRF support from the authenticator extension flag', () => {
        const authDataWithEd = Buffer.concat([sha256(RP_ID), Buffer.from([0x01 | 0x80]), Buffer.alloc(4)]);
        const authDataWithoutEd = Buffer.concat([sha256(RP_ID), Buffer.from([0x01]), Buffer.alloc(4)]);

        assert.equal(hasPrfExtensionFlag(toBase64Url(authDataWithEd)), true);
        assert.equal(hasPrfExtensionFlag(toBase64Url(authDataWithoutEd)), false);
    });

    it('accepts a valid assertion', () => {
        const credential = createCredential();
        const challenge = toBase64Url(Buffer.alloc(32, 3));
        const assertion = createAssertion({
            credentialId: 'ignored',
            challenge,
            rpId: RP_ID,
            origin: ORIGIN,
            privateKey: credential.privateKey,
        });

        const verdict = verifyAssertion(assertion, challenge, credential.publicKey, CONFIG);
        assert.equal(verdict.ok, true, verdict.reason);
    });

    it('rejects a tampered signature', () => {
        const credential = createCredential();
        const challenge = toBase64Url(Buffer.alloc(32, 4));
        const assertion = createAssertion({
            credentialId: 'ignored',
            challenge,
            rpId: RP_ID,
            origin: ORIGIN,
            privateKey: credential.privateKey,
        });

        const tampered = {
            ...assertion,
            signature: toBase64Url(Buffer.alloc(assertion.signature.length)),
        };
        const verdict = verifyAssertion(tampered, challenge, credential.publicKey, CONFIG);
        assert.equal(verdict.ok, false);
        assert.equal(verdict.reason, 'signature_invalid');
    });

    it('rejects an assertion without user presence', () => {
        const credential = createCredential();
        const challenge = toBase64Url(Buffer.alloc(32, 5));
        const assertion = createAssertion({
            credentialId: 'ignored',
            challenge,
            rpId: RP_ID,
            origin: ORIGIN,
            privateKey: credential.privateKey,
            overrides: { flags: 0x00 },
        });

        const verdict = verifyAssertion(assertion, challenge, credential.publicKey, CONFIG);
        assert.equal(verdict.ok, false);
        assert.equal(verdict.reason, 'user_presence_required');
    });

    it('rejects a challenge mismatch', () => {
        const credential = createCredential();
        const assertion = createAssertion({
            credentialId: 'ignored',
            challenge: toBase64Url(Buffer.alloc(32, 6)),
            rpId: RP_ID,
            origin: ORIGIN,
            privateKey: credential.privateKey,
        });

        const verdict = verifyAssertion(assertion, toBase64Url(Buffer.alloc(32, 9)), credential.publicKey, CONFIG);
        assert.equal(verdict.ok, false);
        assert.equal(verdict.reason, 'challenge_mismatch');
    });
});
