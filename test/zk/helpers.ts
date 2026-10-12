import { generateKeyPairSync, sign as cryptoSign, KeyObject } from 'node:crypto';
import { sha256, toBase64Url } from '../../src/zk/base64.ts';

export interface TestCredential {
    publicKey: string;
    privateKey: KeyObject;
}

export function createCredential(): TestCredential {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return {
        publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        privateKey,
    };
}

export interface AssertionInput {
    credentialId: string;
    challenge: string;
    rpId: string;
    origin: string;
    privateKey: KeyObject;
    overrides?: {
        type?: string;
        challenge?: string;
        origin?: string;
        rpId?: string;
        flags?: number;
    };
}

/**
 * Build a spec-conformant WebAuthn assertion so the server-side verifier can be
 * exercised without a real authenticator. `overrides` allows tests to produce
 * deliberately broken assertions.
 */
export function createAssertion(input: AssertionInput) {
    const overrides = input.overrides ?? {};
    const rpIdHash = sha256(overrides.rpId ?? input.rpId);
    const flags = Buffer.from([overrides.flags ?? 0x01]); // UP set, no ED/AT flags
    const signCount = Buffer.alloc(4);
    signCount.writeUInt32BE(1, 0);
    const authData = Buffer.concat([rpIdHash, flags, signCount]);

    const clientDataJSON = Buffer.from(JSON.stringify({
        type: overrides.type ?? 'webauthn.get',
        challenge: overrides.challenge ?? input.challenge,
        origin: overrides.origin ?? input.origin,
    }), 'utf8');

    const signedData = Buffer.concat([authData, sha256(clientDataJSON)]);
    const signature = cryptoSign('sha256', signedData, { key: input.privateKey, dsaEncoding: 'der' });

    return {
        credentialId: input.credentialId,
        authenticatorData: toBase64Url(authData),
        clientDataJSON: toBase64Url(clientDataJSON),
        signature: toBase64Url(signature),
    };
}

export function fakeCiphertext(length = 64): string {
    return Buffer.alloc(length, 7).toString('base64url');
}
