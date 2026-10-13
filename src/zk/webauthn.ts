import { createPublicKey, verify as cryptoVerify, KeyObject } from 'node:crypto';
import { fromBase64Url, sha256 } from './base64.ts';

const FLAG_USER_PRESENT = 0x01;
const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;
const FLAG_EXTENSION_DATA = 0x80;
const MIN_AUTH_DATA_LENGTH = 37;
const AUTH_DATA_VERIFY_LENGTH = 37;

export interface WebAuthnConfig {
    /** Optional fixed RP ID. By default the hostname of the allowlisted origin is used. */
    rpId?: string;
    /** Origins that are accepted in the clientDataJSON. */
    origins: string[];
}

export interface WebAuthnVerification {
    ok: boolean;
    reason?: string;
}

interface ClientData {
    type?: string;
    challenge?: string;
    origin?: string;
}

interface AssertionInput {
    credentialId: string;
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
}

export function isPrfCapableFlags(flags: number): boolean {
    // The PRF extension result is reported in the authenticator extension data
    // (ED flag). Without ED there is no PRF output and zero-knowledge mode is
    // not available, so callers fall back to local storage.
    return (flags & FLAG_EXTENSION_DATA) !== 0;
}

function parseAuthData(authData: Buffer): { flags: number; signCount: number; rpIdHash: Buffer } {
    if (authData.length < MIN_AUTH_DATA_LENGTH) {
        throw new Error('authenticatorData too short');
    }

    return {
        rpIdHash: authData.subarray(0, 32),
        flags: authData[32],
        signCount: authData.readUInt32BE(33),
    };
}

function toKeyObject(publicKey: string): KeyObject | null {
    const der = fromBase64Url(publicKey);
    if (!der) {
        return null;
    }

    try {
        return createPublicKey({ key: der, format: 'der', type: 'spki' });
    }
    catch {
        return null;
    }
}

/**
 * Verify a WebAuthn assertion. The server must perform this check before
 * releasing `encryptedSk`; otherwise an attacker could fetch the wrapped
 * private key and attack it offline.
 */
export function verifyAssertion(
    input: AssertionInput,
    expectedChallenge: string,
    publicKey: string,
    config: WebAuthnConfig,
): WebAuthnVerification {
    const authData = fromBase64Url(input.authenticatorData);
    const clientDataRaw = fromBase64Url(input.clientDataJSON);
    const signature = fromBase64Url(input.signature);
    if (!authData || !clientDataRaw || !signature) {
        return { ok: false, reason: 'malformed_assertion' };
    }

    let clientData: ClientData;
    try {
        clientData = JSON.parse(clientDataRaw.toString('utf8'));
    }
    catch {
        return { ok: false, reason: 'invalid_client_data_json' };
    }

    if (clientData.type !== 'webauthn.get') {
        return { ok: false, reason: 'unexpected_type' };
    }

    if (clientData.challenge !== expectedChallenge) {
        return { ok: false, reason: 'challenge_mismatch' };
    }

    if (!clientData.origin || !config.origins.includes(clientData.origin)) {
        return { ok: false, reason: 'origin_mismatch' };
    }

    let parsed;
    try {
        parsed = parseAuthData(authData);
    }
    catch (err) {
        return { ok: false, reason: 'invalid_authenticator_data' };
    }

    if ((parsed.flags & FLAG_USER_PRESENT) === 0) {
        return { ok: false, reason: 'user_presence_required' };
    }

    // The frontend creates credentials with its own hostname as the RP ID.
    // The client origin is checked against the server's allowlist above, so
    // deriving the default from it supports localhost and multiple frontends
    // without coupling the passkey RP ID to the unrelated OIDC issuer host.
    let rpId = config.rpId;
    if (!rpId) {
        try {
            rpId = new URL(clientData.origin!).hostname;
        }
        catch {
            return { ok: false, reason: 'origin_mismatch' };
        }
    }

    const rpIdHash = sha256(rpId);
    if (!parsed.rpIdHash.equals(rpIdHash)) {
        return { ok: false, reason: 'rp_id_mismatch' };
    }

    // Assertions must not carry attested credential data.
    if ((parsed.flags & FLAG_ATTESTED_CREDENTIAL_DATA) !== 0) {
        return { ok: false, reason: 'unexpected_attested_credential_data' };
    }

    const key = toKeyObject(publicKey);
    if (!key) {
        return { ok: false, reason: 'invalid_public_key' };
    }

    const signedData = Buffer.concat([
        authData.subarray(0, AUTH_DATA_VERIFY_LENGTH),
        sha256(clientDataRaw),
    ]);

    let valid = false;
    try {
        valid = cryptoVerify('sha256', signedData, { key }, signature);
    }
    catch {
        valid = false;
    }

    return valid ? { ok: true } : { ok: false, reason: 'signature_invalid' };
}

export function hasPrfExtensionFlag(authenticatorData: string): boolean {
    const authData = fromBase64Url(authenticatorData);
    if (!authData) {
        return false;
    }

    try {
        return isPrfCapableFlags(parseAuthData(authData).flags);
    }
    catch {
        return false;
    }
}
