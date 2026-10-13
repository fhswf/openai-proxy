# Zero-Knowledge, cross-device chats (backend)

The proxy hosts the server side of the zero-knowledge chat vault described in
issue #44. The vault is designed so chat content and user private keys are
encrypted by the client before storage. The server does not decrypt them. It
does see account and chat IDs, timestamps, ciphertext sizes, and sharing
relationships. It verifies passkey assertions but does not validate chat or
private-key ciphertext. All endpoints live
under `/api/zk` and use the same OIDC bearer token / session cookie as the rest
of the proxy. When attestation signing is enabled, registration can also store
selected OIDC profile claims (`name`, `email`, verification status, and
username) with the key if the user opts into profile disclosure. Binary values
are base64url-encoded.

## Key hierarchy

- `K_chat`: random AES-GCM-256 key per chat, used to encrypt the serialized chat.
- `PK_user` / `SK_user`: the user's chat-key wrapping key pair. New clients can
  use P-256 ECDH; legacy RSA-OAEP-SHA256 keys and envelopes remain stored and
  identified. The public key is stored in cleartext; the private key is stored
  wrapped with the passkey-derived `K_pass`.
- `PK_credential` / `SK_credential`: WebAuthn passkey key pair used to verify
  assertions and derive `K_pass` via PRF. Its public key is stored separately
  from `PK_user`.
- A proxy-signed identity attestation binds the authenticated OIDC issuer and
  subject (and available profile claims) to the fingerprint of `PK_user`. It
  contains selected claims, never the user's bearer JWT.
- `chat_keys`: one wrapped `K_chat` per recipient (multi-recipient header).
  Sharing a chat only adds a new envelope, it never re-encrypts the ciphertext.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/zk/keys/registration-challenge` | Issue a short-lived registration challenge |
| POST | `/api/zk/keys` | Register keys; optional `identityDisclosure: "subject" | "profile"` controls identity claims in the attestation |
| POST | `/api/zk/keys/assertion-challenge` | Issue a challenge bound to a `credentialId` |
| POST | `/api/zk/keys/assertion` | Verify `{credentialId, challenge, authenticatorData, clientDataJSON, signature}`; unlocks `encryptedSk` |
| GET | `/api/zk/keys/me` | Return the caller's keys and identity attestation (wrapped `encryptedSk` only after a fresh assertion) |
| DELETE | `/api/zk/keys/me` | Remove the caller's keys; encrypted chat records remain inaccessible |
| GET | `/api/zk/keys/attestation-jwks` | Return the proxy's public verification key |
| GET | `/api/zk/keys/{userId}/public-key` | Another user's key and identity attestation, for sharing |
| POST | `/api/zk/keys/rotate` | Re-wrap `SK_user` under a new passkey/credential; may also update identity disclosure |
| GET | `/api/zk/chats` | List chats visible to the caller (no ciphertext) |
| GET | `/api/zk/chats/{id}` | Fetch a chat with all key envelopes |
| PUT | `/api/zk/chats/{id}` | Create or update a chat (`baseRev` for optimistic locking) |
| POST | `/api/zk/chats/{id}/share` | Add a wrapped `K_chat` for a recipient |
| POST | `/api/zk/chats/{id}/revoke` | Remove a recipient's envelope (owner only) |
| DELETE | `/api/zk/chats/{id}` | Delete a chat (owner only) |

`publicKeyAlgorithm` is `ECDH-P256` for new clients or `RSA-OAEP-SHA256` for
legacy clients. Clients should send it when registering or rotating keys; an
omitted value is treated as RSA for compatibility. For ECDH, use an SPKI DER
P-256 public key encoded as base64url.

## Identity-to-key attestation

When configured, key responses include `identityAttestation`, a compact JWS
signed by the proxy with RS256. Its header has `typ: zk-key-attestation+jwt`
and a `kid` matching the public key at `/api/zk/keys/attestation-jwks`. Its
claims are:

- `iss`: the configured attestation issuer, normally the proxy's public URL.
- `aud`: `openai-proxy-zk-key`; `sub`: the OIDC subject.
- `purpose`: `zk-key-identity-attestation`.
- `identity`: the verified OIDC `issuer` and `subject`, plus available `name`,
  `email`, `emailVerified`, and `preferredUsername` claims. New registrations
  also include `observedAt`, the time this identity claim snapshot was copied
  from the JWT.
- `key`: `algorithm` and the base64url-encoded SHA-256 fingerprint of
  the exact public key, using the formula below.
- `iat` and `exp`: issuance time and a 24-hour expiry.

Registration and rotation accept `identityDisclosure`. `subject` (the default)
attests only the OIDC issuer and subject. `profile` also publishes the available
`name`, `email`, `emailVerified`, and `preferredUsername` claims to authenticated
users who fetch the key. Only claims present in the verified JWT are included;
the server stores this profile snapshot with the key until the user changes the
disclosure or removes the key. A user can update disclosure by repeating key
registration with the same key and wrapped private key.

The proxy checks the configured OIDC issuer when verifying incoming JWTs, then
copies only these selected claims into its attestation. It does not persist or
return the JWT. Profile claims are stored with the user's key record and are
returned to authenticated clients through the signed attestation only after the
user opts into `profile` disclosure. Clients should treat email as verified
only when `identity.emailVerified` is `true`.
Display profile values as claims observed at `identity.observedAt`; they may be
stale until the user registers or rotates their key again.
Older key records without saved profile claims can still receive an
attestation with the configured OIDC issuer and subject.

To verify, clients must trust the configured proxy attestation issuer, load its
JWKS, require RS256, validate `kid`, signature, `iss`, `aud`, `purpose`, and
`exp`; check that `sub`, `identity.subject`, and the response `userId` agree;
check `identity.issuer` against the expected OIDC issuer; then recompute the
fingerprint from the accompanying algorithm and public key and compare it to
`key.fingerprint`. The public key and attestation
returned together by the API are not independently trusted until this succeeds.
The attestation is an application-server statement that an authenticated OIDC
account registered that key; it is not an IdP-signed proof. Clients need an
independently trusted proxy issuer and verification key. If they fetch both the
key and JWKS from the same untrusted backend, that alone does not establish
trust. A proxy operator who can use the signing key can issue false
attestations, so this does not remove the malicious-backend limitation below.

Configure `ZK_ATTESTATION_PRIVATE_KEY` with an RSA private key of at least 2048
bits, `ZK_ATTESTATION_ISSUER` with the proxy's stable public issuer identifier,
and optionally `ZK_ATTESTATION_KEY_ID` (defaults to `zk-attestation-1`). Store
the private key as a deployment secret. If these values are absent, existing
key operations continue and `identityAttestation` is `null`; clients must treat
the key as unattested. During signing-key rotation, clients should refresh the
JWKS and fetch a fresh attestation. Operators must keep the configured `kid`
unique for each signing key.

For example, generate a key with
`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out zk-attestation.pem`.

The `PK_user` key is for encryption/key agreement, not signatures. This
attestation associates the account with its sharing key; it does not prove who
authored a particular chat. Content authorship would require a separate
signing key, also bound to the identity, and a signature over a chat manifest.

Each chat envelope includes `envelopeAlgorithm`. RSA envelopes use
`RSA-OAEP-SHA256` and keep the existing `wrappedKey` representation. ECDH
envelopes use `ECDH-P256-HKDF-SHA256-AES-256-GCM`: `ephemeralPublicKey` is the
sender's ephemeral P-256 public key (SPKI DER, base64url), `wrappedKeyIv` is the
12-byte AES-GCM nonce, and `wrappedKey` is the 48-byte ciphertext plus tag for
the 32-byte chat key. The server stores these fields without interpreting or
decrypting them. Envelopes written before algorithm metadata are treated as
RSA-OAEP-SHA256.

When changing an existing account from RSA to ECDH, the client must first
unwrap and rewrap that user's existing chat-key envelopes, then rotate the
registered key. The chat ciphertext itself does not need to be re-encrypted.

## Threat model and limitations

This design aims to protect chat plaintext from a backend operator who can read
stored data but whose server and client software follow the protocol. It does
not protect users from an actively malicious or compromised backend. If
attestations are configured, the proxy signs the account-to-key mapping, but
the same service controls the signer and serves both the attestation and its
JWKS. The operator can therefore issue a false attestation or replace the
verification key unless clients pin it through an independent trusted channel.
A malicious backend can also delete data, hide updates, or replay an older valid
chat version. `baseRev` prevents ordinary concurrent overwrites; it is not
protection against a backend that controls the stored revision.

**Client requirement, not implemented by this backend:** before accepting a
public key from the backend, the client should display its fingerprint and
require the user to verify it with the key owner through a separate trusted
channel. The fingerprint is the full SHA-256 digest of the algorithm and
decoded SPKI DER public key:

```
SHA-256(UTF-8("openai-proxy-user-key-v1\0") ||
        UTF-8(publicKeyAlgorithm) || 0x00 || decoded-SPKI-DER)
```

For the `key.fingerprint` JWS claim, encode the 32-byte digest as base64url.

Display the full digest in a copyable, human-readable form. Do not treat a key
as verified just because its fingerprint came from the same backend as the
key. Stop sharing if the comparison fails; verify any changed fingerprint
again after key rotation. Until that UI exists, label backend-provided keys as
unverified and warn before sharing. Trust on first use does not catch a backend
that substitutes a key at first contact, and independent fingerprint checks
alone do not detect a backend showing different keys to different users. A key
transparency system with independent witnesses would be needed to address that
kind of equivocation at scale.

Authenticated encryption can detect ciphertext changes when clients verify the
authentication tag, but it does not by itself detect replay or rollback. The
client must bind each envelope to its chat, recipient, key version, and
algorithm, and must track revisions or authenticated history if rollback
detection is required. This backend stores cryptographic payloads opaquely; it
does not verify those client-side checks. The ECDH format documented above is a
storage/API format, not evidence that a client has implemented or verified the
cryptography correctly.

If the backend also serves or can replace the browser client, it could deliver
modified code that reads plaintext or keys after decryption. Protecting against
that requires an independently trusted client release. The passkey assertion
gate is also backend behavior: it limits what the honest API releases, but it
cannot constrain a backend operator who can change the API or its database.

## Security properties

- The API releases `encryptedSk` only after a valid WebAuthn assertion. This
  limits exposure through the honest API; it is not a defense against a
  malicious backend operator (see above).
- Assertions are verified with the stored WebAuthn credential public key and
  against the configured RP id and origin, with a
  single-use challenge bound to the credential.
- Public-key responses can include a 24-hour proxy-signed binding between
  selected identity claims and the key fingerprint when attestation signing is
  configured.
- The server uses `chat_keys` entries solely for authorization, never for
  decryption.
- `wrappedKey` (1024 bytes, including legacy RSA-OAEP-4096), `encryptedSk`
  (16 KiB), `iv` (16 bytes) and ciphertext (5 MB) are bounded; oversized
  values yield `413 payload_too_large`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `WEBAUTHN_RP_ID` | host of `ISSUER` | Relying-party id accepted in assertions |
| `WEBAUTHN_ORIGINS` | `CORS_ORIGINS` | JSON array or comma-separated list of accepted origins |
| `ZK_WRITE_RATE_LIMIT` | `120` | Write requests per user per minute for `/api/zk` |

Storage uses the existing MongoDB connection (`user_keys`, `chats`,
`chat_keys`, `zk_challenges`). With `IGNORE_DB=true` an in-memory store is used
for local development and tests.
