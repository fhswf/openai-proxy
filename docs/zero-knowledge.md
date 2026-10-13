# Zero-Knowledge, cross-device chats (backend)

The proxy hosts the server side of the zero-knowledge chat vault described in
issue #44. The vault is designed so chat content and user private keys are
encrypted by the client before storage. The server does not decrypt them. It
does see account and chat IDs, timestamps, ciphertext sizes, and sharing
relationships. It verifies passkey assertions but does not validate chat or
private-key ciphertext. All endpoints live
under `/api/zk` and use the same OIDC bearer token / session cookie as the rest
of the proxy. Binary values are base64url-encoded.

## Key hierarchy

- `K_chat`: random AES-GCM-256 key per chat, used to encrypt the serialized chat.
- `PK_user` / `SK_user`: the user's chat-key wrapping key pair. New clients can
  use P-256 ECDH; legacy RSA-OAEP-SHA256 keys and envelopes remain stored and
  identified. The public key is stored in cleartext; the private key is stored
  wrapped with the passkey-derived `K_pass`.
- `PK_credential` / `SK_credential`: WebAuthn passkey key pair used to verify
  assertions and derive `K_pass` via PRF. Its public key is stored separately
  from `PK_user`.
- `chat_keys`: one wrapped `K_chat` per recipient (multi-recipient header).
  Sharing a chat only adds a new envelope, it never re-encrypts the ciphertext.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/zk/keys/registration-challenge` | Issue a short-lived registration challenge |
| POST | `/api/zk/keys` | Register `credentialId`, WebAuthn `credentialPublicKey`, `publicKeyAlgorithm`, `publicKey`, wrapped `encryptedSk` |
| POST | `/api/zk/keys/assertion-challenge` | Issue a challenge bound to a `credentialId` |
| POST | `/api/zk/keys/assertion` | Verify `{credentialId, challenge, authenticatorData, clientDataJSON, signature}`; unlocks `encryptedSk` |
| GET | `/api/zk/keys/me` | Return the caller's keys (wrapped `encryptedSk` only after a fresh assertion) |
| DELETE | `/api/zk/keys/me` | Remove the caller's keys; encrypted chat records remain inaccessible |
| GET | `/api/zk/keys/{userId}/public-key` | Another user's `publicKeyAlgorithm` and public key, for sharing |
| POST | `/api/zk/keys/rotate` | Re-wrap `SK_user` under a new passkey/credential |
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
not currently protect users from an actively malicious or compromised backend.
The API returns public keys from its database without an independent signature
or transparency proof. A malicious backend could substitute a recipient's key
when a client fetches it, causing future shared chat keys to be encrypted to an
attacker. It can also delete data, hide updates, or replay an older valid chat
version. `baseRev` prevents ordinary concurrent overwrites; it is not protection
against a backend that controls the stored revision.

**Client requirement, not implemented by this backend:** before accepting a
public key from the backend, the client should display its fingerprint and
require the user to verify it with the key owner through a separate trusted
channel. The fingerprint is the full SHA-256 digest of the algorithm and
decoded SPKI DER public key:

```
SHA-256(UTF-8("openai-proxy-user-key-v1\0") ||
        UTF-8(publicKeyAlgorithm) || 0x00 || decoded-SPKI-DER)
```

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
