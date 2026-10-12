# Zero-Knowledge, cross-device chats (backend)

The proxy hosts the server side of the zero-knowledge chat vault described in
issue #44. The server only ever stores ciphertext and public keys; it never sees
plaintext chats. It verifies passkey assertions but does not validate chat or
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

## Security properties

- `encryptedSk` is only released after a valid WebAuthn assertion, so the
  wrapped private key cannot be fetched and attacked offline.
- Assertions are verified with the stored WebAuthn credential public key and
  against the configured RP id and origin, with a
  single-use challenge bound to the credential.
- The server uses `chat_keys` entries solely for authorization, never for
  decryption.
- `wrappedKey` (256 bytes), `encryptedSk` (16 KiB), `iv` (16 bytes) and
  ciphertext (5 MB) are bounded; oversized values yield `413 payload_too_large`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `WEBAUTHN_RP_ID` | host of `ISSUER` | Relying-party id accepted in assertions |
| `WEBAUTHN_ORIGINS` | `CORS_ORIGINS` | JSON array or comma-separated list of accepted origins |
| `ZK_WRITE_RATE_LIMIT` | `120` | Write requests per user per minute for `/api/zk` |

Storage uses the existing MongoDB connection (`user_keys`, `chats`,
`chat_keys`, `zk_challenges`). With `IGNORE_DB=true` an in-memory store is used
for local development and tests.
