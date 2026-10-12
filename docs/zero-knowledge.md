# Zero-Knowledge, cross-device chats (backend)

The proxy hosts the server side of the zero-knowledge chat vault described in
issue #44. The server only ever stores ciphertext and public keys; it never sees
plaintext chats. It verifies passkey assertions but does not validate chat or
private-key ciphertext. All endpoints live
under `/api/zk` and use the same OIDC bearer token / session cookie as the rest
of the proxy. Binary values are base64url-encoded.

## Key hierarchy

- `K_chat`: random AES-GCM-256 key per chat, used to encrypt the serialized chat.
- `PK_user` / `SK_user`: user RSA-OAEP key pair for wrapping chat keys. The
  public key is stored in cleartext; the private key is stored wrapped with the
  passkey-derived `K_pass`.
- `PK_credential` / `SK_credential`: WebAuthn passkey key pair used to verify
  assertions and derive `K_pass` via PRF. Its public key is stored separately
  from `PK_user`.
- `chat_keys`: one wrapped `K_chat` per recipient (multi-recipient header).
  Sharing a chat only adds a new envelope, it never re-encrypts the ciphertext.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/zk/keys/registration-challenge` | Issue a short-lived registration challenge |
| POST | `/api/zk/keys` | Register `credentialId`, WebAuthn `credentialPublicKey`, RSA `publicKey`, wrapped `encryptedSk` |
| POST | `/api/zk/keys/assertion-challenge` | Issue a challenge bound to a `credentialId` |
| POST | `/api/zk/keys/assertion` | Verify `{credentialId, challenge, authenticatorData, clientDataJSON, signature}`; unlocks `encryptedSk` |
| GET | `/api/zk/keys/me` | Return the caller's keys (wrapped `encryptedSk` only after a fresh assertion) |
| DELETE | `/api/zk/keys/me` | Remove the caller's keys; encrypted chat records remain inaccessible |
| GET | `/api/zk/keys/{userId}/public-key` | Public key of another user, for sharing |
| POST | `/api/zk/keys/rotate` | Re-wrap `SK_user` under a new passkey/credential |
| GET | `/api/zk/chats` | List chats visible to the caller (no ciphertext) |
| GET | `/api/zk/chats/{id}` | Fetch a chat with all key envelopes |
| PUT | `/api/zk/chats/{id}` | Create or update a chat (`baseRev` for optimistic locking) |
| POST | `/api/zk/chats/{id}/share` | Add a wrapped `K_chat` for a recipient |
| POST | `/api/zk/chats/{id}/revoke` | Remove a recipient's envelope (owner only) |
| DELETE | `/api/zk/chats/{id}` | Delete a chat (owner only) |

## Security properties

- `encryptedSk` is only released after a valid WebAuthn assertion, so the
  wrapped private key cannot be fetched and attacked offline.
- Assertions are verified with the stored WebAuthn credential public key and
  against the configured RP id and origin, with a
  single-use challenge bound to the credential.
- The server uses `chat_keys` entries solely for authorization, never for
  decryption.
- `wrappedKey` (256 bytes), `iv` (16 bytes) and ciphertext (5 MB) are bounded;
  oversized ciphertext yields `413 payload_too_large`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `WEBAUTHN_RP_ID` | host of `ISSUER` | Relying-party id accepted in assertions |
| `WEBAUTHN_ORIGINS` | `CORS_ORIGINS` | JSON array or comma-separated list of accepted origins |
| `ZK_WRITE_RATE_LIMIT` | `120` | Write requests per user per minute for `/api/zk` |

Storage uses the existing MongoDB connection (`user_keys`, `chats`,
`chat_keys`, `zk_challenges`). With `IGNORE_DB=true` an in-memory store is used
for local development and tests.
