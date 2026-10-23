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
are base64url-encoded. Attachment bodies use `application/octet-stream` and
are streamed through GridFS.

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
| POST | `/api/zk/keys` | Register the user's first passkey or add another named passkey; optional `identityDisclosure: "subject" | "profile"` controls identity claims in the attestation |
| POST | `/api/zk/keys/assertion-challenge` | Issue a challenge bound to a `credentialId` |
| POST | `/api/zk/keys/assertion` | Verify `{credentialId, challenge, authenticatorData, clientDataJSON, signature}`; unlocks `encryptedSk` |
| GET | `/api/zk/keys/me` | Return the caller's named passkeys, public key, and identity attestation (a passkey's wrapped `encryptedSk` only after a fresh assertion) |
| PATCH | `/api/zk/keys/me/identity-disclosure` | Choose whether verified profile claims, including email, are discoverable for chat sharing |
| DELETE | `/api/zk/keys/me` | Remove the caller's keys; encrypted chat records remain inaccessible |
| PATCH | `/api/zk/keys/me/credentials/{credentialId}` | Rename one of the caller's passkeys |
| DELETE | `/api/zk/keys/me/credentials/{credentialId}` | Remove one passkey, leaving the user's key and other passkeys in place |
| GET | `/api/zk/keys/attestation-jwks` | Return the proxy's public verification key |
| GET | `/api/zk/keys/{userId}/public-key` | Another user's key and identity attestation, for sharing |
| GET | `/api/zk/keys/lookup?email={email}` | Find a recipient by verified email within the caller's email domain |
| POST | `/api/zk/keys/rotate` | Re-wrap `SK_user` under a new passkey/credential; may also update identity disclosure |
| GET | `/api/zk/group-catalog` | Fetch the caller's encrypted saved-group roster catalog and self-envelope |
| PUT | `/api/zk/group-catalog` | Create or update the encrypted saved-group roster catalog (`baseRev` for optimistic locking) |
| GET | `/api/zk/chats` | List chats visible to the caller (no ciphertext) |
| GET | `/api/zk/chats/{id}` | Fetch a chat and its available key envelopes (group chats return only the caller's) |
| PUT | `/api/zk/chats/{id}` | Create or update a chat (`baseRev` for optimistic locking) |
| POST | `/api/zk/chats/{id}/group` | Enable group collaboration on an owner-created chat with epoch 1 envelopes for every member |
| GET | `/api/zk/chats/{id}/group` | Fetch active member IDs and the caller's key envelopes for each granted epoch |
| PUT | `/api/zk/chats/{id}/group/membership` | Replace group membership and rotate to a new key epoch (owner only) |
| GET | `/api/zk/chats/{id}/events?after={cursor}&limit={limit}` | Fetch committed encrypted events after a sequence cursor |
| POST | `/api/zk/chats/{id}/events` | Append an encrypted group event (active member and current epoch required) |
| GET (upgrade) | `/api/zk/ws` | Authenticate a WebSocket for group event catch-up and live delivery |
| POST | `/api/zk/chats/{id}/share` | Add a wrapped `K_chat` for a recipient |
| POST | `/api/zk/chats/{id}/share-link` | Create a seven-day, revocable capability link (owner only) |
| POST | `/api/zk/chats/{id}/share-link/revoke` | Revoke a capability link using its token (owner only) |
| POST | `/api/zk/public-shares/redeem` | Return linked chat ciphertext for a valid token; no account required |
| POST | `/api/zk/public-shares/redeem-attachment` | Return linked attachment ciphertext for a valid token |
| POST | `/api/zk/chats/{id}/revoke` | Remove a recipient's envelope (owner only) |
| DELETE | `/api/zk/chats/{id}` | Delete a chat (owner only) |
| HEAD | `/api/zk/chats/{id}/attachments/{attachmentId}` | Check whether an encrypted attachment exists |
| GET | `/api/zk/chats/{id}/attachments/{attachmentId}` | Stream an encrypted attachment to any chat recipient |
| PUT | `/api/zk/chats/{id}/attachments/{attachmentId}` | Stream an encrypted attachment upload (owner only, 100 MiB maximum) |
| DELETE | `/api/zk/chats/{id}/attachments/{attachmentId}` | Delete one attachment (owner only) |

Attachment requests use `application/octet-stream`. The server streams the
opaque IV-plus-ciphertext body to and from MongoDB GridFS; it does not receive
the filename or plaintext. A chat envelope is required to download an
attachment. Upload and deletion are restricted to the owner for regular chats;
active group members may upload or delete group-chat attachments. Legacy
whole-chat writes, individual share/revoke, and share links are disabled for
group chats; use group events and membership APIs instead.

### Group catalogs, membership, events, and WebSockets

The group catalog is an opaque client-encrypted object owned by one user. Its
AES-GCM ciphertext and self-envelope are stored under that user ID with a
monotone revision. `PUT` uses `baseRev`; omit it for the first write and send
`0` to assert that no catalog exists. The public key algorithm on the envelope
must match the caller's registered key.

`POST /chats/{id}/group` enables collaboration on a chat already created by
the owner. The request supplies a unique member ID list (including the owner)
and exactly one wrapped epoch key per member. The owner is assigned role
`owner`; all others receive role `member`. Each member must have registered
zk keys, and each envelope algorithm must match that member's registered
public key.

`GET /chats/{id}/group` is available to active members. It returns the active
member IDs, current epoch, committed event cursor, and only the caller's
envelopes. The legacy `GET /chats/{id}` response also limits a group member to
their own current-epoch envelope. A membership
replacement requires `baseEpoch` and the full new member list. The request
must include a fresh epoch envelope for every active member. It may also
include envelopes for prior epochs to grant a newly added member access to
history. The owner cannot remove themself. Epoch comparison is atomic, so a
stale update returns `409` with `currentEpoch`.

Events contain a client-generated `eventId`, epoch, AES-GCM IV, and opaque
ciphertext (up to 256 KiB decoded, with a 12-byte IV). The proxy assigns a per-chat sequence and an authenticated
`actorId`; duplicate event IDs from the same actor are idempotent. Event writes
require current membership and the current epoch. Event reads require current
membership and use a sequence cursor. Removed users cannot fetch events after
removal, although ciphertext or keys already downloaded cannot be recalled.
The proxy does not validate event plaintext or AES-GCM additional authenticated
data.

The WebSocket endpoint is available at the same API prefix as the REST router,
at `/api/zk/ws` (and `/zk/ws` when the deployment strips `/api`). The upgrade
requires an allowed `Origin` and the proxy's OIDC token cookie or a Bearer
token. Clients send JSON messages:

```json
{ "type": "subscribe", "chatId": "chat-id", "after": 42 }
{ "type": "append", "requestId": "req-id", "chatId": "chat-id", "eventId": "event-id", "epoch": 2, "ciphertext": "...", "iv": "..." }
{ "type": "unsubscribe", "chatId": "chat-id" }
```

The server sends `ready`, `subscribed`, `event`, `ack`, `catchup_complete`,
`unsubscribed`, and structured `error` messages. Appends go through the same
idempotent event store as the REST endpoint. Events are persisted before they
are broadcast. Clients should retain their cursor and use REST or socket
catch-up after reconnecting; the WebSocket is a delivery channel, not the
durable source of truth.

MongoDB stores durable events in `zk_group_chat_events`. Cross-replica event
notifications use the capped `zk_group_chat_notifications` collection with a
tailable cursor, so every proxy instance can relay events to its connected
sockets without requiring MongoDB change streams or an external pub/sub
service. The capped collection is only a notification outbox; clients recover
from the durable event collection by cursor.

Converting a chat to a group also revokes any existing capability share links.
Regular-chat share links cannot be redeemed once a chat is a group chat.

Email lookup is available only for an authenticated user's verified email
domain and recipients who explicitly enabled profile disclosure. Both a miss
and an undiscoverable account return `404`. Share-link tokens contain 256 bits
of randomness; the database stores only their SHA-256 hashes. The share URL
keeps both the token and AES chat key in its fragment, so neither is sent with
the page request. The client sends the token in the redemption request body.
Link redemption returns ciphertext without an envelope and is rate-limited by IP.
The owner can revoke a link before its seven-day expiry.

Register a passkey with a user-provided `credentialName` (up to 80 printable
characters). For a second or later passkey, send the same account
`publicKeyAlgorithm` and `publicKey` as the first registration, plus that
credential's WebAuthn public key and a copy of `SK_user` wrapped under that
passkey's PRF-derived key. The server stores one wrapped copy per passkey. A
registration without `credentialName` is accepted for older clients and is
named `Passkey`. Existing passkeys can be renamed with `PATCH` to the
credential resource using `{ "credentialName": "..." }`.

`GET /api/zk/keys/me` returns a `credentials` array containing each
`credentialId`, `name`, and `createdAt`. The legacy top-level `credentialId`
and `credentialName` fields identify the passkey whose `encryptedSk` is
returned after assertion, or the first passkey when no recent assertion exists.
Assertion challenges are bound to the requested `credentialId`. Only the
wrapped key for the most recently asserted credential is released, for the
existing 15-minute window. The final passkey cannot be removed individually;
use `DELETE /api/zk/keys/me` to remove the whole key account.

`POST /api/zk/keys/rotate` remains a replacement operation: it installs one
credential wrapper for the rotated user key and removes the account's other
passkeys. Use `POST /api/zk/keys` to add a passkey without rotating the user's
public key.

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
- Attachment bodies remain AES-GCM ciphertext in the `zk_attachments` GridFS
  bucket and are streamed without base64 expansion.
- `wrappedKey` (1024 bytes, including legacy RSA-OAEP-4096), `encryptedSk`
  (16 KiB), `iv` (16 bytes) and ciphertext (5 MB) are bounded; oversized
  values yield `413 payload_too_large`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `WEBAUTHN_RP_ID` | hostname of the allowlisted request origin | Optional fixed relying-party id accepted in assertions; by default the server uses the hostname of the allowlisted frontend origin |
| `WEBAUTHN_ORIGINS` | `CORS_ORIGINS` | JSON array or comma-separated list of accepted origins |
| `ZK_WRITE_RATE_LIMIT` | `120` | Write requests per user per minute for `/api/zk` |

Storage uses the existing MongoDB connection (`user_keys`, `chats`,
`chat_keys`, `zk_challenges`, `zk_group_catalogs`, `zk_group_chats`,
`zk_group_chat_events`, and the capped `zk_group_chat_notifications`). With
`IGNORE_DB=true` an in-memory store is used for local development and tests;
its WebSocket event delivery is process-local.
