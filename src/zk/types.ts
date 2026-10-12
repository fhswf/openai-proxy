export interface UserKeysRecord {
    userId: string;
    credentialId: string;
    publicKey: string;
    encryptedSk: string;
    encryptedSkIv: string;
    /** Timestamp of the last successful WebAuthn assertion for this user. */
    assertedAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
}

export interface ChatRecord {
    id: string;
    ownerId: string;
    ciphertext: string;
    iv: string;
    metadataCt: string | null;
    metadataIv: string | null;
    rev: number;
    createdAt: Date;
    updatedAt: Date;
}

export interface ChatEnvelopeRecord {
    chat_id: string;
    recipient_id: string;
    wrapped_key: string;
    wrapped_key_iv: string | null;
    is_owner: boolean;
    created_at: Date;
}

export interface PendingChallengeRecord {
    challenge: string;
    kind: 'registration' | 'assertion';
    credentialId: string | null;
    userId: string | null;
    expiresAt: Date;
}

export interface ChatSummary {
    id: string;
    ownerId: string;
    updatedAt: Date;
    rev: number;
}

/**
 * Persistence boundary for the zero-knowledge vault. The server only ever sees
 * ciphertext and public keys; implementations must never inspect or interpret
 * the opaque payloads they store.
 */
export interface ZkStore {
    init(): Promise<void>;

    getUserKeysByUserId(userId: string): Promise<UserKeysRecord | null>;
    getUserKeysByCredentialId(credentialId: string): Promise<UserKeysRecord | null>;
    upsertUserKeys(record: UserKeysRecord): Promise<void>;
    findUserKeysByPublicKey(publicKey: string): Promise<UserKeysRecord | null>;
    markAsserted(userId: string, at: Date): Promise<void>;

    saveChallenge(record: PendingChallengeRecord): Promise<void>;
    takeChallenge(challenge: string): Promise<PendingChallengeRecord | null>;

    listChatsForRecipient(recipientId: string): Promise<ChatSummary[]>;
    getChat(id: string): Promise<ChatRecord | null>;
    upsertChat(record: ChatRecord, selfEnvelope: ChatEnvelopeRecord, baseRev?: number | null): Promise<'created' | 'updated' | 'conflict'>;
    deleteChat(id: string): Promise<void>;

    listEnvelopes(chatId: string): Promise<ChatEnvelopeRecord[]>;
    getEnvelope(chatId: string, recipientId: string): Promise<ChatEnvelopeRecord | null>;
    upsertEnvelope(record: ChatEnvelopeRecord): Promise<void>;
    deleteEnvelope(chatId: string, recipientId: string): Promise<void>;
    hasEnvelope(chatId: string, recipientId: string): Promise<boolean>;
}
