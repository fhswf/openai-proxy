import type { Readable } from 'node:stream';

export type UserKeyAlgorithm = 'RSA-OAEP-SHA256' | 'ECDH-P256';
export type EnvelopeAlgorithm = 'RSA-OAEP-SHA256' | 'ECDH-P256-HKDF-SHA256-AES-256-GCM';

/** Selected identity-provider claims copied from the verified JWT. */
export interface UserIdentityClaims {
    issuer: string;
    subject: string;
    name?: string;
    email?: string;
    emailVerified?: boolean;
    preferredUsername?: string;
    /** Time this identity claim snapshot was copied from the authenticated JWT. */
    observedAt?: string;
}

export interface UserPasskeyRecord {
    credentialId: string;
    name: string;
    credentialPublicKey: string;
    encryptedSk: string;
    encryptedSkIv: string;
    /** Timestamp of the last successful assertion with this credential. */
    assertedAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
}

export interface UserKeysRecord {
    userId: string;
    publicKeyAlgorithm: UserKeyAlgorithm;
    publicKey: string;
    /** Identity claims from the authenticated registration or rotation. */
    identity?: UserIdentityClaims | null;
    /** Each passkey has its own assertion key and wrapped copy of SK_user. */
    credentials: UserPasskeyRecord[];
    createdAt: Date;
    updatedAt: Date;
}

export interface UserCredentialRecord {
    userKeys: UserKeysRecord;
    credential: UserPasskeyRecord;
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

export interface ChatShareLinkRecord {
    tokenHash: string;
    chatId: string;
    ownerId: string;
    createdAt: Date;
    expiresAt: Date;
}

export interface ChatEnvelopeRecord {
    chat_id: string;
    recipient_id: string;
    envelope_algorithm: EnvelopeAlgorithm;
    ephemeral_public_key: string | null;
    wrapped_key: string;
    wrapped_key_iv: string | null;
    is_owner: boolean;
    created_at: Date;
    epoch?: number;
}

export interface GroupCatalogEnvelope {
    envelope_algorithm: EnvelopeAlgorithm;
    ephemeral_public_key: string | null;
    wrapped_key: string;
    wrapped_key_iv: string | null;
}

export interface GroupCatalogRecord {
    userId: string;
    ciphertext: string;
    iv: string;
    envelope: GroupCatalogEnvelope;
    rev: number;
    updatedAt: Date;
}

export type GroupChatRole = 'owner' | 'member';

export interface GroupChatMemberRecord {
    userId: string;
    role: GroupChatRole;
}

export interface GroupChatEpochEnvelope {
    recipientId: string;
    epoch: number;
    envelope_algorithm: EnvelopeAlgorithm;
    ephemeral_public_key: string | null;
    wrapped_key: string;
    wrapped_key_iv: string | null;
    created_at: Date;
}

export interface GroupChatRecord {
    chatId: string;
    ownerId: string;
    currentEpoch: number;
    committedSequence: number;
    members: GroupChatMemberRecord[];
    /** Historical envelopes are retained so authorized new members may be granted history. */
    envelopes: GroupChatEpochEnvelope[];
    createdAt: Date;
    updatedAt: Date;
}

export interface GroupChatEventRecord {
    chatId: string;
    sequence: number;
    eventId: string;
    actorId: string;
    epoch: number;
    ciphertext: string;
    iv: string;
    createdAt: Date;
}

export type GroupChatEventListener = (event: GroupChatEventRecord) => void;

export interface NewGroupChatEvent {
    chatId: string;
    eventId: string;
    actorId: string;
    epoch: number;
    ciphertext: string;
    iv: string;
    createdAt: Date;
}

export type GroupChatEventAppendResult =
    | { status: 'created' | 'existing'; event: GroupChatEventRecord }
    | { status: 'not_found' }
    | { status: 'forbidden' }
    | { status: 'conflict' };

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

export interface ZkAttachmentDownload {
    stream: Readable;
    size: number;
}

/**
 * Persistence boundary for the zero-knowledge vault. The server only ever sees
 * ciphertext and public keys; implementations must never inspect or interpret
 * the opaque payloads they store.
 */
export interface ZkStore {
    init(): Promise<void>;

    getUserKeysByUserId(userId: string): Promise<UserKeysRecord | null>;
    getUserCredentialById(credentialId: string): Promise<UserCredentialRecord | null>;
    upsertUserKeys(record: UserKeysRecord): Promise<void>;
    deleteUserKeys(userId: string): Promise<void>;
    deleteUserCredential(userId: string, credentialId: string): Promise<void>;
    renameUserCredential(userId: string, credentialId: string, name: string, at: Date): Promise<void>;
    updateUserIdentity(userId: string, identity: UserIdentityClaims | null): Promise<void>;
    findUserKeysByPublicKey(publicKey: string): Promise<UserKeysRecord | null>;
    findUserKeysByEmail(email: string): Promise<UserKeysRecord | null>;
    markAsserted(userId: string, credentialId: string, at: Date): Promise<void>;

    saveChallenge(record: PendingChallengeRecord): Promise<void>;
    takeChallenge(challenge: string): Promise<PendingChallengeRecord | null>;

    listChatsForRecipient(recipientId: string): Promise<ChatSummary[]>;
    getChat(id: string): Promise<ChatRecord | null>;
    upsertChat(record: ChatRecord, selfEnvelope: ChatEnvelopeRecord, baseRev?: number | null): Promise<'created' | 'updated' | 'conflict'>;
    deleteChat(id: string): Promise<void>;

    saveChatShareLink(record: ChatShareLinkRecord): Promise<void>;
    getChatShareLink(tokenHash: string): Promise<ChatShareLinkRecord | null>;
    deleteChatShareLink(tokenHash: string): Promise<void>;
    deleteChatShareLinksForChat(chatId: string): Promise<void>;

    putAttachment(chatId: string, attachmentId: string, source: Readable): Promise<void>;
    getAttachment(chatId: string, attachmentId: string): Promise<ZkAttachmentDownload | null>;
    hasAttachment(chatId: string, attachmentId: string): Promise<boolean>;
    deleteAttachment(chatId: string, attachmentId: string): Promise<void>;
    deleteAttachmentsForChat(chatId: string): Promise<void>;

    listEnvelopes(chatId: string): Promise<ChatEnvelopeRecord[]>;
    getEnvelope(chatId: string, recipientId: string): Promise<ChatEnvelopeRecord | null>;
    upsertEnvelope(record: ChatEnvelopeRecord): Promise<void>;
    deleteEnvelope(chatId: string, recipientId: string): Promise<void>;
    hasEnvelope(chatId: string, recipientId: string): Promise<boolean>;

    getGroupCatalog(userId: string): Promise<GroupCatalogRecord | null>;
    putGroupCatalog(record: GroupCatalogRecord, baseRev?: number | null): Promise<'created' | 'updated' | 'conflict'>;

    getGroupChat(chatId: string): Promise<GroupChatRecord | null>;
    createGroupChat(record: GroupChatRecord): Promise<'created' | 'exists' | 'not_found' | 'forbidden'>;
    replaceGroupChatMembership(
        chatId: string,
        actorId: string,
        expectedEpoch: number,
        record: GroupChatRecord,
    ): Promise<'updated' | 'not_found' | 'forbidden' | 'conflict'>;
    hasGroupChatMembership(chatId: string, userId: string): Promise<boolean>;
    appendGroupChatEvent(event: NewGroupChatEvent): Promise<GroupChatEventAppendResult>;
    listGroupChatEvents(
        chatId: string,
        userId: string,
        after: number,
        limit: number,
    ): Promise<GroupChatEventRecord[] | null>;
    watchGroupChatEvents(listener: GroupChatEventListener): () => void;
}

