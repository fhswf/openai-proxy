import type { Collection, Db } from 'mongodb';
import type {
    ChatEnvelopeRecord,
    ChatRecord,
    ChatSummary,
    PendingChallengeRecord,
    UserKeysRecord,
    ZkStore,
} from './types.ts';

interface UserKeysDoc {
    _id: string;
    credential_id: string;
    credential_public_key: string;
    public_key_algorithm?: 'RSA-OAEP-SHA256' | 'ECDH-P256';
    public_key: string;
    encrypted_sk: string;
    encrypted_sk_iv: string;
    asserted_at: Date | null;
    created_at: Date;
    updated_at: Date;
}

interface ChallengeDoc {
    _id: string;
    kind: 'registration' | 'assertion';
    credential_id: string | null;
    user_id: string | null;
    expires_at: Date;
}

interface ChatDoc {
    _id: string;
    owner_id: string;
    ciphertext: string;
    iv: string;
    metadata_ct: string | null;
    metadata_iv: string | null;
    rev: number;
    created_at: Date;
    updated_at: Date;
}

interface ChatKeyDoc {
    chat_id: string;
    recipient_id: string;
    envelope_algorithm?: 'RSA-OAEP-SHA256' | 'ECDH-P256-HKDF-SHA256-AES-256-GCM';
    ephemeral_public_key?: string | null;
    wrapped_key: string;
    wrapped_key_iv: string | null;
    is_owner: boolean;
    created_at: Date;
}

const chatKeyKey = (chatId: string, recipientId: string) => ({ chat_id: chatId, recipient_id: recipientId });

/**
 * MongoDB-backed {@link ZkStore}. Collections follow the data model in the
 * issue: `user_keys`, `chats`, `chat_keys` and a short-lived `zk_challenges`.
 */
export class MongoZkStore implements ZkStore {
    private readonly getDb: () => Db;

    constructor(getDb: () => Db) {
        this.getDb = getDb;
    }

    private users(): Collection<UserKeysDoc> {
        return this.getDb().collection<UserKeysDoc>('user_keys');
    }

    private challenges(): Collection<ChallengeDoc> {
        return this.getDb().collection<ChallengeDoc>('zk_challenges');
    }

    private chatsCollection(): Collection<ChatDoc> {
        return this.getDb().collection<ChatDoc>('chats');
    }

    private chatKeys(): Collection<ChatKeyDoc> {
        return this.getDb().collection<ChatKeyDoc>('chat_keys');
    }

    async init(): Promise<void> {
        await this.users().createIndex({ credential_id: 1 }, { unique: true });
        await this.chatsCollection().createIndex({ owner_id: 1, updated_at: -1 });
        await this.chatKeys().createIndex({ recipient_id: 1 });
        await this.chatKeys().createIndex({ chat_id: 1, recipient_id: 1 }, { unique: true });
        // Expire abandoned challenges so they never linger as replay material.
        await this.challenges().createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });
    }

    private toUserKeys(doc: UserKeysDoc | null): UserKeysRecord | null {
        if (!doc) {
            return null;
        }

        return {
            userId: doc._id,
            credentialId: doc.credential_id,
            credentialPublicKey: doc.credential_public_key,
            // Documents created before algorithm metadata used RSA-OAEP.
            publicKeyAlgorithm: doc.public_key_algorithm ?? 'RSA-OAEP-SHA256',
            publicKey: doc.public_key,
            encryptedSk: doc.encrypted_sk,
            encryptedSkIv: doc.encrypted_sk_iv,
            assertedAt: doc.asserted_at ?? null,
            createdAt: doc.created_at,
            updatedAt: doc.updated_at,
        };
    }

    async getUserKeysByUserId(userId: string): Promise<UserKeysRecord | null> {
        return this.toUserKeys(await this.users().findOne({ _id: userId }));
    }

    async getUserKeysByCredentialId(credentialId: string): Promise<UserKeysRecord | null> {
        return this.toUserKeys(await this.users().findOne({ credential_id: credentialId }));
    }

    async findUserKeysByPublicKey(publicKey: string): Promise<UserKeysRecord | null> {
        return this.toUserKeys(await this.users().findOne({ public_key: publicKey }));
    }

    async upsertUserKeys(record: UserKeysRecord): Promise<void> {
        const existing = await this.users().findOne({ _id: record.userId });
        await this.users().updateOne(
            { _id: record.userId },
            {
                $set: {
                    credential_id: record.credentialId,
                    credential_public_key: record.credentialPublicKey,
                    public_key_algorithm: record.publicKeyAlgorithm,
                    public_key: record.publicKey,
                    encrypted_sk: record.encryptedSk,
                    encrypted_sk_iv: record.encryptedSkIv,
                    asserted_at: record.assertedAt,
                    updated_at: record.updatedAt,
                },
                $setOnInsert: {
                    created_at: existing?.created_at ?? record.createdAt,
                },
            },
            { upsert: true },
        );
    }

    async deleteUserKeys(userId: string): Promise<void> {
        await this.users().deleteOne({ _id: userId });
    }

    async markAsserted(userId: string, at: Date): Promise<void> {
        await this.users().updateOne({ _id: userId }, { $set: { asserted_at: at } });
    }

    async saveChallenge(record: PendingChallengeRecord): Promise<void> {
        await this.challenges().deleteMany({ expires_at: { $lte: new Date() } });
        await this.challenges().insertOne({
            _id: record.challenge,
            kind: record.kind,
            credential_id: record.credentialId,
            user_id: record.userId,
            expires_at: record.expiresAt,
        });
    }

    async takeChallenge(challenge: string): Promise<PendingChallengeRecord | null> {
        // findOneAndDelete makes the challenge single-use.
        const doc = await this.challenges().findOneAndDelete({ _id: challenge });
        if (!doc || doc.expires_at.getTime() <= Date.now()) {
            return null;
        }

        return {
            challenge: doc._id,
            kind: doc.kind,
            credentialId: doc.credential_id,
            userId: doc.user_id,
            expiresAt: doc.expires_at,
        };
    }

    async listChatsForRecipient(recipientId: string): Promise<ChatSummary[]> {
        const envelopes = await this.chatKeys().find({ recipient_id: recipientId }).toArray();
        const chatIds = envelopes.map(envelope => envelope.chat_id);
        if (chatIds.length === 0) {
            return [];
        }

        const docs = await this.chatsCollection().find({ _id: { $in: chatIds } }).toArray();
        return docs
            .map(doc => ({
                id: doc._id,
                ownerId: doc.owner_id,
                updatedAt: doc.updated_at,
                rev: doc.rev,
            }))
            .sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
    }

    async getChat(id: string): Promise<ChatRecord | null> {
        const doc = await this.chatsCollection().findOne({ _id: id });
        if (!doc) {
            return null;
        }

        return {
            id: doc._id,
            ownerId: doc.owner_id,
            ciphertext: doc.ciphertext,
            iv: doc.iv,
            metadataCt: doc.metadata_ct,
            metadataIv: doc.metadata_iv,
            rev: doc.rev,
            createdAt: doc.created_at,
            updatedAt: doc.updated_at,
        };
    }

    async upsertChat(
        record: ChatRecord,
        selfEnvelope: ChatEnvelopeRecord,
        baseRev?: number | null,
    ): Promise<'created' | 'updated' | 'conflict'> {
        const existing = await this.chatsCollection().findOne({ _id: record.id });

        if (existing && existing.owner_id !== record.ownerId) {
            return 'conflict';
        }

        if (existing && baseRev != null && existing.rev !== baseRev) {
            return 'conflict';
        }

        const rev = existing ? existing.rev + 1 : 1;
        const now = new Date();
        await this.chatsCollection().updateOne(
            { _id: record.id },
            {
                $set: {
                    owner_id: record.ownerId,
                    ciphertext: record.ciphertext,
                    iv: record.iv,
                    metadata_ct: record.metadataCt,
                    metadata_iv: record.metadataIv,
                    rev,
                    updated_at: now,
                },
                $setOnInsert: { created_at: existing?.created_at ?? record.createdAt },
            },
            { upsert: true },
        );

        await this.upsertEnvelope({ ...selfEnvelope, chat_id: record.id, created_at: selfEnvelope.created_at ?? now });
        return existing ? 'updated' : 'created';
    }

    async deleteChat(id: string): Promise<void> {
        await this.chatsCollection().deleteOne({ _id: id });
        await this.chatKeys().deleteMany({ chat_id: id });
    }

    async listEnvelopes(chatId: string): Promise<ChatEnvelopeRecord[]> {
        const docs = await this.chatKeys().find({ chat_id: chatId }).toArray();
        return docs.map(doc => ({
            chat_id: doc.chat_id,
            recipient_id: doc.recipient_id,
            envelope_algorithm: doc.envelope_algorithm ?? 'RSA-OAEP-SHA256',
            ephemeral_public_key: doc.ephemeral_public_key ?? null,
            wrapped_key: doc.wrapped_key,
            wrapped_key_iv: doc.wrapped_key_iv,
            is_owner: doc.is_owner,
            created_at: doc.created_at,
        }));
    }

    async getEnvelope(chatId: string, recipientId: string): Promise<ChatEnvelopeRecord | null> {
        const doc = await this.chatKeys().findOne(chatKeyKey(chatId, recipientId));
        if (!doc) {
            return null;
        }

        return {
            chat_id: doc.chat_id,
            recipient_id: doc.recipient_id,
            envelope_algorithm: doc.envelope_algorithm ?? 'RSA-OAEP-SHA256',
            ephemeral_public_key: doc.ephemeral_public_key ?? null,
            wrapped_key: doc.wrapped_key,
            wrapped_key_iv: doc.wrapped_key_iv,
            is_owner: doc.is_owner,
            created_at: doc.created_at,
        };
    }

    async upsertEnvelope(record: ChatEnvelopeRecord): Promise<void> {
        await this.chatKeys().updateOne(
            chatKeyKey(record.chat_id, record.recipient_id),
            {
                $set: {
                    envelope_algorithm: record.envelope_algorithm,
                    ephemeral_public_key: record.ephemeral_public_key,
                    wrapped_key: record.wrapped_key,
                    wrapped_key_iv: record.wrapped_key_iv,
                    is_owner: record.is_owner,
                },
                $setOnInsert: { created_at: record.created_at },
            },
            { upsert: true },
        );
    }

    async deleteEnvelope(chatId: string, recipientId: string): Promise<void> {
        await this.chatKeys().deleteOne(chatKeyKey(chatId, recipientId));
    }

    async hasEnvelope(chatId: string, recipientId: string): Promise<boolean> {
        const count = await this.chatKeys().countDocuments(chatKeyKey(chatId, recipientId), { limit: 1 });
        return count > 0;
    }
}
