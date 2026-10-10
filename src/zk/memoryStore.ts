import type {
    ChatEnvelopeRecord,
    ChatRecord,
    ChatSummary,
    PendingChallengeRecord,
    UserKeysRecord,
    ZkStore,
} from './types.ts';

const clone = <T>(value: T): T => structuredClone(value);

/**
 * In-memory {@link ZkStore} used for local development and tests. It enforces
 * the same invariants as the Mongo implementation so the router behaves
 * identically regardless of the backing store.
 */
export class MemoryZkStore implements ZkStore {
    private userKeysById = new Map<string, UserKeysRecord>();
    private userKeysByCredential = new Map<string, UserKeysRecord>();
    private challenges = new Map<string, PendingChallengeRecord>();
    private chats = new Map<string, ChatRecord>();
    private envelopes = new Map<string, ChatEnvelopeRecord>();

    async init(): Promise<void> {
        // Nothing to initialise for the in-memory store.
    }

    private envelopeKey(chatId: string, recipientId: string) {
        return `${chatId}\u0000${recipientId}`;
    }

    async getUserKeysByUserId(userId: string): Promise<UserKeysRecord | null> {
        const record = this.userKeysById.get(userId);
        return record ? clone(record) : null;
    }

    async getUserKeysByCredentialId(credentialId: string): Promise<UserKeysRecord | null> {
        const record = this.userKeysByCredential.get(credentialId);
        return record ? clone(record) : null;
    }

    async upsertUserKeys(record: UserKeysRecord): Promise<void> {
        const existing = this.userKeysById.get(record.userId);
        const stored: UserKeysRecord = {
            ...record,
            createdAt: existing?.createdAt ?? record.createdAt,
            updatedAt: record.updatedAt,
        };
        this.userKeysById.set(stored.userId, stored);
        this.userKeysByCredential.set(stored.credentialId, stored);
    }

    async markAsserted(userId: string, at: Date): Promise<void> {
        const record = this.userKeysById.get(userId);
        if (record) {
            record.assertedAt = at;
        }
    }

    async findUserKeysByPublicKey(publicKey: string): Promise<UserKeysRecord | null> {
        for (const record of this.userKeysById.values()) {
            if (record.publicKey === publicKey) {
                return clone(record);
            }
        }

        return null;
    }

    async saveChallenge(record: PendingChallengeRecord): Promise<void> {
        const now = Date.now();
        for (const [key, value] of this.challenges.entries()) {
            if (value.expiresAt.getTime() <= now) {
                this.challenges.delete(key);
            }
        }
        this.challenges.set(record.challenge, clone(record));
    }

    async takeChallenge(challenge: string): Promise<PendingChallengeRecord | null> {
        const record = this.challenges.get(challenge);
        if (!record) {
            return null;
        }

        this.challenges.delete(challenge);
        if (record.expiresAt.getTime() <= Date.now()) {
            return null;
        }

        return clone(record);
    }

    async listChatsForRecipient(recipientId: string): Promise<ChatSummary[]> {
        const summaries: ChatSummary[] = [];
        for (const envelope of this.envelopes.values()) {
            if (envelope.recipient_id !== recipientId) {
                continue;
            }

            const chat = this.chats.get(envelope.chat_id);
            if (!chat) {
                continue;
            }

            summaries.push({
                id: chat.id,
                ownerId: chat.ownerId,
                updatedAt: chat.updatedAt,
                rev: chat.rev,
            });
        }

        summaries.sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
        return summaries;
    }

    async getChat(id: string): Promise<ChatRecord | null> {
        const record = this.chats.get(id);
        return record ? clone(record) : null;
    }

    async upsertChat(
        record: ChatRecord,
        selfEnvelope: ChatEnvelopeRecord,
        baseRev?: number | null,
    ): Promise<'created' | 'updated' | 'conflict'> {
        const existing = this.chats.get(record.id);

        if (existing) {
            if (existing.ownerId !== record.ownerId) {
                return 'conflict';
            }

            if (baseRev != null && existing.rev !== baseRev) {
                return 'conflict';
            }

            const updated: ChatRecord = {
                ...record,
                rev: existing.rev + 1,
                createdAt: existing.createdAt,
                updatedAt: record.updatedAt,
            };
            this.chats.set(updated.id, updated);
            this.envelopes.set(
                this.envelopeKey(updated.id, selfEnvelope.recipient_id),
                clone(selfEnvelope),
            );
            return 'updated';
        }

        const created: ChatRecord = { ...record, rev: 1 };
        this.chats.set(created.id, created);
        this.envelopes.set(
            this.envelopeKey(created.id, selfEnvelope.recipient_id),
            clone(selfEnvelope),
        );
        return 'created';
    }

    async deleteChat(id: string): Promise<void> {
        this.chats.delete(id);
        for (const [key, envelope] of this.envelopes.entries()) {
            if (envelope.chat_id === id) {
                this.envelopes.delete(key);
            }
        }
    }

    async listEnvelopes(chatId: string): Promise<ChatEnvelopeRecord[]> {
        const result: ChatEnvelopeRecord[] = [];
        for (const envelope of this.envelopes.values()) {
            if (envelope.chat_id === chatId) {
                result.push(clone(envelope));
            }
        }

        return result;
    }

    async getEnvelope(chatId: string, recipientId: string): Promise<ChatEnvelopeRecord | null> {
        const record = this.envelopes.get(this.envelopeKey(chatId, recipientId));
        return record ? clone(record) : null;
    }

    async upsertEnvelope(record: ChatEnvelopeRecord): Promise<void> {
        this.envelopes.set(this.envelopeKey(record.chat_id, record.recipient_id), clone(record));
    }

    async deleteEnvelope(chatId: string, recipientId: string): Promise<void> {
        this.envelopes.delete(this.envelopeKey(chatId, recipientId));
    }

    async hasEnvelope(chatId: string, recipientId: string): Promise<boolean> {
        return this.envelopes.has(this.envelopeKey(chatId, recipientId));
    }
}
