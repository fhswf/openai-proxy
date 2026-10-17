import { Readable } from 'node:stream';
import type {
    ChatEnvelopeRecord,
    ChatRecord,
    ChatSummary,
    ZkAttachmentDownload,
    PendingChallengeRecord,
    UserCredentialRecord,
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
    private userKeysByCredential = new Map<string, UserCredentialRecord>();
    private challenges = new Map<string, PendingChallengeRecord>();
    private chats = new Map<string, ChatRecord>();
    private envelopes = new Map<string, ChatEnvelopeRecord>();
    private attachments = new Map<string, Buffer>();

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

    async getUserCredentialById(credentialId: string): Promise<UserCredentialRecord | null> {
        const record = this.userKeysByCredential.get(credentialId);
        return record ? clone(record) : null;
    }

    async upsertUserKeys(record: UserKeysRecord): Promise<void> {
        const existing = this.userKeysById.get(record.userId);
        for (const credential of record.credentials) {
            const owner = this.userKeysByCredential.get(credential.credentialId);
            if (owner && owner.userKeys.userId !== record.userId) {
                throw new Error('Credential already registered to another user');
            }
        }

        const stored: UserKeysRecord = {
            ...record,
            credentials: record.credentials.map(credential => ({ ...credential })),
            createdAt: existing?.createdAt ?? record.createdAt,
            updatedAt: record.updatedAt,
        };

        for (const credential of existing?.credentials ?? []) {
            this.userKeysByCredential.delete(credential.credentialId);
        }
        this.userKeysById.set(stored.userId, stored);
        for (const credential of stored.credentials) {
            this.userKeysByCredential.set(credential.credentialId, {
                userKeys: stored,
                credential,
            });
        }
    }

    async deleteUserKeys(userId: string): Promise<void> {
        const existing = this.userKeysById.get(userId);
        if (!existing) return;
        this.userKeysById.delete(userId);
        for (const credential of existing.credentials) {
            this.userKeysByCredential.delete(credential.credentialId);
        }
    }

    async deleteUserCredential(userId: string, credentialId: string): Promise<void> {
        const existing = this.userKeysById.get(userId);
        if (!existing) return;
        const credential = existing.credentials.find(item => item.credentialId === credentialId);
        if (!credential) return;
        existing.credentials = existing.credentials.filter(item => item.credentialId !== credentialId);
        this.userKeysByCredential.delete(credentialId);
        for (const item of existing.credentials) {
            this.userKeysByCredential.set(item.credentialId, {
                userKeys: existing,
                credential: item,
            });
        }
    }

    async renameUserCredential(userId: string, credentialId: string, name: string, at: Date): Promise<void> {
        const record = this.userKeysById.get(userId);
        const credential = record?.credentials.find(item => item.credentialId === credentialId);
        if (!record || !credential) return;
        credential.name = name;
        credential.updatedAt = at;
        record.updatedAt = at;
    }

    async markAsserted(userId: string, credentialId: string, at: Date): Promise<void> {
        const record = this.userKeysById.get(userId);
        if (record) {
            const credential = record.credentials.find(item => item.credentialId === credentialId);
            if (credential) credential.assertedAt = at;
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
        await this.deleteAttachmentsForChat(id);
    }

    private attachmentKey(chatId: string, attachmentId: string) {
        return `${chatId}\u0000${attachmentId}`;
    }

    async putAttachment(chatId: string, attachmentId: string, source: Readable): Promise<void> {
        const chunks: Buffer[] = [];
        for await (const chunk of source) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        this.attachments.set(this.attachmentKey(chatId, attachmentId), Buffer.concat(chunks));
    }

    async getAttachment(chatId: string, attachmentId: string): Promise<ZkAttachmentDownload | null> {
        const data = this.attachments.get(this.attachmentKey(chatId, attachmentId));
        return data ? { stream: Readable.from([data]), size: data.length } : null;
    }

    async hasAttachment(chatId: string, attachmentId: string): Promise<boolean> {
        return this.attachments.has(this.attachmentKey(chatId, attachmentId));
    }

    async deleteAttachment(chatId: string, attachmentId: string): Promise<void> {
        this.attachments.delete(this.attachmentKey(chatId, attachmentId));
    }

    async deleteAttachmentsForChat(chatId: string): Promise<void> {
        const prefix = `${chatId}\u0000`;
        for (const key of this.attachments.keys()) {
            if (key.startsWith(prefix)) this.attachments.delete(key);
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
