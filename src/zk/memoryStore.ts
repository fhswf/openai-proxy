import { Readable } from 'node:stream';
import type {
    ChatEnvelopeRecord,
    ChatRecord,
    ChatShareLinkRecord,
    ChatSummary,
    GroupCatalogRecord,
    GroupChatRecord,
    GroupChatEventRecord,
    GroupChatEventAppendResult,
    NewGroupChatEvent,
    ZkAttachmentDownload,
    PendingChallengeRecord,
    UserCredentialRecord,
    UserKeysRecord,
    UserIdentityClaims,
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
    private chatShareLinks = new Map<string, ChatShareLinkRecord>();
    private groupCatalogs = new Map<string, GroupCatalogRecord>();
    private groupChats = new Map<string, GroupChatRecord>();
    private groupChatEvents = new Map<string, GroupChatEventRecord[]>();

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
        if (existing) {
            this.userKeysById.delete(userId);
            for (const credential of existing.credentials) {
                this.userKeysByCredential.delete(credential.credentialId);
            }
        }
        for (const [tokenHash, link] of this.chatShareLinks) {
            if (link.ownerId === userId) this.chatShareLinks.delete(tokenHash);
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

    async updateUserIdentity(userId: string, identity: UserIdentityClaims | null): Promise<void> {
        const record = this.userKeysById.get(userId);
        if (record) record.identity = identity ? clone(identity) : null;
    }

    async markAsserted(userId: string, credentialId: string, at: Date, rpId: string): Promise<void> {
        const record = this.userKeysById.get(userId);
        if (record) {
            const credential = record.credentials.find(item => item.credentialId === credentialId);
            if (credential) {
                credential.assertedAt = at;
                credential.rpId = rpId;
            }
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

    async findUserKeysByEmail(email: string): Promise<UserKeysRecord | null> {
        const normalizedEmail = email.toLowerCase();
        for (const record of this.userKeysById.values()) {
            if (
                record.identity?.emailVerified === true &&
                record.identity.email?.toLowerCase() === normalizedEmail
            ) {
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
        const summaries = new Map<string, ChatSummary>();
        for (const envelope of this.envelopes.values()) {
            if (envelope.recipient_id !== recipientId) {
                continue;
            }

            const group = this.groupChats.get(envelope.chat_id);
            if (group && !group.members.some(member => member.userId === recipientId)) {
                continue;
            }

            const chat = this.chats.get(envelope.chat_id);
            if (!chat) {
                continue;
            }

            summaries.set(chat.id, {
                id: chat.id,
                ownerId: chat.ownerId,
                updatedAt: chat.updatedAt,
                rev: chat.rev,
            });
        }

        for (const group of this.groupChats.values()) {
            if (!group.members.some(member => member.userId === recipientId)) continue;
            const chat = this.chats.get(group.chatId);
            if (!chat) continue;
            summaries.set(chat.id, {
                id: chat.id,
                ownerId: chat.ownerId,
                updatedAt: group.updatedAt,
                rev: chat.rev,
            });
        }

        return [...summaries.values()].sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
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
        this.groupChats.delete(id);
        this.groupChatEvents.delete(id);
        for (const [key, envelope] of this.envelopes.entries()) {
            if (envelope.chat_id === id) {
                this.envelopes.delete(key);
            }
        }
        await this.deleteAttachmentsForChat(id);
        await this.deleteChatShareLinksForChat(id);
    }

    async saveChatShareLink(record: ChatShareLinkRecord): Promise<void> {
        this.chatShareLinks.set(record.tokenHash, clone(record));
    }

    async getChatShareLink(tokenHash: string): Promise<ChatShareLinkRecord | null> {
        const record = this.chatShareLinks.get(tokenHash);
        return record ? clone(record) : null;
    }

    async deleteChatShareLink(tokenHash: string): Promise<void> {
        this.chatShareLinks.delete(tokenHash);
    }

    async deleteChatShareLinksForChat(chatId: string): Promise<void> {
        for (const [tokenHash, record] of this.chatShareLinks) {
            if (record.chatId === chatId) this.chatShareLinks.delete(tokenHash);
        }
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
        const group = this.groupChats.get(chatId);
        if (group) {
            return group.envelopes
                .filter(envelope => envelope.epoch === group.currentEpoch)
                .map(envelope => ({
                    chat_id: chatId,
                    recipient_id: envelope.recipientId,
                    envelope_algorithm: envelope.envelope_algorithm,
                    ephemeral_public_key: envelope.ephemeral_public_key,
                    wrapped_key: envelope.wrapped_key,
                    wrapped_key_iv: envelope.wrapped_key_iv,
                    is_owner: envelope.recipientId === group.ownerId,
                    created_at: envelope.created_at,
                    epoch: envelope.epoch,
                }));
        }

        const result: ChatEnvelopeRecord[] = [];
        for (const envelope of this.envelopes.values()) {
            if (envelope.chat_id === chatId) {
                result.push(clone(envelope));
            }
        }

        return result;
    }

    async getEnvelope(chatId: string, recipientId: string): Promise<ChatEnvelopeRecord | null> {
        const group = this.groupChats.get(chatId);
        if (group) {
            const envelope = group.envelopes.find(item =>
                item.epoch === group.currentEpoch && item.recipientId === recipientId,
            );
            return envelope ? {
                chat_id: chatId,
                recipient_id: recipientId,
                envelope_algorithm: envelope.envelope_algorithm,
                ephemeral_public_key: envelope.ephemeral_public_key,
                wrapped_key: envelope.wrapped_key,
                wrapped_key_iv: envelope.wrapped_key_iv,
                is_owner: recipientId === group.ownerId,
                created_at: envelope.created_at,
                epoch: envelope.epoch,
            } : null;
        }
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
        const group = this.groupChats.get(chatId);
        if (group) {
            return group.members.some(member => member.userId === recipientId);
        }
        return this.envelopes.has(this.envelopeKey(chatId, recipientId));
    }

    async getGroupCatalog(userId: string): Promise<GroupCatalogRecord | null> {
        const record = this.groupCatalogs.get(userId);
        return record ? clone(record) : null;
    }

    async putGroupCatalog(record: GroupCatalogRecord, baseRev?: number | null): Promise<'created' | 'updated' | 'conflict'> {
        const existing = this.groupCatalogs.get(record.userId);
        if (existing && baseRev != null && existing.rev !== baseRev) return 'conflict';
        if (existing && baseRev == null) return 'conflict';
        if (!existing && baseRev != null && baseRev !== 0) return 'conflict';
        this.groupCatalogs.set(record.userId, clone({
            ...record,
            rev: existing ? existing.rev + 1 : 1,
            updatedAt: record.updatedAt,
        }));
        return existing ? 'updated' : 'created';
    }

    async getGroupChat(chatId: string): Promise<GroupChatRecord | null> {
        const record = this.groupChats.get(chatId);
        return record ? clone(record) : null;
    }

    async createGroupChat(record: GroupChatRecord): Promise<'created' | 'exists' | 'not_found' | 'forbidden'> {
        const chat = this.chats.get(record.chatId);
        if (!chat) return 'not_found';
        if (chat.ownerId !== record.ownerId) return 'forbidden';
        if (this.groupChats.has(record.chatId)) return 'exists';
        this.groupChats.set(record.chatId, clone(record));
        return 'created';
    }

    async replaceGroupChatMembership(
        chatId: string,
        actorId: string,
        expectedEpoch: number,
        record: GroupChatRecord,
    ): Promise<'updated' | 'not_found' | 'forbidden' | 'conflict'> {
        const existing = this.groupChats.get(chatId);
        if (!existing) return 'not_found';
        if (existing.ownerId !== actorId) return 'forbidden';
        if (existing.currentEpoch !== expectedEpoch || record.currentEpoch !== expectedEpoch + 1) return 'conflict';
        this.groupChats.set(chatId, clone({
            ...record,
            chatId,
            ownerId: existing.ownerId,
            committedSequence: existing.committedSequence,
            createdAt: existing.createdAt,
        }));
        return 'updated';
    }

    async hasGroupChatMembership(chatId: string, userId: string): Promise<boolean> {
        return Boolean(this.groupChats.get(chatId)?.members.some(member => member.userId === userId));
    }

    async appendGroupChatEvent(event: NewGroupChatEvent): Promise<GroupChatEventAppendResult> {
        const group = this.groupChats.get(event.chatId);
        if (!group) return { status: 'not_found' };
        if (!group.members.some(member => member.userId === event.actorId)) return { status: 'forbidden' };

        const events = this.groupChatEvents.get(event.chatId) ?? [];
        const existing = events.find(item => item.eventId === event.eventId);
        if (existing) {
            return existing.actorId === event.actorId
                ? { status: 'existing', event: clone(existing) }
                : { status: 'conflict' };
        }
        if (event.epoch !== group.currentEpoch) return { status: 'conflict' };

        const stored: GroupChatEventRecord = {
            ...event,
            sequence: group.committedSequence + 1,
        };
        group.committedSequence = stored.sequence;
        events.push(stored);
        this.groupChatEvents.set(event.chatId, events);
        group.updatedAt = event.createdAt;
        return { status: 'created', event: clone(stored) };
    }

    async listGroupChatEvents(
        chatId: string,
        userId: string,
        after: number,
        limit: number,
    ): Promise<GroupChatEventRecord[] | null> {
        const group = this.groupChats.get(chatId);
        if (!group?.members.some(member => member.userId === userId)) return null;
        return clone((this.groupChatEvents.get(chatId) ?? [])
            .filter(event => event.sequence > after && event.sequence <= group.committedSequence)
            .slice(0, limit));
    }

    watchGroupChatEvents(_listener: (event: GroupChatEventRecord) => void): () => void {
        // The development store is process-local, so the router publishes
        // directly to its in-process event bus after each append.
        return () => undefined;
    }
}
