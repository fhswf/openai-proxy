import { GridFSBucket, type Collection, type Db, type FindCursor } from 'mongodb';
import { randomUUID } from 'node:crypto';
import type { Readable } from 'node:stream';
import type {
    ChatEnvelopeRecord,
    ChatRecord,
    ChatShareLinkRecord,
    ChatSummary,
    GroupCatalogRecord,
    GroupChatRecord,
    GroupChatEventRecord,
    GroupChatEventListener,
    GroupChatEventAppendResult,
    NewGroupChatEvent,
    PendingChallengeRecord,
    UserCredentialRecord,
    UserKeysRecord,
    UserIdentityClaims,
    ZkAttachmentDownload,
    ZkStore,
} from './types.ts';

interface UserKeysDoc {
    _id: string;
    credentials?: UserPasskeyDoc[];
    // Legacy mirror fields are retained for rolling compatibility with older
    // proxy instances while a deployment is being upgraded.
    credential_id?: string;
    credential_public_key?: string;
    public_key_algorithm?: 'RSA-OAEP-SHA256' | 'ECDH-P256';
    public_key: string;
    identity_claims?: UserKeysRecord['identity'];
    encrypted_sk?: string;
    encrypted_sk_iv?: string;
    asserted_at?: Date | null;
    created_at: Date;
    updated_at: Date;
}

interface UserPasskeyDoc {
    credential_id: string;
    name: string;
    rp_id?: string | null;
    credential_public_key: string;
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
    rp_id?: string | null;
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

interface ChatShareLinkDoc {
    _id: string;
    chat_id: string;
    owner_id: string;
    created_at: Date;
    expires_at: Date;
}

interface GroupCatalogDoc {
    _id: string;
    ciphertext: string;
    iv: string;
    envelope_algorithm: GroupCatalogRecord['envelope']['envelope_algorithm'];
    ephemeral_public_key: string | null;
    wrapped_key: string;
    wrapped_key_iv: string | null;
    rev: number;
    updated_at: Date;
}

interface GroupChatMemberDoc {
    user_id: string;
    role: 'owner' | 'member';
}

interface GroupChatEnvelopeDoc {
    recipient_id: string;
    epoch: number;
    envelope_algorithm: GroupChatRecord['envelopes'][number]['envelope_algorithm'];
    ephemeral_public_key: string | null;
    wrapped_key: string;
    wrapped_key_iv: string | null;
    created_at: Date;
}

interface GroupChatDoc {
    _id: string;
    owner_id: string;
    current_epoch: number;
    committed_sequence: number;
    members: GroupChatMemberDoc[];
    envelopes: GroupChatEnvelopeDoc[];
    created_at: Date;
    updated_at: Date;
}

interface GroupChatEventDoc {
    chat_id: string;
    sequence: number;
    event_id: string;
    actor_id: string;
    epoch: number;
    ciphertext: string;
    iv: string;
    created_at: Date;
}

interface GroupChatNotificationDoc extends GroupChatEventDoc {
    origin_id: string;
    published_at: Date;
}

const chatKeyKey = (chatId: string, recipientId: string) => ({ chat_id: chatId, recipient_id: recipientId });

/**
 * MongoDB-backed {@link ZkStore}. Collections store user keys, chats, group
 * catalogs, group membership, durable events, and short-lived challenges.
 */
export class MongoZkStore implements ZkStore {
    private readonly getDb: () => Db;
    private readonly instanceId = randomUUID();

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

    private chatShareLinks(): Collection<ChatShareLinkDoc> {
        return this.getDb().collection<ChatShareLinkDoc>('zk_chat_share_links');
    }

    private groupCatalogs(): Collection<GroupCatalogDoc> {
        return this.getDb().collection<GroupCatalogDoc>('zk_group_catalogs');
    }

    private groupChats(): Collection<GroupChatDoc> {
        return this.getDb().collection<GroupChatDoc>('zk_group_chats');
    }

    private groupChatEvents(): Collection<GroupChatEventDoc> {
        return this.getDb().collection<GroupChatEventDoc>('zk_group_chat_events');
    }

    private groupChatNotifications(): Collection<GroupChatNotificationDoc> {
        return this.getDb().collection<GroupChatNotificationDoc>('zk_group_chat_notifications');
    }

    private attachments(): GridFSBucket {
        return new GridFSBucket(this.getDb(), { bucketName: 'zk_attachments' });
    }

    async init(): Promise<void> {
        await this.users().createIndex({ credential_id: 1 }, { unique: true });
        await this.users().createIndex({ 'credentials.credential_id': 1 }, { unique: true });
        await this.chatsCollection().createIndex({ owner_id: 1, updated_at: -1 });
        await this.chatKeys().createIndex({ recipient_id: 1 });
        await this.chatKeys().createIndex({ chat_id: 1, recipient_id: 1 }, { unique: true });
        await this.groupChats().createIndex({ 'members.user_id': 1 });
        await this.groupChatEvents().createIndex({ chat_id: 1, event_id: 1 }, { unique: true });
        await this.groupChatEvents().createIndex({ chat_id: 1, sequence: 1 }, { unique: true });
        const notificationCollectionExists = await this.getDb()
            .listCollections({ name: 'zk_group_chat_notifications', type: 'collection' })
            .hasNext();
        if (!notificationCollectionExists) {
            try {
                await this.getDb().createCollection('zk_group_chat_notifications', {
                    capped: true,
                    size: 32 * 1024 * 1024,
                    max: 100_000,
                });
            } catch (error) {
                // Another proxy replica may have created the capped outbox
                // during startup.
                if ((error as { code?: number }).code !== 48) throw error;
            }
        }
        await this.chatShareLinks().createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });
        await this.getDb().collection('zk_attachments.files').createIndex({
            'metadata.chatId': 1,
            'metadata.attachmentId': 1,
            uploadDate: -1,
        });
        // Expire abandoned challenges so they never linger as replay material.
        await this.challenges().createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 });

        // Upgrade existing single-credential documents in place. Keep the old
        // flat fields as a mirror so older instances can continue reading them
        // during a rolling deployment.
        const legacyDocs = await this.users().find({ credentials: { $exists: false } }).toArray();
        for (const doc of legacyDocs) {
            const record = this.toUserKeys(doc);
            if (record) await this.upsertUserKeys(record);
        }
    }

    private toUserKeys(doc: UserKeysDoc | null): UserKeysRecord | null {
        if (!doc) {
            return null;
        }

        return {
            userId: doc._id,
            // Documents created before algorithm metadata used RSA-OAEP.
            publicKeyAlgorithm: doc.public_key_algorithm ?? 'RSA-OAEP-SHA256',
            publicKey: doc.public_key,
            identity: doc.identity_claims ?? null,
            credentials: doc.credentials?.map(credential => ({
                credentialId: credential.credential_id,
                name: credential.name || 'Passkey',
                rpId: credential.rp_id ?? null,
                credentialPublicKey: credential.credential_public_key,
                encryptedSk: credential.encrypted_sk,
                encryptedSkIv: credential.encrypted_sk_iv,
                assertedAt: credential.asserted_at ?? null,
                createdAt: credential.created_at,
                updatedAt: credential.updated_at,
            })) ?? (doc.credential_id && doc.credential_public_key && doc.encrypted_sk && doc.encrypted_sk_iv
                ? [{
                    credentialId: doc.credential_id,
                    name: 'Passkey',
                    rpId: null,
                    credentialPublicKey: doc.credential_public_key,
                    encryptedSk: doc.encrypted_sk,
                    encryptedSkIv: doc.encrypted_sk_iv,
                    assertedAt: doc.asserted_at ?? null,
                    createdAt: doc.created_at,
                    updatedAt: doc.updated_at,
                }]
                : []),
            createdAt: doc.created_at,
            updatedAt: doc.updated_at,
        };
    }

    async getUserKeysByUserId(userId: string): Promise<UserKeysRecord | null> {
        return this.toUserKeys(await this.users().findOne({ _id: userId }));
    }

    async getUserCredentialById(credentialId: string): Promise<UserCredentialRecord | null> {
        const doc = await this.users().findOne({
            $or: [
                { 'credentials.credential_id': credentialId },
                { credential_id: credentialId },
            ],
        });
        const userKeys = this.toUserKeys(doc);
        if (!userKeys) return null;
        const credential = userKeys.credentials.find(item => item.credentialId === credentialId);
        return credential ? { userKeys, credential } : null;
    }

    async findUserKeysByPublicKey(publicKey: string): Promise<UserKeysRecord | null> {
        return this.toUserKeys(await this.users().findOne({ public_key: publicKey }));
    }

    async findUserKeysByEmail(email: string): Promise<UserKeysRecord | null> {
        const escapedEmail = email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return this.toUserKeys(await this.users().findOne({
            'identity_claims.email': { $regex: `^${escapedEmail}$`, $options: 'i' },
            'identity_claims.emailVerified': true,
        }));
    }

    async upsertUserKeys(record: UserKeysRecord): Promise<void> {
        const existing = await this.users().findOne({ _id: record.userId });
        const firstCredential = record.credentials[0];
        await this.users().updateOne(
            { _id: record.userId },
            {
                $set: {
                    credentials: record.credentials.map(credential => ({
                        credential_id: credential.credentialId,
                        name: credential.name,
                        rp_id: credential.rpId ?? null,
                        credential_public_key: credential.credentialPublicKey,
                        encrypted_sk: credential.encryptedSk,
                        encrypted_sk_iv: credential.encryptedSkIv,
                        asserted_at: credential.assertedAt,
                        created_at: credential.createdAt,
                        updated_at: credential.updatedAt,
                    })),
                    ...(firstCredential ? {
                        credential_id: firstCredential.credentialId,
                        credential_public_key: firstCredential.credentialPublicKey,
                        encrypted_sk: firstCredential.encryptedSk,
                        encrypted_sk_iv: firstCredential.encryptedSkIv,
                        asserted_at: firstCredential.assertedAt,
                    } : {}),
                    public_key_algorithm: record.publicKeyAlgorithm,
                    public_key: record.publicKey,
                    identity_claims: record.identity ?? null,
                    updated_at: record.updatedAt,
                },
                $setOnInsert: {
                    created_at: existing?.created_at ?? record.createdAt,
                },
                ...(!firstCredential ? {
                    $unset: {
                        credential_id: '',
                        credential_public_key: '',
                        encrypted_sk: '',
                        encrypted_sk_iv: '',
                        asserted_at: '',
                    },
                } : {}),
            },
            { upsert: true },
        );
    }

    async deleteUserKeys(userId: string): Promise<void> {
        await this.users().deleteOne({ _id: userId });
        await this.chatShareLinks().deleteMany({ owner_id: userId });
    }

    async deleteUserCredential(userId: string, credentialId: string): Promise<void> {
        const existing = await this.getUserKeysByUserId(userId);
        if (!existing) return;
        const credentials = existing.credentials.filter(item => item.credentialId !== credentialId);
        await this.upsertUserKeys({ ...existing, credentials, updatedAt: new Date() });
    }

    async renameUserCredential(userId: string, credentialId: string, name: string, at: Date): Promise<void> {
        const existing = await this.getUserKeysByUserId(userId);
        if (!existing) return;
        const credentials = existing.credentials.map(credential => credential.credentialId === credentialId
            ? { ...credential, name, updatedAt: at }
            : credential);
        await this.upsertUserKeys({ ...existing, credentials, updatedAt: at });
    }

    async updateUserIdentity(userId: string, identity: UserIdentityClaims | null): Promise<void> {
        await this.users().updateOne(
            { _id: userId },
            { $set: { identity_claims: identity, updated_at: new Date() } },
        );
    }

    async markAsserted(userId: string, credentialId: string, at: Date, rpId: string): Promise<void> {
        await this.users().updateOne(
            { _id: userId, 'credentials.credential_id': credentialId },
            {
                $set: {
                    'credentials.$.asserted_at': at,
                    'credentials.$.rp_id': rpId,
                    updated_at: at,
                },
            },
        );
        // Keep the legacy mirror's assertion timestamp in sync only when its
        // mirrored credential was the one just asserted.
        await this.users().updateOne(
            { _id: userId, credential_id: credentialId },
            { $set: { asserted_at: at } },
        );
    }

    async saveChallenge(record: PendingChallengeRecord): Promise<void> {
        await this.challenges().deleteMany({ expires_at: { $lte: new Date() } });
        await this.challenges().insertOne({
            _id: record.challenge,
            kind: record.kind,
            credential_id: record.credentialId,
            user_id: record.userId,
            rp_id: record.rpId ?? null,
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
            rpId: doc.rp_id ?? null,
            expiresAt: doc.expires_at,
        };
    }

    async listChatsForRecipient(recipientId: string): Promise<ChatSummary[]> {
        const envelopes = await this.chatKeys().find({ recipient_id: recipientId }).toArray();
        const groups = await this.groupChats().find({ 'members.user_id': recipientId }).toArray();
        const chatIds = Array.from(new Set([
            ...envelopes.map(envelope => envelope.chat_id),
            ...groups.map(group => group._id),
        ]));
        if (chatIds.length === 0) {
            return [];
        }

        const docs = await this.chatsCollection().find({ _id: { $in: chatIds } }).toArray();
        const groupStates = await this.groupChats().find({ _id: { $in: chatIds } }).toArray();
        const groupById = new Map(groupStates.map(group => [group._id, group]));
        const activeGroupIds = new Set(groups.map(group => group._id));
        return docs
            .filter(doc => !groupById.has(doc._id) || activeGroupIds.has(doc._id))
            .map(doc => ({
                id: doc._id,
                ownerId: doc.owner_id,
                updatedAt: groupById.get(doc._id)?.updated_at ?? doc.updated_at,
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
        await this.groupChats().deleteOne({ _id: id });
        await this.groupChatEvents().deleteMany({ chat_id: id });
        await this.deleteAttachmentsForChat(id);
        await this.deleteChatShareLinksForChat(id);
    }

    async saveChatShareLink(record: ChatShareLinkRecord): Promise<void> {
        await this.chatShareLinks().insertOne({
            _id: record.tokenHash,
            chat_id: record.chatId,
            owner_id: record.ownerId,
            created_at: record.createdAt,
            expires_at: record.expiresAt,
        });
    }

    async getChatShareLink(tokenHash: string): Promise<ChatShareLinkRecord | null> {
        const doc = await this.chatShareLinks().findOne({ _id: tokenHash });
        if (!doc) return null;
        return {
            tokenHash: doc._id,
            chatId: doc.chat_id,
            ownerId: doc.owner_id,
            createdAt: doc.created_at,
            expiresAt: doc.expires_at,
        };
    }

    async deleteChatShareLink(tokenHash: string): Promise<void> {
        await this.chatShareLinks().deleteOne({ _id: tokenHash });
    }

    async deleteChatShareLinksForChat(chatId: string): Promise<void> {
        await this.chatShareLinks().deleteMany({ chat_id: chatId });
    }

    async putAttachment(chatId: string, attachmentId: string, source: Readable): Promise<void> {
        const bucket = this.attachments();
        const upload = bucket.openUploadStream(`${chatId}/${attachmentId}`, {
            metadata: { chatId, attachmentId },
        });
        await new Promise<void>((resolve, reject) => {
            let settled = false;
            const fail = (error: Error) => {
                if (settled) return;
                settled = true;
                source.off('error', fail);
                upload.off('error', fail);
                source.unpipe(upload);
                void upload.abort().then(() => reject(error), () => reject(error));
            };
            const finish = () => {
                if (settled) return;
                settled = true;
                source.off('error', fail);
                upload.off('error', fail);
                resolve();
            };
            source.once('error', fail);
            upload.once('error', fail);
            upload.once('finish', finish);
            source.pipe(upload);
        });

        const previous = await bucket.find({
            'metadata.chatId': chatId,
            'metadata.attachmentId': attachmentId,
            _id: { $ne: upload.id },
        }).toArray();
        await Promise.all(previous.map((file) => bucket.delete(file._id)));
    }

    async getAttachment(chatId: string, attachmentId: string): Promise<ZkAttachmentDownload | null> {
        const bucket = this.attachments();
        const files = await bucket.find({
            'metadata.chatId': chatId,
            'metadata.attachmentId': attachmentId,
        }).sort({ uploadDate: -1 }).limit(1).toArray();
        const file = files[0];
        if (!file) return null;
        return {
            stream: bucket.openDownloadStream(file._id),
            size: file.length,
        };
    }

    async hasAttachment(chatId: string, attachmentId: string): Promise<boolean> {
        const bucket = this.attachments();
        const files = await bucket.find({
            'metadata.chatId': chatId,
            'metadata.attachmentId': attachmentId,
        }).limit(1).toArray();
        return files.length > 0;
    }

    async deleteAttachment(chatId: string, attachmentId: string): Promise<void> {
        const bucket = this.attachments();
        const files = await bucket.find({
            'metadata.chatId': chatId,
            'metadata.attachmentId': attachmentId,
        }).toArray();
        await Promise.all(files.map((file) => bucket.delete(file._id)));
    }

    async deleteAttachmentsForChat(chatId: string): Promise<void> {
        const bucket = this.attachments();
        const files = await bucket.find({ 'metadata.chatId': chatId }).toArray();
        await Promise.all(files.map((file) => bucket.delete(file._id)));
    }

    async listEnvelopes(chatId: string): Promise<ChatEnvelopeRecord[]> {
        const group = await this.getGroupChat(chatId);
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
        const group = await this.getGroupChat(chatId);
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
        const group = await this.groupChats().findOne({ _id: chatId });
        if (group) {
            return group.members.some(member => member.user_id === recipientId);
        }
        const count = await this.chatKeys().countDocuments(chatKeyKey(chatId, recipientId), { limit: 1 });
        return count > 0;
    }

    async getGroupCatalog(userId: string): Promise<GroupCatalogRecord | null> {
        const doc = await this.groupCatalogs().findOne({ _id: userId });
        if (!doc) return null;
        return {
            userId: doc._id,
            ciphertext: doc.ciphertext,
            iv: doc.iv,
            envelope: {
                envelope_algorithm: doc.envelope_algorithm,
                ephemeral_public_key: doc.ephemeral_public_key,
                wrapped_key: doc.wrapped_key,
                wrapped_key_iv: doc.wrapped_key_iv,
            },
            rev: doc.rev,
            updatedAt: doc.updated_at,
        };
    }

    async putGroupCatalog(record: GroupCatalogRecord, baseRev?: number | null): Promise<'created' | 'updated' | 'conflict'> {
        const collection = this.groupCatalogs();
        const existing = await collection.findOne({ _id: record.userId });
        const fields = {
            ciphertext: record.ciphertext,
            iv: record.iv,
            envelope_algorithm: record.envelope.envelope_algorithm,
            ephemeral_public_key: record.envelope.ephemeral_public_key,
            wrapped_key: record.envelope.wrapped_key,
            wrapped_key_iv: record.envelope.wrapped_key_iv,
            updated_at: record.updatedAt,
        };

        if (!existing) {
            if (baseRev != null && baseRev !== 0) return 'conflict';
            try {
                await collection.insertOne({
                    _id: record.userId,
                    ...fields,
                    rev: 1,
                });
                return 'created';
            } catch (error) {
                if ((error as { code?: number }).code === 11000) return 'conflict';
                throw error;
            }
        }

        if (baseRev == null || existing.rev !== baseRev) return 'conflict';
        const result = await collection.updateOne(
            { _id: record.userId, rev: baseRev },
            { $set: fields, $inc: { rev: 1 } },
        );
        return result.modifiedCount === 1 ? 'updated' : 'conflict';
    }

    async getGroupChat(chatId: string): Promise<GroupChatRecord | null> {
        const doc = await this.groupChats().findOne({ _id: chatId });
        if (!doc) return null;
        return {
            chatId: doc._id,
            ownerId: doc.owner_id,
            currentEpoch: doc.current_epoch,
            committedSequence: doc.committed_sequence ?? 0,
            members: doc.members.map(member => ({ userId: member.user_id, role: member.role })),
            envelopes: doc.envelopes.map(envelope => ({
                recipientId: envelope.recipient_id,
                epoch: envelope.epoch,
                envelope_algorithm: envelope.envelope_algorithm,
                ephemeral_public_key: envelope.ephemeral_public_key,
                wrapped_key: envelope.wrapped_key,
                wrapped_key_iv: envelope.wrapped_key_iv,
                created_at: envelope.created_at,
            })),
            createdAt: doc.created_at,
            updatedAt: doc.updated_at,
        };
    }

    async createGroupChat(record: GroupChatRecord): Promise<'created' | 'exists' | 'not_found' | 'forbidden'> {
        const chat = await this.chatsCollection().findOne({ _id: record.chatId });
        if (!chat) return 'not_found';
        if (chat.owner_id !== record.ownerId) return 'forbidden';
        try {
            await this.groupChats().insertOne({
                _id: record.chatId,
                owner_id: record.ownerId,
                current_epoch: record.currentEpoch,
                committed_sequence: record.committedSequence,
                members: record.members.map(member => ({ user_id: member.userId, role: member.role })),
                envelopes: record.envelopes.map(envelope => ({
                    recipient_id: envelope.recipientId,
                    epoch: envelope.epoch,
                    envelope_algorithm: envelope.envelope_algorithm,
                    ephemeral_public_key: envelope.ephemeral_public_key,
                    wrapped_key: envelope.wrapped_key,
                    wrapped_key_iv: envelope.wrapped_key_iv,
                    created_at: envelope.created_at,
                })),
                created_at: record.createdAt,
                updated_at: record.updatedAt,
            });
            return 'created';
        } catch (error) {
            if ((error as { code?: number }).code === 11000) return 'exists';
            throw error;
        }
    }

    async replaceGroupChatMembership(
        chatId: string,
        actorId: string,
        expectedEpoch: number,
        record: GroupChatRecord,
    ): Promise<'updated' | 'not_found' | 'forbidden' | 'conflict'> {
        const result = await this.groupChats().updateOne(
            { _id: chatId, owner_id: actorId, current_epoch: expectedEpoch },
            {
                $set: {
                    current_epoch: record.currentEpoch,
                    members: record.members.map(member => ({ user_id: member.userId, role: member.role })),
                    envelopes: record.envelopes.map(envelope => ({
                        recipient_id: envelope.recipientId,
                        epoch: envelope.epoch,
                        envelope_algorithm: envelope.envelope_algorithm,
                        ephemeral_public_key: envelope.ephemeral_public_key,
                        wrapped_key: envelope.wrapped_key,
                        wrapped_key_iv: envelope.wrapped_key_iv,
                        created_at: envelope.created_at,
                    })),
                    updated_at: record.updatedAt,
                },
            },
        );
        if (result.modifiedCount === 1) return 'updated';
        const current = await this.groupChats().findOne({ _id: chatId });
        if (!current) return 'not_found';
        if (current.owner_id !== actorId) return 'forbidden';
        return 'conflict';
    }

    async hasGroupChatMembership(chatId: string, userId: string): Promise<boolean> {
        return Boolean(await this.groupChats().findOne({
            _id: chatId,
            members: { $elemMatch: { user_id: userId } },
        }, { projection: { _id: 1 } }));
    }

    async appendGroupChatEvent(event: NewGroupChatEvent): Promise<GroupChatEventAppendResult> {
        const collection = this.groupChatEvents();
        for (let attempt = 0; attempt < 20; attempt += 1) {
            const state = await this.groupChats().findOne({ _id: event.chatId });
            if (!state) return { status: 'not_found' };
            if (!state.members.some(member => member.user_id === event.actorId)) return { status: 'forbidden' };

            const existing = await collection.findOne({ chat_id: event.chatId, event_id: event.eventId });
            if (existing) {
                if (existing.actor_id !== event.actorId) return { status: 'conflict' };
                await this.advanceGroupChatCommittedSequence(event.chatId);
                const stored = this.toGroupChatEvent(existing);
                await this.publishGroupChatNotification(stored);
                return { status: 'existing', event: stored };
            }
            if (state.current_epoch !== event.epoch) return { status: 'conflict' };

            // Insert at the next committed cursor. If another replica wins the
            // same sequence, advance through its event and retry. This avoids
            // exposing a later sequence before an earlier concurrent append.
            const sequence = (state.committed_sequence ?? 0) + 1;
            const doc: GroupChatEventDoc = {
                chat_id: event.chatId,
                sequence,
                event_id: event.eventId,
                actor_id: event.actorId,
                epoch: event.epoch,
                ciphertext: event.ciphertext,
                iv: event.iv,
                created_at: event.createdAt,
            };
            try {
                await collection.insertOne(doc);
                await this.groupChats().updateOne(
                    { _id: event.chatId },
                    { $set: { updated_at: event.createdAt } },
                );
                await this.advanceGroupChatCommittedSequence(event.chatId);
                const stored = this.toGroupChatEvent(doc);
                await this.publishGroupChatNotification(stored);
                return { status: 'created', event: stored };
            } catch (error) {
                if ((error as { code?: number }).code !== 11000) throw error;
                const duplicate = await collection.findOne({ chat_id: event.chatId, event_id: event.eventId });
                if (duplicate) {
                    if (duplicate.actor_id !== event.actorId) return { status: 'conflict' };
                    await this.advanceGroupChatCommittedSequence(event.chatId);
                    const stored = this.toGroupChatEvent(duplicate);
                    await this.publishGroupChatNotification(stored);
                    return { status: 'existing', event: stored };
                }
                await this.advanceGroupChatCommittedSequence(event.chatId);
            }
        }
        return { status: 'conflict' };
    }

    async listGroupChatEvents(
        chatId: string,
        userId: string,
        after: number,
        limit: number,
    ): Promise<GroupChatEventRecord[] | null> {
        if (!(await this.hasGroupChatMembership(chatId, userId))) return null;
        const group = await this.groupChats().findOne({ _id: chatId }, { projection: { committed_sequence: 1 } });
        if (!group) return null;
        const docs = await this.groupChatEvents()
            .find({ chat_id: chatId, sequence: { $gt: after, $lte: group.committed_sequence ?? 0 } })
            .sort({ sequence: 1 })
            .limit(limit)
            .toArray();
        return docs.map(doc => this.toGroupChatEvent(doc));
    }

    watchGroupChatEvents(listener: GroupChatEventListener): () => void {
        let stopped = false;
        let cursor: FindCursor<GroupChatNotificationDoc> | undefined;
        const startedAt = new Date();

        const pump = async () => {
            while (!stopped) {
                try {
                    cursor ??= this.groupChatNotifications()
                        .find({ published_at: { $gte: startedAt }, origin_id: { $ne: this.instanceId } }, {
                            tailable: true,
                            awaitData: true,
                            noCursorTimeout: true,
                            maxAwaitTimeMS: 1_000,
                        })
                        .sort({ $natural: 1 });
                    const notification = await cursor.tryNext();
                    if (!notification) continue;
                    try {
                        listener(this.toGroupChatEvent(notification));
                    } catch {
                        // A socket listener must not stop delivery to other replicas.
                    }
                } catch {
                    await cursor?.close().catch(() => undefined);
                    cursor = undefined;
                    await new Promise(resolve => setTimeout(resolve, 1_000));
                }
            }
            await cursor?.close().catch(() => undefined);
        };

        void pump();
        return () => {
            stopped = true;
            void cursor?.close().catch(() => undefined);
        };
    }

    private async publishGroupChatNotification(event: GroupChatEventRecord): Promise<void> {
        await this.groupChatNotifications().insertOne({
            chat_id: event.chatId,
            sequence: event.sequence,
            event_id: event.eventId,
            actor_id: event.actorId,
            epoch: event.epoch,
            ciphertext: event.ciphertext,
            iv: event.iv,
            created_at: event.createdAt,
            origin_id: this.instanceId,
            published_at: new Date(),
        });
    }

    private async advanceGroupChatCommittedSequence(chatId: string): Promise<void> {
        while (true) {
            const group = await this.groupChats().findOne({ _id: chatId }, {
                projection: { committed_sequence: 1 },
            });
            if (!group) return;
            const committed = group.committed_sequence ?? 0;
            const next = await this.groupChatEvents().findOne({
                chat_id: chatId,
                sequence: committed + 1,
            }, { projection: { _id: 1 } });
            if (!next) return;
            const updated = await this.groupChats().updateOne(
                { _id: chatId, committed_sequence: committed },
                { $set: { committed_sequence: committed + 1 } },
            );
            if (updated.modifiedCount !== 1) continue;
        }
    }

    private toGroupChatEvent(doc: GroupChatEventDoc): GroupChatEventRecord {
        return {
            chatId: doc.chat_id,
            sequence: doc.sequence,
            eventId: doc.event_id,
            actorId: doc.actor_id,
            epoch: doc.epoch,
            ciphertext: doc.ciphertext,
            iv: doc.iv,
            createdAt: doc.created_at,
        };
    }
}
