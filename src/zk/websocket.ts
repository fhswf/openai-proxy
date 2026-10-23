import type { IncomingMessage, Server } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocket, WebSocketServer } from 'ws';
import { byteLength } from './base64.ts';
import type { GroupChatEventBus } from './groupChatEventBus.ts';
import type { GroupChatEventRecord, ZkStore } from './types.ts';

const MAX_EVENT_CIPHERTEXT_BYTES = 256 * 1024;
const MAX_SOCKET_PAYLOAD_BYTES = 400_000;
const MAX_BACKFILL_EVENTS = 20;

type SocketMessage = Record<string, unknown>;

export interface ZkWebSocketOptions {
    store: ZkStore;
    eventBus: GroupChatEventBus;
    allowedOrigins: string[];
    verifyToken: (token: string) => Promise<string | null>;
    writeRateLimit?: { windowMs: number; max: number };
}

function send(socket: WebSocket, value: unknown): void {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(value));
}

function rejectUpgrade(socket: Duplex, status: 401 | 403 | 404): void {
    const message = status === 401 ? 'Unauthorized' : status === 403 ? 'Forbidden' : 'Not Found';
    socket.write(`HTTP/1.1 ${status} ${message}\r\nConnection: close\r\n\r\n`);
    socket.destroy();
}

function tokenFromRequest(request: IncomingMessage): string | null {
    const authorization = request.headers.authorization;
    if (typeof authorization === 'string') {
        const match = authorization.match(/^Bearer\s+(.+)$/i);
        if (match?.[1]) return match[1];
    }

    const cookieHeader = request.headers.cookie;
    if (!cookieHeader) return null;
    for (const part of cookieHeader.split(';')) {
        const separator = part.indexOf('=');
        if (separator < 0 || part.slice(0, separator).trim() !== 'token') continue;
        const value = part.slice(separator + 1).trim();
        try {
            return decodeURIComponent(value);
        } catch {
            return value;
        }
    }
    return null;
}

function validId(value: unknown): value is string {
    return typeof value === 'string'
        && value.length > 0
        && value.length <= 128
        && !/[\u0000-\u001f]/.test(value);
}

function validBase64(value: unknown, maxBytes: number): value is string {
    const length = byteLength(value);
    return length !== null && length > 0 && length <= maxBytes;
}

function eventToJson(event: GroupChatEventRecord) {
    return {
        chatId: event.chatId,
        sequence: event.sequence,
        eventId: event.eventId,
        actorId: event.actorId,
        epoch: event.epoch,
        ciphertext: event.ciphertext,
        iv: event.iv,
        createdAt: event.createdAt.toISOString(),
    };
}

/** Attach the authenticated group-chat socket endpoint to the app's HTTP server. */
export function attachZkWebSocketServer(server: Server, options: ZkWebSocketOptions): () => void {
    const webSocketServer = new WebSocketServer({ noServer: true, maxPayload: MAX_SOCKET_PAYLOAD_BYTES });
    const userBySocket = new WeakMap<WebSocket, string>();
    const allowedOrigins = new Set(options.allowedOrigins.map(value => {
        try {
            return new URL(value).origin;
        } catch {
            return value;
        }
    }));
    const writeCounters = new Map<string, { startsAt: number; count: number }>();
    const writeWindowMs = options.writeRateLimit?.windowMs ?? 60_000;
    const writeLimit = options.writeRateLimit?.max ?? 120;

    const handleUpgrade = (request: IncomingMessage, socket: Duplex, head: Buffer) => {
        let pathname: string;
        try {
            pathname = new URL(request.url || '/', 'http://localhost').pathname;
        } catch {
            return;
        }
        if (!pathname.endsWith('/zk/ws')) return;

        const origin = request.headers.origin;
        if (!origin || !allowedOrigins.has(origin)) {
            rejectUpgrade(socket, 403);
            return;
        }

        const token = tokenFromRequest(request);
        if (!token) {
            rejectUpgrade(socket, 401);
            return;
        }

        void options.verifyToken(token).then(userId => {
            if (!userId) {
                rejectUpgrade(socket, 401);
                return;
            }

            webSocketServer.handleUpgrade(request, socket, head, webSocket => {
                userBySocket.set(webSocket, userId);
                webSocketServer.emit('connection', webSocket, request);
            });
        }).catch(() => rejectUpgrade(socket, 401));
    };

    server.on('upgrade', handleUpgrade);

    webSocketServer.on('connection', (socket: WebSocket, _request: IncomingMessage) => {
        const userId = userBySocket.get(socket);
        if (!userId) {
            socket.close(1008, 'Authentication required');
            return;
        }
        const subscriptions = new Map<string, () => void>();
        let messageQueue = Promise.resolve();

        const handleMessage = async (raw: Buffer) => {
            let message: SocketMessage;
            try {
                message = JSON.parse(raw.toString('utf8')) as SocketMessage;
            } catch {
                send(socket, { type: 'error', code: 'invalid_message', message: 'Message must be JSON' });
                return;
            }

            if (message.type === 'subscribe') {
                const chatId = message.chatId;
                const after = message.after ?? 0;
                if (!validId(chatId) || !Number.isSafeInteger(after) || Number(after) < 0) {
                    send(socket, { type: 'error', code: 'invalid_payload', message: 'chatId and after cursor are invalid' });
                    return;
                }
                if (!(await options.store.hasGroupChatMembership(chatId, userId))) {
                    send(socket, { type: 'error', chatId, code: 'forbidden', message: 'No access to this group chat' });
                    return;
                }

                subscriptions.get(chatId)?.();
                const unsubscribe = options.eventBus.subscribe(chatId, event => {
                    void options.store.hasGroupChatMembership(chatId, userId).then(isMember => {
                        if (!isMember) {
                            subscriptions.get(chatId)?.();
                            subscriptions.delete(chatId);
                            send(socket, { type: 'access_revoked', chatId });
                            return;
                        }
                        send(socket, { type: 'event', event: eventToJson(event) });
                    }).catch(() => undefined);
                });
                subscriptions.set(chatId, unsubscribe);

                const events = await options.store.listGroupChatEvents(chatId, userId, Number(after), MAX_BACKFILL_EVENTS);
                if (events === null) {
                    unsubscribe();
                    subscriptions.delete(chatId);
                    send(socket, { type: 'error', chatId, code: 'forbidden', message: 'No access to this group chat' });
                    return;
                }
                send(socket, { type: 'subscribed', chatId, cursor: events.at(-1)?.sequence ?? Number(after) });
                for (const event of events) send(socket, { type: 'event', event: eventToJson(event) });
                send(socket, { type: 'catchup_complete', chatId, hasMore: events.length === MAX_BACKFILL_EVENTS });
                return;
            }

            if (message.type === 'unsubscribe') {
                const chatId = message.chatId;
                if (!validId(chatId)) {
                    send(socket, { type: 'error', code: 'invalid_payload', message: 'chatId is invalid' });
                    return;
                }
                subscriptions.get(chatId)?.();
                subscriptions.delete(chatId);
                send(socket, { type: 'unsubscribed', chatId });
                return;
            }

            if (message.type === 'append') {
                const chatId = message.chatId;
                const eventId = message.eventId;
                const epoch = message.epoch;
                const ciphertext = message.ciphertext;
                const iv = message.iv;
                const requestId = validId(message.requestId) ? message.requestId : undefined;
                if (
                    !validId(chatId)
                    || !validId(eventId)
                    || !Number.isSafeInteger(epoch)
                    || Number(epoch) < 1
                    || !validBase64(ciphertext, MAX_EVENT_CIPHERTEXT_BYTES)
                    || byteLength(iv) !== 12
                ) {
                    send(socket, { type: 'error', requestId, code: 'invalid_payload', message: 'Event fields are invalid' });
                    return;
                }

                const timestamp = Date.now();
                const counter = writeCounters.get(userId);
                if (!counter || timestamp - counter.startsAt >= writeWindowMs) {
                    writeCounters.set(userId, { startsAt: timestamp, count: 1 });
                } else if (counter.count >= writeLimit) {
                    send(socket, { type: 'error', requestId, chatId, code: 'rate_limited', message: 'Too many writes' });
                    return;
                } else {
                    counter.count += 1;
                }

                const result = await options.store.appendGroupChatEvent({
                    chatId,
                    eventId,
                    actorId: userId,
                    epoch: Number(epoch),
                    ciphertext,
                    iv: iv as string,
                    createdAt: new Date(),
                });
                if (result.status === 'not_found') {
                    send(socket, { type: 'error', requestId, chatId, code: 'not_found', message: 'Group chat not found' });
                    return;
                }
                if (result.status === 'forbidden') {
                    send(socket, { type: 'error', requestId, chatId, code: 'forbidden', message: 'No access to this group chat' });
                    return;
                }
                if (result.status === 'conflict') {
                    send(socket, { type: 'error', requestId, chatId, code: 'conflict', message: 'Group membership or key epoch changed' });
                    return;
                }

                options.eventBus.publish(result.event);
                send(socket, {
                    type: 'ack',
                    requestId,
                    chatId,
                    eventId,
                    sequence: result.event.sequence,
                    duplicate: result.status === 'existing',
                });
                return;
            }

            send(socket, { type: 'error', code: 'invalid_message', message: 'Unknown message type' });
        };

        socket.on('message', raw => {
            const rawBuffer = Array.isArray(raw)
                ? Buffer.concat(raw)
                : Buffer.isBuffer(raw)
                    ? raw
                    : Buffer.from(raw as ArrayBuffer);
            messageQueue = messageQueue
                .then(() => handleMessage(rawBuffer))
                .catch(() => send(socket, { type: 'error', code: 'internal', message: 'Could not process message' }));
        });
        socket.on('close', () => {
            for (const unsubscribe of subscriptions.values()) unsubscribe();
            subscriptions.clear();
        });
        socket.on('error', () => {
            for (const unsubscribe of subscriptions.values()) unsubscribe();
            subscriptions.clear();
        });
        send(socket, { type: 'ready' });
    });

    return () => {
        server.off('upgrade', handleUpgrade);
        webSocketServer.close();
    };
}
