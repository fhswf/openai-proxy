import type { GroupChatEventRecord } from './types.ts';

export type GroupChatEventListener = (event: GroupChatEventRecord) => void;

/** In-process notification fan-out. The database remains the durable source of truth. */
export class GroupChatEventBus {
    private listeners = new Map<string, Set<GroupChatEventListener>>();

    subscribe(chatId: string, listener: GroupChatEventListener): () => void {
        let chatListeners = this.listeners.get(chatId);
        if (!chatListeners) {
            chatListeners = new Set();
            this.listeners.set(chatId, chatListeners);
        }
        chatListeners.add(listener);

        let subscribed = true;
        return () => {
            if (!subscribed) return;
            subscribed = false;
            chatListeners?.delete(listener);
            if (chatListeners?.size === 0 && this.listeners.get(chatId) === chatListeners) {
                this.listeners.delete(chatId);
            }
        };
    }

    publish(event: GroupChatEventRecord): void {
        for (const listener of this.listeners.get(event.chatId) ?? []) {
            try {
                listener(event);
            } catch {
                // A disconnected socket must not fail a committed event append.
            }
        }
    }
}
