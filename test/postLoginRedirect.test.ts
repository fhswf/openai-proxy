import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
    RETURN_STATE_TTL_MS,
    createReturnState,
    parseList,
    readReturnState,
    resolveReturnUrl,
} from '../src/postLoginRedirect.ts';

const SECRET = 'test-secret';
const REQUEST_ORIGIN = 'https://proxy.example.org';
const ALLOWED = ['https://staging.example.org'];

describe('parseList', () => {
    it('parses a JSON array', () => {
        assert.deepEqual(parseList('["a","b"]', ['fallback']), ['a', 'b']);
    });

    it('parses a comma separated list', () => {
        assert.deepEqual(parseList('a, b ,c', ['fallback']), ['a', 'b', 'c']);
    });

    it('falls back when the value is missing', () => {
        assert.deepEqual(parseList(undefined, ['fallback']), ['fallback']);
    });
});

describe('resolveReturnUrl', () => {
    it('returns the root when no return url is given', () => {
        assert.equal(resolveReturnUrl(undefined, REQUEST_ORIGIN, ALLOWED), '/');
    });

    it('allows the request origin', () => {
        assert.equal(
            resolveReturnUrl(`${REQUEST_ORIGIN}/chat`, REQUEST_ORIGIN, ALLOWED),
            `${REQUEST_ORIGIN}/chat`,
        );
    });

    it('allows an explicitly configured frontend origin', () => {
        // This is the staging/dev case from the issue: the frontend lives on a
        // different origin than the proxy.
        assert.equal(
            resolveReturnUrl('https://staging.example.org/chat', REQUEST_ORIGIN, ALLOWED),
            'https://staging.example.org/chat',
        );
    });

    it('resolves relative return urls against the proxy origin', () => {
        assert.equal(
            resolveReturnUrl('/dashboard', REQUEST_ORIGIN, ALLOWED),
            `${REQUEST_ORIGIN}/dashboard`,
        );
    });

    it('rejects an unconfigured origin to avoid an open redirect', () => {
        assert.equal(
            resolveReturnUrl('https://evil.example.com/x', REQUEST_ORIGIN, ALLOWED),
            '/',
        );
    });

    it('rejects malformed return urls', () => {
        assert.equal(resolveReturnUrl('http://[invalid', REQUEST_ORIGIN, ALLOWED), '/');
    });
});

describe('return state', () => {
    it('round-trips the return url', () => {
        const state = createReturnState('https://staging.example.org/chat', SECRET);
        assert.equal(readReturnState(state, SECRET), 'https://staging.example.org/chat');
    });

    it('rejects a tampered state', () => {
        const state = createReturnState('https://staging.example.org/chat', SECRET);
        const [payload, signature] = state.split('.');
        const tamperedPayload = Buffer.from(
            JSON.stringify({ r: 'https://evil.example.com/x', t: Date.now() }),
            'utf8',
        ).toString('base64url');
        assert.equal(readReturnState(`${tamperedPayload}.${signature}`, SECRET), undefined);
        assert.equal(readReturnState(`${payload}.${signature}x`, SECRET), undefined);
    });

    it('rejects a state signed with another secret', () => {
        const state = createReturnState('https://staging.example.org/chat', 'other-secret');
        assert.equal(readReturnState(state, SECRET), undefined);
    });

    it('rejects an expired state', () => {
        const state = createReturnState('https://staging.example.org/chat', SECRET, 0);
        assert.equal(readReturnState(state, SECRET, RETURN_STATE_TTL_MS + 1), undefined);
    });

    it('rejects missing or malformed state', () => {
        assert.equal(readReturnState(undefined, SECRET), undefined);
        assert.equal(readReturnState('garbage', SECRET), undefined);
    });
});
