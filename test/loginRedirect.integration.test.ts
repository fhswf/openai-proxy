import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import jwt from 'jsonwebtoken';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROXY_ORIGIN = (port: number) => `http://localhost:${port}`;
const STAGING_ORIGIN = 'https://staging.example.org';

interface MockOidc {
    issuer: string;
    close: () => Promise<void>;
}

function freePort(): Promise<number> {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.on('error', reject);
        server.listen(0, () => {
            const address = server.address();
            const port = typeof address === 'object' && address ? address.port : 0;
            server.close(() => resolve(port));
        });
    });
}

async function startMockOidc(): Promise<MockOidc> {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = { ...publicKey.export({ format: 'jwk' }) } as Record<string, unknown>;
    jwk.kid = 'test-key';
    jwk.alg = 'RS256';
    jwk.use = 'sig';

    let issuer = '';
    const server = http.createServer((req, res) => {
        const url = new URL(req.url!, issuer);

        if (url.pathname === '/.well-known/openid-configuration') {
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({
                issuer,
                authorization_endpoint: `${issuer}/authorize`,
                token_endpoint: `${issuer}/token`,
                jwks_uri: `${issuer}/jwks`,
                response_types_supported: ['code'],
                subject_types_supported: ['public'],
                id_token_signing_alg_values_supported: ['RS256'],
                code_challenge_methods_supported: ['S256'],
            }));
            return;
        }

        if (url.pathname === '/jwks') {
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ keys: [jwk] }));
            return;
        }

        if (url.pathname === '/authorize') {
            const target = new URL(url.searchParams.get('redirect_uri')!);
            target.searchParams.set('code', 'mock-code');
            const state = url.searchParams.get('state');
            if (state) {
                target.searchParams.set('state', state);
            }
            res.statusCode = 302;
            res.setHeader('location', target.toString());
            res.end();
            return;
        }

        if (url.pathname === '/token') {
            const idToken = jwt.sign(
                { sub: 'test-user', iss: issuer, aud: 'test-client' },
                privateKey,
                { algorithm: 'RS256', keyid: 'test-key', expiresIn: '1h' },
            );
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({
                access_token: 'mock-access-token',
                id_token: idToken,
                token_type: 'Bearer',
                expires_in: 3600,
            }));
            return;
        }

        res.statusCode = 404;
        res.end('not found');
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    const oidcPort = typeof address === 'object' && address ? address.port : 0;
    issuer = `http://127.0.0.1:${oidcPort}`;

    return {
        issuer,
        close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
}

async function startProxy(env: Record<string, string>): Promise<{ port: number; process: ChildProcess }> {
    const port = await freePort();
    const child = spawn(process.execPath, ['--experimental-strip-types', 'src/index.ts'], {
        cwd: REPO_ROOT,
        env: {
            ...process.env,
            PORT: String(port),
            REDIRECT_URIS: JSON.stringify([`http://localhost:${port}/callback`]),
            CORS_ORIGINS: `http://localhost:5173,${STAGING_ORIGIN}`,
            RETURN_URL_ORIGINS: STAGING_ORIGIN,
            IGNORE_DB: 'true',
            API_URL: 'https://api.openai.com/v1',
            API_KEY: 'dummy',
            ...env,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
    });

    await new Promise<void>((resolve, reject) => {
        let output = '';
        const timer = setTimeout(() => reject(new Error(`proxy did not start:\n${output}`)), 20000);
        const onData = (chunk: Buffer) => {
            output += chunk.toString();
            if (output.includes('Proxy server is running')) {
                clearTimeout(timer);
                resolve();
            }
        };
        child.stdout?.on('data', onData);
        child.stderr?.on('data', onData);
        child.on('exit', (code) => {
            clearTimeout(timer);
            reject(new Error(`proxy exited early (${code}):\n${output}`));
        });
    });

    return { port, process: child };
}

const fetchRedirect = async (url: string): Promise<string> => {
    const response = await fetch(url, { redirect: 'manual' });
    return response.headers.get('location') || '';
};

let oidc: MockOidc;
let proxy: { port: number; process: ChildProcess };

before(async () => {
    oidc = await startMockOidc();
    proxy = await startProxy({
        ISSUER: oidc.issuer,
        CLIENT_ID: 'test-client',
        CLIENT_SECRET: 'test-secret',
    });
});

after(async () => {
    proxy?.process.kill('SIGTERM');
    await oidc?.close();
});

async function loginAndFollowToCallback(returnUrl: string): Promise<string> {
    const proxyOrigin = PROXY_ORIGIN(proxy.port);
    const authorizationUrl = await fetchRedirect(
        `${proxyOrigin}/login?return_url=${encodeURIComponent(returnUrl)}`,
    );
    assert.ok(authorizationUrl.startsWith(oidc.issuer), `unexpected authorization url: ${authorizationUrl}`);

    const callbackUrl = await fetchRedirect(authorizationUrl);
    assert.ok(callbackUrl.startsWith(`${proxyOrigin}/callback`), `unexpected callback url: ${callbackUrl}`);

    // Fetch the callback without reusing the login cookie to emulate a frontend
    // on a different registrable domain, where the proxy's cookie is rejected.
    return fetchRedirect(callbackUrl);
}

describe('post-login redirect', () => {
    it('redirects to a configured frontend on another origin', async () => {
        const target = `${STAGING_ORIGIN}/chat`;
        assert.equal(await loginAndFollowToCallback(target), target);
    });

    it('falls back to the proxy root for an unconfigured origin', async () => {
        const location = await loginAndFollowToCallback('https://evil.example.com/x');
        assert.ok(
            location === '/' || location === `${PROXY_ORIGIN(proxy.port)}/`,
            `unexpected location: ${location}`,
        );
    });
});
