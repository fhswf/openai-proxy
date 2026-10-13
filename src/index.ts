import dotenv from 'dotenv';
dotenv.config();

import { createLogger, format, transports } from 'winston';
import express from 'express';
import proxy from 'express-http-proxy';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';


import { initClient, getSigningKey } from './initClient.ts';
import {
    parseList,
    resolveReturnUrl,
    createReturnState,
    readReturnStateData,
} from './postLoginRedirect.ts';
import { mongo_connect, logRequest, countRequests, checkConnection, getDb } from './db.ts';
import { createZkRouter } from './zk/router.ts';
import { MemoryZkStore } from './zk/memoryStore.ts';
import { MongoZkStore } from './zk/mongoStore.ts';
import { KeyAttestor } from './zk/attestation.ts';
import type { ZkStore } from './zk/types.ts';

const { combine, timestamp, json, errors } = format;
const logger = createLogger({
    level: 'debug',
    format: combine(errors({ stack: true }), timestamp(), format.json()),
    transports: [new transports.Console()],
});

const serializeError = (err) => {
    if (err instanceof Error) {
        return {
            message: err.message,
            name: err.name,
            stack: err.stack,
        };
    }

    return err;
};

const logRequestError = (message, err, req?) => {
    logger.error(message, {
        error: serializeError(err),
        request: req ? {
            method: req.method,
            path: req.path,
            host: req.headers.host,
            forwardedHost: req.headers['x-forwarded-host'],
            forwardedProto: req.headers['x-forwarded-proto'],
            forwardedPrefix: req.headers['x-forwarded-prefix'],
        } : undefined,
    });
};

process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled promise rejection', { error: serializeError(reason) });
});

process.on('uncaughtException', (err) => {
    logger.error('Uncaught exception', { error: serializeError(err) });
    process.exit(1);
});

const app = express();
// don't advertise that we are using express
app.set('x-powered-by', false);

export const CLIENT_ID = process.env.CLIENT_ID;
export const CLIENT_SECRET = process.env.CLIENT_SECRET;
export const REDIRECT_URIS = parseList(
    process.env.REDIRECT_URIS,
    ['http://localhost:3000/callback'],
);
export const ISSUER = process.env.ISSUER;
const PREFIX = process.env.API_PREFIX || '/api';
const API_URL = process.env.API_URL;
const API_KEY = process.env.API_KEY;
const BASE_URL = process.env.BASE_URL;
const POST_LOGOUT_REDIRECT_URI = process.env.POST_LOGOUT_REDIRECT_URI || "https://ki.fh-swf.de";
export const CORS_ORIGINS = parseList(process.env.CORS_ORIGINS, ['http://localhost:5173']);
// Origins a frontend may be redirected to after login. Defaults to CORS_ORIGINS
// so a frontend whose calls are already allowed can also be a return target.
export const RETURN_URL_ORIGINS = parseList(process.env.RETURN_URL_ORIGINS, CORS_ORIGINS);
// Secret used to sign the OAuth state that carries the post-login return URL.
// Falls back to CLIENT_SECRET so no extra configuration is required.
const LOGIN_STATE_SECRET = process.env.LOGIN_STATE_SECRET || CLIENT_SECRET || 'openai-proxy-login-state';
const LEGACY_COOKIE_DOMAINS = (process.env.LEGACY_COOKIE_DOMAINS || '')
    .split(',')
    .map(domain => domain.trim())
    .filter(Boolean);
const TOKEN_COOKIE_NAME = 'token';
const RETURN_URL_COOKIE_NAME = 'return_url';

// Zero-knowledge vault configuration. The RP id defaults to the issuer host and
// the accepted origins default to the configured CORS origins.
export const WEBAUTHN_RP_ID = process.env.WEBAUTHN_RP_ID;
export const WEBAUTHN_ORIGINS = parseList(process.env.WEBAUTHN_ORIGINS, CORS_ORIGINS);


// log config values to console
logger.debug('Config values:');
logger.debug('PREFIX', PREFIX);
logger.debug('CLIENT_ID', CLIENT_ID);
logger.debug('CLIENT_SECRET', CLIENT_SECRET);
logger.debug('REDIRECT_URIS', REDIRECT_URIS);
logger.debug('ISSUER', ISSUER);
logger.debug('API_URL', API_URL);
logger.debug('API_KEY', API_KEY);
logger.debug('BASE_URL', BASE_URL);
logger.debug('CORS_ORIGINS', CORS_ORIGINS);
logger.debug('RETURN_URL_ORIGINS', RETURN_URL_ORIGINS);

app.set('trust proxy', 1)

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

logger.info('enabling cors on all requests');
app.use(cors({
    credentials: true,
    origin: (origin, callback) => {
        // Requests without an Origin header include direct navigations, such as
        // the OAuth callback, and should not receive an ACAO header.
        if (!origin) {
            callback(null, false);
            return;
        }

        callback(null, CORS_ORIGINS.includes(origin));
    },
}));

let client;

const asyncRoute = (handler) => (req, res, next) => {
    Promise.resolve()
        .then(() => handler(req, res, next))
        .catch(next);
};

const getFirstHeaderValue = (header?: string | string[]) => {
    const value = Array.isArray(header) ? header[0] : header;
    return value
        ?.split(',')
        .map(part => part.trim())
        .find(Boolean);
};

const getForwardedProto = (req) => {
    const proto = getFirstHeaderValue(req.headers['x-forwarded-proto']) || req.protocol;
    const normalizedProto = proto.toLowerCase();

    if (normalizedProto !== 'http' && normalizedProto !== 'https') {
        throw new Error(`Cannot build callback URL with invalid protocol: ${proto}`);
    }

    return normalizedProto;
};

const getForwardedHost = (req) => {
    const host = getFirstHeaderValue(req.headers['x-forwarded-host']) || getFirstHeaderValue(req.headers.host);
    if (!host) {
        throw new Error('Cannot build callback URL without a Host or X-Forwarded-Host header');
    }

    return host;
};

const getForwardedPrefix = (req) => {
    const prefix = getFirstHeaderValue(req.headers['x-forwarded-prefix']) || '';
    if (!prefix) {
        return '';
    }

    return `/${prefix.replace(/^\/+|\/+$/g, '')}`;
};

const getHostname = (host?: string | string[]) => {
    const hostValue = getFirstHeaderValue(host);
    if (!hostValue) {
        return undefined;
    }

    return hostValue
        .replace(/^\[/, '')
        .replace(/\](:\d+)?$/, '')
        .split(':')[0]
        .toLowerCase();
};

const isCookieDomainCandidate = (hostname?: string) => {
    return Boolean(hostname)
        && hostname !== 'localhost'
        && !/^\d+\.\d+\.\d+\.\d+$/.test(hostname);
};

const getCookieDomain = (host?: string | string[]) => {
    const hostname = getHostname(host);
    if (!hostname) {
        return undefined;
    }

    if (hostname === 'localhost' || /^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        return undefined;
    }

    const parts = hostname.split('.');
    if (parts.length < 2) {
        return undefined;
    }

    return parts.slice(-2).join('.');
};

const getRequestCookieDomains = (req) => {
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const hostname = getHostname(host);
    const cookieDomain = getCookieDomain(host);

    return Array.from(new Set([
        cookieDomain,
        isCookieDomainCandidate(hostname) ? hostname : undefined,
        ...LEGACY_COOKIE_DOMAINS,
    ].filter(Boolean)));
};

const clearCookieVariants = (req, res, name) => {
    const baseOptions = {
        path: '/',
        sameSite: 'lax',
        secure: true,
    };

    res.clearCookie(name, baseOptions);
    getRequestCookieDomains(req).forEach((domain) => {
        res.clearCookie(name, {
            ...baseOptions,
            domain,
        });
    });
};

const getCookieValues = (req, name) => {
    const header = Array.isArray(req.headers.cookie)
        ? req.headers.cookie.join('; ')
        : req.headers.cookie;

    if (!header) {
        return [];
    }

    return header
        .split(';')
        .map(part => part.trim())
        .reduce((values, part) => {
            const separatorIndex = part.indexOf('=');
            if (separatorIndex === -1) {
                return values;
            }

            const key = part.slice(0, separatorIndex).trim();
            if (key !== name) {
                return values;
            }

            const value = part.slice(separatorIndex + 1);
            try {
                values.push(decodeURIComponent(value));
            }
            catch {
                values.push(value);
            }

            return values;
        }, []);
};

const getAuthorizationToken = (req) => {
    const authorization = getFirstHeaderValue(req.headers.authorization);
    if (!authorization) {
        return undefined;
    }

    const [scheme, token] = authorization.split(/\s+/, 2);
    return scheme?.toLowerCase() === 'bearer' ? token : undefined;
};

const getTokenCandidates = (req) => {
    return Array.from(new Set([
        ...getCookieValues(req, TOKEN_COOKIE_NAME),
        req.cookies[TOKEN_COOKIE_NAME],
        getAuthorizationToken(req),
    ].filter(Boolean)));
};

const setTokenCookie = (req, res, token, returnUrl, callbackUri?: string) => {
    const callbackUrl = new URL(callbackUri || getRequestOrigin(req));
    const callbackCookieDomain = getCookieDomain(callbackUrl.host);
    let cookieDomain = callbackCookieDomain;
    let sameSite: 'lax' | 'none' = 'lax';

    try {
        const frontendUrl = new URL(returnUrl, callbackUrl.origin);
        const frontendHostname = frontendUrl.hostname.toLowerCase();

        // A browser cannot set a localhost cookie from the hosted callback.
        // Keep local development sessions off the proxy's shared parent domain.
        if (frontendHostname === 'localhost' || /^\d+\.\d+\.\d+\.\d+$/.test(frontendHostname)) {
            cookieDomain = undefined;
        }

        // The frontend may call the proxy from a different site (for example
        // localhost:5173 calling the hosted proxy), which requires SameSite=None.
        if (frontendUrl.origin !== callbackUrl.origin) {
            sameSite = 'none';
        }
    }
    catch {
        // Keep the secure, same-site defaults if the target cannot be parsed.
    }

    res.cookie(TOKEN_COOKIE_NAME, token, {
        maxAge: 86400000,
        httpOnly: true,
        secure: true,
        sameSite,
        path: '/',
        ...(cookieDomain ? { domain: cookieDomain } : {}),
    });
};

const verifyTokenCandidates = (tokens, callback) => {
    let lastError;

    const verifyNext = (index) => {
        const token = tokens[index];
        if (!token) {
            callback(lastError);
            return;
        }

        jwt.verify(token, getSigningKey, {
            algorithms: ['RS256'],
            ...(ISSUER ? { issuer: ISSUER } : {}),
        }, (err, user) => {
            if (!err) {
                callback(null, user, token);
                return;
            }

            lastError = err;
            logger.debug('token candidate invalid', { index, error: serializeError(err) });
            verifyNext(index + 1);
        });
    };

    verifyNext(0);
};

const getCallbackUrl = (req) => {
    const proto = getForwardedProto(req);
    const host = getForwardedHost(req);
    const prefix = getForwardedPrefix(req);
    const callbackUrl = new URL(`${proto}://${host}`);
    callbackUrl.pathname = `${prefix}/callback`;

    return callbackUrl;
};

class CallbackUrlConfigurationError extends Error {
    constructor(callbackUrl: URL) {
        super(
            `OAuth login is unavailable because callback URL ${callbackUrl} is not listed in REDIRECT_URIS. `
            + `Add this exact URL to the proxy's REDIRECT_URIS setting and register it with the OIDC provider.`,
        );
        this.name = 'CallbackUrlConfigurationError';
    }
}

const getConfiguredCallbackUrl = (req, requestedCallbackUri?: string) => {
    const callbackUrl = requestedCallbackUri
        ? new URL(requestedCallbackUri)
        : getCallbackUrl(req);
    if (!REDIRECT_URIS.includes(callbackUrl.toString())) {
        throw new CallbackUrlConfigurationError(callbackUrl);
    }

    return callbackUrl;
};

const getRequestOrigin = (req) => `${getForwardedProto(req)}://${getForwardedHost(req)}`;

const getReturnUrl = (req) => {
    const returnUrl = req.query.return_url || req.headers.referer;
    const requestOrigin = getRequestOrigin(req);
    const resolved = resolveReturnUrl(returnUrl, requestOrigin, RETURN_URL_ORIGINS);

    if (resolved === '/' && returnUrl) {
        logger.warn('ignoring login return URL from unconfigured origin', {
            returnUrl,
            requestOrigin,
        });
    }

    return resolved;
};

/** 
 * Add rate limit. 
 * Default limit is 100 requests per 15 minutes.
 */
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: Number.parseInt(process.env.RATE_LIMIT || "100"),
    keyGenerator: (req) => {
        const key = req['user']?.email || req.header("X-Real-IP") || req.ip;
        return key;
    },
    standardHeaders: "draft-8",
    message: 'Too many requests, try again later!'
});

app.get('/ip', (request, response) => response.send(request.ip))

app.get('/login', asyncRoute(async (req, res) => {
    const requestedCallbackUri = req.query.callback_uri;
    if (requestedCallbackUri !== undefined && typeof requestedCallbackUri !== 'string') {
        throw new Error('callback_uri must be a single URL');
    }

    const redirect_uri = getConfiguredCallbackUrl(req, requestedCallbackUri);
    logger.debug('login callback URL', { redirect_uri: redirect_uri.toString() });

    const returnUrl = getReturnUrl(req);
    const state = createReturnState(returnUrl, LOGIN_STATE_SECRET, {
        callbackUrl: redirect_uri.toString(),
    });

    const authorizationUrl = client.authorizationUrl({
        scope: 'openid profile email',
        redirect_uri: redirect_uri.toString(),
        state,
    });
    const authorizationRedirectUri = new URL(authorizationUrl).searchParams.get('redirect_uri');
    logger.debug('login authorization request', {
        client_id: CLIENT_ID,
        token_endpoint: client.issuer.token_endpoint,
        redirect_uri: authorizationRedirectUri,
    });
    if (authorizationRedirectUri !== redirect_uri.toString()) {
        throw new Error(
            `OIDC authorization request redirect_uri ${authorizationRedirectUri} does not match callback URL ${redirect_uri}`,
        );
    }

    const loginCookieDomain = getCookieDomain(req.headers['x-forwarded-host'] || req.headers.host);
    clearCookieVariants(req, res, RETURN_URL_COOKIE_NAME);
    res.cookie(RETURN_URL_COOKIE_NAME, returnUrl, {
        maxAge: 120000,
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        ...(loginCookieDomain ? { domain: loginCookieDomain } : {}),
    });
    res.redirect(authorizationUrl);
}));

app.get('/logout', asyncRoute((req, res) => {
    const token = getTokenCandidates(req)[0];
    logger.debug('token', token);
    clearCookieVariants(req, res, TOKEN_COOKIE_NAME);
    clearCookieVariants(req, res, RETURN_URL_COOKIE_NAME);

    if (token) {
        const endSessionUrl = client.endSessionUrl({
            post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
            client_id: CLIENT_ID,
            id_token_hint: token
        });
        res.redirect(endSessionUrl)
    }
    else {
        res.redirect(BASE_URL);
    }
}));

app.get('/callback', asyncRoute(async (req, res) => {
    try {
        const params = client.callbackParams(req);
        const stateData = readReturnStateData(params.state, LOGIN_STATE_SECRET);
        const stateCallbackUrl = stateData?.callbackUrl;
        let redirect_uri: string;
        if (stateCallbackUrl) {
            if (!REDIRECT_URIS.includes(stateCallbackUrl)) {
                throw new CallbackUrlConfigurationError(new URL(stateCallbackUrl));
            }

            redirect_uri = stateCallbackUrl;
        }
        else {
            redirect_uri = getConfiguredCallbackUrl(req).toString();
        }

        logger.debug('callback token exchange', {
            client_id: CLIENT_ID,
            token_endpoint: client.issuer.token_endpoint,
            redirect_uri,
        });

        // The return URL travels in the signed OAuth state so the login flow
        // works for frontends that cannot receive the proxy's return_url
        // cookie (e.g. a different registrable domain) or that land on a
        // different proxy replica.
        const checks = { code_verifier: client.code_verifier, ...(params.state ? { state: params.state } : {}) };
        const tokenSet = await client.callback(redirect_uri, params, checks);
        const user = jwt.decode(tokenSet.id_token);
        logger.debug('callback user', user);
        const token = tokenSet.id_token;

        clearCookieVariants(req, res, TOKEN_COOKIE_NAME);
        // The state is signed, so its return URL was already validated when the
        // login started. Only the cookie fallback needs to be re-validated.
        const cookieReturnUrl = getCookieValues(req, RETURN_URL_COOKIE_NAME).at(-1) || req.cookies[RETURN_URL_COOKIE_NAME];
        const return_url = stateData?.returnUrl
            || resolveReturnUrl(cookieReturnUrl, getRequestOrigin(req), RETURN_URL_ORIGINS);
        setTokenCookie(req, res, token, return_url, redirect_uri);
        clearCookieVariants(req, res, RETURN_URL_COOKIE_NAME);
        res.redirect(return_url);
    }
    catch (err) {
        logRequestError('OIDC callback failed', err, req);
        if (res.headersSent) {
            throw err;
        }

        const status = err instanceof CallbackUrlConfigurationError ? 500 : 400;
        res.status(status).send(err instanceof Error ? err.message : 'OIDC callback failed');
    }
}));

/** Health check endpoint */
app.get('/healthz', limiter, (req, res) => {
    // check if db connection is open
    logger.debug('healthz: checking db connection');
    checkConnection()
        .then(() => {
            logger.debug('db connection ok');
            res.send({ status: 'ok' });
        })
        .catch((err) => {
            logger.error('db connection error', err);
            res.status(500).send({
                status: 'error',
                error: err
            });
        });
});

/**
 * Middleware to check if the user is authenticated
 */
const checkAuth = (req, res, next) => {

    const tokenCandidates = getTokenCandidates(req);
    logger.debug('token candidates', { count: tokenCandidates.length });

    if (tokenCandidates.length === 0) {
        return res.status(401).json({ message: 'Token not found' });
    }

    verifyTokenCandidates(tokenCandidates, (err, user, token) => {
        if (err) {
            logger.debug('err', err);
            clearCookieVariants(req, res, TOKEN_COOKIE_NAME);
            return res.status(401).json({ message: 'Invalid token' });
        }
        logger.debug('decoded', user);

        if (tokenCandidates.length > 1 || token !== tokenCandidates[0]) {
            clearCookieVariants(req, res, TOKEN_COOKIE_NAME);
            setTokenCookie(req, res, token, req.headers.origin || getRequestOrigin(req));
        }

        try {
            let affiliations = {};
            let raw: Object = Object.groupBy(
                user['affiliation']
                    .map((affiliation) => {
                        const [role, org] = affiliation.split('@');
                        return { role, org }
                    }),
                (affiliation) => affiliation['org']
            )
            Object.entries(raw)
                .forEach(([org, roles]) => {
                    affiliations[org] = roles.map(role => role['role']);
                });
            user['affiliations'] = affiliations;
        } catch (err) {
            logger.error('Error grouping affiliations: ', err);
        }
        logger.debug('user', user);

        req['user'] = {
            name: user['name'],
            email: user['email'],
            email_verified: user['email_verified'],
            sub: user.sub,
            iss: user['iss'],
            preferred_username: user['preferred_username'],
            affiliations: user['affiliations']
        }
        logger.debug('req.user', req['user']);
        next();
    })
}

const redactHeaders = (req, res, next) => {
    const _redactHeaders = Object.keys(req.headers)
        .filter((header) => header == 'cookie' || header.startsWith('x-'));
    logger.debug('redactHeaders', _redactHeaders);
    _redactHeaders.forEach((header) => {
        if (req.headers['origin']?.startsWith('http://localhost')) {
            req.headers[header] = 'redacted';
        }
        else {
            delete req.headers[header];
        }
    });
    next();
};

if (process.env.IGNORE_AUTH !== "true") {
    app.use(checkAuth);
    /** redact headers */
    app.use(redactHeaders);
}
else {
    console.log("ignoring authorizaton")
}

app.get('/user', (req, res) => {
    res.send(req['user']);
});

// --- Zero-knowledge, cross-device chat vault -----------------------------
const createZkStore = (): ZkStore => {
    if (process.env.IGNORE_DB) {
        logger.info('ignoring database, using in-memory zero-knowledge store');
        return new MemoryZkStore();
    }

    return new MongoZkStore(getDb);
};

const resolveRpId = (): string | undefined => WEBAUTHN_RP_ID;

const zkStore = createZkStore();
const zkAttestor = KeyAttestor.fromEnvironment();
if (zkAttestor) {
    logger.info('zero-knowledge key identity attestations enabled');
}
else {
    logger.warn('zero-knowledge key identity attestations disabled; configure ZK_ATTESTATION_PRIVATE_KEY and ZK_ATTESTATION_ISSUER');
}
const zkRouter = createZkRouter({
    store: zkStore,
    attestor: zkAttestor,
    identityIssuer: ISSUER,
    webauthn: {
        rpId: resolveRpId(),
        origins: WEBAUTHN_ORIGINS,
    },
    writeRateLimit: {
        windowMs: 60 * 1000,
        max: Number.parseInt(process.env.ZK_WRITE_RATE_LIMIT || '120'),
    },
});
app.use(`${PREFIX}/zk`, zkRouter);
// The production ingress strips its public /api prefix before forwarding.
// API_PREFIX is /v1 there for OpenAI proxying, so ZK requests arrive as /zk/...
// and need this mount in addition to the prefixed mount used in local setups.
app.use('/zk', zkRouter);


app.use(limiter);

app.get('/dashboard', (req, res) => {
    const promise = countRequests();
    logger.debug('promise', promise);
    promise
        .then(requests => {
            res.json(requests);
        })
        .catch(err => {
            logger.error('Error: ', err);
            res.status(500).send('Error: ' + err);
        });
});



function logResponseBody(req, res, next) {
    let oldWrite = res.write;
    let oldEnd = res.end;

    let chunks = [];

    res.write = function (chunk) {
        chunks.push(Buffer.from(chunk));
        oldWrite.apply(res, arguments);
    };

    res.end = function (chunk) {
        if (chunk)
            chunks.push(Buffer.from(chunk));

        let body = Buffer.concat(chunks).toString('utf8');
        oldEnd.apply(res, arguments);
    };

    res.on('data', () => {

    });

    /** Logs the request to the database */
    res.on('finish', () => {
        const headers = res.getHeaders();
        let model = "";
        if (req.body instanceof Object && "model" in req.body) {
            model = req.body.model
        }
        else if ('openai-model' in headers) {
            model = headers['openai-model'];
        }

        const request = {
            user: req.user,
            req_id: headers['x-request-id'],
            model,
            organization: headers['openai-organization'],
            date: Date.now(),
        };
        logRequest(request)
            .catch(err => logRequestError('Failed to log request', err, req));
    });

    next();
}

app.use(logResponseBody);

const getProxyPath = (req) => `/v1${req.originalUrl.slice(PREFIX.length)}`;

const doProxy = (req, res) => {

    const parsingProxy = proxy(API_URL, {
        https: true,
        limit: '10mb',
        parseReqBody: true,
        proxyReqPathResolver: function (req) {
            const path = getProxyPath(req);
            logger.debug('path: ', req.baseUrl, path);
            return path;
        },
        proxyErrorHandler: function (err, res, next) {
            logger.error({ 'error': err });
            switch (err && err.code) {
                case 'ECONNRESET': { return res.status(504).send('Connection reset'); }
                case 'ECONNREFUSED': { return res.status(502).send('Connection refused'); }
                default: { next(err); }
            }
        },
        proxyReqOptDecorator: function (proxyReqOpts, srcReq) {
            proxyReqOpts.headers['authorization'] = `Bearer ${API_KEY}`;
            //proxyReqOpts.headers['OpenAI-Beta'] = 'assistants=v2';
            return proxyReqOpts;
        },
        proxyReqBodyDecorator: function (bodyContent, srcReq) {
            if (!srcReq.body || srcReq.method === 'GET') {
                return "";
            }

            return bodyContent;
        }
    })

    const rawProxy = proxy(API_URL, {
        https: true,
        limit: '10mb',
        parseReqBody: false,
        proxyReqPathResolver: function (req) {
            const path = getProxyPath(req);

            return path;
        },
        proxyErrorHandler: function (err, res, next) {
            logger.error({ 'error': err });
            switch (err && err.code) {
                case 'ECONNRESET': { return res.status(504).send('Connection reset'); }
                case 'ECONNREFUSED': { return res.status(502).send('Connection refused'); }
                default: { next(err); }
            }
        },
        proxyReqOptDecorator: function (proxyReqOpts, srcReq) {
            proxyReqOpts.headers['authorization'] = `Bearer ${API_KEY}`;
            //proxyReqOpts.headers['OpenAI-Beta'] = 'assistants=v2';
            return proxyReqOpts;
        },
    })

    if (req.headers['content-type'] === 'application/json') {
        parsingProxy(req, res);
    } else {
        rawProxy(req, res);
    }
}

app.use(PREFIX, doProxy);

app.use((err, req, res, next) => {
    logRequestError('Unhandled request error', err, req);

    if (res.headersSent) {
        next(err);
        return;
    }

    if (err instanceof CallbackUrlConfigurationError) {
        res.status(500).send(err.message);
        return;
    }

    res.status(500).send('Internal server error');
});


try {
    if (!process.env.IGNORE_DB) {
        logger.debug('connecting to mongo');
        await mongo_connect();
        await zkStore.init();
    }
    if (!process.env.IGNORE_AUTH) {
        client = await initClient();
    }
    const port = Number.parseInt(process.env.PORT || '3000', 10);
    app.listen(port, () => {
        logger.debug(`Proxy server is running on port ${port}`);
    });
}
catch (err) {
    logger.error('Error: ', err);
    process.exit(1);
};
