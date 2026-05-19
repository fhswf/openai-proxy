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
import { mongo_connect, logRequest, countRequests, checkConnection } from './db.ts';

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
            originalUrl: req.originalUrl,
            path: req.path,
            query: req.query,
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
export const REDIRECT_URIS = JSON.parse(process.env.REDIRECT_URIS || '["http://localhost:3000/callback"]');
export const ISSUER = process.env.ISSUER;
const PREFIX = process.env.API_PREFIX || '/api';
const API_URL = process.env.API_URL;
const API_KEY = process.env.API_KEY;
const BASE_URL = process.env.BASE_URL;
const POST_LOGOUT_REDIRECT_URI = process.env.POST_LOGOUT_REDIRECT_URI || "https://ki.fh-swf.de";
const LEGACY_COOKIE_DOMAINS = (process.env.LEGACY_COOKIE_DOMAINS || '')
    .split(',')
    .map(domain => domain.trim())
    .filter(Boolean);
const TOKEN_COOKIE_NAME = 'token';
const RETURN_URL_COOKIE_NAME = 'return_url';


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

app.set('trust proxy', 1)

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

logger.info('enabling cors on all requests');
app.use(cors({ origin: "http://localhost:5173", credentials: true }));

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

const setTokenCookie = (req, res, token) => {
    const callbackCookieDomain = getCookieDomain(req.headers['x-forwarded-host'] || req.headers.host);

    res.cookie(TOKEN_COOKIE_NAME, token, {
        maxAge: 86400000,
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        ...(callbackCookieDomain ? { domain: callbackCookieDomain } : {}),
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

        jwt.verify(token, getSigningKey, { algorithms: ['RS256'] }, (err, user) => {
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
    const redirect_uri = getCallbackUrl(req);
    logger.debug('login callback URL', { redirect_uri: redirect_uri.toString() });

    const authorizationUrl = client.authorizationUrl({
        scope: 'openid profile email',
        redirect_uri: redirect_uri.toString(),
    });

    const loginCookieDomain = getCookieDomain(req.headers['x-forwarded-host'] || req.headers.host);
    clearCookieVariants(req, res, RETURN_URL_COOKIE_NAME);
    res.cookie(RETURN_URL_COOKIE_NAME, req.query.return_url || req.headers.referer, {
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
        const redirect_uri = getCallbackUrl(req);
        const params = client.callbackParams(req);
        logger.debug('req.headers', req.headers);
        logger.debug('req: ', req.protocol, req.hostname, req.baseUrl, req.url, req.originalUrl, req.path, req.query);

        const tokenSet = await client.callback(redirect_uri.toString(), params, { code_verifier: client.code_verifier });
        const user = jwt.decode(tokenSet.id_token);
        logger.debug('callback user', user);
        const token = tokenSet.id_token;

        clearCookieVariants(req, res, TOKEN_COOKIE_NAME);
        setTokenCookie(req, res, token);
        const return_url = getCookieValues(req, RETURN_URL_COOKIE_NAME).at(-1) || req.cookies[RETURN_URL_COOKIE_NAME] || "/";
        clearCookieVariants(req, res, RETURN_URL_COOKIE_NAME);
        res.redirect(return_url);
    }
    catch (err) {
        logRequestError('OIDC callback failed', err, req);
        if (res.headersSent) {
            throw err;
        }

        res.status(400).send('Error: ' + (err instanceof Error ? err.message : err));
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
            setTokenCookie(req, res, token);
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
            sub: user.sub,
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

const doProxy = (req, res) => {

    const parsingProxy = proxy(API_URL, {
        https: true,
        limit: '10mb',
        parseReqBody: true,
        proxyReqPathResolver: function (req) {
            const path = req.baseUrl.replace(PREFIX, '/v1');
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
            const path = req.baseUrl.replace(PREFIX, '/v1');

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

app.use(`${PREFIX}*`, doProxy);

app.use((err, req, res, next) => {
    logRequestError('Unhandled request error', err, req);

    if (res.headersSent) {
        next(err);
        return;
    }

    res.status(500).send('Internal server error');
});


try {
    if (!process.env.IGNORE_DB) {
        logger.debug('connecting to mongo');
        await mongo_connect();
    }
    if (!process.env.IGNORE_AUTH) {
        client = await initClient();
    }
    app.listen(3000, () => {
        logger.debug('Proxy server is running on port 3000');
    });
}
catch (err) {
    logger.error('Error: ', err);
    process.exit(1);
};
