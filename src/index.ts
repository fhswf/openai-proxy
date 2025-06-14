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
import { mongo_connect, logRequest, countRequests } from './db.ts';

const { combine, timestamp, json, errors } = format;
const logger = createLogger({
    level: 'debug',
    format: combine(errors({ stack: true }), timestamp(), format.json()),
    transports: [new transports.Console()],
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

app.use(express.json());
app.use(cookieParser());

logger.info('enabling cors on all requests');
app.use(cors({ origin: "http://localhost:5173", credentials: true }));

let client;
let redirect_uri;

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

app.get('/login', async (req, res) => {
    const params = req.query;

    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const prefix = req.headers['x-forwarded-prefix'] || '';

    redirect_uri = new URL(proto + '://' + host + prefix + '/callback');

    const authorizationUrl = client.authorizationUrl({
        scope: 'openid profile email',
        redirect_uri: redirect_uri.toString(),
    });

    res.cookie("return_url", req.query.return_url || req.headers.referer, { maxAge: 120000, httpOnly: true, secure: true, sameSite: 'none' });
    res.redirect(authorizationUrl);
});

app.get('/logout', (req, res) => {
    let token = req.cookies.token;
    if (!token && req.headers.authorization) {
        token = req.headers.authorization.split(' ')[1];
    }
    logger.debug('token', token);
    if (token) {
        const endSessionUrl = client.endSessionUrl({
            post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
            client_id: CLIENT_ID,
            id_token_hint: token
        });
        res.clearCookie('token')
        res.redirect(endSessionUrl)
    }
    else {
        res.redirect(BASE_URL);
    }
});

app.get('/callback', async (req, res) => {
    const params = client.callbackParams(req);
    logger.debug('req.headers', req.headers);
    logger.debug('req: ', req.protocol, req.hostname, req.baseUrl, req.url, req.originalUrl, req.path, req.query);

    client.callback(redirect_uri.toString(), params, { code_verifier: client.code_verifier })
        .then(tokenSet => {
            const user = jwt.decode(tokenSet.id_token);
            const token = tokenSet.id_token;

            res.cookie('token', token, { maxAge: 86400000, httpOnly: true, secure: true, sameSite: 'none' });
            const return_url = req.cookies.return_url || "/";
            res.redirect(return_url);
        })
        .catch(err => {
            logger.debug('error', err);
            res.status(400).send('Error: ' + err);
        });
});

/** Health check endpoint */
app.get('/healthz', limiter, (req, res) => {
    // check if db connection is open
    countRequests()
        .then(() => {
            res.send({ status: 'ok' });
        })
        .catch((err) => {
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

    let token = req.cookies.token;
    console.log("token: ", token)

    if (!token && req.headers.authorization) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ message: 'Token not found' });
    }

    jwt.verify(token, getSigningKey, { algorithms: ['RS256'] }, (err, user) => {
        if (err) {
            logger.debug('err', err);
            return res.status(401).json({ message: 'Invalid token' });
        }
        logger.debug('decoded', user);

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
        logRequest(request);
    });

    next();
}

app.use(logResponseBody);

const doProxy = (req, res) => {

    const parsingProxy = proxy(API_URL, {
        https: true,
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
            proxyReqOpts.headers['OpenAI-Beta'] = 'assistants=v2';
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
            proxyReqOpts.headers['OpenAI-Beta'] = 'assistants=v2';
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


