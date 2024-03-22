import dotenv from 'dotenv';
dotenv.config();

import { createLogger, format, transports } from 'winston';
import express from 'express';
import proxy from 'express-http-proxy';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { Strategy } from 'openid-client';
import jwt from 'jsonwebtoken';

import fs from 'fs';
import https from 'https';

import { initClient, getSigningKey } from './initClient.js';
import { mongo_connect, logRequest, countRequests } from './db.js';

const { combine, timestamp, json, errors } = format;
const logger = createLogger({
    level: 'debug',
    format: combine(errors({ stack: true }), timestamp(), format.json()),
    transports: [new transports.Console()],
});

const app = express();


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



app.use(express.json());
app.use(cookieParser());

logger.info('enabling cors on all requests');
app.use(cors({ origin: "http://localhost:5173", credentials: true }));

let client;
let redirect_uri;



app.get('/login', async (req, res) => {
    const params = req.query;
    logger.debug('req.headers', req.headers);
    logger.debug('req: ', req.protocol, req.hostname, req.baseUrl, req.url, req.originalUrl, req.path, req.query);

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

            logger.debug('tokenSet', tokenSet);
            const user = jwt.decode(tokenSet.id_token);

            const token = tokenSet.id_token;

            res.cookie('token', token, { maxAge: 120000, httpOnly: true, secure: true, sameSite: 'none' });
            const return_url = req.cookies.return_url || "/";
            logger.debug('return_url', return_url);
            res.redirect(return_url);
        })
        .catch(err => {
            logger.debug('error', err);
            res.status(400).send('Error: ' + err);
        });
});

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


/**
 * Middleware to check if the user is authenticated
 */
app.use((req, res, next) => {

    let token = req.cookies.token;
    if (!token && req.headers.authorization) {
        token = req.headers.authorization.split(' ')[1];
    }
    logger.debug('token', token);

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
            user['scopedAffiliations'] = Object.groupBy(
                user['affiliation']
                    .map((affiliation) => {
                        const [role, org] = affiliation.split('@');
                        return { role, org }
                    }),
                (affiliation) => affiliation['org']
            );
        } catch (err) {
            logger.error('Error grouping affiliations: ', err);
        }
        logger.debug('user', user);

        req['user'] = {
            name: user['name'],
            email: user['email'],
            sub: user.sub,
            preferred_username: user['preferred_username'],
            affiliations: user['scopedAffiliations']
        }
        logger.debug('req.user', req['user']);
        next();
    })

});

app.get('/user', (req, res) => {
    res.send(req['user']);
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

        var body = Buffer.concat(chunks).toString('utf8');
        logger.debug(req.path, body);

        oldEnd.apply(res, arguments);
    };

    res.on('finish', () => {
        logger.debug(`request url = ${req.originalUrl}`);
        const headers = res.getHeaders();
        logger.debug("headers: ", headers);

        const request = {
            user: req.user,
            req_id: headers['x-request-id'],
            model: headers['openai-model'],
            organization: headers['openai-organization'],
            date: Date.now(),
        };
        logRequest(request);
    });

    next();
}

app.use(logResponseBody);

app.use(`${PREFIX}*`,
    proxy(API_URL, {
        https: true,
        proxyReqPathResolver: function (req) {
            const path = req.baseUrl.replace(PREFIX, '/v1');
            logger.debug('path: ', req.baseUrl, path);
            return path;
        },
        proxyErrorHandler: function (err, res, next) {
            switch (err && err.code) {
                case 'ECONNRESET': { return res.status(405).send('504 became 405'); }
                case 'ECONNREFUSED': { return res.status(200).send('gotcher back'); }
                default: { next(err); }
            }
        },
        proxyReqOptDecorator: function (proxyReqOpts, srcReq) {
            proxyReqOpts.headers['Authorization'] = `Bearer ${API_KEY}`;
            logger.debug('headers', proxyReqOpts.headers);
            logger.debug('body', srcReq.body);
            return proxyReqOpts;
        }
    })
);


try {
    await mongo_connect();
    client = await initClient();
    app.listen(3000, () => {
        logger.debug('Proxy server is running on port 3000');
    });
}
catch (err) {
    console.error('Error: ', err);
    process.exit(1);
};


