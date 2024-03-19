import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import proxy from 'express-http-proxy';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { Strategy } from 'openid-client';
import jwt from 'jsonwebtoken';

import fs from 'fs';
import https from 'https';

import { initClient, getSigningKey } from './initClient.js';
import { mongo_connect, logRequest } from './db.js';


const app = express();


export const CLIENT_ID = process.env.CLIENT_ID;
export const CLIENT_SECRET = process.env.CLIENT_SECRET;
export const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3000/callback';
export const ISSUER = process.env.ISSUER;
const PREFIX = process.env.API_PREFIX || '/api';
const API_URL = process.env.API_URL;
const API_KEY = process.env.API_KEY;
const BASE_URL = process.env.BASE_URL;


// log config values to console
console.log('Config values:');
console.log('PREFIX', PREFIX);
console.log('CLIENT_ID', CLIENT_ID);
console.log('CLIENT_SECRET', CLIENT_SECRET);
console.log('REDIRECT_URI', REDIRECT_URI);
console.log('ISSUER', ISSUER);
console.log('API_URL', API_URL);
console.log('API_KEY', API_KEY);
console.log('BASE_URL', BASE_URL);



app.use(express.json());
app.use(cookieParser());

console.log('enabling cors on all requests');
app.use(cors());

let client;

app.get('/login', async (req, res) => {
    const params = req.query;
    const redirect_url = new URL(req.protocol + '://' + req.hostname + req.baseUrl + '/callback');


    const authorizationUrl = client.authorizationUrl({
        scope: 'openid profile email',
        redirect_uri: redirect_url.toString(),
    });

    res.redirect(authorizationUrl);
});

app.get('/callback', async (req, res) => {
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(REDIRECT_URI, params, { code_verifier: client.code_verifier });

    console.log('tokenSet', tokenSet);
    const user = jwt.decode(tokenSet.id_token);
    const token = tokenSet.id_token;//jwt.sign({ user }, 'your_secret_key');

    res.cookie('token', token);
    const redirect_url = new URL(req.protocol + '://' + req.hostname);
    res.redirect(redirect_url);
});

app.get('/dashboard', (req, res) => {
    console.log('req.cookies', req.cookies);
    const token = req.cookies.token || req.headers.authorization;

    if (!token) {
        return res.status(401).json({ message: 'Token not found' });
    }

    console.log(client.metadata)
    try {
        const decoded = jwt.decode(token)
        res.send(decoded);
    }
    catch (err) {
        console.log('err', err);
        return res.status(401).json({ message: 'Invalid token' });
    }
});


/**
 * Middleware to check if the user is authenticated
 */
app.use((req, res, next) => {

    let token = req.cookies.token;
    if (!token && req.headers.authorization) {
        token = req.headers.authorization.split(' ')[1];
    }
    console.log('token', token);

    if (!token) {
        return res.status(401).json({ message: 'Token not found' });
    }

    jwt.verify(token, getSigningKey, { algorithms: ['RS256'] }, (err, decoded) => {
        if (err) {
            console.log('err', err);
            return res.status(401).json({ message: 'Invalid token' });
        }
        console.log('decoded', decoded);
        req.user = {
            name: decoded.name,
            email: decoded.email,
            sub: decoded.sub,
            preferred_username: decoded.preferred_username
        }
        console.log('req.user', req.user);
        next();
    })

});

app.get('/user', (req, res) => {
    res.send(req.user);
});

function logResponseBody(req, res, next) {
    var oldWrite = res.write,
        oldEnd = res.end;

    var chunks = [];

    res.write = function (chunk) {
        chunks.push(new Buffer.from(chunk));

        oldWrite.apply(res, arguments);
    };

    res.end = function (chunk) {
        if (chunk)
            chunks.push(new Buffer.from(chunk));

        var body = Buffer.concat(chunks).toString('utf8');
        console.log(req.path, body);

        oldEnd.apply(res, arguments);
    };

    res.on('finish', () => {
        console.log(`request url = ${req.originalUrl}`);
        const headers = res.getHeaders();
        console.log("headers: ", headers);

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
            console.log('path: ', req.baseUrl, path);
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
            console.log('headers', proxyReqOpts.headers);
            console.log('body', srcReq.body);
            return proxyReqOpts;
        }
    })
);


try {
    await mongo_connect();
    client = await initClient();
    app.listen(3000, () => {
        console.log('Proxy server is running on port 3000');
    });
}
catch (err) {
    console.error('Error: ', err);
    process.exit(1);
};


