import dotenv from 'dotenv';
dotenv.config();


import express from 'express';
import proxy from 'express-http-proxy';
import cookieParser from 'cookie-parser';
import { Issuer, Strategy } from 'openid-client';
import jwt from 'jsonwebtoken';

import fs from 'fs';
import https from 'https';
import jwksClient from 'jwks-rsa';

const app = express();
// const proxy = httpProxy.createProxyServer();



const PREFIX = process.env.API_PREFIX || '/api';
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3000/callback';
const ISSUER = process.env.ISSUER;
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

let issuer;
let client;
let getSigningKey;


app.get('/login', async (req, res) => {
    const params = req.query;

    const authorizationUrl = client.authorizationUrl({
        scope: 'openid profile email',
        redirect_uri: REDIRECT_URI
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
    res.redirect(BASE_URL + '/dashboard');
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


app.use((req, res, next) => {

    let token = req.cookies.token;
    if (req.headers.authorization) {
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
        req.user = decoded.user;
        next();
    })

});

/*
app.all(`${PREFIX}*`, (req, res) => {
    const path = req.path.replace(PREFIX, '');
    const target_url = `${API_URL}${path}`;
    console.log('target_url', target_url);
    const headers = [{}]
    proxy.web(req, res,
        { target: target_url, changeOrigin: true, ignorePath: true, headers: { 'Authorization': `Bearer ${API_KEY}` }, proxyTimeout: 60000, timeout: 60000 },
        (err) => {
            console.log('err', err);
            res.status(500).json({ message: 'Error', err });
        });
});
*/

app.use(`${PREFIX}*`, proxy(API_URL, {
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
}));

initClient()
    .then((_client) => {
        client = _client
        console.log('Client is ready: %o', client);
        app.listen(3000, () => {
            console.log('Proxy server is running on port 3000');
        });

    })
    .catch((err) => {
        console.error('Error: ', err);
        process.exit(1);
    });

function initClient() {

    return Issuer.discover(ISSUER)
        .then((_issuer) => {
            issuer = _issuer;
            //console.log(issuer)
            console.log(issuer.jwks_uri)
            let _client = jwksClient({
                jwksUri: issuer.jwks_uri
            })
            console.log(_client)
            getSigningKey = (header, callback) => {
                _client.getSigningKey(header.kid, function (err, key) {
                    var signingKey = key.publicKey || key.rsaPublicKey;
                    callback(null, signingKey);
                });
            }
            return new issuer.Client({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uris: [REDIRECT_URI],
                response_types: ['code']
            });
        })


}

