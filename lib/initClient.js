import { Issuer } from 'openid-client';
import jwksClient from 'jwks-rsa';
import { ISSUER, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI } from './index.js';

export let getSigningKey;

export function initClient() {

    return Issuer.discover(ISSUER)
        .then((issuer) => {
            //console.log(issuer)
            console.log(issuer.jwks_uri);
            let _client = jwksClient({
                jwksUri: issuer.jwks_uri
            });
            console.log(_client);
            getSigningKey = (header, callback) => {
                _client.getSigningKey(header.kid, function (err, key) {
                    let signingKey = key.publicKey || key.rsaPublicKey;
                    callback(null, signingKey);
                });
            };
            return new issuer.Client({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uris: [REDIRECT_URI],
                response_types: ['code']
            });
        });


}
