[![quality gate status](https://hopper.fh-swf.de/sonarqube/api/project_badges/measure?project=fhswf_openai-proxy_AY5lcaShWNlYFiIpzZcO&metric=alert_status&token=sqb_22dc5cd061114f9aa66b1ef9cb98f7ba37c9ab6e)](https://hopper.fh-swf.de/sonarqube/dashboard?id=fhswf_openai-proxy_AY5lcaShWNlYFiIpzZcO)
[![deployment status](https://login.ki.fh-swf.de/argocd/api/badge?name=openai-proxy&revision=true)](https://login.ki.fh-swf.de/argocd/applications/argocd/openai-proxy)

# Proxy server for the OpenAI API
This proxy uses an OIDC server to authenticate users and forwards requests 
to the OpenAI API. 
The proxy adds an API key to authenticate requests.

This proxying enables university members to use the OpenAI API without revealing person related data. 

At FH Südwestfalen, the proxy is available at [login.ki.fh-swf.de/openai/ui/index.html](https://login.ki.fh-swf.de/openai/ui/index.html).

## Usage

The proxy server is a docker container. To start the server, run the following command:

```bash
docker pull ghcr.io/fhswf/openai-proxy:latest
docker run -p 3000:3000 -e ISSUER=https://your-oidc-server -e CLIENT_ID=your-client-id -e CLIENT_SECRET=your-client-secret -e OPENAI_API_KEY=your-openai-api-key ghcr.io/fhswf/openai-proxy:latest
```

### Environment variables
The following environment variables are used to configure the proxy server:

| Variable            | Default                    | Description                                              |
|---------------------|----------------------------|----------------------------------------------------------|
| API_URL             | https://api.openai.com/v1  | The URL of the OpenAI API                                |
| API_KEY             |                            | The API key used to authernticate against the OpenAI API |
| CLIENT_ID           |                            | The client id of the OIDC server                         |
| CLIENT_SECRET       |                            | The client secret of the OIDC server                     |   
| ISSUER              |                            | The issuer of the OIDC server                            |
| REDIRECT_URIS       | `["http://localhost:3000/callback"]` | JSON array or comma-separated list of callback URLs registered for the OIDC client |
| CORS_ORIGINS        | `http://localhost:5173`    | Comma-separated frontend origins allowed to call the proxy with credentials |
| WEBAUTHN_RP_ID      | host of `ISSUER`           | Relying-party id accepted when verifying WebAuthn assertions (zero-knowledge chat vault) |
| WEBAUTHN_ORIGINS    | `CORS_ORIGINS`             | Comma-separated list (or JSON array) of origins accepted in WebAuthn assertions |
| ZK_WRITE_RATE_LIMIT | `120`                      | Write requests per user per minute for the `/api/zk` endpoints |
| ZK_ATTESTATION_PRIVATE_KEY | unset | RSA private key used to sign zero-knowledge identity-to-key attestations; store as a deployment secret |
| ZK_ATTESTATION_ISSUER | unset | Stable public issuer identifier for proxy-signed key attestations |
| ZK_ATTESTATION_KEY_ID | `zk-attestation-1` | `kid` published in the attestation JWKS; use a new value when rotating the signing key |
| RETURN_URL_ORIGINS  | value of `CORS_ORIGINS`    | Comma-separated frontend origins a user may be redirected to after login |
| LOGIN_STATE_SECRET  | value of `CLIENT_SECRET`   | Secret used to sign the OAuth `state` that carries the post-login return URL |
| PORT                | `3000`                     | Port the proxy listens on                                |
| WEBAUTHN_RP_ID      | host of `ISSUER`           | Relying-party id accepted when verifying WebAuthn assertions (zero-knowledge chat vault) |
| WEBAUTHN_ORIGINS    | `CORS_ORIGINS`             | Comma-separated list (or JSON array) of origins accepted in WebAuthn assertions |
| ZK_WRITE_RATE_LIMIT | `120`                      | Write requests per user per minute for the `/api/zk` endpoints |
| NODE_EXTRA_CA_CERTS |                            | The path to the CA certificate of the OIDC server        |

The proxy derives the OAuth callback URL from the public `Host`, `X-Forwarded-Host`,
`X-Forwarded-Proto`, and `X-Forwarded-Prefix` headers. Each public callback URL must
be present in both `REDIRECT_URIS` and the OIDC client's registered redirect URIs.
For development behind a frontend proxy, `/login` also accepts an optional
`callback_uri` parameter. It must exactly match an entry in `REDIRECT_URIS` and
the OIDC client's registered redirect URIs. For example, a Vite server on port
5173 can proxy `/api/*` to this backend and start login with:

```
/api/login?return_url=http%3A%2F%2Flocalhost%3A5173%2F&callback_uri=http%3A%2F%2Flocalhost%3A5173%2Fapi%2Fcallback
```

The dev server must proxy `/api/callback` to the backend's `/callback` route and
proxy API requests through the same localhost origin. The token cookie is then
host-only for `localhost`; browsers do not allow the hosted backend to set a
cookie for `localhost` directly.

### Multiple frontends
A single proxy can serve several frontends that live on different origins (for
example a production and a staging frontend). Such a frontend passes the URL to
return to after login as the `return_url` query parameter:

```
GET /login?return_url=https://staging.example.org/
```

The return URL is validated against `RETURN_URL_ORIGINS`, encoded into the signed
OAuth `state`, and used as the redirect target once the OIDC callback completes.
Because the return URL is carried in `state`, the flow also works when the
frontend is on a different registrable domain than the proxy and cannot receive
the proxy's `return_url` cookie. Origins that are not listed in
`RETURN_URL_ORIGINS` are rejected to prevent the login endpoint from becoming an
open redirect.


## ToDos

- [ ] Add accounting for the OpenAI API.
- [ ] Add a dashboard with usage statistics.
- [ ] Add a rate limiter.
