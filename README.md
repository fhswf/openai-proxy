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
| NODE_EXTRA_CA_CERTS |                            | The path to the CA certificate of the OIDC server        |

The proxy derives the OAuth callback URL from the public `Host`, `X-Forwarded-Host`,
`X-Forwarded-Proto`, and `X-Forwarded-Prefix` headers. Each public callback URL must
be present in both `REDIRECT_URIS` and the OIDC client's registered redirect URIs.
For a frontend on another origin, add its origin to `CORS_ORIGINS` and pass it as
`return_url` when starting login.


## ToDos

- [ ] Add accounting for the OpenAI API.
- [ ] Add a dashboard with usage statistics.
- [ ] Add a rate limiter.
