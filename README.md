[![Quality Gate Status](https://hopper.fh-swf.de/sonarqube/api/project_badges/measure?project=fhswf_openai-proxy_AY5lcaShWNlYFiIpzZcO&metric=alert_status&token=sqb_22dc5cd061114f9aa66b1ef9cb98f7ba37c9ab6e)](https://hopper.fh-swf.de/sonarqube/dashboard?id=fhswf_openai-proxy_AY5lcaShWNlYFiIpzZcO)
<img src="https://login.ki.fh-swf.de/argocd/api/badge?name=openai-proxy&revision=true">

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
| REDIRECT_URI        |                            | The redirect URI of the OIDC server                      |
| NODE_EXTRA_CA_CERTS |                            | The path to the CA certificate of the OIDC server        |


## ToDos

- [ ] Add accounting for the OpenAI API.
- [ ] Add a dashboard with usage statistics.
- [ ] Add a rate limiter.