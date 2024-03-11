# Proxy server for the OpenAI API
This proxy uses an OIDC server to authenticate users and forwards requests 
to the OpenAI API. 
The proxy adds an API key to authenticate requests.

This proxying enables university members to use the OpenAI API without revealing person related data. 

## Usage

The proxy server is a docker container. To start the server, run the following command:

```bash
docker pull ghcr.io/fhswf/openai-proxy:latest
docker run -p 8080:8080 -e ISSUER=https://your-oidc-server -e CLIENT_ID=your-client-id -e CLIENT_SECRET=your-client-secret -e OPENAI_API_KEY=your-openai-api-key ghcr.io/fhswf/openai-proxy:latest
```

### Environment variables
The following environment variables are used to configure the proxy server:

| Variable  | Default                    | Description                                              |
|-----------|----------------------------|----------------------------------------------------------|
| API_URL   | https://api.openai.com/v1  | The URL of the OpenAI API                                |
| API_KEY   |                            | The API key used to authernticate against the OpenAI API |
| CLIENT_ID |                            | The client id of the OIDC server |
| CLIENT_SECRET |                        | The client secret of the OIDC server |   
| ISSUER    |                            | The issuer of the OIDC server |
| REDIRECT_URI |                         | The redirect URI of the OIDC server |
| NODE_EXTRA_CA_CERTS |                  | The path to the CA certificate of the OIDC server |
