export const createOpenApiDocument = (apiPrefix: string) => ({
    openapi: '3.0.3',
    info: {
        title: 'OpenAI Proxy API',
        version: '1.0.0',
        description: [
            'OpenAI API requests are forwarded to the upstream API configured by API_URL. ',
            'The proxy adds its upstream API key. Authenticate with the proxy OIDC token ',
            'using the token cookie or a Bearer token. The proxy also forwards upstream ',
            'routes that are not listed in this document.',
        ].join(''),
    },
    // Resolve the configured Express prefix relative to the public docs URL. This
    // keeps the UI working when an ingress adds and strips an external path prefix.
    servers: [{
        url: `..${apiPrefix}`,
        description: 'Proxy API base path',
    }],
    security: [{ proxyToken: [] }],
    tags: [{ name: 'Models' }, { name: 'Chat' }, { name: 'Responses' }, { name: 'Embeddings' }],
    paths: {
        '/models': {
            get: {
                tags: ['Models'],
                summary: 'List available models',
                operationId: 'listModels',
                responses: {
                    '200': { description: 'Model list returned by the upstream API.' },
                    ...proxyErrorResponses,
                },
            },
        },
        '/models/{model}': {
            get: {
                tags: ['Models'],
                summary: 'Retrieve a model',
                operationId: 'retrieveModel',
                parameters: [{
                    name: 'model',
                    in: 'path',
                    required: true,
                    schema: { type: 'string' },
                }],
                responses: {
                    '200': { description: 'Model returned by the upstream API.' },
                    ...proxyErrorResponses,
                },
            },
        },
        '/chat/completions': {
            post: {
                tags: ['Chat'],
                summary: 'Create a chat completion',
                operationId: 'createChatCompletion',
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: { $ref: '#/components/schemas/ChatCompletionRequest' },
                        },
                    },
                },
                responses: {
                    '200': { description: 'Chat completion returned by the upstream API.' },
                    ...proxyErrorResponses,
                },
            },
        },
        '/responses': {
            post: {
                tags: ['Responses'],
                summary: 'Create a response',
                operationId: 'createResponse',
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: { $ref: '#/components/schemas/ResponseRequest' },
                        },
                    },
                },
                responses: {
                    '200': { description: 'Response returned by the upstream API.' },
                    ...proxyErrorResponses,
                },
            },
        },
        '/embeddings': {
            post: {
                tags: ['Embeddings'],
                summary: 'Create embeddings',
                operationId: 'createEmbeddings',
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: { $ref: '#/components/schemas/EmbeddingRequest' },
                        },
                    },
                },
                responses: {
                    '200': { description: 'Embeddings returned by the upstream API.' },
                    ...proxyErrorResponses,
                },
            },
        },
    },
    components: {
        securitySchemes: {
            proxyToken: {
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT',
                description: 'Proxy OIDC token. A token cookie from the login flow is also accepted.',
            },
        },
        schemas: {
            ChatCompletionRequest: {
                type: 'object',
                required: ['model', 'messages'],
                properties: {
                    model: { type: 'string', example: 'gpt-4o-mini' },
                    messages: {
                        type: 'array',
                        items: {
                            type: 'object',
                            required: ['role', 'content'],
                            properties: {
                                role: { type: 'string', example: 'user' },
                                content: { type: 'string', example: 'Hello!' },
                            },
                            additionalProperties: true,
                        },
                    },
                    stream: { type: 'boolean', default: false },
                },
                additionalProperties: true,
            },
            ResponseRequest: {
                type: 'object',
                required: ['model', 'input'],
                properties: {
                    model: { type: 'string', example: 'gpt-4o-mini' },
                    input: {
                        oneOf: [
                            { type: 'string', example: 'Hello!' },
                            { type: 'array', items: { type: 'object', additionalProperties: true } },
                        ],
                    },
                    stream: { type: 'boolean', default: false },
                },
                additionalProperties: true,
            },
            EmbeddingRequest: {
                type: 'object',
                required: ['model', 'input'],
                properties: {
                    model: { type: 'string', example: 'text-embedding-3-small' },
                    input: {
                        oneOf: [
                            { type: 'string' },
                            { type: 'array', items: { type: 'string' } },
                        ],
                    },
                },
                additionalProperties: true,
            },
        },
    },
});

const proxyErrorResponses = {
    '401': { description: 'Proxy authentication failed.' },
    '429': { description: 'The proxy rate limit was exceeded.' },
    '502': { description: 'The upstream API could not be reached.' },
};
