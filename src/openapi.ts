const proxyErrorResponses = {
    '401': { description: 'Proxy authentication failed.' },
    '429': { description: 'The proxy rate limit was exceeded.' },
    '502': { description: 'The upstream API could not be reached.' },
};

const zkErrorResponses = {
    '400': { description: 'The request payload is invalid.' },
    '401': { description: 'Authentication or WebAuthn verification failed.' },
    '403': { description: 'The caller is not allowed to perform this operation.' },
    '404': { description: 'The requested key, chat, or attachment was not found.' },
    '409': { description: 'The request conflicts with the current resource state.' },
    '413': { description: 'The request payload is too large.' },
    '415': { description: 'The request content type is not supported.' },
    '429': { description: 'The request rate limit was exceeded.' },
};

const requestBody = (schema: string) => ({
    required: true,
    content: { 'application/json': { schema: { $ref: `#/components/schemas/${schema}` } } },
});

const pathParameters = (...names: string[]) => names.map(name => ({
    name,
    in: 'path',
    required: true,
    schema: { type: 'string' },
}));

const zkOperation = (
    operationId: string,
    summary: string,
    successCode: string,
    successDescription: string,
    bodySchema?: string,
) => ({
    tags: ['Zero-knowledge vault'],
    operationId,
    summary,
    ...(bodySchema ? { requestBody: requestBody(bodySchema) } : {}),
    responses: {
        [successCode]: { description: successDescription },
        ...zkErrorResponses,
    },
});

// In production the ingress exposes the service under /api and strips that
// prefix before forwarding. Relative server URLs keep the spec usable both
// behind that ingress and when the app is run directly at its root.
const zkPath = (operations: Record<string, unknown>) => ({
    servers: [{ url: '../', description: 'API root (the ingress may add /api)' }],
    ...operations,
});

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
        description: 'OpenAI proxy API base path',
    }],
    security: [{ proxyToken: [] }],
    tags: [
        { name: 'Models' },
        { name: 'Chat' },
        { name: 'Responses' },
        { name: 'Embeddings' },
        { name: 'User' },
        { name: 'Zero-knowledge vault', description: 'Encrypted chat storage and passkey management.' },
    ],
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
                parameters: pathParameters('model'),
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
                requestBody: requestBody('ChatCompletionRequest'),
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
                requestBody: requestBody('ResponseRequest'),
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
                requestBody: requestBody('EmbeddingRequest'),
                responses: {
                    '200': { description: 'Embeddings returned by the upstream API.' },
                    ...proxyErrorResponses,
                },
            },
        },
        '/user': {
            servers: [{ url: '../', description: 'Application API root' }],
            get: {
                tags: ['User'],
                summary: 'Get the authenticated user profile',
                operationId: 'getCurrentUser',
                responses: {
                    '200': {
                        description: 'Authenticated OIDC user profile.',
                        content: { 'application/json': { schema: { $ref: '#/components/schemas/UserProfile' } } },
                    },
                    ...proxyErrorResponses,
                },
            },
        },
        '/zk/keys/registration-challenge': zkPath({
            post: zkOperation('createRegistrationChallenge', 'Create a passkey registration challenge', '200', 'Challenge created.', undefined),
        }),
        '/zk/keys': zkPath({
            post: zkOperation('registerKey', 'Register a user key and passkey', '201', 'Key and passkey registered.', 'RegisterKeyRequest'),
        }),
        '/zk/keys/assertion-challenge': zkPath({
            post: zkOperation('createAssertionChallenge', 'Create a passkey assertion challenge', '200', 'Challenge created.', 'AssertionChallengeRequest'),
        }),
        '/zk/keys/assertion': zkPath({
            post: zkOperation('assertKey', 'Verify a passkey assertion', '204', 'Passkey assertion verified.', 'AssertionRequest'),
        }),
        '/zk/keys/me': zkPath({
            get: zkOperation('getMyKeys', 'Get the authenticated user’s keys and passkeys', '200', 'Key account returned.', undefined),
            delete: zkOperation('deleteMyKeys', 'Delete the authenticated user’s key account', '204', 'Key account deleted.'),
        }),
        '/zk/keys/me/identity-disclosure': zkPath({
            patch: zkOperation('updateIdentityDisclosure', 'Set identity disclosure for shared keys', '200', 'Disclosure setting updated.', 'IdentityDisclosureRequest'),
        }),
        '/zk/keys/me/credentials/{credentialId}': zkPath({
            patch: {
                ...zkOperation('renameCredential', 'Rename one of the authenticated user’s passkeys', '200', 'Passkey renamed.', 'RenameCredentialRequest'),
                parameters: pathParameters('credentialId'),
            },
            delete: {
                ...zkOperation('deleteCredential', 'Remove one of the authenticated user’s passkeys', '204', 'Passkey removed.'),
                parameters: pathParameters('credentialId'),
            },
        }),
        '/zk/keys/attestation-jwks': zkPath({
            get: zkOperation('getAttestationJwks', 'Get the proxy public key for identity attestations', '200', 'Attestation JSON Web Key Set returned.'),
        }),
        '/zk/keys/{userId}/public-key': zkPath({
            get: {
                ...zkOperation('getUserPublicKey', 'Get another user’s public key', '200', 'Public key and identity attestation returned.'),
                parameters: pathParameters('userId'),
            },
        }),
        '/zk/keys/lookup': zkPath({
            get: {
                ...zkOperation('lookupKeyByEmail', 'Find a recipient by verified email address', '200', 'Recipient public key returned.'),
                parameters: [{ name: 'email', in: 'query', required: true, schema: { type: 'string', format: 'email' } }],
            },
        }),
        '/zk/keys/rotate': zkPath({
            post: zkOperation('rotateKey', 'Replace the user key and registered passkeys', '204', 'Key rotated and chats rewrapped.', 'RotateKeyRequest'),
        }),
        '/zk/chats': zkPath({
            get: zkOperation('listChats', 'List chats visible to the authenticated user', '200', 'Visible chats returned.'),
        }),
        '/zk/chats/{id}': zkPath({
            get: {
                ...zkOperation('getChat', 'Get an encrypted chat and its key envelopes', '200', 'Chat returned.'),
                parameters: pathParameters('id'),
            },
            put: {
                ...zkOperation('putChat', 'Create or update an encrypted chat', '200', 'Chat saved.', 'PutChatRequest'),
                parameters: pathParameters('id'),
                responses: {
                    '200': { description: 'Existing chat updated.' },
                    '201': { description: 'Chat created.' },
                    ...zkErrorResponses,
                },
            },
            delete: {
                ...zkOperation('deleteChat', 'Delete an encrypted chat', '204', 'Chat deleted.'),
                parameters: pathParameters('id'),
            },
        }),
        '/zk/chats/{id}/share': zkPath({
            post: {
                ...zkOperation('shareChat', 'Share a chat with another user', '201', 'Chat shared.', 'ShareChatRequest'),
                parameters: pathParameters('id'),
            },
        }),
        '/zk/chats/{id}/share-link': zkPath({
            post: {
                ...zkOperation('createShareLink', 'Create a revocable chat share link', '201', 'Share link created.'),
                parameters: pathParameters('id'),
            },
        }),
        '/zk/chats/{id}/share-link/revoke': zkPath({
            post: {
                ...zkOperation('revokeShareLink', 'Revoke a chat share link', '204', 'Share link revoked.', 'RevokeShareLinkRequest'),
                parameters: pathParameters('id'),
            },
        }),
        '/zk/public-shares/redeem': zkPath({
            post: {
                ...zkOperation('redeemShareLink', 'Redeem a public chat share link', '200', 'Encrypted chat returned.', 'RedeemShareRequest'),
                security: [],
            },
        }),
        '/zk/public-shares/redeem-attachment': zkPath({
            post: {
                ...zkOperation('redeemShareAttachment', 'Redeem an attachment from a public chat share link', '200', 'Encrypted attachment returned.'),
                requestBody: requestBody('RedeemAttachmentRequest'),
                security: [],
                responses: {
                    '200': {
                        description: 'Encrypted attachment bytes.',
                        content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } },
                    },
                    ...zkErrorResponses,
                },
            },
        }),
        '/zk/chats/{id}/revoke': zkPath({
            post: {
                ...zkOperation('revokeChatAccess', 'Remove a recipient’s access to a chat', '204', 'Recipient access revoked.', 'RevokeChatAccessRequest'),
                parameters: pathParameters('id'),
            },
        }),
        '/zk/chats/{id}/attachments/{attachmentId}': zkPath({
            head: {
                ...zkOperation('headAttachment', 'Check whether an encrypted attachment exists', '204', 'Attachment exists.'),
                parameters: pathParameters('id', 'attachmentId'),
            },
            get: {
                ...zkOperation('getAttachment', 'Download an encrypted attachment', '200', 'Encrypted attachment bytes.'),
                parameters: pathParameters('id', 'attachmentId'),
                responses: {
                    '200': {
                        description: 'Encrypted attachment bytes.',
                        content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } },
                    },
                    ...zkErrorResponses,
                },
            },
            put: {
                ...zkOperation('putAttachment', 'Upload an encrypted attachment', '204', 'Attachment uploaded.'),
                parameters: pathParameters('id', 'attachmentId'),
                requestBody: {
                    required: true,
                    content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } },
                },
            },
            delete: {
                ...zkOperation('deleteAttachment', 'Delete an encrypted attachment', '204', 'Attachment deleted.'),
                parameters: pathParameters('id', 'attachmentId'),
            },
        }),
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
            UserProfile: {
                type: 'object',
                properties: {
                    name: { type: 'string' },
                    email: { type: 'string', format: 'email' },
                    email_verified: { type: 'boolean' },
                    sub: { type: 'string' },
                    iss: { type: 'string' },
                    preferred_username: { type: 'string' },
                    affiliations: { type: 'object', additionalProperties: { type: 'array', items: { type: 'string' } } },
                },
            },
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
            RegisterKeyRequest: {
                type: 'object',
                required: ['credentialId', 'credentialPublicKey', 'publicKey', 'encryptedSk', 'encryptedSkIv', 'challenge'],
                properties: {
                    credentialId: { type: 'string', description: 'Base64url passkey credential identifier.' },
                    credentialPublicKey: { type: 'string', description: 'Base64url serialized WebAuthn public key.' },
                    publicKeyAlgorithm: { type: 'string', enum: ['RSA-OAEP-SHA256', 'ECDH-P256'] },
                    publicKey: { type: 'string', description: 'Base64url user public key.' },
                    encryptedSk: { type: 'string', description: 'Base64url encrypted user private key.' },
                    encryptedSkIv: { type: 'string' },
                    challenge: { type: 'string', description: 'Challenge from the registration-challenge endpoint.' },
                    credentialName: { type: 'string' },
                    identityDisclosure: { type: 'string', enum: ['subject', 'profile'] },
                },
            },
            AssertionChallengeRequest: {
                type: 'object', required: ['credentialId'], properties: { credentialId: { type: 'string' } },
            },
            AssertionRequest: {
                type: 'object',
                required: ['credentialId', 'challenge', 'authenticatorData', 'clientDataJSON', 'signature'],
                properties: {
                    credentialId: { type: 'string' },
                    challenge: { type: 'string' },
                    authenticatorData: { type: 'string' },
                    clientDataJSON: { type: 'string' },
                    signature: { type: 'string' },
                },
            },
            IdentityDisclosureRequest: {
                type: 'object',
                required: ['identityDisclosure'],
                properties: { identityDisclosure: { type: 'string', enum: ['subject', 'profile'] } },
            },
            RenameCredentialRequest: {
                type: 'object', required: ['credentialName'], properties: { credentialName: { type: 'string' } },
            },
            RotateKeyRequest: {
                allOf: [{ $ref: '#/components/schemas/RegisterKeyRequest' }],
                description: 'Replacement key material and passkey registration proof for an existing key account.',
            },
            Envelope: {
                type: 'object',
                required: ['wrappedKey'],
                properties: {
                    envelopeAlgorithm: { type: 'string', enum: ['RSA-OAEP-SHA256', 'ECDH-P256-HKDF-SHA256-AES-256-GCM'] },
                    ephemeralPublicKey: { type: 'string' },
                    wrappedKey: { type: 'string' },
                    wrappedKeyIv: { type: 'string' },
                },
            },
            PutChatRequest: {
                type: 'object',
                required: ['ciphertext', 'iv', 'selfEnvelope'],
                properties: {
                    ciphertext: { type: 'string' },
                    iv: { type: 'string' },
                    metadataCt: { type: 'string' },
                    metadataIv: { type: 'string' },
                    baseRev: { type: 'integer', minimum: 0, nullable: true },
                    selfEnvelope: { $ref: '#/components/schemas/Envelope' },
                },
            },
            ShareChatRequest: {
                allOf: [
                    { type: 'object', required: ['recipientId'], properties: { recipientId: { type: 'string' } } },
                    { $ref: '#/components/schemas/Envelope' },
                ],
            },
            RevokeChatAccessRequest: {
                type: 'object', required: ['recipientId'], properties: { recipientId: { type: 'string' } },
            },
            RevokeShareLinkRequest: {
                type: 'object', required: ['token'], properties: { token: { type: 'string' } },
            },
            RedeemShareRequest: {
                type: 'object', required: ['token'], properties: { token: { type: 'string' } },
            },
            RedeemAttachmentRequest: {
                type: 'object',
                required: ['token', 'attachmentId'],
                properties: { token: { type: 'string' }, attachmentId: { type: 'string' } },
            },
        },
    },
});
