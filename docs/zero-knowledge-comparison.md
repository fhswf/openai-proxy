# Zero-knowledge vault and KI:connect.nrw

Reviewed 2026-10-13.

## Summary

The zero-knowledge chat vault in this repository and KI:connect.nrw address
different parts of using generative AI. The vault is designed to protect saved
chat content from the proxy backend through client-side encryption. KI:connect
provides universities with centrally managed access to multiple AI services;
its published privacy approach relies on institutional configuration,
contracts, and data-protection measures. KI:connect's public documentation does
not describe a client-encrypted chat vault equivalent to ours.

Neither approach makes an inference request zero knowledge: a model provider
must receive the prompt content needed to produce a response.

## Comparison

| Area | This repository | KI:connect.nrw |
| --- | --- | --- |
| **Primary purpose** | The `/api/zk` API stores and shares cross-device chats. The wider proxy authenticates users and forwards model requests. | A shared portal and API for universities to provide access to multiple commercial and open models. Each institution can configure the models and conditions it offers. |
| **Saved chat content** | The client encrypts chat content before storage. The backend stores ciphertext and wrapped chat-key envelopes; it does not decrypt them. It can see account and chat IDs, timestamps, ciphertext sizes, and sharing relationships. | University guidance documents saved, searchable, and shareable chats in deployments such as FernUni Hagen. KI:connect's public material describes data-protection and contractual controls, but not an equivalent client-side encryption guarantee. |
| **Inference prompts** | Prompts sent through the regular proxy are forwarded to the configured model provider. The proxy's accounting records contain user/request metadata, not prompt content. | Prompts are sent to the chosen model service. KI:connect's contract guidance covers prompt content sent to providers. |
| **Identity at the model provider** | The proxy replaces the incoming authorization header with its configured provider API key and removes cookies and `x-` headers before forwarding. The proxy still authenticates and records the user internally for accounting. | In the RUB deployment, users are not represented by personal provider accounts; provider communication uses a central university account. This is an institution-specific description, not a universal guarantee for every KI:connect deployment. |
| **Basis for privacy** | Cryptographic protection of stored chat content, assuming the client follows the protocol and keeps keys safe. | Institutional and organizational controls: model/provider selection, processing agreements, and local data-protection processes. The precise setup can vary by institution and provider. |

## What our “zero knowledge” claim covers

The vault is a storage and sharing design, not an inference privacy layer and not
a zero-knowledge proof protocol. Its documented key hierarchy uses a separate
random AES-256-GCM key per chat. User private keys are wrapped with a
passkey-derived key; chat keys are wrapped for each recipient. The backend
stores these encrypted values without interpreting or decrypting them.

The documented guarantee assumes the client and server software follow the
protocol. It does not protect against an actively malicious backend operator:
the backend could substitute an unverified public key, hide or roll back data,
or serve modified client code. Public-key fingerprint verification is described
as a client requirement and is not implemented by this backend. The backend
also retains identifying and relationship metadata described above.

Separately, the regular proxy forwards prompts to its configured AI provider.
Its request accounting stores the authenticated user object and request
metadata, while the proxy flow documentation says prompts are not logged. The
vault's encryption therefore protects saved vault content from the backend; it
does not hide active prompts from the model provider or make the entire service
zero knowledge.

## KI:connect privacy model and deployment differences

KI:connect's project documentation describes a centrally coordinated way for
universities to provide several commercial and open models. Its deployment
guidance includes agreements with RWTH for the platform and agreements with AI
providers for processing prompt content. University service pages describe
additional choices and controls. For example, the RUB page says chats are not
used for training and that provider communication uses a central university
account; FernUni Hagen documents saved chats and sharing features.

These examples should not be generalized to every institution, model, provider,
or hosting arrangement. The local university's current privacy notice,
acceptable-use rules, and model configuration determine the applicable details.

## Sources

### This repository

- [Zero-knowledge vault backend design](zero-knowledge.md)
- [Proxy data-flow diagram](proxy.mmd)
- [Proxy request handling and header redaction](../src/index.ts)
- [Accounting database fields](../src/db.ts)

### KI:connect.nrw and university deployments

- [KI:connect.nrw project overview](https://kiconnect.pages.rwth-aachen.de/pages/theproject/)
- [KI:connect.nrw contract documents and provider agreements](https://kiconnect.pages.rwth-aachen.de/pages/provision-agreement/)
- [KI:connect.nrw handout for adapting its data-protection impact assessment](https://kiconnect.pages.rwth-aachen.de/pages/provision-dsfa/)
- [Ruhr University Bochum service page](https://www.it-services.ruhr-uni-bochum.de/services/sl/KIconnect.html.de)
- [FernUni Hagen service page](https://www.fernuni-hagen.de/zli/produkte/weitere-tools/ki-connect-nrw.shtml)
