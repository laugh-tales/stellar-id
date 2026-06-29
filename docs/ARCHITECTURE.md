# Architecture

## Overview

StellarID is a single Soroban smart contract providing shared identity infrastructure on Stellar. All state lives on-chain. There is no backend server or database — consumers query the contract directly.

## Core Concepts

### Issuers
Entities approved by the contract admin to issue credentials. Each issuer has a trust level (1–100) that influences the reputation score of subjects they credential. Issuers can authorize sub-issuers to issue on their behalf.

### Schemas
Credential types defined by issuers. A schema has a name and description — for example "KYC Verified", "Accredited Investor", or "Merchant". Any approved issuer can register schemas. Schemas are immutable once registered.

### Credentials
Individual attestations issued to a subject wallet address. Each credential references a schema, has an issuer, and optionally has an expiry timestamp. Credentials can be revoked but never deleted — revocation is recorded permanently.

### Identities
Automatically created the first time a credential is issued to a wallet. Tracks credential count and a reputation score derived from how many credentials exist and the trust levels of the issuers.

## Data Model

```
Admin (instance storage)
  └── Controls issuer registry

Issuer (persistent storage, keyed by Address)
  ├── name
  ├── trust_level (1-100)
  ├── active
  └── credential_count

Schema (persistent storage, keyed by schema_id u32)
  ├── name
  ├── description
  ├── issuer
  └── active

Credential (persistent storage, keyed by credential_id u64)
  ├── subject
  ├── issuer
  ├── schema_id
  ├── issued_at
  ├── expires_at (0 = no expiry)
  └── revoked

Identity (persistent storage, keyed by subject Address)
  ├── credential_count
  ├── reputation_score
  └── created_at

SubjectCredentials (persistent storage, keyed by subject Address)
  └── Vec<u64> of credential IDs

SubIssuer (persistent storage, keyed by (parent, sub) tuple)
  └── bool — authorized or not
```

## Storage Strategy

- `instance()` — used for global counters (CredentialCount, SchemaCount) and Admin
- `persistent()` — used for all user data (Issuers, Schemas, Credentials, Identities)

Persistent storage entries have their own TTL and survive contract upgrades. Instance storage is tied to the contract instance.

## Access Control

| Function | Caller |
|---|---|
| `initialize` | Anyone (once) |
| `register_issuer` | Admin only |
| `deactivate_issuer` | Admin only |
| `authorize_sub_issuer` | Parent issuer only |
| `revoke_sub_issuer` | Parent issuer only |
| `register_schema` | Active issuer only |
| `issue_credential` | Active registered issuer only |
| `revoke_credential` | Original issuer only |
| All `get_*` / `has_*` | Anyone — no auth required |

## Events

| Event | Emitted When |
|---|---|
| `issuer_registered` | New issuer approved |
| `issuer_deactivated` | Issuer disabled |
| `sub_issuer_authorized` | Sub-issuer delegation granted |
| `sub_issuer_revoked` | Sub-issuer delegation removed |
| `schema_registered` | New schema created |
| `credential_issued` | Credential issued to subject |
| `credential_revoked` | Credential revoked |

## Reputation Score Formula

```
reputation = min(credential_count × 10 + (trust_level / 10), 1000)
```

The score increases as more trusted issuers credential the subject. It caps at 1000 to prevent overflow. The score is re-computed on every new credential issuance.

## Credential Commitment Scheme

StellarID credentials are stored in plaintext. The commitment layer lets a subject prove they hold a valid credential without revealing which one.

### How it works

1. **Commit** — the subject picks a random 32-byte blinding factor `r` and computes:
   ```
   commitment = SHA-256(credential_id_as_8_le_bytes || r)
   ```
   They call `submit_commitment(subject, schema_id, commitment)`. Only the hash goes on-chain.

2. **Prove** — when a verifier calls `verify_commitment(subject, schema_id, credential_id, r)`, the contract recomputes the hash and checks it matches the stored commitment. It also checks the credential is valid (not revoked, not expired, owned by subject).

3. **Query** — `has_valid_commitment(subject, schema_id)` returns whether a commitment exists and the subject holds at least one live credential for that schema, without revealing which credential.

### Security properties

- **Hiding** — SHA-256 is a one-way function; the commitment reveals nothing about `credential_id` or `r`.
- **Binding** — it is computationally infeasible to find a different `(credential_id', r')` that produces the same commitment.
- **Privacy** — observers on-chain see only the hash, not the credential ID or issuer.

### Limitations

- `has_valid_commitment` is a weaker guarantee than `verify_commitment`. It confirms a commitment exists and a live credential exists for the schema, but does not bind the two together. Full binding requires the subject to reveal the opening via `verify_commitment`.
- The commitment is per `(subject, schema_id)`. Submitting again overwrites the previous commitment.

