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
  ├── revoked
  └── credential_hash (BytesN<32>)

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

- `instance()` — used for global counters (CredentialCount, SchemaCount, ProposalCount, SelectiveCredentialCount) and Admin
- `persistent()` — used for all user data (Issuers, Schemas, Credentials, Identities, Proposals, Accumulators, Merkle Credentials, DelegationLinks)

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
| `issue_credential` | Active registered/delegated issuer only |
| `revoke_credential` | Original issuer only |
| `create_proposal` | Active registered issuer only |
| `vote` | Active registered issuer only |
| `finalize_proposal` | Anyone (after voting period) |
| `execute_proposal` | Anyone (after time-lock) |
| `veto_proposal` | Admin only |
| `emergency_admin_action` | Admin only (48h cooldown) |
| `issue_selective_credential` | Active issuer only |
| `create_delegation` | Parent issuer only |
| `revoke_delegation` | Parent issuer only |
| All `get_*` / `has_*` / `verify_*` | Anyone — no auth required |

---

## Canonical Credential Hashing Standard (EIP-712 Style)

Credential authenticity in StellarID supports off-chain verification using an EIP-712-style deterministic typed structured data hashing scheme.

### Domain Separator
```
domain_separator = SHA-256( ASCII("StellarID:v1:") || contract_address_32_bytes )
```

### Credential Encoding
```
credential_hash = SHA-256(
    domain_separator (32 bytes) ||
    schema_id (4 bytes big-endian u32) ||
    subject_address (32 bytes) ||
    issuer_address (32 bytes) ||
    issued_at (8 bytes big-endian u64) ||
    expires_at (8 bytes big-endian u64)
)
```

All field byte encodings are fixed-width big-endian values. Address values are converted into 32-byte fixed representation. Off-chain verifiers can reproduce this hash using the issuer's public key and credential metadata without querying Stellar.

---

## Anonymous XOR Accumulator & Membership Proofs

StellarID maintains a privacy-preserving cryptographic accumulator for each credential schema.

### Accumulator Formula
For a set of credential holders `{addr1, addr2, ..., addrN}`:
```
acc_0 = 0x00...00 (32 bytes of 0s)
acc_k = SHA-256( acc_{k-1} XOR SHA-256(subject_bytes) )
```

### Verification & Witness
- `generate_membership_witness(env, subject, schema_id)` returns `(subject_hash, accumulator)`.
- `verify_membership_witness(env, schema_id, subject_hash, snapshot)` verifies whether `subject_hash` matches an active credential holder at `snapshot`.
- `get_schema_holder_count(env, schema_id)` exposes total active holder count without revealing wallet addresses.

### Limitations
This scheme relies on snapshot consistency. Off-chain verifiers should request recent accumulator snapshots to verify membership.

---

## On-Chain Credential Governance System

StellarID features fully decentralized on-chain proposal voting and time-locked execution.

### Proposal Lifecycle
1. **Creation**: An active issuer calls `create_proposal(proposer, proposal_type, payload)`. Voting window is set to 7 days.
2. **Voting**: Registered active issuers call `vote(issuer, proposal_id, support)`. Each issuer has exactly 1 vote per proposal.
3. **Finalization**: After 7 days, `finalize_proposal(proposal_id)` transitions status to `Passed` if `votes_for > votes_against` and `votes_for >= 3` (quorum), or `Failed` otherwise.
4. **Execution**: After a 2-day time-lock (`executes_at`), `execute_proposal(proposal_id)` decodes payload and executes the governance action.
5. **Veto & Emergency**: Admin can veto proposals during voting or time-lock via `veto_proposal`. `emergency_admin_action` enforces a 48-hour global cooldown.

---

## Selective Disclosure Proofs (Merkle Trees)

Selective disclosure allows subjects to prove individual credential attributes (e.g. `age: 30`) without revealing other fields.

### Merkle Tree Specification
- **Leaf Hash**: `SHA-256( field_name_xdr || ASCII(":") || field_value_xdr )`
- **Internal Nodes**: Binary Merkle tree combining adjacent pairs: `SHA-256( left || right )`. Odd leaf layers duplicate the last leaf.
- **Proof Verification**: `verify_credential_field` recomputes the Merkle path and verifies against `merkle_root` stored on `SelectiveCredential`.

---

## Transitive Credential Delegation Chain

StellarID supports multi-hop hierarchical delegation chains with depth limits and trust decay.

### Delegation Link
A `DelegationLink` defines `(parent, delegate, max_depth, trust_fraction)`.

### Trust Decay Calculation
Trust decays across delegate hops using fixed-point integer math:
```
delegated_trust = (root_trust × fraction_1 / 10000 × fraction_2 / 10000 × ... × fraction_k / 10000)
```
where `trust_fraction` is expressed in basis points (max 10,000 = 100%).

### Safety Mechanisms
- **Circular Delegation**: `create_delegation` walks the parent chain and rejects circular loops.
- **Depth Limit**: Rejects delegation chains exceeding `max_depth`.
- **Cascading Revocation**: Calling `revoke_delegation(parent, delegate)` recursively revokes the link and all sub-delegate descendant links.
