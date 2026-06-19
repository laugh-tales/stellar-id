# Integration Guide

How to integrate StellarID's `has_valid_credential()` into your Stellar dApp or Soroban contract.

## Overview

StellarID is shared infrastructure — you don't need to run your own KYC system. Deploy your contract, call `has_valid_credential()`, and you instantly support any credential issued by any registered StellarID issuer.

## Contract-to-Contract Call (Soroban)

Gate a function in your contract to require a valid credential:

```rust
use soroban_sdk::{contractclient, Address, Env};

#[contractclient(name = "StellarIdClient")]
trait StellarId {
    fn has_valid_credential(env: Env, subject: Address, schema_id: u32) -> bool;
}

pub fn my_gated_function(env: Env, user: Address) {
    user.require_auth();

    let stellar_id_contract = Address::from_str(
        &env,
        "STELLAR_ID_CONTRACT_ADDRESS_HERE",
    );
    let client = StellarIdClient::new(&env, &stellar_id_contract);

    let kyc_schema_id: u32 = 1; // KYC Verified schema
    assert!(
        client.has_valid_credential(&user, &kyc_schema_id),
        "User must have a valid KYC credential"
    );

    // proceed with gated logic
}
```

## Backend / SDK Call

From a TypeScript backend using the Stellar SDK:

```typescript
import { Contract, SorobanRpc, TransactionBuilder, Networks } from "@stellar/stellar-sdk";

const server = new SorobanRpc.Server("https://soroban-testnet.stellar.org");
const STELLAR_ID_CONTRACT = "YOUR_CONTRACT_ID";

async function hasValidCredential(
  subjectAddress: string,
  schemaId: number
): Promise<boolean> {
  const contract = new Contract(STELLAR_ID_CONTRACT);

  const result = await server.simulateTransaction(
    new TransactionBuilder(/* ... */)
      .addOperation(
        contract.call(
          "has_valid_credential",
          // encode subject and schema_id as XDR args
        )
      )
      .build()
  );

  return result.result?.retval?.value() === true;
}
```

## Common Schema IDs

Contact the issuer or check on-chain to confirm schema IDs for your network deployment.

| Schema Name | Typical Schema ID | Description |
|---|---|---|
| KYC Verified | 1 | Basic identity verification |
| Accredited Investor | 2 | Accredited investor status |
| Merchant Verified | 3 | Verified merchant |
| AML Cleared | 4 | AML screening passed |

> **Note:** Schema IDs are assigned in order of registration. Verify the correct ID for your deployment using `get_schema(id)`.

## Checking Credential Expiry

`has_valid_credential()` automatically handles expiry — it returns `false` if the credential has passed its `expires_at` timestamp. You do not need to check expiry separately.

## Checking Issuer

If you want to only accept credentials from a specific issuer (e.g., only your own anchor):

```rust
let is_our_issuer = client.has_credential_from_issuer(&user, &our_issuer_address);
assert!(is_our_issuer, "Must be credentialed by our anchor");
```

## Checking Identity Reputation

```rust
let identity = client.get_identity(&user);
assert!(identity.reputation_score >= 50, "Insufficient reputation");
```

## Events to Index

Subscribe to these contract events to keep your database in sync:

| Event | Payload | When to Act |
|---|---|---|
| `credential_issued` | `(credential_id, subject, issuer)` | Grant access, update user record |
| `credential_revoked` | `(credential_id, issuer)` | Revoke access, flag user |
| `issuer_deactivated` | `(issuer)` | Invalidate all credentials from that issuer |
