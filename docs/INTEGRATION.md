# Integration Guide

How to integrate StellarID's `has_valid_credential()` into your Stellar dApp or Soroban contract.

## Overview

StellarID is shared infrastructure — you don't need to run your own KYC system. Deploy your contract, call `has_valid_credential()`, and you instantly support any credential issued by any registered StellarID issuer.

## Contract-to-Contract Call (Soroban)

### Example: Gated Vault

Here's a complete example of a gated vault contract that only lets KYC-verified addresses deposit and withdraw:

#### 1. Cargo.toml

```toml
[package]
name = "gated-vault"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
soroban-sdk = { version = "21.7.6", features = [] }

[dev-dependencies]
soroban-sdk = { version = "21.7.6", features = ["testutils"] }
stellar-id = { path = "../stellar-id" }
```

#### 2. src/lib.rs

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, contractclient, Address, Env};

// ── External contract interface ─────────────────────────────────────────
// #[contractclient] generates `StellarIdClient` — a cross-contract caller
// that wraps env.invoke_contract(). The trait methods must match the exact
// signatures of the StellarID contract's public functions.
#[contractclient(name = "StellarIdClient")]
trait StellarId {
    fn has_valid_credential(env: Env, subject: Address, schema_id: u32) -> bool;
    fn has_credential_from_issuer(env: Env, subject: Address, issuer: Address) -> bool;
    fn get_identity(env: Env, subject: Address) -> Identity;
}

// The Identity type must be replicated so the generated client can decode
// the cross-contract return value. Keep this in sync with the StellarID
// contract definition.
#[contracttype]
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: Address,
    pub credential_count: u32,
    pub reputation_score: u32,
    pub created_at: u64,
}

// ── Storage keys ────────────────────────────────────────────────────────
#[contracttype]
enum DataKey {
    Admin,
    StellarIdContract,
    KycSchemaId,
    Balance(Address),
}

// ── Gated Vault contract ────────────────────────────────────────────────
#[contract]
pub struct GatedVault;

#[contractimpl]
impl GatedVault {
    pub fn initialize(env: Env, admin: Address, stellar_id_contract: Address, kyc_schema_id: u32) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::StellarIdContract, &stellar_id_contract);
        env.storage().instance().set(&DataKey::KycSchemaId, &kyc_schema_id);
    }

    pub fn deposit(env: Env, user: Address, amount: u64) {
        user.require_auth();
        Self::assert_kyc_verified(&env, &user);
        let mut balance: u64 = env.storage().persistent().get(&DataKey::Balance(user.clone())).unwrap_or(0);
        balance += amount;
        env.storage().persistent().set(&DataKey::Balance(user), &balance);
    }

    pub fn withdraw(env: Env, user: Address, amount: u64) {
        user.require_auth();
        Self::assert_kyc_verified(&env, &user);
        let mut balance: u64 = env.storage().persistent().get(&DataKey::Balance(user.clone())).unwrap_or(0);
        assert!(balance >= amount, "Insufficient balance");
        balance -= amount;
        env.storage().persistent().set(&DataKey::Balance(user), &balance);
    }

    pub fn get_balance(env: Env, user: Address) -> u64 {
        env.storage().persistent().get(&DataKey::Balance(user)).unwrap_or(0)
    }

    fn assert_kyc_verified(env: &Env, user: &Address) {
        let stellar_id_contract: Address = env.storage().instance().get(&DataKey::StellarIdContract).expect("Not initialized");
        let kyc_schema_id: u32 = env.storage().instance().get(&DataKey::KycSchemaId).expect("Not initialized");
        // Build a cross-contract client and call has_valid_credential
        let client = StellarIdClient::new(env, &stellar_id_contract);
        assert!(
            client.has_valid_credential(user, &kyc_schema_id),
            "User must have a valid KYC credential"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Env, String,
    };
    use stellar_id::{StellarIdContract, StellarIdContractClient};

    #[test]
    fn test_gated_vault() {
        let env = Env::default();
        env.mock_all_auths();

        // Deploy StellarID
        let stellar_id_admin = Address::generate(&env);
        let stellar_id_contract = env.register_contract(None, StellarIdContract);
        let stellar_id_client = StellarIdContractClient::new(&env, &stellar_id_contract);
        stellar_id_client.initialize(&stellar_id_admin);

        // Register issuer and schema
        let issuer = Address::generate(&env);
        stellar_id_client.register_issuer(&stellar_id_admin, &issuer, &String::from_str(&env, "Test Issuer"), &80u32);
        let schema_id = stellar_id_client.register_schema(&issuer, &String::from_str(&env, "KYC Verified"), &String::from_str(&env, "KYC Credential"));

        // Deploy GatedVault
        let vault_admin = Address::generate(&env);
        let vault_contract = env.register_contract(None, GatedVault);
        let vault_client = GatedVaultClient::new(&env, &vault_contract);
        vault_client.initialize(&vault_admin, &stellar_id_contract, &schema_id);

        // Test user
        let user = Address::generate(&env);

        // Deposit without KYC should fail
        let result = std::panic::catch_unwind(|| {
            vault_client.deposit(&user, &100u64);
        });
        assert!(result.is_err());

        // Issue KYC credential
        env.ledger().set_timestamp(1000);
        stellar_id_client.issue_credential(&issuer, &user, &schema_id, &0u64);

        // Deposit with KYC should succeed
        vault_client.deposit(&user, &100u64);
        assert_eq!(vault_client.get_balance(&user), 100);

        // Withdraw
        vault_client.withdraw(&user, &50u64);
        assert_eq!(vault_client.get_balance(&user), 50);
    }
}
```

### How to Test Contract-to-Contract Calls

In your test environment:

1. Deploy the StellarID contract using `env.register_contract(None, StellarIdContract)`
2. Initialize it with an admin
3. Register an issuer, schema, and issue a credential
4. Deploy your gated contract
5. Call gated functions and verify they work correctly

The test code above shows a complete example.

## Backend / SDK Call

From a TypeScript backend using the Stellar SDK, you can verify credentials via `simulateTransaction` — no wallet or user signature is required since `has_valid_credential` is read-only.

### Prerequisites

```bash
npm install @stellar/stellar-sdk
```

### Complete Example

```typescript
import {
  Address,
  Contract,
  Keypair,
  nativeToScVal,
  Networks,
  scvalToNative,
  SorobanRpc,
  TransactionBuilder,
} from "@stellar/stellar-sdk";

const RPC_URL = "https://soroban-testnet.stellar.org";
const STELLAR_ID_CONTRACT_ID = "CA3D..."; // Deployed contract ID

const server = new SorobanRpc.Server(RPC_URL);
const networkPassphrase = Networks.TESTNET;

/**
 * Check whether a subject address holds a valid credential for a given schema.
 *
 * This is a pure simulate call — no fees, no signatures, no on-chain footprint.
 */
async function hasValidCredential(
  subjectAddress: string,
  schemaId: number,
): Promise<boolean> {
  const contract = new Contract(STELLAR_ID_CONTRACT_ID);

  const subjectScVal = Address.fromString(subjectAddress).toScVal();
  const schemaIdScVal = nativeToScVal(schemaId, { type: "u32" });

  // A random keypair is fine for simulation — the source account is never
  // charged because the transaction is never submitted.
  const source = Keypair.random();

  const tx = new TransactionBuilder(source, {
    fee: "100",
    networkPassphrase,
  })
    .addOperation(
      contract.call("has_valid_credential", subjectScVal, schemaIdScVal),
    )
    .setTimeout(30)
    .build();

  const result = await server.simulateTransaction(tx);

  if (result.error) {
    throw new Error(`Simulation failed: ${result.error}`);
  }

  const retval = result.result?.retval;
  if (!retval) {
    throw new Error("No return value — check contract ID and network");
  }

  return scvalToNative(retval) as boolean;
}
```

### Usage

```typescript
const isVerified = await hasValidCredential(
  "GBPLP3Y3TPF6T3Q5KNHX6PRFGKELN33NX2K5C4YKP32Y36B6H5XJ7GKL",
  1, // KYC Verified schema
);

if (isVerified) {
  console.log("User is KYC-verified, granting access");
} else {
  console.log("User does not have a valid KYC credential");
}
```

### Express Middleware Example

```typescript
import express from "express";

const app = express();

app.use(async (req, res, next) => {
  const userAddress = req.headers["x-stellar-address"] as string;
  if (!userAddress) {
    return res.status(401).json({ error: "Missing x-stellar-address header" });
  }

  try {
    const isVerified = await hasValidCredential(userAddress, 1);
    if (!isVerified) {
      return res.status(403).json({ error: "KYC verification required" });
    }
    next();
  } catch (err) {
    return res.status(500).json({ error: "Verification check failed" });
  }
});
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
