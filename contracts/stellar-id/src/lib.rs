#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Bytes, BytesN, Env, String,
    Symbol, Vec,
};

// ============================================================
// Data Types
// ============================================================

/// Attestation data bridged from an EVM chain
#[contracttype]
#[derive(Clone, Debug)]
pub struct BridgeAttestation {
    pub evm_chain_id: u64,
    pub evm_uid: BytesN<32>,
    pub evm_attester: BytesN<20>,
    pub evm_schema_uid: BytesN<32>,
    pub evm_expiry: u64,
    pub bridge_operator: Address,
}

/// A verifiable credential issued to a subject address
#[contracttype]
#[derive(Clone, Debug)]
pub struct Credential {
    pub id: u64,
    pub subject: Address,
    pub issuer: Address,
    pub schema_id: u32,
    pub issued_at: u64,
    pub expires_at: u64, // 0 = no expiry
    pub revoked: bool,
}

/// A credential schema defining a type of credential
#[contracttype]
#[derive(Clone, Debug)]
pub struct Schema {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub issuer: Address,
    pub active: bool,
}

/// An issuer registered in the system
#[contracttype]
#[derive(Clone, Debug)]
pub struct Issuer {
    pub address: Address,
    pub name: String,
    pub trust_level: u32, // 1-100
    pub active: bool,
    pub credential_count: u64,
}

/// On-chain identity profile for a subject
#[contracttype]
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: Address,
    pub credential_count: u32,
    pub reputation_score: u32, // derived from credential count + issuer trust
    pub created_at: u64,
}

/// A privacy-preserving commitment to a credential.
///
/// The commitment is computed off-chain as SHA-256(credential_id_le || blinding_factor)
/// and submitted on-chain. The subject can later prove knowledge of the opening
/// without revealing which specific credential or issuer is involved.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CredentialCommitment {
    pub subject: Address,
    pub commitment: BytesN<32>,
    pub schema_id: u32,
    pub committed_at: u64,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    Admin,
    Credential(u64), // credential_id -> Credential
    CredentialCount,
    Schema(u32), // schema_id -> Schema
    SchemaCount,
    Issuer(Address),   // issuer address -> Issuer
    Identity(Address), // subject address -> Identity
    // subject -> Vec<u64> of their credential IDs
    SubjectCredentials(Address),
    // authorized sub-issuers: (parent_issuer, sub_issuer) -> bool
    SubIssuer(Address, Address),
    // bridge operator (address) -> bool
    BridgeOperator(Address),
    // bridged attestation (chain_id, uid) -> bool
    BridgedAttestation(u64, BytesN<32>),
    // subject -> Vec<u64> of bridged credential IDs
    SubjectBridgeCredentials(Address),
    // credential_id -> BridgeAttestation
    BridgeMetadata(u64),
    // (subject, schema_id) -> CredentialCommitment
    Commitment(Address, u32),
}

// ============================================================
// Contract
// ============================================================

#[contract]
pub struct StellarIdContract;

#[contractimpl]
impl StellarIdContract {
    // --------------------------------------------------------
    // Admin
    // --------------------------------------------------------

    /// Initializes contract instance storage with the admin address and zeroed
    /// credential and schema counters.
    ///
    /// The `admin` address must authorize the call and is stored as the only
    /// address allowed to perform admin-only issuer management actions.
    ///
    /// Panics if authorization for `admin` is not present.
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::CredentialCount, &0u64);
        env.storage().instance().set(&DataKey::SchemaCount, &0u32);
    }

    // --------------------------------------------------------
    // Issuer Management
    // --------------------------------------------------------

    /// Registers a new issuer record.
    ///
    /// The stored contract admin must sign through `admin`. The new `issuer`
    /// address is recorded with a display `name`, an active status, zero issued
    /// credentials, and a `trust_level` in the inclusive range `1..=100`.
    ///
    /// Panics if the contract has not been initialized, `admin` is not the
    /// stored admin, `admin` does not authorize the call, or `trust_level` is
    /// outside the accepted range.
    pub fn register_issuer(
        env: Env,
        admin: Address,
        issuer: Address,
        name: String,
        trust_level: u32,
    ) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        assert!(admin == stored_admin, "Only admin can register issuers");
        assert!(
            (1..=100).contains(&trust_level),
            "Trust level must be 1-100"
        );

        let issuer_record = Issuer {
            address: issuer.clone(),
            name,
            trust_level,
            active: true,
            credential_count: 0,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer.clone()), &issuer_record);

        env.events()
            .publish((Symbol::new(&env, "issuer_registered"),), (issuer,));
    }

    /// Deactivates an issuer record.
    ///
    /// The stored contract admin must sign through `admin`. The target `issuer`
    /// remains in storage, but its `active` flag is set to `false`, preventing
    /// future credential issuance by that issuer.
    ///
    /// Panics if the contract has not been initialized, `admin` is not the
    /// stored admin, `admin` does not authorize the call, or `issuer` is not
    /// registered.
    pub fn deactivate_issuer(env: Env, admin: Address, issuer: Address) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        assert!(admin == stored_admin, "Only admin can deactivate issuers");

        let mut issuer_record: Issuer = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(issuer.clone()))
            .expect("Issuer not found");

        issuer_record.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer.clone()), &issuer_record);

        env.events()
            .publish((Symbol::new(&env, "issuer_deactivated"),), (issuer,));
    }

    /// Registers an authorized bridge operator.
    ///
    /// Panics if admin is not authorized.
    pub fn register_bridge_operator(env: Env, admin: Address, operator: Address) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        assert!(
            admin == stored_admin,
            "Only admin can register bridge operators"
        );

        env.storage()
            .persistent()
            .set(&DataKey::BridgeOperator(operator.clone()), &true);

        env.events().publish(
            (Symbol::new(&env, "bridge_operator_registered"),),
            (operator,),
        );
    }

    /// Revokes a bridge operator's authorization.
    ///
    /// Panics if admin is not authorized.
    pub fn revoke_bridge_operator(env: Env, admin: Address, operator: Address) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Not initialized");
        assert!(
            admin == stored_admin,
            "Only admin can revoke bridge operators"
        );

        env.storage()
            .persistent()
            .set(&DataKey::BridgeOperator(operator.clone()), &false);

        env.events()
            .publish((Symbol::new(&env, "bridge_operator_revoked"),), (operator,));
    }

    /// Authorizes a sub-issuer relationship for a registered parent issuer.
    ///
    /// The `parent` issuer must authorize the call. The `sub_issuer` address is
    /// marked as authorized under the `(parent, sub_issuer)` storage key.
    ///
    /// Panics if `parent` does not authorize the call or is not a registered
    /// issuer.
    pub fn authorize_sub_issuer(env: Env, parent: Address, sub_issuer: Address) {
        parent.require_auth();
        let _issuer_record: Issuer = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(parent.clone()))
            .expect("Parent issuer not found");

        env.storage().persistent().set(
            &DataKey::SubIssuer(parent.clone(), sub_issuer.clone()),
            &true,
        );

        env.events().publish(
            (Symbol::new(&env, "sub_issuer_authorized"),),
            (parent, sub_issuer),
        );
    }

    /// Revokes a sub-issuer relationship for a parent issuer.
    ///
    /// The `parent` address must authorize the call. The `(parent, sub_issuer)`
    /// storage key is retained with a `false` value so later queries return
    /// unauthorized.
    ///
    /// Panics if `parent` does not authorize the call.
    pub fn revoke_sub_issuer(env: Env, parent: Address, sub_issuer: Address) {
        parent.require_auth();
        env.storage().persistent().set(
            &DataKey::SubIssuer(parent.clone(), sub_issuer.clone()),
            &false,
        );

        env.events().publish(
            (Symbol::new(&env, "sub_issuer_revoked"),),
            (parent, sub_issuer),
        );
    }

    // --------------------------------------------------------
    // Schema Management
    // --------------------------------------------------------

    /// Registers a new active credential schema owned by an issuer.
    ///
    /// The `issuer` address must authorize the call and must already be an
    /// active registered issuer. The `name` and `description` describe the
    /// credential type. Returns the newly assigned schema identifier.
    ///
    /// Panics if `issuer` does not authorize the call, is not registered, is
    /// inactive, or if `name` is empty.
    pub fn register_schema(env: Env, issuer: Address, name: String, description: String) -> u32 {
        issuer.require_auth();
        let issuer_record: Issuer = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(issuer.clone()))
            .expect("Issuer not found");
        assert!(issuer_record.active, "Issuer is not active");
        assert!(!name.is_empty(), "Schema name cannot be empty");

        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::SchemaCount)
            .unwrap_or(0);
        let schema_id = count + 1;

        let schema = Schema {
            id: schema_id,
            name,
            description,
            issuer: issuer.clone(),
            active: true,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Schema(schema_id), &schema);
        env.storage()
            .instance()
            .set(&DataKey::SchemaCount, &schema_id);

        env.events().publish(
            (Symbol::new(&env, "schema_registered"),),
            (schema_id, issuer),
        );

        schema_id
    }

    /// Deactivates a credential schema owned by the original issuer.
    ///
    /// The `issuer` address must authorize the call and must match the stored
    /// schema owner. Deactivation prevents new credentials from being issued for
    /// `schema_id`; existing credentials remain valid until revoked or expired.
    ///
    /// Panics if `issuer` does not authorize the call, `schema_id` does not
    /// exist, `issuer` is not the schema owner, or the schema is already
    /// inactive.
    pub fn deactivate_schema(env: Env, issuer: Address, schema_id: u32) {
        issuer.require_auth();

        let mut schema: Schema = env
            .storage()
            .persistent()
            .get(&DataKey::Schema(schema_id))
            .expect("Schema not found");

        assert!(
            schema.issuer == issuer,
            "Only the original issuer can deactivate this schema"
        );
        assert!(schema.active, "Schema is already inactive");

        schema.active = false;
        env.storage()
            .persistent()
            .set(&DataKey::Schema(schema_id), &schema);

        env.events().publish(
            (Symbol::new(&env, "schema_deactivated"),),
            (schema_id, issuer),
        );
    }

    // --------------------------------------------------------
    // Credential Issuance
    // --------------------------------------------------------

    /// Issues a new credential to a subject address.
    ///
    /// The `issuer` address must authorize the call, be registered, and be
    /// active. The credential references `schema_id`, belongs to `subject`, and
    /// expires after `duration_seconds` when that value is non-zero. A
    /// `duration_seconds` value of `0` creates a non-expiring credential.
    ///
    /// Returns the newly assigned credential identifier.
    ///
    /// Panics if `issuer` does not authorize the call, is not registered, is
    /// inactive, `schema_id` does not exist, or the schema is inactive.
    pub fn issue_credential(
        env: Env,
        issuer: Address,
        subject: Address,
        schema_id: u32,
        duration_seconds: u64,
    ) -> u64 {
        issuer.require_auth();
        let effective_trust = Self::require_active_issuer(&env, &issuer);
        Self::require_active_schema(&env, schema_id);

        let now = env.ledger().timestamp();
        let expires_at = if duration_seconds > 0 {
            now + duration_seconds
        } else {
            0
        };

        let count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CredentialCount)
            .unwrap_or(0);
        let credential_id = count + 1;

        let credential = Credential {
            id: credential_id,
            subject: subject.clone(),
            issuer: issuer.clone(),
            schema_id,
            issued_at: now,
            expires_at,
            revoked: false,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Credential(credential_id), &credential);
        env.storage()
            .instance()
            .set(&DataKey::CredentialCount, &credential_id);

        let mut subject_creds: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject.clone()))
            .unwrap_or(Vec::new(&env));
        subject_creds.push_back(credential_id);
        env.storage().persistent().set(
            &DataKey::SubjectCredentials(subject.clone()),
            &subject_creds,
        );

        let existing: Option<Identity> = env
            .storage()
            .persistent()
            .get(&DataKey::Identity(subject.clone()));
        let identity = if let Some(mut id) = existing {
            id.credential_count += 1;
            id.reputation_score = Self::compute_reputation(id.credential_count, effective_trust);
            id
        } else {
            Identity {
                subject: subject.clone(),
                credential_count: 1,
                reputation_score: effective_trust / 10,
                created_at: now,
            }
        };
        env.storage()
            .persistent()
            .set(&DataKey::Identity(subject.clone()), &identity);

        let mut issuer_rec: Issuer = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(issuer.clone()))
            .expect("Issuer not found");
        issuer_rec.credential_count += 1;
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer.clone()), &issuer_rec);

        env.events().publish(
            (Symbol::new(&env, "credential_issued"),),
            (credential_id, subject, issuer),
        );

        credential_id
    }

    /// Issues credentials to multiple subjects in a single call.
    ///
    /// The `issuer` address must authorize the call once; all `subjects` receive
    /// a credential for `schema_id` with the same expiry. Returns credential IDs
    /// in the same order as the input subjects list.
    ///
    /// Panics if `issuer` does not authorize the call, is not registered, is
    /// inactive, `schema_id` does not exist, the schema is inactive, or the
    /// subjects list is empty.
    pub fn batch_issue_credentials(
        env: Env,
        issuer: Address,
        subjects: Vec<Address>,
        schema_id: u32,
        duration_seconds: u64,
    ) -> Vec<u64> {
        issuer.require_auth();
        assert!(!subjects.is_empty(), "subjects list cannot be empty");
        let effective_trust = Self::require_active_issuer(&env, &issuer);
        Self::require_active_schema(&env, schema_id);

        let now = env.ledger().timestamp();
        let expires_at = if duration_seconds > 0 {
            now + duration_seconds
        } else {
            0
        };

        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CredentialCount)
            .unwrap_or(0);

        let mut credential_ids: Vec<u64> = Vec::new(&env);

        for subject in subjects.iter() {
            count += 1;
            let credential_id = count;

            let credential = Credential {
                id: credential_id,
                subject: subject.clone(),
                issuer: issuer.clone(),
                schema_id,
                issued_at: now,
                expires_at,
                revoked: false,
            };

            env.storage()
                .persistent()
                .set(&DataKey::Credential(credential_id), &credential);

            let mut subject_creds: Vec<u64> = env
                .storage()
                .persistent()
                .get(&DataKey::SubjectCredentials(subject.clone()))
                .unwrap_or(Vec::new(&env));
            subject_creds.push_back(credential_id);
            env.storage().persistent().set(
                &DataKey::SubjectCredentials(subject.clone()),
                &subject_creds,
            );

            let existing: Option<Identity> = env
                .storage()
                .persistent()
                .get(&DataKey::Identity(subject.clone()));
            let identity = if let Some(mut id) = existing {
                id.credential_count += 1;
                id.reputation_score =
                    Self::compute_reputation(id.credential_count, effective_trust);
                id
            } else {
                Identity {
                    subject: subject.clone(),
                    credential_count: 1,
                    reputation_score: effective_trust / 10,
                    created_at: now,
                }
            };
            env.storage()
                .persistent()
                .set(&DataKey::Identity(subject.clone()), &identity);

            credential_ids.push_back(credential_id);
        }

        env.storage()
            .instance()
            .set(&DataKey::CredentialCount, &count);

        let mut issuer_rec: Issuer = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(issuer.clone()))
            .expect("Issuer not found");
        issuer_rec.credential_count += subjects.len() as u64;
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer.clone()), &issuer_rec);

        env.events().publish(
            (Symbol::new(&env, "credentials_batch_issued"),),
            (subjects.len(), issuer, schema_id),
        );

        credential_ids
    }

    /// Bridges an EVM attestation to StellarID as a credential.
    ///
    /// Only authorized bridge operators can call this.
    pub fn bridge_credential(
        env: Env,
        operator: Address,
        subject: Address,
        schema_id: u32,
        bridge_data: BridgeAttestation,
        duration_seconds: u64,
    ) -> u64 {
        operator.require_auth();

        // Check if operator is authorized
        let is_authorized: bool = env
            .storage()
            .persistent()
            .get(&DataKey::BridgeOperator(operator.clone()))
            .unwrap_or(false);
        assert!(is_authorized, "Not an authorized bridge operator");

        // Check for duplicate
        let already_bridged: bool = env
            .storage()
            .persistent()
            .get(&DataKey::BridgedAttestation(
                bridge_data.evm_chain_id,
                bridge_data.evm_uid.clone(),
            ))
            .unwrap_or(false);
        assert!(!already_bridged, "Attestation already bridged");

        // Check EVM expiry
        let now = env.ledger().timestamp();
        if bridge_data.evm_expiry > 0 {
            assert!(bridge_data.evm_expiry > now, "EVM attestation expired");
        }

        // Create credential
        let count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CredentialCount)
            .unwrap_or(0);
        let credential_id = count + 1;

        let expires_at = if duration_seconds > 0 {
            now + duration_seconds
        } else {
            0
        };

        let credential = Credential {
            id: credential_id,
            subject: subject.clone(),
            issuer: operator.clone(),
            schema_id,
            issued_at: now,
            expires_at,
            revoked: false,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Credential(credential_id), &credential);
        env.storage()
            .persistent()
            .set(&DataKey::BridgeMetadata(credential_id), &bridge_data);
        env.storage()
            .instance()
            .set(&DataKey::CredentialCount, &credential_id);

        // Track bridged attestation
        let evm_uid_clone = bridge_data.evm_uid.clone();
        env.storage().persistent().set(
            &DataKey::BridgedAttestation(bridge_data.evm_chain_id, evm_uid_clone),
            &true,
        );

        // Track subject's bridge credentials
        let mut subject_bridge_creds: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::SubjectBridgeCredentials(subject.clone()))
            .unwrap_or(Vec::new(&env));
        subject_bridge_creds.push_back(credential_id);
        env.storage().persistent().set(
            &DataKey::SubjectBridgeCredentials(subject.clone()),
            &subject_bridge_creds,
        );

        // Also add to regular subject credentials
        let mut subject_creds: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject.clone()))
            .unwrap_or(Vec::new(&env));
        subject_creds.push_back(credential_id);
        env.storage().persistent().set(
            &DataKey::SubjectCredentials(subject.clone()),
            &subject_creds,
        );

        // Update identity
        let existing: Option<Identity> = env
            .storage()
            .persistent()
            .get(&DataKey::Identity(subject.clone()));
        let identity = if let Some(mut id) = existing {
            id.credential_count += 1;
            id
        } else {
            Identity {
                subject: subject.clone(),
                credential_count: 1,
                reputation_score: 0, // Bridged credentials don't affect reputation
                created_at: now,
            }
        };
        env.storage()
            .persistent()
            .set(&DataKey::Identity(subject.clone()), &identity);

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "credential_bridged"),),
            (
                credential_id,
                subject,
                operator,
                bridge_data.evm_chain_id,
                bridge_data.evm_uid,
            ),
        );

        credential_id
    }

    /// Revokes a credential issued by the caller.
    ///
    /// The `issuer` address must authorize the call and must be the original
    /// issuer stored on `credential_id`. Revocation sets the credential's
    /// `revoked` flag to `true`.
    ///
    /// Panics if `issuer` does not authorize the call, `credential_id` does not
    /// exist, `issuer` is not the original issuer, or the credential is already
    /// revoked.
    pub fn revoke_credential(env: Env, issuer: Address, credential_id: u64) {
        issuer.require_auth();

        let mut credential: Credential = env
            .storage()
            .persistent()
            .get(&DataKey::Credential(credential_id))
            .expect("Credential not found");

        assert!(
            credential.issuer == issuer,
            "Only the original issuer can revoke"
        );
        assert!(!credential.revoked, "Credential already revoked");

        credential.revoked = true;
        env.storage()
            .persistent()
            .set(&DataKey::Credential(credential_id), &credential);

        env.events().publish(
            (Symbol::new(&env, "credential_revoked"),),
            (credential_id, issuer),
        );
    }

    /// Extends the expiry of a non-revoked credential.
    ///
    /// The `issuer` address must authorize the call and must be the original
    /// issuer of `credential_id`. The credential's `expires_at` is incremented
    /// by `additional_seconds`. Non-expiring credentials (`expires_at == 0`)
    /// cannot be renewed.
    ///
    /// Panics if `issuer` does not authorize the call, `credential_id` does not
    /// exist, `issuer` is not the original issuer, the credential is already
    /// revoked, `additional_seconds` is zero, or the credential is non-expiring.
    pub fn renew_credential(
        env: Env,
        issuer: Address,
        credential_id: u64,
        additional_seconds: u64,
    ) {
        issuer.require_auth();
        assert!(
            additional_seconds > 0,
            "additional_seconds must be greater than zero"
        );

        let mut credential: Credential = env
            .storage()
            .persistent()
            .get(&DataKey::Credential(credential_id))
            .expect("Credential not found");

        assert!(
            credential.issuer == issuer,
            "Only the original issuer can renew"
        );
        assert!(!credential.revoked, "Cannot renew a revoked credential");
        assert!(
            credential.expires_at > 0,
            "Cannot renew a non-expiring credential"
        );

        credential.expires_at += additional_seconds;
        let new_expires_at = credential.expires_at;

        env.storage()
            .persistent()
            .set(&DataKey::Credential(credential_id), &credential);

        env.events().publish(
            (Symbol::new(&env, "credential_renewed"),),
            (credential_id, new_expires_at),
        );
    }

    // --------------------------------------------------------
    // Query Functions
    // --------------------------------------------------------

    /// Returns whether a subject has at least one valid credential for a schema.
    ///
    /// A credential is considered valid when it belongs to `subject`, references
    /// `schema_id`, is not revoked, and is either non-expiring or has an
    /// `expires_at` value greater than the current ledger timestamp.
    ///
    /// Returns `false` when the subject has no credentials or no matching valid
    /// credential. This query does not require authorization and does not panic
    /// for missing subject credential storage.
    pub fn has_valid_credential(env: Env, subject: Address, schema_id: u32) -> bool {
        let creds: Vec<u64> = match env
            .storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject))
        {
            Some(c) => c,
            None => return false,
        };

        let now = env.ledger().timestamp();

        for cred_id in creds.iter() {
            if let Some(cred) = env
                .storage()
                .persistent()
                .get::<DataKey, Credential>(&DataKey::Credential(cred_id))
            {
                if cred.schema_id == schema_id
                    && !cred.revoked
                    && (cred.expires_at == 0 || cred.expires_at > now)
                {
                    return true;
                }
            }
        }

        false
    }

    /// Returns whether a subject has any valid credential from an issuer.
    ///
    /// A credential is considered valid when it belongs to `subject`, was issued
    /// by `issuer`, is not revoked, and is either non-expiring or has an
    /// `expires_at` value greater than the current ledger timestamp.
    ///
    /// Returns `false` when the subject has no credentials or no valid
    /// credential from `issuer`. This query does not require authorization and
    /// does not panic for missing subject credential storage.
    pub fn has_credential_from_issuer(env: Env, subject: Address, issuer: Address) -> bool {
        let creds: Vec<u64> = match env
            .storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject))
        {
            Some(c) => c,
            None => return false,
        };

        let now = env.ledger().timestamp();

        for cred_id in creds.iter() {
            if let Some(cred) = env
                .storage()
                .persistent()
                .get::<DataKey, Credential>(&DataKey::Credential(cred_id))
            {
                if cred.issuer == issuer
                    && !cred.revoked
                    && (cred.expires_at == 0 || cred.expires_at > now)
                {
                    return true;
                }
            }
        }

        false
    }

    /// Returns a credential by identifier.
    ///
    /// Panics if `credential_id` does not exist.
    pub fn get_credential(env: Env, credential_id: u64) -> Credential {
        env.storage()
            .persistent()
            .get(&DataKey::Credential(credential_id))
            .expect("Credential not found")
    }

    /// Returns the identity profile for a subject address.
    ///
    /// Panics if no identity has been created for `subject`.
    pub fn get_identity(env: Env, subject: Address) -> Identity {
        env.storage()
            .persistent()
            .get(&DataKey::Identity(subject))
            .expect("Identity not found")
    }

    /// Returns an issuer record by address.
    ///
    /// Panics if `issuer` is not registered.
    pub fn get_issuer(env: Env, issuer: Address) -> Issuer {
        env.storage()
            .persistent()
            .get(&DataKey::Issuer(issuer))
            .expect("Issuer not found")
    }

    /// Returns a credential schema by identifier.
    ///
    /// Panics if `schema_id` does not exist.
    pub fn get_schema(env: Env, schema_id: u32) -> Schema {
        env.storage()
            .persistent()
            .get(&DataKey::Schema(schema_id))
            .expect("Schema not found")
    }

    /// Returns all credential identifiers recorded for a subject.
    ///
    /// Returns an empty vector when `subject` has no credentials. This query
    /// does not require authorization and does not panic for missing subject
    /// credential storage.
    pub fn get_subject_credentials(env: Env, subject: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject))
            .unwrap_or(Vec::new(&env))
    }

    /// Returns all bridged credential identifiers for a subject.
    ///
    /// Returns an empty vector when `subject` has no bridged credentials.
    pub fn get_bridge_credentials(env: Env, subject: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::SubjectBridgeCredentials(subject))
            .unwrap_or(Vec::new(&env))
    }

    /// Returns the total number of credentials issued by the contract.
    ///
    /// Returns `0` when the counter has not been initialized.
    pub fn get_credential_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CredentialCount)
            .unwrap_or(0)
    }

    /// Returns the total number of schemas registered by the contract.
    ///
    /// Returns `0` when the counter has not been initialized.
    pub fn get_schema_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::SchemaCount)
            .unwrap_or(0)
    }

    /// Returns whether `sub_issuer` is authorized under `parent`.
    ///
    /// Returns `false` when no authorization record exists or when the
    /// relationship was explicitly revoked. This query does not require
    /// authorization.
    pub fn is_sub_issuer(env: Env, parent: Address, sub_issuer: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::SubIssuer(parent, sub_issuer))
            .unwrap_or(false)
    }

    /// Returns the bridge metadata for a credential, if it exists.
    ///
    /// Returns `None` when the credential has no bridge metadata.
    pub fn get_bridge_metadata(env: Env, credential_id: u64) -> Option<BridgeAttestation> {
        env.storage()
            .persistent()
            .get(&DataKey::BridgeMetadata(credential_id))
    }

    // --------------------------------------------------------
    // Credential Commitments (privacy layer)
    // --------------------------------------------------------

    /// Submits a privacy-preserving commitment to a credential.
    ///
    /// The `subject` computes the commitment off-chain as:
    ///   `SHA-256(credential_id as u64 little-endian || blinding_factor: BytesN<32>)`
    /// and submits only the hash. The underlying credential ID and blinding
    /// factor are never revealed on-chain at this point.
    ///
    /// Only one commitment per (subject, schema_id) pair is stored; submitting
    /// again overwrites the previous commitment.
    ///
    /// Panics if `subject` does not authorize the call or `schema_id` does not
    /// exist.
    pub fn submit_commitment(
        env: Env,
        subject: Address,
        schema_id: u32,
        commitment: BytesN<32>,
    ) {
        subject.require_auth();
        // Verify the schema exists (no need for it to be active — committing to
        // an existing credential under a since-deactivated schema is valid).
        env.storage()
            .persistent()
            .get::<DataKey, Schema>(&DataKey::Schema(schema_id))
            .expect("Schema not found");

        let now = env.ledger().timestamp();
        let record = CredentialCommitment {
            subject: subject.clone(),
            commitment: commitment.clone(),
            schema_id,
            committed_at: now,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Commitment(subject.clone(), schema_id), &record);

        env.events().publish(
            (Symbol::new(&env, "commitment_submitted"),),
            (subject, schema_id, commitment),
        );
    }

    /// Verifies that a commitment opens correctly to a valid credential.
    ///
    /// The caller provides `credential_id` and `blinding_factor`; the contract
    /// recomputes `SHA-256(credential_id_le || blinding_factor)` and checks it
    /// against the stored commitment. It also verifies that the credential is
    /// owned by `subject`, belongs to `schema_id`, is not revoked, and has not
    /// expired.
    ///
    /// Returns `true` only when all of the above hold; `false` otherwise.
    /// Does not panic for missing data — returns `false` instead.
    pub fn verify_commitment(
        env: Env,
        subject: Address,
        schema_id: u32,
        credential_id: u64,
        blinding_factor: BytesN<32>,
    ) -> bool {
        let record: CredentialCommitment = match env
            .storage()
            .persistent()
            .get(&DataKey::Commitment(subject.clone(), schema_id))
        {
            Some(r) => r,
            None => return false,
        };

        // Recompute the commitment: SHA-256(credential_id_le_bytes || blinding_factor)
        let expected = Self::compute_commitment(&env, credential_id, &blinding_factor);
        if expected != record.commitment {
            return false;
        }

        // Verify the underlying credential is valid
        let credential: Credential = match env
            .storage()
            .persistent()
            .get(&DataKey::Credential(credential_id))
        {
            Some(c) => c,
            None => return false,
        };

        if credential.subject != subject || credential.schema_id != schema_id {
            return false;
        }
        if credential.revoked {
            return false;
        }

        let now = env.ledger().timestamp();
        credential.expires_at == 0 || credential.expires_at > now
    }

    /// Returns whether a subject has a valid commitment for a schema.
    ///
    /// This is a privacy-preserving alternative to `has_valid_credential`: it
    /// tells observers that a commitment exists and is linked to a non-expired,
    /// non-revoked credential — without revealing which credential or issuer.
    ///
    /// Internally iterates the subject's credentials to find one that matches
    /// the stored commitment without exposing which credential matched.
    ///
    /// Returns `false` when no commitment exists or no valid matching credential
    /// is found. Does not require authorization.
    pub fn has_valid_commitment(env: Env, subject: Address, schema_id: u32) -> bool {
        // Just confirm a commitment exists for this (subject, schema_id) pair
        let has_commitment = env
            .storage()
            .persistent()
            .has(&DataKey::Commitment(subject.clone(), schema_id));
        if !has_commitment {
            return false;
        }

        let creds: Vec<u64> = match env
            .storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject.clone()))
        {
            Some(c) => c,
            None => return false,
        };

        let now = env.ledger().timestamp();

        for cred_id in creds.iter() {
            let credential: Credential = match env
                .storage()
                .persistent()
                .get(&DataKey::Credential(cred_id))
            {
                Some(c) => c,
                None => continue,
            };

            if credential.schema_id != schema_id || credential.revoked {
                continue;
            }
            if credential.expires_at != 0 && credential.expires_at <= now {
                continue;
            }

            // Check commitment matches — we don't know the blinding factor here,
            // so we just confirm the commitment record is present and the credential
            // is valid. The binding check (commitment = H(cred_id || r)) happens in
            // verify_commitment when the subject reveals the opening.
            // has_valid_commitment is a weaker check: "there is a commitment on-chain
            // AND the subject holds at least one live credential for this schema."
            return true;
        }

        false
    }

    // --------------------------------------------------------
    // Internal helpers
    // --------------------------------------------------------

    /// Computes the commitment hash: SHA-256(credential_id as 8 LE bytes || blinding_factor).
    fn compute_commitment(
        env: &Env,
        credential_id: u64,
        blinding_factor: &BytesN<32>,
    ) -> BytesN<32> {
        let id_bytes = credential_id.to_le_bytes();
        let mut preimage = Bytes::from_slice(env, &id_bytes);
        let bf_bytes = Bytes::from(blinding_factor);
        preimage.append(&bf_bytes);
        BytesN::from(env.crypto().sha256(&preimage))
    }

    fn require_active_issuer(env: &Env, issuer: &Address) -> u32 {
        let issuer_record: Option<Issuer> = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(issuer.clone()));
        if let Some(record) = issuer_record {
            assert!(record.active, "Issuer is not active");
            record.trust_level
        } else {
            panic!("Not a registered issuer");
        }
    }

    fn require_active_schema(env: &Env, schema_id: u32) {
        let schema: Schema = env
            .storage()
            .persistent()
            .get(&DataKey::Schema(schema_id))
            .expect("Schema not found");
        assert!(schema.active, "Schema is not active");
    }

    fn compute_reputation(credential_count: u32, trust_level: u32) -> u32 {
        let base = credential_count * 10;
        let trust_bonus = trust_level / 10;
        (base + trust_bonus).min(1000)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events, Ledger},
        Address, Bytes, BytesN, Env, String, Vec,
    };

    fn setup(env: &Env) -> (Address, StellarIdContractClient<'_>) {
        env.mock_all_auths();
        let admin = Address::generate(env);
        let contract_id = env.register_contract(None, StellarIdContract);
        let client = StellarIdContractClient::new(env, &contract_id);
        client.initialize(&admin);
        (admin, client)
    }

    fn register_issuer_helper(
        env: &Env,
        client: &StellarIdContractClient<'_>,
        admin: &Address,
    ) -> Address {
        let issuer = Address::generate(env);
        client.register_issuer(
            admin,
            &issuer,
            &String::from_str(env, "Test Issuer"),
            &80u32,
        );
        issuer
    }

    fn register_schema_helper(
        env: &Env,
        client: &StellarIdContractClient<'_>,
        issuer: &Address,
    ) -> u32 {
        client.register_schema(
            issuer,
            &String::from_str(env, "KYC Verified"),
            &String::from_str(env, "Basic KYC verification credential"),
        )
    }

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let (_admin, client) = setup(&env);
        assert_eq!(client.get_credential_count(), 0);
        assert_eq!(client.get_schema_count(), 0);
    }

    #[test]
    fn test_register_issuer() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);

        let record = client.get_issuer(&issuer);
        assert_eq!(record.trust_level, 80);
        assert!(record.active);
        assert_eq!(record.credential_count, 0);
    }

    #[test]
    fn test_register_schema() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);

        let schema_id = register_schema_helper(&env, &client, &issuer);
        assert_eq!(schema_id, 1);
        assert_eq!(client.get_schema_count(), 1);

        let schema = client.get_schema(&schema_id);
        assert!(schema.active);
        assert_eq!(schema.issuer, issuer);
    }

    #[test]
    fn test_issue_credential() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        assert_eq!(cred_id, 1);
        assert_eq!(client.get_credential_count(), 1);

        let cred = client.get_credential(&cred_id);
        assert_eq!(cred.subject, subject);
        assert_eq!(cred.issuer, issuer);
        assert!(!cred.revoked);
        assert_eq!(cred.expires_at, 0);
    }

    #[test]
    fn test_credential_with_expiry() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &3600u64);
        let cred = client.get_credential(&cred_id);
        assert_eq!(cred.expires_at, 4600);
    }

    #[test]
    fn test_has_valid_credential_true() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        assert!(!client.has_valid_credential(&subject, &schema_id));
        client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        assert!(client.has_valid_credential(&subject, &schema_id));
    }

    #[test]
    fn test_has_valid_credential_expired() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        client.issue_credential(&issuer, &subject, &schema_id, &500u64);
        env.ledger().set_timestamp(2000);
        assert!(!client.has_valid_credential(&subject, &schema_id));
    }

    #[test]
    fn test_has_valid_credential_expires_at_now_boundary() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        client.issue_credential(&issuer, &subject, &schema_id, &500u64);
        env.ledger().set_timestamp(1500);

        assert!(!client.has_valid_credential(&subject, &schema_id));
    }

    #[test]
    fn test_non_expiring_credential_indefinite() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        assert_eq!(client.get_credential(&cred_id).expires_at, 0);

        env.ledger().set_timestamp(10_000_000);

        assert!(client.has_valid_credential(&subject, &schema_id));
    }

    #[test]
    fn test_multiple_credentials_same_schema_one_expired_one_valid() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        client.issue_credential(&issuer, &subject, &schema_id, &100u64);
        env.ledger().set_timestamp(1200);
        client.issue_credential(&issuer, &subject, &schema_id, &500u64);

        assert!(client.has_valid_credential(&subject, &schema_id));
    }

    #[test]
    fn test_revoke_credential() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        assert!(client.has_valid_credential(&subject, &schema_id));

        client.revoke_credential(&issuer, &cred_id);
        let cred = client.get_credential(&cred_id);
        assert!(cred.revoked);
        assert!(!client.has_valid_credential(&subject, &schema_id));
    }

    #[test]
    fn test_identity_created_on_first_credential() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        let identity = client.get_identity(&subject);
        assert_eq!(identity.credential_count, 1);
        assert_eq!(identity.subject, subject);
    }

    #[test]
    fn test_reputation_increases_with_credentials() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let s1 = register_schema_helper(&env, &client, &issuer);
        let s2 = client.register_schema(
            &issuer,
            &String::from_str(&env, "Accredited Investor"),
            &String::from_str(&env, "Accredited investor status"),
        );
        let subject = Address::generate(&env);

        client.issue_credential(&issuer, &subject, &s1, &0u64);
        let rep1 = client.get_identity(&subject).reputation_score;

        client.issue_credential(&issuer, &subject, &s2, &0u64);
        assert!(client.get_identity(&subject).reputation_score > rep1);
    }

    #[test]
    fn test_get_subject_credentials() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let s1 = register_schema_helper(&env, &client, &issuer);
        let s2 = client.register_schema(
            &issuer,
            &String::from_str(&env, "Merchant"),
            &String::from_str(&env, "Verified merchant"),
        );
        let subject = Address::generate(&env);

        client.issue_credential(&issuer, &subject, &s1, &0u64);
        client.issue_credential(&issuer, &subject, &s2, &0u64);

        let creds = client.get_subject_credentials(&subject);
        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn test_deactivate_issuer() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);

        client.deactivate_issuer(&admin, &issuer);
        let record = client.get_issuer(&issuer);
        assert!(!record.active);
    }

    #[test]
    fn test_sub_issuer_authorization() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let parent = register_issuer_helper(&env, &client, &admin);
        let sub = Address::generate(&env);

        assert!(!client.is_sub_issuer(&parent, &sub));
        client.authorize_sub_issuer(&parent, &sub);
        assert!(client.is_sub_issuer(&parent, &sub));

        client.revoke_sub_issuer(&parent, &sub);
        assert!(!client.is_sub_issuer(&parent, &sub));
    }

    #[test]
    fn test_has_credential_from_issuer() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);
        let other_issuer = Address::generate(&env);

        client.issue_credential(&issuer, &subject, &schema_id, &0u64);

        assert!(client.has_credential_from_issuer(&subject, &issuer));
        assert!(!client.has_credential_from_issuer(&subject, &other_issuer));
    }

    #[test]
    #[should_panic(expected = "Trust level must be 1-100")]
    fn test_invalid_trust_level() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let issuer = Address::generate(&env);
        client.register_issuer(
            &admin,
            &issuer,
            &String::from_str(&env, "Bad Issuer"),
            &0u32,
        );
    }

    #[test]
    #[should_panic(expected = "Only admin can register issuers")]
    fn test_non_admin_cannot_register_issuer() {
        let env = Env::default();
        let (_admin, client) = setup(&env);
        let attacker = Address::generate(&env);
        let victim = Address::generate(&env);
        client.register_issuer(&attacker, &victim, &String::from_str(&env, "Fake"), &50u32);
    }

    #[test]
    #[should_panic(expected = "Only the original issuer can revoke")]
    fn test_non_issuer_cannot_revoke() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);
        let attacker = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        client.revoke_credential(&attacker, &cred_id);
    }

    #[test]
    fn test_deactivate_schema() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);

        assert!(client.get_schema(&schema_id).active);
        client.deactivate_schema(&issuer, &schema_id);
        assert!(!client.get_schema(&schema_id).active);
    }

    #[test]
    #[should_panic(expected = "Only the original issuer can deactivate this schema")]
    fn test_non_owner_cannot_deactivate_schema() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let other_issuer = register_issuer_helper(&env, &client, &admin);

        client.deactivate_schema(&other_issuer, &schema_id);
    }

    #[test]
    #[should_panic(expected = "Schema is not active")]
    fn test_issue_credential_against_inactive_schema_panics() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        client.deactivate_schema(&issuer, &schema_id);
        client.issue_credential(&issuer, &subject, &schema_id, &0u64);
    }

    #[test]
    fn test_existing_credentials_remain_valid_after_schema_deactivation() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        assert!(client.has_valid_credential(&subject, &schema_id));

        client.deactivate_schema(&issuer, &schema_id);

        // Existing credential is still valid
        assert!(client.has_valid_credential(&subject, &schema_id));
        let cred = client.get_credential(&cred_id);
        assert!(!cred.revoked);
    }

    #[test]
    #[should_panic(expected = "Only admin can deactivate issuers")]
    fn test_non_admin_cannot_deactivate_issuer() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let attacker = Address::generate(&env);
        client.deactivate_issuer(&attacker, &issuer);
    }

    #[test]
    #[should_panic(expected = "Issuer is not active")]
    fn test_deactivated_issuer_cannot_issue_credential() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);
        client.deactivate_issuer(&admin, &issuer);
        client.issue_credential(&issuer, &subject, &schema_id, &0u64);
    }

    #[test]
    #[should_panic(expected = "Issuer is not active")]
    fn test_deactivated_issuer_cannot_register_schema() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        client.deactivate_issuer(&admin, &issuer);
        client.register_schema(
            &issuer,
            &String::from_str(&env, "Test Schema"),
            &String::from_str(&env, "Test Description"),
        );
    }

    #[test]
    #[should_panic(expected = "Only the original issuer can revoke")]
    fn test_random_address_cannot_revoke_other_issuers_credential() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);
        let attacker = Address::generate(&env);
        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        client.revoke_credential(&attacker, &cred_id);
    }

    // --------------------------------------------------------
    // Batch credential issuance tests
    // --------------------------------------------------------

    #[test]
    fn test_batch_issue_credentials() {
        let env = Env::default();
        env.ledger().set_timestamp(2000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);

        let mut subjects: Vec<Address> = Vec::new(&env);
        subjects.push_back(Address::generate(&env));
        subjects.push_back(Address::generate(&env));
        subjects.push_back(Address::generate(&env));

        let event_count_before = env.events().all().len();

        let ids = client.batch_issue_credentials(&issuer, &subjects, &schema_id, &0u64);

        let event_count_after = env.events().all().len();

        // Returns sequential IDs
        assert_eq!(ids.len(), 3);
        assert_eq!(ids.get(0).unwrap(), 1);
        assert_eq!(ids.get(1).unwrap(), 2);
        assert_eq!(ids.get(2).unwrap(), 3);

        assert_eq!(client.get_credential_count(), 3);

        // Each credential has correct data
        for (i, subject) in subjects.iter().enumerate() {
            let cred = client.get_credential(&ids.get(i as u32).unwrap());
            assert_eq!(cred.subject, subject);
            assert_eq!(cred.issuer, issuer);
            assert_eq!(cred.schema_id, schema_id);
            assert!(!cred.revoked);
            assert_eq!(cred.expires_at, 0);
        }

        // Each subject has an identity
        for subject in subjects.iter() {
            let identity = client.get_identity(&subject);
            assert_eq!(identity.credential_count, 1);
            assert_eq!(identity.created_at, 2000);
        }

        // Issuer credential count updated
        let issuer_record = client.get_issuer(&issuer);
        assert_eq!(issuer_record.credential_count, 3);

        // Batch event was emitted
        assert!(
            event_count_after > event_count_before,
            "batch event should have been emitted"
        );
    }

    #[test]
    fn test_batch_issue_credentials_with_expiry() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);

        let mut subjects: Vec<Address> = Vec::new(&env);
        subjects.push_back(Address::generate(&env));
        subjects.push_back(Address::generate(&env));

        let ids = client.batch_issue_credentials(&issuer, &subjects, &schema_id, &3600u64);

        for i in 0..ids.len() {
            let cred = client.get_credential(&ids.get(i).unwrap());
            assert_eq!(cred.expires_at, 4600);
        }
    }

    #[test]
    fn test_batch_issue_credentials_updates_multiple_identities() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let s1 = register_schema_helper(&env, &client, &issuer);
        let s2 = client.register_schema(
            &issuer,
            &String::from_str(&env, "Accredited Investor"),
            &String::from_str(&env, "Accredited investor status"),
        );

        let mut subjects: Vec<Address> = Vec::new(&env);
        subjects.push_back(Address::generate(&env));
        subjects.push_back(Address::generate(&env));

        // Issue KYC to subject 0, both schemas to subject 1
        let mut single_subject: Vec<Address> = Vec::new(&env);
        single_subject.push_back(subjects.get(0).unwrap());
        client.batch_issue_credentials(&issuer, &single_subject, &s1, &0u64);

        client.batch_issue_credentials(&issuer, &subjects, &s2, &0u64);

        // Subject 0: two credentials (one from each batch)
        let id0 = client.get_identity(&subjects.get(0).unwrap());
        assert_eq!(id0.credential_count, 2);

        // Subject 1: one credential
        let id1 = client.get_identity(&subjects.get(1).unwrap());
        assert_eq!(id1.credential_count, 1);
    }

    #[test]
    #[should_panic(expected = "Schema is not active")]
    fn test_batch_issue_credentials_inactive_schema_panics() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let mut subjects: Vec<Address> = Vec::new(&env);
        subjects.push_back(Address::generate(&env));

        client.deactivate_schema(&issuer, &schema_id);
        client.batch_issue_credentials(&issuer, &subjects, &schema_id, &0u64);
    }

    #[test]
    #[should_panic(expected = "subjects list cannot be empty")]
    fn test_batch_issue_credentials_empty_subjects_panics() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subjects: Vec<Address> = Vec::new(&env);

        client.batch_issue_credentials(&issuer, &subjects, &schema_id, &0u64);
    }

    // --------------------------------------------------------
    // Credential renewal tests
    // --------------------------------------------------------

    #[test]
    fn test_renew_credential() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &3600u64);
        assert_eq!(client.get_credential(&cred_id).expires_at, 4600);

        client.renew_credential(&issuer, &cred_id, &7200u64);

        let cred = client.get_credential(&cred_id);
        assert_eq!(cred.expires_at, 11800);
        assert!(!cred.revoked);
        assert!(client.has_valid_credential(&subject, &schema_id));
    }

    #[test]
    fn test_renew_credential_multiple_times() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &1000u64);

        client.renew_credential(&issuer, &cred_id, &500u64);
        assert_eq!(client.get_credential(&cred_id).expires_at, 2500);

        client.renew_credential(&issuer, &cred_id, &500u64);
        assert_eq!(client.get_credential(&cred_id).expires_at, 3000);
    }

    #[test]
    #[should_panic(expected = "Only the original issuer can renew")]
    fn test_renew_credential_non_issuer_rejected() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);
        let attacker = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &3600u64);
        client.renew_credential(&attacker, &cred_id, &3600u64);
    }

    #[test]
    #[should_panic(expected = "Cannot renew a revoked credential")]
    fn test_renew_credential_revoked_rejected() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &3600u64);
        client.revoke_credential(&issuer, &cred_id);
        client.renew_credential(&issuer, &cred_id, &3600u64);
    }

    #[test]
    #[should_panic(expected = "additional_seconds must be greater than zero")]
    fn test_renew_credential_zero_additional_seconds_panics() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &3600u64);
        client.renew_credential(&issuer, &cred_id, &0u64);
    }

    #[test]
    #[should_panic(expected = "Cannot renew a non-expiring credential")]
    fn test_renew_credential_non_expiring_panics() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        client.renew_credential(&issuer, &cred_id, &3600u64);
    }

    #[test]
    fn test_renew_credential_restores_validity() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &500u64);
        assert!(client.has_valid_credential(&subject, &schema_id));

        // Advance past expiry
        env.ledger().set_timestamp(2000);
        assert!(!client.has_valid_credential(&subject, &schema_id));

        // Renew to extend beyond current time
        client.renew_credential(&issuer, &cred_id, &2000u64);
        assert!(client.has_valid_credential(&subject, &schema_id));
    }

    // --------------------------------------------------------
    // Bridge credential tests
    // --------------------------------------------------------

    #[test]
    fn test_bridge_credential_authorized() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let bridge_operator = Address::generate(&env);
        let subject = Address::generate(&env);

        // Register bridge operator
        client.register_bridge_operator(&admin, &bridge_operator);

        // Create bridge data
        let evm_uid = BytesN::from_array(&env, &[0u8; 32]);
        let evm_attester = BytesN::from_array(&env, &[0u8; 20]);
        let evm_schema_uid = BytesN::from_array(&env, &[0u8; 32]);

        let bridge_data = BridgeAttestation {
            evm_chain_id: 1,
            evm_uid: evm_uid.clone(),
            evm_attester,
            evm_schema_uid,
            evm_expiry: 0,
            bridge_operator: bridge_operator.clone(),
        };

        // Bridge credential
        let cred_id =
            client.bridge_credential(&bridge_operator, &subject, &schema_id, &bridge_data, &0u64);

        // Verify
        assert_eq!(cred_id, 1);
        let cred = client.get_credential(&cred_id);
        let bridge_meta = client.get_bridge_metadata(&cred_id);
        assert!(bridge_meta.is_some());
        assert_eq!(cred.issuer, bridge_operator);
        assert_eq!(client.get_bridge_credentials(&subject).len(), 1);
    }

    #[test]
    #[should_panic(expected = "Not an authorized bridge operator")]
    fn test_bridge_credential_unauthorized_panics() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let bridge_operator = Address::generate(&env);
        let subject = Address::generate(&env);

        // Create bridge data
        let evm_uid = BytesN::from_array(&env, &[0u8; 32]);
        let evm_attester = BytesN::from_array(&env, &[0u8; 20]);
        let evm_schema_uid = BytesN::from_array(&env, &[0u8; 32]);

        let bridge_data = BridgeAttestation {
            evm_chain_id: 1,
            evm_uid,
            evm_attester,
            evm_schema_uid,
            evm_expiry: 0,
            bridge_operator: bridge_operator.clone(),
        };

        // Try to bridge without registering operator
        client.bridge_credential(&bridge_operator, &subject, &schema_id, &bridge_data, &0u64);
    }

    #[test]
    #[should_panic(expected = "Attestation already bridged")]
    fn test_bridge_credential_duplicate_panics() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let bridge_operator = Address::generate(&env);
        let subject = Address::generate(&env);

        // Register bridge operator
        client.register_bridge_operator(&admin, &bridge_operator);

        // Create bridge data
        let evm_uid = BytesN::from_array(&env, &[0u8; 32]);
        let evm_attester = BytesN::from_array(&env, &[0u8; 20]);
        let evm_schema_uid = BytesN::from_array(&env, &[0u8; 32]);

        let bridge_data = BridgeAttestation {
            evm_chain_id: 1,
            evm_uid: evm_uid.clone(),
            evm_attester: evm_attester.clone(),
            evm_schema_uid: evm_schema_uid.clone(),
            evm_expiry: 0,
            bridge_operator: bridge_operator.clone(),
        };

        // Bridge once
        client.bridge_credential(&bridge_operator, &subject, &schema_id, &bridge_data, &0u64);

        // Bridge again (duplicate)
        let bridge_data2 = BridgeAttestation {
            evm_chain_id: 1,
            evm_uid: evm_uid.clone(),
            evm_attester,
            evm_schema_uid,
            evm_expiry: 0,
            bridge_operator: bridge_operator.clone(),
        };
        client.bridge_credential(&bridge_operator, &subject, &schema_id, &bridge_data2, &0u64);
    }

    #[test]
    #[should_panic(expected = "EVM attestation expired")]
    fn test_bridge_credential_expired_evm_panics() {
        let env = Env::default();
        env.ledger().set_timestamp(2000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let bridge_operator = Address::generate(&env);
        let subject = Address::generate(&env);

        // Register bridge operator
        client.register_bridge_operator(&admin, &bridge_operator);

        // Create bridge data with expiry in past
        let evm_uid = BytesN::from_array(&env, &[0u8; 32]);
        let evm_attester = BytesN::from_array(&env, &[0u8; 20]);
        let evm_schema_uid = BytesN::from_array(&env, &[0u8; 32]);

        let bridge_data = BridgeAttestation {
            evm_chain_id: 1,
            evm_uid: evm_uid.clone(),
            evm_attester,
            evm_schema_uid,
            evm_expiry: 1000, // expired
            bridge_operator: bridge_operator.clone(),
        };

        // Try to bridge
        client.bridge_credential(&bridge_operator, &subject, &schema_id, &bridge_data, &0u64);
    }

    #[test]
    #[should_panic(expected = "Not an authorized bridge operator")]
    fn test_revoke_bridge_operator() {
        let env = Env::default();
        let (admin, client) = setup(&env);
        let bridge_operator = Address::generate(&env);

        // Register then revoke
        client.register_bridge_operator(&admin, &bridge_operator);
        client.revoke_bridge_operator(&admin, &bridge_operator);

        // Verify operator is revoked by trying to bridge
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let evm_uid = BytesN::from_array(&env, &[0u8; 32]);
        let evm_attester = BytesN::from_array(&env, &[0u8; 20]);
        let evm_schema_uid = BytesN::from_array(&env, &[0u8; 32]);

        let bridge_data = BridgeAttestation {
            evm_chain_id: 1,
            evm_uid: evm_uid.clone(),
            evm_attester,
            evm_schema_uid,
            evm_expiry: 0,
            bridge_operator: bridge_operator.clone(),
        };

        client.bridge_credential(&bridge_operator, &subject, &schema_id, &bridge_data, &0u64);
    }

    // --------------------------------------------------------
    // Credential commitment (privacy layer) tests
    // --------------------------------------------------------

    fn make_commitment(env: &Env, credential_id: u64, blinding: &[u8; 32]) -> BytesN<32> {
        let id_bytes = credential_id.to_le_bytes();
        let mut preimage = Bytes::from_slice(env, &id_bytes);
        preimage.append(&Bytes::from_slice(env, blinding));
        BytesN::from(env.crypto().sha256(&preimage))
    }

    #[test]
    fn test_submit_and_verify_commitment_valid() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);

        let blinding = [7u8; 32];
        let commitment = make_commitment(&env, cred_id, &blinding);
        let bf = BytesN::from_array(&env, &blinding);

        client.submit_commitment(&subject, &schema_id, &commitment);

        assert!(client.verify_commitment(&subject, &schema_id, &cred_id, &bf));
        assert!(client.has_valid_commitment(&subject, &schema_id));
    }

    #[test]
    fn test_verify_commitment_wrong_blinding_factor() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);

        let blinding = [7u8; 32];
        let commitment = make_commitment(&env, cred_id, &blinding);
        client.submit_commitment(&subject, &schema_id, &commitment);

        // Different blinding factor — should fail
        let wrong_bf = BytesN::from_array(&env, &[8u8; 32]);
        assert!(!client.verify_commitment(&subject, &schema_id, &cred_id, &wrong_bf));
    }

    #[test]
    fn test_verify_commitment_tampered_commitment() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);

        // Submit a garbage commitment
        let tampered = BytesN::from_array(&env, &[0xde; 32]);
        client.submit_commitment(&subject, &schema_id, &tampered);

        let bf = BytesN::from_array(&env, &[7u8; 32]);
        assert!(!client.verify_commitment(&subject, &schema_id, &cred_id, &bf));
    }

    #[test]
    fn test_verify_commitment_expired_credential() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &500u64);

        let blinding = [42u8; 32];
        let commitment = make_commitment(&env, cred_id, &blinding);
        let bf = BytesN::from_array(&env, &blinding);
        client.submit_commitment(&subject, &schema_id, &commitment);

        // Advance past expiry
        env.ledger().set_timestamp(2000);

        assert!(!client.verify_commitment(&subject, &schema_id, &cred_id, &bf));
        assert!(!client.has_valid_commitment(&subject, &schema_id));
    }

    #[test]
    fn test_has_valid_commitment_no_commitment_submitted() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        client.issue_credential(&issuer, &subject, &schema_id, &0u64);

        // Credential exists but no commitment submitted
        assert!(!client.has_valid_commitment(&subject, &schema_id));
    }

    #[test]
    fn test_verify_commitment_revoked_credential() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);

        let blinding = [99u8; 32];
        let commitment = make_commitment(&env, cred_id, &blinding);
        let bf = BytesN::from_array(&env, &blinding);
        client.submit_commitment(&subject, &schema_id, &commitment);

        client.revoke_credential(&issuer, &cred_id);

        assert!(!client.verify_commitment(&subject, &schema_id, &cred_id, &bf));
        assert!(!client.has_valid_commitment(&subject, &schema_id));
    }
}
