#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Symbol, Vec};

// ============================================================
// Data Types
// ============================================================

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

        let issuer_record: Option<Issuer> = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(issuer.clone()));

        let effective_trust: u32;

        if let Some(record) = issuer_record {
            assert!(record.active, "Issuer is not active");
            effective_trust = record.trust_level;
        } else {
            panic!("Not a registered issuer");
        }

        let schema: Schema = env
            .storage()
            .persistent()
            .get(&DataKey::Schema(schema_id))
            .expect("Schema not found");
        assert!(schema.active, "Schema is not active");

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

    // --------------------------------------------------------
    // Internal helpers
    // --------------------------------------------------------

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
        testutils::{Address as _, Ledger},
        Address, Env, String,
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
}
