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

    /// Initialize the contract with an admin address
    /// Initializes the contract. Must be called once before any other function.
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

    /// Register a new issuer (admin only)
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

    /// Deactivate an issuer (admin only)
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

    /// Authorize a sub-issuer to issue credentials on behalf of a parent issuer
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

    /// Revoke a sub-issuer authorization
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

    /// Register a new credential schema (issuers only)
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

    // --------------------------------------------------------
    // Credential Issuance
    // --------------------------------------------------------

    /// Issue a credential to a subject
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

    /// Revoke a credential (issuer only)
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

    /// Renew a credential (issuer only)
    pub fn renew_credential(
        env: Env,
        issuer: Address,
        credential_id: u64,
        additional_seconds: u64,
    ) {
        issuer.require_auth();

        let mut credential: Credential = env
            .storage()
            .persistent()
            .get(&DataKey::Credential(credential_id))
            .expect("Credential not found");

        if credential.issuer != issuer {
            panic!("Only the original issuer can renew");
        }
        if credential.revoked {
            panic!("Cannot renew a revoked credential");
        }
        if additional_seconds <= 0 {
            panic!("Additional seconds must be greater than zero");
        }
        
        if credential.expires_at == 0 {
            panic!("Cannot renew a non-expiring credential");
        }

        let new_expires_at = credential.expires_at + additional_seconds;
        credential.expires_at = new_expires_at;
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

    /// Check if a subject has a valid (non-revoked, non-expired) credential for a schema
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

    /// Check if a subject has any valid credential from a specific issuer
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

    /// Get a credential by ID
    pub fn get_credential(env: Env, credential_id: u64) -> Credential {
        env.storage()
            .persistent()
            .get(&DataKey::Credential(credential_id))
            .expect("Credential not found")
    }

    /// Get an identity profile
    pub fn get_identity(env: Env, subject: Address) -> Identity {
        env.storage()
            .persistent()
            .get(&DataKey::Identity(subject))
            .expect("Identity not found")
    }

    /// Get an issuer record
    pub fn get_issuer(env: Env, issuer: Address) -> Issuer {
        env.storage()
            .persistent()
            .get(&DataKey::Issuer(issuer))
            .expect("Issuer not found")
    }

    /// Get a schema by ID
    pub fn get_schema(env: Env, schema_id: u32) -> Schema {
        env.storage()
            .persistent()
            .get(&DataKey::Schema(schema_id))
            .expect("Schema not found")
    }

    /// Get all credential IDs for a subject
    pub fn get_subject_credentials(env: Env, subject: Address) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::SubjectCredentials(subject))
            .unwrap_or(Vec::new(&env))
    }

    /// Get total credential count
    pub fn get_credential_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CredentialCount)
            .unwrap_or(0)
    }

    /// Get total schema count
    pub fn get_schema_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::SchemaCount)
            .unwrap_or(0)
    }

    /// Check if an address is an authorized sub-issuer for a parent
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
    fn test_renew_credential_happy_path() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &3600u64);
        let cred = client.get_credential(&cred_id);
        assert_eq!(cred.expires_at, 4600);

        client.renew_credential(&issuer, &cred_id, &1800u64);
        let renewed_cred = client.get_credential(&cred_id);
        assert_eq!(renewed_cred.expires_at, 6400);
        assert!(!renewed_cred.revoked);
    }

    #[test]
    #[should_panic(expected = "Only the original issuer can renew")]
    fn test_renew_credential_non_issuer() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);
        let attacker = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &3600u64);
        client.renew_credential(&attacker, &cred_id, &1800u64);
    }

    #[test]
    #[should_panic(expected = "Cannot renew a revoked credential")]
    fn test_renew_credential_revoked() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &3600u64);
        client.revoke_credential(&issuer, &cred_id);
        client.renew_credential(&issuer, &cred_id, &1800u64);
    }

    #[test]
    #[should_panic(expected = "Cannot renew a non-expiring credential")]
    fn test_renew_credential_non_expiring() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &0u64);
        client.renew_credential(&issuer, &cred_id, &1800u64);
    }

    #[test]
    #[should_panic(expected = "Additional seconds must be greater than zero")]
    fn test_renew_credential_zero_seconds() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (admin, client) = setup(&env);
        let issuer = register_issuer_helper(&env, &client, &admin);
        let schema_id = register_schema_helper(&env, &client, &issuer);
        let subject = Address::generate(&env);

        let cred_id = client.issue_credential(&issuer, &subject, &schema_id, &3600u64);
        client.renew_credential(&issuer, &cred_id, &0u64);
    }
}
