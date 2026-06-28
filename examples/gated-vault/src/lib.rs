#![no_std]
use soroban_sdk::{contract, contractclient, contractimpl, contracttype, Address, Env};

/// Cross-contract interface for StellarID verification queries.
///
/// `#[contractclient]` generates `StellarIdVerifierClient` — a typed wrapper
/// around `env.invoke_contract()`. Method signatures must match the StellarID
/// contract's public functions exactly.
#[contractclient(name = "StellarIdVerifierClient")]
pub trait StellarIdVerifier {
    fn has_valid_credential(env: Env, subject: Address, schema_id: u32) -> bool;
    fn has_credential_from_issuer(env: Env, subject: Address, issuer: Address) -> bool;
    fn get_identity(env: Env, subject: Address) -> Identity;
}

/// Replicated from the StellarID contract so the generated client can decode
/// cross-contract return values. Keep in sync with `stellar_id::Identity`.
#[contracttype]
#[derive(Clone, Debug)]
pub struct Identity {
    pub subject: Address,
    pub credential_count: u32,
    pub reputation_score: u32,
    pub created_at: u64,
}

/// KYC schema ID — first schema registered on a fresh StellarID deployment.
pub const KYC_SCHEMA_ID: u32 = 1;

#[contracttype]
enum DataKey {
    Admin,
    StellarIdContract,
    KycSchemaId,
    Balance(Address),
}

#[contract]
pub struct GatedVault;

#[contractimpl]
impl GatedVault {
    pub fn initialize(env: Env, admin: Address, stellar_id_contract: Address, kyc_schema_id: u32) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::StellarIdContract, &stellar_id_contract);
        env.storage()
            .instance()
            .set(&DataKey::KycSchemaId, &kyc_schema_id);
    }

    pub fn deposit(env: Env, user: Address, amount: u64) {
        user.require_auth();
        Self::assert_kyc_verified(&env, &user);
        let mut balance: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(user.clone()))
            .unwrap_or(0);
        balance += amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user), &balance);
    }

    pub fn withdraw(env: Env, user: Address, amount: u64) {
        user.require_auth();
        Self::assert_kyc_verified(&env, &user);
        let mut balance: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(user.clone()))
            .unwrap_or(0);
        assert!(balance >= amount, "Insufficient balance");
        balance -= amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user), &balance);
    }

    pub fn get_balance(env: Env, user: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    fn assert_kyc_verified(env: &Env, user: &Address) {
        let stellar_id_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::StellarIdContract)
            .expect("Not initialized");
        let kyc_schema_id: u32 = env
            .storage()
            .instance()
            .get(&DataKey::KycSchemaId)
            .expect("Not initialized");
        let client = StellarIdVerifierClient::new(env, &stellar_id_contract);
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

    fn setup_vault(
        env: &Env,
    ) -> (
        Address,
        StellarIdContractClient<'_>,
        GatedVaultClient<'_>,
        Address,
        u32,
    ) {
        env.mock_all_auths();

        let stellar_id_admin = Address::generate(env);
        let stellar_id_contract = env.register_contract(None, StellarIdContract);
        let stellar_id_client = StellarIdContractClient::new(env, &stellar_id_contract);
        stellar_id_client.initialize(&stellar_id_admin);

        let issuer = Address::generate(env);
        stellar_id_client.register_issuer(
            &stellar_id_admin,
            &issuer,
            &String::from_str(env, "Test Issuer"),
            &80u32,
        );
        let kyc_schema_id = stellar_id_client.register_schema(
            &issuer,
            &String::from_str(env, "KYC Verified"),
            &String::from_str(env, "KYC Credential"),
        );
        assert_eq!(kyc_schema_id, KYC_SCHEMA_ID);

        let vault_admin = Address::generate(env);
        let vault_contract = env.register_contract(None, GatedVault);
        let vault_client = GatedVaultClient::new(env, &vault_contract);
        vault_client.initialize(&vault_admin, &stellar_id_contract, &kyc_schema_id);

        (
            issuer,
            stellar_id_client,
            vault_client,
            stellar_id_contract,
            kyc_schema_id,
        )
    }

    fn issue_kyc(
        env: &Env,
        stellar_id_client: &StellarIdContractClient<'_>,
        issuer: &Address,
        user: &Address,
        kyc_schema_id: u32,
    ) {
        env.ledger().set_timestamp(1000);
        stellar_id_client.issue_credential(issuer, user, &kyc_schema_id, &0u64);
    }

    #[test]
    #[should_panic(expected = "User must have a valid KYC credential")]
    fn test_deposit_rejects_non_kyc_wallet() {
        let env = Env::default();
        let (_, _, vault_client, _, _) = setup_vault(&env);
        let user = Address::generate(&env);
        vault_client.deposit(&user, &100u64);
    }

    #[test]
    fn test_deposit_accepts_kyc_wallet() {
        let env = Env::default();
        let (issuer, stellar_id_client, vault_client, _, kyc_schema_id) = setup_vault(&env);
        let user = Address::generate(&env);
        issue_kyc(&env, &stellar_id_client, &issuer, &user, kyc_schema_id);

        vault_client.deposit(&user, &100u64);
        assert_eq!(vault_client.get_balance(&user), 100);
    }

    #[test]
    #[should_panic(expected = "User must have a valid KYC credential")]
    fn test_deposit_rejects_wrong_schema_credential() {
        let env = Env::default();
        let (issuer, stellar_id_client, vault_client, _, _) = setup_vault(&env);
        let user = Address::generate(&env);

        let other_schema_id = stellar_id_client.register_schema(
            &issuer,
            &String::from_str(&env, "Accredited Investor"),
            &String::from_str(&env, "Investor Credential"),
        );
        assert_ne!(other_schema_id, KYC_SCHEMA_ID);

        env.ledger().set_timestamp(1000);
        stellar_id_client.issue_credential(&issuer, &user, &other_schema_id, &0u64);
        vault_client.deposit(&user, &100u64);
    }

    #[test]
    fn test_withdraw_with_valid_kyc() {
        let env = Env::default();
        let (issuer, stellar_id_client, vault_client, _, kyc_schema_id) = setup_vault(&env);
        let user = Address::generate(&env);
        issue_kyc(&env, &stellar_id_client, &issuer, &user, kyc_schema_id);

        vault_client.deposit(&user, &100u64);
        vault_client.withdraw(&user, &50u64);
        assert_eq!(vault_client.get_balance(&user), 50);
    }

    #[test]
    #[should_panic(expected = "User must have a valid KYC credential")]
    fn test_deposit_rejects_revoked_kyc() {
        let env = Env::default();
        let (issuer, stellar_id_client, vault_client, _, kyc_schema_id) = setup_vault(&env);
        let user = Address::generate(&env);
        issue_kyc(&env, &stellar_id_client, &issuer, &user, kyc_schema_id);

        let cred_ids = stellar_id_client.get_subject_credentials(&user);
        let cred_id = cred_ids.get(0).unwrap();
        stellar_id_client.revoke_credential(&issuer, &cred_id);
        vault_client.deposit(&user, &100u64);
    }

    #[test]
    #[should_panic(expected = "User must have a valid KYC credential")]
    fn test_deposit_rejects_expired_kyc() {
        let env = Env::default();
        let (issuer, stellar_id_client, vault_client, _, kyc_schema_id) = setup_vault(&env);
        let user = Address::generate(&env);

        env.ledger().set_timestamp(1000);
        stellar_id_client.issue_credential(&issuer, &user, &kyc_schema_id, &3600u64);
        env.ledger().set_timestamp(4601);
        vault_client.deposit(&user, &100u64);
    }

    #[test]
    fn test_get_balance_returns_zero_for_new_user() {
        let env = Env::default();
        let (_, _, vault_client, _, _) = setup_vault(&env);
        let user = Address::generate(&env);
        assert_eq!(vault_client.get_balance(&user), 0);
    }

    #[test]
    fn test_gated_vault_end_to_end() {
        let env = Env::default();
        let (issuer, stellar_id_client, vault_client, _, kyc_schema_id) = setup_vault(&env);
        let user = Address::generate(&env);

        issue_kyc(&env, &stellar_id_client, &issuer, &user, kyc_schema_id);

        vault_client.deposit(&user, &100u64);
        assert_eq!(vault_client.get_balance(&user), 100);

        vault_client.withdraw(&user, &50u64);
        assert_eq!(vault_client.get_balance(&user), 50);
    }
}
