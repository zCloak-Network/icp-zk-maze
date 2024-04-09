use ic_cdk_macros::{self, update};

use miden_vm::verify_zk_bool;
use std::str;
mod test;
use ic_cdk::export::{
    candid::CandidType,
    serde::{Deserialize, Serialize},
    Principal,
};
use std::str::FromStr;
use test::TEST_PROOF;

#[derive(CandidType, Serialize, Debug)]
struct PublicKeyReply {
    pub public_key_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureReply {
    pub signature_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureVerificationReply {
    pub is_signature_valid: bool,
}

type CanisterId = Principal;

#[derive(CandidType, Serialize, Debug)]
struct ECDSAPublicKey {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

// local env: TestKeyLocalDevelopment
// dev env: TestKey1
#[update]
async fn public_key() -> Result<PublicKeyReply, String> {
    let request = ECDSAPublicKey {
        canister_id: None,
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };

    let (res,): (ECDSAPublicKeyReply,) =
        ic_cdk::call(mgmt_canister_id(), "ecdsa_public_key", (request,))
            .await
            .map_err(|e| format!("ecdsa_public_key failed {}", e.1))?;

    Ok(PublicKeyReply {
        public_key_hex: hex::encode(&res.public_key),
    })
}

#[ic_cdk::update]
async fn sign(message: String) -> Result<SignatureReply, String> {
    let request = SignWithECDSA {
        message_hash: sha256(&message).to_vec(),
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };

    let (response,): (SignWithECDSAReply,) = ic_cdk::api::call::call_with_payment(
        mgmt_canister_id(),
        "sign_with_ecdsa",
        (request,),
        25_000_000_000,
    )
    .await
    .map_err(|e| format!("sign_with_ecdsa failed {}", e.1))?;

    Ok(SignatureReply {
        signature_hex: hex::encode(&response.signature),
    })
}

#[ic_cdk::update]
async fn sign_get_request_update(message: String) -> Result<SignWithECDSA, String> {
    let request = SignWithECDSA {
        message_hash: sha256(&message).to_vec(),
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };
    Ok(request)
}

#[ic_cdk::query]
async fn sign_get_request_query(message: String) -> Result<SignWithECDSA, String> {
    let request = SignWithECDSA {
        message_hash: sha256(&message).to_vec(),
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };
    Ok(request)
}

#[ic_cdk::query]
async fn verify(
    signature_hex: String,
    message: String,
    public_key_hex: String,
) -> Result<SignatureVerificationReply, String> {
    let signature_bytes = hex::decode(&signature_hex).expect("failed to hex-decode signature");
    let pubkey_bytes = hex::decode(&public_key_hex).expect("failed to hex-decode public key");
    let message_bytes = message.as_bytes();

    use k256::ecdsa::signature::Verifier;
    let signature = k256::ecdsa::Signature::try_from(signature_bytes.as_slice())
        .expect("failed to deserialize signature");
    let is_signature_valid = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .expect("failed to deserialize sec1 encoding into public key")
        .verify(message_bytes, &signature)
        .is_ok();

    Ok(SignatureVerificationReply { is_signature_valid })
}


// for zkVM test only
#[ic_cdk::query]
fn test_proof() -> (bool, Vec<String>) {
    let program_hash = "79414c1c82c0ef42aff896debc5b8ed351189264f32085ea5fad753b19f48d4e";
    let public_input = "7,0,6,5,6,4,6,3,6,2,5,2,4,4,4,3,4,2,3,7,3,5,2,2,2,0,1,2,0,6,0,5,0,2,0,1,18,15,7,7,0,0,8,8";
    let (verify_result, output) = verify_zk_bool(
        program_hash.to_string(),
        public_input.to_string(),
        TEST_PROOF.to_string(),
    );
    (verify_result, output)
}

fn mgmt_canister_id() -> CanisterId {
    CanisterId::from_str(&"aaaaa-aa").unwrap()
}

fn sha256(input: &String) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().into()
}

enum EcdsaKeyIds {
    #[allow(unused)]
    TestKeyLocalDevelopment,
    #[allow(unused)]
    TestKey1,
    #[allow(unused)]
    ProductionKey1,
}

impl EcdsaKeyIds {
    fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::TestKeyLocalDevelopment => "dfx_test_key",
                Self::TestKey1 => "test_key_1",
                Self::ProductionKey1 => "key_1",
            }
            .to_string(),
        }
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


// for local test only 
#[ic_cdk::update]
async fn zk_verify_test(
    // program_hash: String,
    // public_input: String,
    // proof: String,
) -> (String, String, Vec<String>) {
    let program_hash = "79414c1c82c0ef42aff896debc5b8ed351189264f32085ea5fad753b19f48d4e".to_string();
    let public_input = "7,0,6,5,6,4,6,3,6,2,5,2,4,4,4,3,4,2,3,7,3,5,2,2,2,0,1,2,0,6,0,5,0,2,0,1,18,15,7,7,0,0,8,8".to_string();
    let proof = TEST_PROOF.to_string();
    let modified_proof = proof.replace('\'', "\"");

    let (zk_verify_result, output) = verify_zk_bool(
        program_hash.clone(),
        public_input.clone(),
        modified_proof.clone(),
    );

    if zk_verify_result == false {
        return (
            "Verification failed".to_string(),
            "".to_string(),
            Vec::new(),
        );
    } else {
        let public_input_hash = hex::encode(sha256(&public_input));
        let origin_message = program_hash + &public_input_hash + &output.join("");
        let signature = sign(origin_message).await.unwrap();
        // let signature_hex = signature.unwrap().signature_hex;
        // let public_key_string = public_key().await.unwrap().public_key_hex;
        // let verify_result: Result<SignatureVerificationReply, String> = verify(signature_hex.clone(), program_hash.to_string(), public_key_string.clone()).await;
        // sig, publickey, message
        return (signature.signature_hex, public_input_hash, output);
    }
}


#[ic_cdk::update]
async fn zk_verify(
    program_hash: String,
    public_input: String,
    proof: String,
) -> (String, String, Vec<String>) {
    let modified_proof = proof.replace('\'', "\"");

    let (zk_verify_result, output) = verify_zk_bool(
        program_hash.clone(),
        public_input.clone(),
        modified_proof.clone(),
    );

    if zk_verify_result == false {
        return (
            "Verification failed".to_string(),
            "".to_string(),
            Vec::new(),
        );
    } else {
        let public_input_hash = hex::encode(sha256(&public_input));
        let origin_message = program_hash + &public_input_hash + &output.join("");
        let signature = sign(origin_message).await.unwrap();
        // let signature_hex = signature.unwrap().signature_hex;
        // let public_key_string = public_key().await.unwrap().public_key_hex;
        // let verify_result: Result<SignatureVerificationReply, String> = verify(signature_hex.clone(), program_hash.to_string(), public_key_string.clone()).await;
        // sig, publickey, message
        return (signature.signature_hex, public_input_hash, output);
    }
}