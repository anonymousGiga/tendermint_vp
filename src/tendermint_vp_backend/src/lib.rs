use ic_cdk::{query, update};

use signer::*;
pub mod signer;

#[update]
async fn public_key() -> Result<PublicKeyReply, String> {
    signer::public_key().await
}

#[update]
async fn sign(message: String) -> Result<SignatureReply, String> {
    signer::sign(message).await
}

#[query]
async fn verify(
    signature_hex: String,
    message: String,
    public_key_hex: String,
) -> Result<SignatureVerificationReply, String> {
    signer::verify(signature_hex, message, public_key_hex).await
}
