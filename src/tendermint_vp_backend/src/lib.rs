use ic_cdk::export::{
    candid::CandidType,
    serde::{Deserialize, Serialize},
    Principal,
};
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use sha2::digest::generic_array::sequence;
use std::convert::TryFrom;
use std::str::FromStr;

use std::cell::RefCell;
use tendermint_client::channel_builder;
use tendermint_client::connection_builder;
use tendermint_client::header_builder;
use tendermint_client::msg_verifier::{self, *};

use ibc::core::ics02_client::msgs::create_client::MsgCreateClient;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::MsgCreateClient as RawMsgCreateClient;
use ibc_proto::ibc::lightclients::solomachine::v1::ClientState as RawSmClientState;
use ibc_proto::ibc::lightclients::solomachine::v1::ConsensusState as RawSmConsesusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

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

struct TendermintInstance {
    owner: Option<Principal>,
    verifier: Option<msg_verifier::MessageVerifier>,
}

thread_local! {
    static INSTANCE: RefCell<TendermintInstance> = RefCell::new(TendermintInstance { owner: None, verifier: None });
}

#[init]
fn init() {
    ic_cdk::print("Init start!");
    let caller = ic_cdk::api::caller();
    ic_cdk::println!("caller: {:?}", caller);
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance.owner = Some(caller);
    });
    ic_cdk::print("Init finished!");
}

#[update]
fn set_verifier() -> Result<(), String> {
    ic_cdk::print("Set verifier start!");
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        if instance.verifier.is_none() {
            instance.verifier = Some(MessageVerifier::new())
        }
    });
    ic_cdk::print("Set verifier ok!");

    Ok(())
}

#[derive(CandidType, Deserialize, Clone, Default)]
pub struct SmState {
    pub client_state: Vec<u8>,
    pub consensus_state: Vec<u8>,
}

// input: MsgCreateClient
// output: (sm_client_state, sm_consensus_state)
#[query]
async fn create_client(msg: Vec<u8>) -> Result<SmState, String> {
    let msg: MsgCreateClient = RawMsgCreateClient::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let pk = public_key().await.unwrap().public_key_hex;

    let (tm_client_state, tm_consensus_state) = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .create_client(msg)
    })?;

    let sequence = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .expect("Verifier need set")
            .sequence_cnt
    });

    let sm_client_state = header_builder::build_solomachine_client_state(
        sequence,
        &tm_client_state,
        &tm_consensus_state,
        &pk[..],
    )?;

    let sm_consensus_state =
        header_builder::build_solomachine_consensus_state(&pk[..], &tm_consensus_state)?;

    Ok(SmState {
        client_state: RawSmClientState::from(sm_client_state).encode_to_vec(),
        consensus_state: RawSmConsesusState::from(sm_consensus_state).encode_to_vec(),
    })
}
