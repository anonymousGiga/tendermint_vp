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
use tendermint_client::solomachine_store::SoloMachineStateStores;
use tendermint_client::types::ConnectionMsgType;

use ibc::core::{
    ics02_client::msgs::update_client::MsgUpdateClient,
    ics04_channel::msgs::chan_close_init::MsgChannelCloseInit,
    ics04_channel::msgs::chan_open_ack::MsgChannelOpenAck,
    ics04_channel::msgs::chan_open_confirm::MsgChannelOpenConfirm,
    ics04_channel::msgs::chan_open_try::MsgChannelOpenTry,
    ics04_channel::{channel::ChannelEnd, msgs::chan_open_init::MsgChannelOpenInit},
};
use ibc::{
    clients::ics07_tendermint::consensus_state,
    core::ics02_client::msgs::create_client::MsgCreateClient,
};

use ibc_proto::{google::protobuf::Any, ibc::core::client};

use ibc_proto::ibc::lightclients::solomachine::v1::ClientState as RawSmClientState;
use ibc_proto::ibc::lightclients::solomachine::v1::ConsensusState as RawSmConsesusState;
use ibc_proto::ibc::lightclients::solomachine::v1::Header as RawSmHeader;

use ibc_proto::ibc::core::client::v1::MsgCreateClient as RawMsgCreateClient;
use ibc_proto::ibc::core::client::v1::MsgUpdateClient as RawMsgUpdateClient;

use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics03_connection::msgs::conn_open_ack::MsgConnectionOpenAck;
use ibc::core::ics03_connection::msgs::conn_open_confirm::MsgConnectionOpenConfirm;
use ibc::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
use ibc::core::ics03_connection::msgs::conn_open_try::MsgConnectionOpenTry;
use ibc::core::ics24_host::identifier::{ClientId, ConnectionId};
use ibc_proto::ibc::core::connection::v1::ConnectionEnd as RawConnectionEnd;
use ibc_proto::ibc::core::connection::v1::MsgConnectionOpenAck as RawMsgConnectionOpenAck;
use ibc_proto::ibc::core::connection::v1::MsgConnectionOpenInit as RawMsgConnectionOpenInit;
use ibc_proto::ibc::core::connection::v1::MsgConnectionOpenTry as RawMsgConnectionOpenTry;

use ibc_proto::ibc::core::channel::v1::Channel as RawChannelEnd;
use ibc_proto::ibc::core::channel::v1::MsgChannelCloseInit as RawMsgChannelCloseInit;
use ibc_proto::ibc::core::channel::v1::MsgChannelOpenAck as RawMsgChannelOpenAck;
use ibc_proto::ibc::core::channel::v1::MsgChannelOpenConfirm as RawMsgChannelOpenConfirm;
use ibc_proto::ibc::core::channel::v1::MsgChannelOpenInit as RawMsgChannelOpenInit;
use ibc_proto::ibc::core::channel::v1::MsgChannelOpenTry as RawMsgChannelOpenTry;

use ibc::core::ics24_host::identifier::{ChainId, ChannelId, PortId};

use ibc::Height;

use ibc_proto::protobuf::Protobuf;
use prost::Message;

use signer::*;
pub mod signer;

#[update]
async fn public_key() -> Result<PublicKeyReply, String> {
    signer::public_key().await
}

#[update]
async fn sign(message: Vec<u8>) -> Result<SignatureReply, String> {
    signer::sign(&message).await
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
    verifier: Option<MessageVerifier>,
    solo_store: Option<SoloMachineStateStores>,
}

thread_local! {
    static INSTANCE: RefCell<TendermintInstance> = RefCell::new(TendermintInstance { owner: None, verifier: None, solo_store: None});
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
fn start() -> Result<(), String> {
    ic_cdk::print("start!");
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        if instance.verifier.is_none() {
            instance.verifier = Some(MessageVerifier::new())
        }
        if instance.solo_store.is_none() {
            instance.solo_store = Some(SoloMachineStateStores::new())
        }
    });
    ic_cdk::print("Start ok!");

    Ok(())
}

#[derive(CandidType, Deserialize, Clone, Default)]
pub struct SmState {
    pub client_state: Vec<u8>,
    pub consensus_state: Vec<u8>,
}

fn get_sequence() -> u64 {
    let sequence = INSTANCE.with(|instance| {
        let instance = instance.borrow();
        instance
            .verifier
            .as_ref()
            .expect("Verifier need set")
            .sequence_cnt
    });

    increase_sequence();

    sequence
}

fn increase_sequence() {
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .expect("Verifier need set")
            .increase_sequence()
    });
}

// input: MsgCreateClient
// output: (sm_client_state, sm_consensus_state)
#[update]
async fn create_client(msg: Vec<u8>) -> Result<SmState, String> {
    let msg: MsgCreateClient = RawMsgCreateClient::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let pk = public_key().await.unwrap().public_key;

    let (client_id, tm_client_state, tm_consensus_state) = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .create_client(msg)
    })?;

    let sequence = get_sequence();

    let sm_client_state = header_builder::build_solomachine_client_state(
        sequence,
        &tm_client_state,
        &tm_consensus_state,
        &pk[..],
    )?;

    let sm_consensus_state =
        header_builder::build_solomachine_consensus_state(&pk[..], &tm_consensus_state)?;

    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .solo_store
            .as_mut()
            .ok_or("Need start first".to_string())?
            .insert(
                client_id,
                sequence,
                sm_client_state.clone(),
                sm_consensus_state.clone(),
            );

        Ok(SmState {
            client_state: RawSmClientState::from(sm_client_state).encode_to_vec(),
            consensus_state: RawSmConsesusState::from(sm_consensus_state).encode_to_vec(),
        })
    })
}

// input: MsgUpdateClient
// output: sm_header
#[update]
async fn update_client(msg: Vec<u8>) -> Result<Vec<u8>, String> {
    let msg: MsgUpdateClient = RawMsgUpdateClient::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let pk = public_key().await.unwrap().public_key;

    let (client_id, tm_client_state, tm_consensus_state) = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .update_client(msg)
    })?;
    let sequence = get_sequence();

    let (sm_header_temp, sign_bytes) = header_builder::construct_solomachine_header(
        &tm_client_state,
        &tm_consensus_state,
        &pk[..],
        sequence,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let sm_header = header_builder::build_solomachine_header(sm_header_temp, &raw_signature)?;

    let sm_client_state = header_builder::build_solomachine_client_state(
        sequence,
        &tm_client_state,
        &tm_consensus_state,
        &pk[..],
    )?;

    let sm_consensus_state =
        header_builder::build_solomachine_consensus_state(&pk[..], &tm_consensus_state)?;

    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .solo_store
            .as_mut()
            .ok_or("Need start first".to_string())?
            .insert(client_id, sequence, sm_client_state, sm_consensus_state);
        Ok(RawSmHeader::from(sm_header).encode_to_vec())
    })
}

// input:
// output:
// upgrade_client

// input:
// output:
// misbehaviour

// input
// output
#[update]
async fn conn_open_init(msg: Vec<u8>) -> Result<(), String> {
    let msg: MsgConnectionOpenInit = RawMsgConnectionOpenInit::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .conn_open_init(msg)
    })?;

    Ok(())
}

#[derive(CandidType, Deserialize, Clone, Default)]
pub struct Proofs {
    pub sm_client_state: Vec<u8>,
    pub object_proof: Vec<u8>,
    pub client_state_proof: Vec<u8>,
    pub consensus_state_proof: Vec<u8>,
    pub consensue_height: String,
    pub height: String,
}

// input: sgConnectionOpenTry, conn_id, conn_end, client_id
// output: connection_proofs
#[update]
async fn conn_open_try(
    msg: Vec<u8>,
    conn_id: String,
    conn_end: Vec<u8>,
    client_id: String,
) -> Result<Proofs, String> {
    let msg: MsgConnectionOpenTry = RawMsgConnectionOpenTry::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let conn_id = ConnectionId::from_str(&conn_id).map_err(|_| "parse conn_id error")?;

    let conn_end: ConnectionEnd = RawConnectionEnd::decode(&conn_end[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let client_id = ClientId::from_str(&client_id).map_err(|_| "parse client_id error")?;

    // verify message
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .conn_open_try(msg)
    })?;

    let sm_client_state = INSTANCE.with(|instance| {
        let instance = instance.borrow_mut();
        instance
            .solo_store
            .as_ref()
            .ok_or("Need start first".to_string())?
            .get_client_state(&client_id)
    })?;

    let sm_consensus_state = INSTANCE.with(|instance| {
        let instance = instance.borrow_mut();
        instance
            .solo_store
            .as_ref()
            .ok_or("Need start first".to_string())?
            .get_consensus_state(&client_id, &sm_client_state.sequence)
    })?;

    // construct connection proof
    let sequence = get_sequence();
    let (sign_bytes, time) = connection_builder::construct_solomachine_connection_sign_bytes(
        &conn_id, &conn_end, sequence,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof =
        connection_builder::build_solomachine_connection_proof(&raw_signature, time)?;
    let height = Height::new(0, sequence).expect("Construct height error");

    // construct client_state proof
    let sequence = get_sequence();
    let (sign_bytes, time) = connection_builder::construct_solomachine_client_state_sign_bytes(
        ConnectionMsgType::OpenTry,
        &client_id,
        sequence,
        &sm_client_state,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let client_proof =
        connection_builder::build_solomachine_connection_proof(&raw_signature, time)?;

    // construct consensus state proof
    let sequence = get_sequence();
    let (sign_bytes, time) = connection_builder::construct_solomachine_consensus_state_sign_bytes(
        ConnectionMsgType::OpenTry,
        &client_id,
        sequence,
        &sm_client_state,
        &sm_consensus_state,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let (consensus_state_proof, consensus_height) =
        connection_builder::build_solomachine_consensus_state_proof(
            ConnectionMsgType::OpenTry,
            &sm_client_state,
            &raw_signature,
            time,
        )?;

    let proofs = Proofs {
        sm_client_state: RawSmClientState::from(sm_client_state).encode_to_vec(),
        object_proof: object_proof.into(),
        client_state_proof: client_proof.into(),
        consensus_state_proof: consensus_state_proof.into(),
        consensue_height: consensus_height.into(),
        height: height.into(),
    };

    Ok(proofs)
}

// input: MsgConnectionOpenAck, conn_id, conn_end, client_id
// output: connection_proofs
#[update]
async fn conn_open_ack(
    msg: Vec<u8>,
    conn_id: String,
    conn_end: Vec<u8>,
    client_id: String,
) -> Result<Proofs, String> {
    let msg: MsgConnectionOpenAck = RawMsgConnectionOpenAck::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let conn_id = ConnectionId::from_str(&conn_id).map_err(|_| "parse conn_id error")?;

    let conn_end: ConnectionEnd = RawConnectionEnd::decode(&conn_end[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let client_id = ClientId::from_str(&client_id).map_err(|_| "parse client_id error")?;

    // verify message
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .conn_open_ack(msg)
    })?;

    let sm_client_state = INSTANCE.with(|instance| {
        let instance = instance.borrow_mut();
        instance
            .solo_store
            .as_ref()
            .ok_or("Need start first".to_string())?
            .get_client_state(&client_id)
    })?;

    let sm_consensus_state = INSTANCE.with(|instance| {
        let instance = instance.borrow_mut();
        instance
            .solo_store
            .as_ref()
            .ok_or("Need start first".to_string())?
            .get_consensus_state(&client_id, &sm_client_state.sequence)
    })?;

    // construct connection proof
    let sequence = get_sequence();
    let (sign_bytes, time) = connection_builder::construct_solomachine_connection_sign_bytes(
        &conn_id, &conn_end, sequence,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof =
        connection_builder::build_solomachine_connection_proof(&raw_signature, time)?;
    let height = Height::new(0, sequence).expect("Construct height error");

    // construct client_state proof
    let sequence = get_sequence();
    let (sign_bytes, time) = connection_builder::construct_solomachine_client_state_sign_bytes(
        ConnectionMsgType::OpenTry,
        &client_id,
        sequence,
        &sm_client_state,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let client_proof =
        connection_builder::build_solomachine_connection_proof(&raw_signature, time)?;

    // construct consensus state proof
    let sequence = get_sequence();
    let (sign_bytes, time) = connection_builder::construct_solomachine_consensus_state_sign_bytes(
        ConnectionMsgType::OpenTry,
        &client_id,
        sequence,
        &sm_client_state,
        &sm_consensus_state,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let (consensus_state_proof, consensus_height) =
        connection_builder::build_solomachine_consensus_state_proof(
            ConnectionMsgType::OpenTry,
            &sm_client_state,
            &raw_signature,
            time,
        )?;

    let proofs = Proofs {
        sm_client_state: RawSmClientState::from(sm_client_state).encode_to_vec(),
        object_proof: object_proof.into(),
        client_state_proof: client_proof.into(),
        consensus_state_proof: consensus_state_proof.into(),
        consensue_height: consensus_height.into(),
        height: height.into(),
    };

    Ok(proofs)
}

#[update]
async fn conn_open_confirm(
    msg: Vec<u8>,
    conn_id: String,
    conn_end: Vec<u8>,
    client_id: String,
) -> Result<Proofs, String> {
    let msg: MsgConnectionOpenAck = RawMsgConnectionOpenAck::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let conn_id = ConnectionId::from_str(&conn_id).map_err(|_| "parse conn_id error")?;

    let conn_end: ConnectionEnd = RawConnectionEnd::decode(&conn_end[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let client_id = ClientId::from_str(&client_id).map_err(|_| "parse client_id error")?;

    // verify message
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .conn_open_ack(msg)
    })?;

    let sm_client_state = INSTANCE.with(|instance| {
        let instance = instance.borrow_mut();
        instance
            .solo_store
            .as_ref()
            .ok_or("Need start first".to_string())?
            .get_client_state(&client_id)
    })?;

    // construct connection proof
    let sequence = get_sequence();
    let (sign_bytes, time) = connection_builder::construct_solomachine_connection_sign_bytes(
        &conn_id, &conn_end, sequence,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof =
        connection_builder::build_solomachine_connection_proof(&raw_signature, time)?;
    let height = Height::new(0, sequence).expect("Construct height error");

    let proofs = Proofs {
        sm_client_state: RawSmClientState::from(sm_client_state).encode_to_vec(),
        object_proof: object_proof.into(),
        client_state_proof: vec![],
        consensus_state_proof: vec![],
        consensue_height: "".to_string(),
        height: height.into(),
    };

    Ok(proofs)
}

#[update]
async fn chan_open_init(msg: Vec<u8>) -> Result<(), String> {
    let msg: MsgChannelOpenInit = RawMsgChannelOpenInit::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    // verify message
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .chan_open_init(&msg)
            .map_err(|_| "verify msg error".to_string())
    })?;

    Ok(())
}

#[update]
async fn chan_open_try(
    msg: Vec<u8>,
    port_id: String,
    chann_id: String,
    chann_end: Vec<u8>,
) -> Result<Proofs, String> {
    let msg: MsgChannelOpenTry = RawMsgChannelOpenTry::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let port_id = PortId::from_str(&port_id).map_err(|_| "parse port_id error")?;
    let chann_id = ChannelId::from_str(&chann_id).map_err(|_| "parse chann_id error")?;

    let chann_end: ChannelEnd = RawChannelEnd::decode(&chann_end[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    // verify message
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .chan_open_try(&msg)
            .map_err(|_| "verify message error".to_string())
    })?;

    // construct channel proof
    let sequence = get_sequence();
    let (sign_bytes, time) = channel_builder::construct_solomachine_channel_sign_bytes(
        &port_id, &chann_id, &chann_end, sequence,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof = channel_builder::build_solomachine_channel_proof(&raw_signature, time)?;

    let proofs = Proofs {
        sm_client_state: vec![],
        object_proof: object_proof.into(),
        client_state_proof: vec![],
        consensus_state_proof: vec![],
        consensue_height: "".to_string(),
        height: "".to_string(),
    };

    Ok(proofs)
}

#[update]
async fn chan_open_ack(
    msg: Vec<u8>,
    port_id: String,
    chann_id: String,
    chann_end: Vec<u8>,
) -> Result<Proofs, String> {
    let msg: MsgChannelOpenAck = RawMsgChannelOpenAck::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let port_id = PortId::from_str(&port_id).map_err(|_| "parse port_id error")?;
    let chann_id = ChannelId::from_str(&chann_id).map_err(|_| "parse chann_id error")?;

    let chann_end: ChannelEnd = RawChannelEnd::decode(&chann_end[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    // verify message
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .chan_open_ack(&msg)
            .map_err(|_| "verify message error".to_string())
    })?;

    // construct channel proof
    let sequence = get_sequence();
    let (sign_bytes, time) = channel_builder::construct_solomachine_channel_sign_bytes(
        &port_id, &chann_id, &chann_end, sequence,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof = channel_builder::build_solomachine_channel_proof(&raw_signature, time)?;

    let proofs = Proofs {
        sm_client_state: vec![],
        object_proof: object_proof.into(),
        client_state_proof: vec![],
        consensus_state_proof: vec![],
        consensue_height: "".to_string(),
        height: "".to_string(),
    };

    Ok(proofs)
}

#[update]
async fn chan_open_confirm(
    msg: Vec<u8>,
    port_id: String,
    chann_id: String,
    chann_end: Vec<u8>,
) -> Result<Proofs, String> {
    let msg: MsgChannelOpenConfirm = RawMsgChannelOpenConfirm::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    let port_id = PortId::from_str(&port_id).map_err(|_| "parse port_id error")?;
    let chann_id = ChannelId::from_str(&chann_id).map_err(|_| "parse chann_id error")?;

    let chann_end: ChannelEnd = RawChannelEnd::decode(&chann_end[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    // verify message
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .chan_open_confirm(&msg)
            .map_err(|_| "verify message error".to_string())
    })?;

    // construct channel proof
    let sequence = get_sequence();
    let (sign_bytes, time) = channel_builder::construct_solomachine_channel_sign_bytes(
        &port_id, &chann_id, &chann_end, sequence,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof = channel_builder::build_solomachine_channel_proof(&raw_signature, time)?;

    let proofs = Proofs {
        sm_client_state: vec![],
        object_proof: object_proof.into(),
        client_state_proof: vec![],
        consensus_state_proof: vec![],
        consensue_height: "".to_string(),
        height: "".to_string(),
    };

    Ok(proofs)
}

#[update]
async fn chan_close_init(msg: Vec<u8>) -> Result<(), String> {
    let msg: MsgChannelCloseInit = RawMsgChannelCloseInit::decode(&msg[..])
        .map_err(|_| "parse msg error".to_string())?
        .try_into()
        .map_err(|_| "parse msg error".to_string())?;

    // verify message
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .chan_close_init(&msg)
            .map_err(|_| "verify message error".to_string())
    })?;

    Ok(())
}
