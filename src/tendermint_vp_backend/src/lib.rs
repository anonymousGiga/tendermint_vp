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
use tendermint_client::solomachine::client_state::ClientState as SmClientState;
use tendermint_client::solomachine::consensus_state::ConsensusState as SmConsensusState;
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
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;
    let msg = MsgCreateClient::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;

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
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg = MsgUpdateClient::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("msg: {:?}", msg);

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

#[update]
async fn test() -> Result<(), String> {
    let raw_create_client = vec![
        10, 35, 47, 105, 98, 99, 46, 99, 111, 114, 101, 46, 99, 108, 105, 101, 110, 116, 46, 118,
        49, 46, 77, 115, 103, 67, 114, 101, 97, 116, 101, 67, 108, 105, 101, 110, 116, 18, 228, 2,
        10, 169, 1, 10, 43, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110,
        116, 115, 46, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 46, 118, 49, 46, 67, 108,
        105, 101, 110, 116, 83, 116, 97, 116, 101, 18, 122, 10, 5, 105, 98, 99, 45, 49, 18, 4, 8,
        2, 16, 3, 26, 4, 8, 128, 234, 73, 34, 4, 8, 128, 223, 110, 42, 2, 8, 40, 50, 0, 58, 4, 8,
        1, 16, 4, 66, 25, 10, 9, 8, 1, 24, 1, 32, 1, 42, 1, 0, 18, 12, 10, 2, 0, 1, 16, 33, 24, 4,
        32, 12, 48, 1, 66, 25, 10, 9, 8, 1, 24, 1, 32, 1, 42, 1, 0, 18, 12, 10, 2, 0, 1, 16, 32,
        24, 1, 32, 1, 48, 1, 74, 7, 117, 112, 103, 114, 97, 100, 101, 74, 16, 117, 112, 103, 114,
        97, 100, 101, 100, 73, 66, 67, 83, 116, 97, 116, 101, 80, 1, 88, 1, 18, 134, 1, 10, 46, 47,
        105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115, 46, 116, 101,
        110, 100, 101, 114, 109, 105, 110, 116, 46, 118, 49, 46, 67, 111, 110, 115, 101, 110, 115,
        117, 115, 83, 116, 97, 116, 101, 18, 84, 10, 12, 8, 171, 254, 223, 163, 6, 16, 187, 166,
        166, 244, 2, 18, 34, 10, 32, 37, 100, 190, 21, 79, 123, 117, 182, 251, 48, 236, 198, 184,
        63, 165, 158, 77, 189, 113, 220, 163, 89, 249, 199, 121, 104, 99, 169, 23, 49, 219, 12, 26,
        32, 87, 50, 83, 175, 219, 82, 146, 212, 206, 219, 21, 197, 1, 28, 78, 153, 103, 183, 208,
        219, 16, 185, 66, 102, 137, 237, 218, 226, 165, 215, 31, 95, 26, 45, 99, 111, 115, 109,
        111, 115, 49, 118, 117, 51, 57, 120, 57, 116, 106, 112, 56, 108, 112, 57, 121, 101, 101,
        119, 97, 115, 116, 110, 118, 110, 51, 116, 48, 52, 108, 106, 101, 116, 48, 116, 116, 55,
        110, 120, 118,
    ];
    let raw_update_client = vec![
        10, 35, 47, 105, 98, 99, 46, 99, 111, 114, 101, 46, 99, 108, 105, 101, 110, 116, 46, 118,
        49, 46, 77, 115, 103, 85, 112, 100, 97, 116, 101, 67, 108, 105, 101, 110, 116, 18, 189, 7,
        10, 16, 48, 54, 45, 115, 111, 108, 111, 109, 97, 99, 104, 105, 110, 101, 45, 48, 18, 249,
        6, 10, 38, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115,
        46, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 46, 118, 49, 46, 72, 101, 97, 100,
        101, 114, 18, 206, 6, 10, 199, 4, 10, 139, 3, 10, 2, 8, 11, 18, 5, 105, 98, 99, 45, 48, 24,
        13, 34, 12, 8, 215, 254, 223, 163, 6, 16, 223, 244, 181, 140, 2, 42, 72, 10, 32, 66, 254,
        221, 169, 126, 110, 11, 240, 195, 230, 242, 38, 57, 173, 46, 198, 198, 226, 110, 117, 216,
        177, 30, 216, 120, 115, 230, 3, 77, 108, 16, 202, 18, 36, 8, 1, 18, 32, 236, 14, 255, 244,
        184, 227, 109, 197, 37, 189, 33, 192, 226, 5, 250, 228, 91, 8, 149, 173, 10, 205, 140, 58,
        70, 95, 225, 147, 251, 79, 149, 135, 50, 32, 213, 192, 10, 177, 142, 227, 84, 237, 23, 86,
        63, 103, 172, 242, 210, 133, 149, 96, 187, 99, 55, 86, 55, 193, 144, 31, 2, 127, 144, 178,
        200, 32, 58, 32, 131, 248, 129, 192, 28, 180, 60, 68, 202, 1, 13, 79, 74, 62, 174, 178,
        188, 39, 211, 233, 189, 51, 101, 4, 146, 55, 11, 215, 64, 152, 13, 73, 66, 32, 214, 137,
        221, 30, 41, 208, 233, 179, 244, 221, 224, 94, 169, 21, 179, 136, 213, 61, 137, 191, 249,
        151, 47, 61, 41, 33, 11, 30, 102, 131, 191, 145, 74, 32, 214, 137, 221, 30, 41, 208, 233,
        179, 244, 221, 224, 94, 169, 21, 179, 136, 213, 61, 137, 191, 249, 151, 47, 61, 41, 33, 11,
        30, 102, 131, 191, 145, 82, 32, 4, 128, 145, 188, 125, 220, 40, 63, 119, 191, 191, 145,
        215, 60, 68, 218, 88, 195, 223, 138, 156, 188, 134, 116, 5, 216, 183, 243, 218, 173, 162,
        47, 90, 32, 106, 181, 140, 167, 170, 30, 84, 149, 184, 244, 129, 202, 179, 213, 93, 225,
        102, 17, 32, 149, 215, 61, 86, 28, 108, 239, 191, 179, 209, 38, 40, 30, 98, 32, 227, 176,
        196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100,
        155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85, 106, 32, 227, 176, 196, 66, 152, 252,
        28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164,
        149, 153, 27, 120, 82, 184, 85, 114, 20, 115, 55, 229, 244, 110, 197, 222, 159, 111, 63,
        221, 214, 133, 212, 142, 75, 17, 103, 222, 152, 18, 182, 1, 8, 13, 26, 72, 10, 32, 131, 43,
        144, 222, 148, 137, 62, 127, 251, 59, 0, 63, 242, 132, 91, 27, 43, 142, 243, 44, 20, 239,
        44, 185, 62, 155, 212, 239, 202, 185, 141, 17, 18, 36, 8, 1, 18, 32, 199, 10, 160, 75, 24,
        104, 221, 3, 123, 183, 205, 35, 137, 37, 137, 217, 43, 120, 197, 228, 218, 193, 163, 225,
        2, 166, 237, 117, 231, 11, 146, 215, 34, 104, 8, 2, 18, 20, 115, 55, 229, 244, 110, 197,
        222, 159, 111, 63, 221, 214, 133, 212, 142, 75, 17, 103, 222, 152, 26, 12, 8, 220, 254,
        223, 163, 6, 16, 236, 175, 231, 154, 2, 34, 64, 237, 229, 174, 126, 74, 83, 148, 67, 15,
        126, 136, 140, 230, 201, 160, 179, 238, 130, 188, 194, 236, 129, 165, 18, 116, 175, 212,
        181, 3, 136, 22, 100, 113, 99, 237, 250, 32, 104, 172, 27, 99, 120, 41, 33, 123, 161, 176,
        48, 77, 57, 180, 191, 130, 122, 214, 227, 118, 79, 48, 163, 35, 142, 61, 11, 18, 126, 10,
        60, 10, 20, 115, 55, 229, 244, 110, 197, 222, 159, 111, 63, 221, 214, 133, 212, 142, 75,
        17, 103, 222, 152, 18, 34, 10, 32, 163, 103, 186, 141, 28, 153, 174, 178, 198, 225, 164,
        33, 248, 29, 255, 66, 255, 18, 165, 188, 183, 9, 158, 232, 209, 122, 163, 228, 81, 6, 253,
        166, 24, 10, 18, 60, 10, 20, 115, 55, 229, 244, 110, 197, 222, 159, 111, 63, 221, 214, 133,
        212, 142, 75, 17, 103, 222, 152, 18, 34, 10, 32, 163, 103, 186, 141, 28, 153, 174, 178,
        198, 225, 164, 33, 248, 29, 255, 66, 255, 18, 165, 188, 183, 9, 158, 232, 209, 122, 163,
        228, 81, 6, 253, 166, 24, 10, 24, 10, 26, 2, 16, 4, 34, 126, 10, 60, 10, 20, 115, 55, 229,
        244, 110, 197, 222, 159, 111, 63, 221, 214, 133, 212, 142, 75, 17, 103, 222, 152, 18, 34,
        10, 32, 163, 103, 186, 141, 28, 153, 174, 178, 198, 225, 164, 33, 248, 29, 255, 66, 255,
        18, 165, 188, 183, 9, 158, 232, 209, 122, 163, 228, 81, 6, 253, 166, 24, 10, 18, 60, 10,
        20, 115, 55, 229, 244, 110, 197, 222, 159, 111, 63, 221, 214, 133, 212, 142, 75, 17, 103,
        222, 152, 18, 34, 10, 32, 163, 103, 186, 141, 28, 153, 174, 178, 198, 225, 164, 33, 248,
        29, 255, 66, 255, 18, 165, 188, 183, 9, 158, 232, 209, 122, 163, 228, 81, 6, 253, 166, 24,
        10, 24, 10, 26, 45, 99, 111, 115, 109, 111, 115, 49, 118, 117, 51, 57, 120, 57, 116, 106,
        112, 56, 108, 112, 57, 121, 101, 101, 119, 97, 115, 116, 110, 118, 110, 51, 116, 48, 52,
        108, 106, 101, 116, 48, 116, 116, 55, 110, 120, 118,
    ];

    start()?;

    let sm_state = create_client(raw_create_client).await?;
    ic_cdk::println!("sm client state: {:?}", sm_state.client_state);
    let sm_client_state = RawSmClientState::decode(sm_state.client_state.as_ref())
        .map_err(|_| "parse client_state error".to_string())?;

    let sm_consensus_state = RawSmConsesusState::decode(sm_state.consensus_state.as_ref())
        .map_err(|_| "parse consensus_state error".to_string())?;

    ic_cdk::println!("sm client state: {:?}", sm_client_state);
    ic_cdk::println!("sm consensus state: {:?}", sm_consensus_state);

    let sm_header = update_client(raw_update_client).await?;
    let sm_header =
        RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
    ic_cdk::println!("sm header: {:?}", sm_header);

    Ok(())
}
