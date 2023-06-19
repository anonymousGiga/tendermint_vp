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
use tendermint_client::channel_proof_builder;
use tendermint_client::connection_proof_builder;
use tendermint_client::header_builder;
use tendermint_client::msg_verifier::{self, *};
use tendermint_client::packet_proof_builder;
use tendermint_client::solomachine::client_state::ClientState as SmClientState;
use tendermint_client::solomachine::consensus_state::ConsensusState as SmConsensusState;
use tendermint_client::solomachine_counter::SoloMachineCounter;
use tendermint_client::solomachine_store::SequenceAndTimeStore;
use tendermint_client::solomachine_store::SoloMachineStateStores;

use tendermint_client::types::ConnectionMsgType;

use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::core::{
    ics02_client::msgs::update_client::MsgUpdateClient,
    ics03_connection::handler::conn_open_confirm,
    ics04_channel::msgs::chan_close_init::MsgChannelCloseInit,
    ics04_channel::msgs::chan_open_try::MsgChannelOpenTry,
    ics04_channel::msgs::{
        acknowledgement::MsgAcknowledgement, chan_open_confirm::MsgChannelOpenConfirm,
    },
    ics04_channel::msgs::{chan_open_ack::MsgChannelOpenAck, recv_packet::MsgRecvPacket},
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
mod mock_data;
mod mock_data1;
mod mock_data2;
pub mod signer;
pub mod storage;

#[update]
async fn public_key() -> Result<Vec<u8>, String> {
    let ret = signer::public_key().await?;
    Ok(ret.public_key)
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
    solo_counter: Option<SoloMachineCounter>,
    sequence_times: Option<SequenceAndTimeStore>,
}

thread_local! {
    static INSTANCE: RefCell<TendermintInstance> = RefCell::new(TendermintInstance { owner: None, verifier: None, solo_store: None, solo_counter: None, sequence_times: None});
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
        if instance.solo_counter.is_none() {
            instance.solo_counter = Some(SoloMachineCounter::new(1u64))
        }
        if instance.owner.is_none() {
            ic_cdk::print("Start error: owner should not empty");
        }
        if instance.sequence_times.is_none() {
            instance.sequence_times = Some(SequenceAndTimeStore::new())
        }
    });
    ic_cdk::print("Start ok!");

    Ok(())
}

fn is_authorized() -> Result<(), String> {
    let user = ic_cdk::api::caller();
    INSTANCE.with(|instance| {
        let instance = instance.borrow();
        if instance.owner.expect("Owner should not empty") != user {
            Err("unauthorized!".into())
        } else {
            Ok(())
        }
    })
}

#[update(guard = "is_authorized")]
fn restart() -> Result<(), String> {
    ic_cdk::print("restart!");
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance.verifier = Some(MessageVerifier::new());
        instance.solo_store = Some(SoloMachineStateStores::new());
        instance.solo_counter = Some(SoloMachineCounter::new(1u64));
        instance.sequence_times = Some(SequenceAndTimeStore::new());
    });
    ic_cdk::print("restart ok!");

    Ok(())
}

fn update_sequence_times(sequence: u64, time: u64) {
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .sequence_times
            .as_mut()
            .expect("Need start first!")
            .insert(sequence, time)
    });
}

#[query]
fn get_sequence_times(sequence: u64) -> Result<u64, String> {
    INSTANCE.with(|instance| {
        let instance = instance.borrow();
        instance
            .sequence_times
            .as_ref()
            .expect("Need start first!")
            .get_sequence_time(sequence)
    })
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
            .solo_counter
            .as_ref()
            .expect("Verifier need set")
            .sequence_cnt()
    });

    increase_sequence();

    ic_cdk::println!("sequence is : {:?}", sequence);
    sequence
}

fn increase_sequence() {
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .solo_counter
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

    ic_cdk::println!("msg: {:?}", msg);

    let pk = public_key().await.expect("Pubkey should exist!");

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

    let time: u64 = tm_consensus_state.timestamp().nanoseconds();
    update_sequence_times(sequence, time);

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
    ic_cdk::println!("update client  msg: {:?}", msg);

    let pk = public_key().await.expect("Pubkey should exist!");

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

    let time: u64 = tm_consensus_state.timestamp().nanoseconds();
    update_sequence_times(sequence, time);

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
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;
    ic_cdk::println!("conn_open_init msg in any: {:?}", msg);

    let msg =
        MsgConnectionOpenInit::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("conn_open_init msg: {:?}", msg);

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

#[derive(CandidType, Deserialize, Clone, Default, Debug)]
pub struct Proofs {
    pub height: String,
    pub object_proof: Vec<u8>,
    pub sm_client_state: Vec<u8>,
    pub client_state_proof: Vec<u8>,
    pub consensue_height: String,
    pub consensus_state_proof: Vec<u8>,
}

// input: sgConnectionOpenTry, conn_id, conn_end, client_id
// output: connection_proofs
#[update]
async fn conn_open_try(msg: Vec<u8>) -> Result<Proofs, String> {
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg =
        MsgConnectionOpenTry::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("conn_open_try msg: {:?}", msg);

    // verify message
    let (client_id, conn_id, conn_end, time) = INSTANCE.with(|instance| {
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
    let sign_bytes = connection_proof_builder::construct_solomachine_connection_sign_bytes(
        &conn_id, &conn_end, sequence, time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof =
        connection_proof_builder::build_solomachine_connection_proof(&raw_signature, time)?;
    let height = Height::new(0, sequence).expect("Construct height error");
    update_sequence_times(sequence, time);

    // construct client_state proof
    let sequence = get_sequence();
    let sign_bytes = connection_proof_builder::construct_solomachine_client_state_sign_bytes(
        ConnectionMsgType::OpenTry,
        &client_id,
        sequence,
        &sm_client_state,
        time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let client_proof =
        connection_proof_builder::build_solomachine_connection_proof(&raw_signature, time)?;
    update_sequence_times(sequence, time);

    // construct consensus state proof
    let sequence = get_sequence();
    let sign_bytes = connection_proof_builder::construct_solomachine_consensus_state_sign_bytes(
        ConnectionMsgType::OpenTry,
        &client_id,
        sequence,
        &sm_client_state,
        &sm_consensus_state,
        time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let (consensus_state_proof, consensus_height) =
        connection_proof_builder::build_solomachine_consensus_state_proof(
            ConnectionMsgType::OpenTry,
            &sm_client_state,
            &raw_signature,
            time,
        )?;
    update_sequence_times(sequence, time);

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
async fn conn_open_ack(msg: Vec<u8>) -> Result<Proofs, String> {
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg =
        MsgConnectionOpenAck::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("conn_open_ack msg: {:?}", msg);

    // verify message
    let (client_id, conn_id, conn_end, time) = INSTANCE.with(|instance| {
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
    let sign_bytes = connection_proof_builder::construct_solomachine_connection_sign_bytes(
        &conn_id, &conn_end, sequence, time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof =
        connection_proof_builder::build_solomachine_connection_proof(&raw_signature, time)?;
    let height = Height::new(0, sequence).expect("Construct height error");
    update_sequence_times(sequence, time);

    // construct client_state proof
    let sequence = get_sequence();
    let sign_bytes = connection_proof_builder::construct_solomachine_client_state_sign_bytes(
        ConnectionMsgType::OpenTry,
        &client_id,
        sequence,
        &sm_client_state,
        time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let client_proof =
        connection_proof_builder::build_solomachine_connection_proof(&raw_signature, time)?;
    update_sequence_times(sequence, time);

    // construct consensus state proof
    let sequence = get_sequence();
    let sign_bytes = connection_proof_builder::construct_solomachine_consensus_state_sign_bytes(
        ConnectionMsgType::OpenTry,
        &client_id,
        sequence,
        &sm_client_state,
        &sm_consensus_state,
        time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let (consensus_state_proof, consensus_height) =
        connection_proof_builder::build_solomachine_consensus_state_proof(
            ConnectionMsgType::OpenTry,
            &sm_client_state,
            &raw_signature,
            time,
        )?;
    update_sequence_times(sequence, time);

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
async fn conn_open_confirm(msg: Vec<u8>) -> Result<Proofs, String> {
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg = MsgConnectionOpenConfirm::decode_vec(&msg.value)
        .map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("conn_open_confirm msg: {:?}", msg);

    // verify message
    let (client_id, conn_id, conn_end, time) = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .conn_open_confirm(msg)
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
    let sign_bytes = connection_proof_builder::construct_solomachine_connection_sign_bytes(
        &conn_id, &conn_end, sequence, time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof =
        connection_proof_builder::build_solomachine_connection_proof(&raw_signature, time)?;
    let height = Height::new(0, sequence).expect("Construct height error");
    update_sequence_times(sequence, time);

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
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg =
        MsgChannelOpenInit::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("channel open init msg: {:?}", msg);

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
async fn chan_open_try(msg: Vec<u8>) -> Result<Proofs, String> {
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg =
        MsgChannelOpenTry::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("channel open try msg: {:?}", msg);

    // verify message
    let (port_id, chann_id, chann_end, time) = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .chan_open_try(&msg)
    })?;

    // construct channel proof
    let sequence = get_sequence();
    let sign_bytes = channel_proof_builder::construct_solomachine_channel_sign_bytes(
        &port_id, &chann_id, &chann_end, sequence, time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof =
        channel_proof_builder::build_solomachine_channel_proof(&raw_signature, time)?;
    update_sequence_times(sequence, time);

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
async fn chan_open_ack(msg: Vec<u8>) -> Result<Proofs, String> {
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg =
        MsgChannelOpenAck::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("channel open ack msg: {:?}", msg);

    // verify message
    let (port_id, chann_id, chann_end, time) = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .chan_open_ack(&msg)
        // .map_err(|_| "verify message error".to_string())
    })?;

    // construct channel proof
    let sequence = get_sequence();
    let sign_bytes = channel_proof_builder::construct_solomachine_channel_sign_bytes(
        &port_id, &chann_id, &chann_end, sequence, time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof =
        channel_proof_builder::build_solomachine_channel_proof(&raw_signature, time)?;
    update_sequence_times(sequence, time);

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
async fn chan_open_confirm(msg: Vec<u8>) -> Result<Proofs, String> {
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg =
        MsgChannelOpenConfirm::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("channel open confirm msg: {:?}", msg);

    // verify message
    let (port_id, chann_id, chann_end, time) = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .chan_open_confirm(&msg)
        // .map_err(|_| "verify message error".to_string())
    })?;

    // construct channel proof
    let sequence = get_sequence();
    let sign_bytes = channel_proof_builder::construct_solomachine_channel_sign_bytes(
        &port_id, &chann_id, &chann_end, sequence, time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof =
        channel_proof_builder::build_solomachine_channel_proof(&raw_signature, time)?;
    update_sequence_times(sequence, time);

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
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg =
        MsgChannelCloseInit::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("channel close init msg: {:?}", msg);

    // verify message
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .chan_close_init(&msg)
        // .map_err(|_| "verify message error".to_string())
    })?;

    Ok(())
}

#[update]
async fn recv_packet(msg: Vec<u8>) -> Result<Proofs, String> {
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg = MsgRecvPacket::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("recv packet msg: {:?}", msg);

    // verify message
    let (port_id, chann_id, packet, time) = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .recv_packet(&msg)
        // .map_err(|_| "verify message error".to_string())
    })?;

    // construct channel proof
    let sequence = get_sequence();
    let sign_bytes = packet_proof_builder::construct_solomachine_recv_packet_sign_bytes(
        &port_id, &chann_id, &packet, sequence, time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof = packet_proof_builder::build_solomachine_packet_proof(&raw_signature, time)?;
    update_sequence_times(sequence, time);

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
async fn ack_packet(msg: Vec<u8>) -> Result<Proofs, String> {
    let msg = Any::decode(msg.as_ref()).map_err(|_| "error".to_string())?;

    let msg =
        MsgAcknowledgement::decode_vec(&msg.value).map_err(|_| "parse msg error".to_string())?;
    ic_cdk::println!("recv packet msg: {:?}", msg);

    // verify message
    let (port_id, chann_id, packet, time) = INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance
            .verifier
            .as_mut()
            .ok_or("Verifier need set".to_string())?
            .acknowledgement(&msg)
        // .map_err(|_| "verify message error".to_string())
    })?;

    // construct channel proof
    let sequence = get_sequence();
    let sign_bytes = packet_proof_builder::construct_solomachine_recv_packet_sign_bytes(
        &port_id, &chann_id, &packet, sequence, time,
    )?;
    let raw_signature = sign(sign_bytes).await?.signature;
    let object_proof = packet_proof_builder::build_solomachine_packet_proof(&raw_signature, time)?;
    update_sequence_times(sequence, time);

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

#[pre_upgrade]
fn pre_upgrade() {
    ic_cdk::println!("Need storage something!");
}

#[post_upgrade]
fn post_upgrade() {
    ic_cdk::println!("Need restore something frome storage!");
    INSTANCE.with(|instance| {
        let mut instance = instance.borrow_mut();
        instance.owner = Some(ic_cdk::api::caller());
    });
}

// #[update]
// async fn test0() -> Result<(), String> {
//     use mock_data::*;
//     let raw_create_client = get_ibc0_create_client();

//     restart()?;
//     let sm_state = create_client(raw_create_client).await?;
//     ic_cdk::println!("sm client state: {:?}", sm_state.client_state);
//     let sm_client_state = RawSmClientState::decode(sm_state.client_state.as_ref())
//         .map_err(|_| "parse client_state error".to_string())?;
//     let sm_consensus_state = RawSmConsesusState::decode(sm_state.consensus_state.as_ref())
//         .map_err(|_| "parse consensus_state error".to_string())?;

//     ic_cdk::println!("sm client state: {:?}", sm_client_state);
//     ic_cdk::println!("sm consensus state: {:?}", sm_consensus_state);

//     let raw_update_client = get_ibc0_update_client1();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_update_client = get_ibc1_update_client2();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_connection_open_try = get_ibc1_connection_open_try();
//     let proofs = conn_open_try(raw_connection_open_try).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let raw_update_client = get_ibc1_update_client3();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_connection_open_confirm = get_ibc1_connection_open_confirm();
//     let proofs = conn_open_confirm(raw_connection_open_confirm).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let raw_update_client = get_ibc1_update_client4();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_channel_open_try = get_ibc1_channel_open_try();
//     let proofs = chan_open_try(raw_channel_open_try).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let raw_update_client = get_ibc1_update_client5();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_chann_open_confirm = get_ibc1_channel_open_confirm();
//     let proofs = chan_open_confirm(raw_chann_open_confirm).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let time = get_sequence_times(1)?;
//     ic_cdk::println!("time: {:?}", time);

//     Ok(())
// }

// #[update]
// async fn test1() -> Result<Proofs, String> {
//     use mock_data::*;
//     let raw_create_client = get_ibc1_create_client();

//     restart()?;
//     let sm_state = create_client(raw_create_client).await?;
//     ic_cdk::println!("sm client state: {:?}", sm_state.client_state);
//     let sm_client_state = RawSmClientState::decode(sm_state.client_state.as_ref())
//         .map_err(|_| "parse client_state error".to_string())?;
//     let sm_consensus_state = RawSmConsesusState::decode(sm_state.consensus_state.as_ref())
//         .map_err(|_| "parse consensus_state error".to_string())?;

//     ic_cdk::println!("sm client state: {:?}", sm_client_state);
//     ic_cdk::println!("sm consensus state: {:?}", sm_consensus_state);

//     let raw_connection_open_init = get_ibc0_connection_open_init();
//     conn_open_init(raw_connection_open_init).await?;

//     let raw_update_client = get_ibc1_update_client1();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_update_client = get_ibc0_update_client2();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_connection_open_ack = get_ibc0_connection_open_ack();
//     let proofs = conn_open_ack(raw_connection_open_ack).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let raw_channel_open_init = get_ibc0_channel_open_init();
//     chan_open_init(raw_channel_open_init).await?;

//     let raw_update_client = get_ibc0_update_client3();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_chann_open_ack = get_ibc0_channel_open_ack();
//     let proofs = chan_open_ack(raw_chann_open_ack).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     Ok(proofs)
// }

// #[update]
// async fn test2() -> Result<(), String> {
//     use mock_data2::*;

//     restart()?;

//     let raw_create_client = get_ibc1_create_client();
//     let sm_state = create_client(raw_create_client).await?;
//     ic_cdk::println!("sm client state: {:?}", sm_state.client_state);
//     let sm_client_state = RawSmClientState::decode(sm_state.client_state.as_ref())
//         .map_err(|_| "parse client_state error".to_string())?;
//     let sm_consensus_state = RawSmConsesusState::decode(sm_state.consensus_state.as_ref())
//         .map_err(|_| "parse consensus_state error".to_string())?;
//     ic_cdk::println!("sm client state: {:?}", sm_client_state);
//     ic_cdk::println!("sm consensus state: {:?}", sm_consensus_state);

//     let raw_update_client = get_ibc1_update_client1();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_connection_open_try = get_ibc1_connection_open_try();
//     let proofs = conn_open_try(raw_connection_open_try).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let raw_update_client = get_ibc1_update_client2();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_connection_open_confirm = get_ibc1_connection_open_confirm();
//     let proofs = conn_open_confirm(raw_connection_open_confirm).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let raw_update_client = get_ibc1_update_client3();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_channel_open_try = get_ibc1_channel_open_try();
//     let proofs = chan_open_try(raw_channel_open_try).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let raw_update_client = get_ibc1_update_client4();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_chann_open_confirm = get_ibc1_channel_open_confirm();
//     let proofs = chan_open_confirm(raw_chann_open_confirm).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let raw_update_client = get_ibc1_update_client5();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_recv_packet = get_ibc1_recv_packet();
//     let proofs = recv_packet(raw_recv_packet).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     let raw_update_client = get_ibc1_update_client6();
//     let sm_header = update_client(raw_update_client).await?;
//     let sm_header =
//         RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
//     ic_cdk::println!("sm header: {:?}", sm_header);

//     let raw_ack_packet = get_ibc1_ack_packet();
//     let proofs = ack_packet(raw_ack_packet).await?;
//     ic_cdk::println!("proofs: {:?}", proofs);

//     // // let time = get_sequence_times(1)?;
//     // // ic_cdk::println!("time: {:?}", time);

//     Ok(())
// }

#[update]
async fn test3() -> Result<(), String> {
    use mock_data2::*;
    restart()?;

    let raw_create_client = get_ibc0_create_client();
    let sm_state = create_client(raw_create_client).await?;
    ic_cdk::println!("sm client state: {:?}", sm_state.client_state);
    let sm_client_state = RawSmClientState::decode(sm_state.client_state.as_ref())
        .map_err(|_| "parse client_state error".to_string())?;
    let sm_consensus_state = RawSmConsesusState::decode(sm_state.consensus_state.as_ref())
        .map_err(|_| "parse consensus_state error".to_string())?;

    ic_cdk::println!("sm client state: {:?}", sm_client_state);
    ic_cdk::println!("sm consensus state: {:?}", sm_consensus_state);

    let raw_connection_open_init = get_ibc0_connection_open_init();
    conn_open_init(raw_connection_open_init).await?;

    let raw_update_client = get_ibc0_update_client1();
    let sm_header = update_client(raw_update_client).await?;
    let sm_header =
        RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
    ic_cdk::println!("sm header: {:?}", sm_header);

    let raw_update_client = get_ibc0_update_client2();
    let sm_header = update_client(raw_update_client).await?;
    let sm_header =
        RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
    ic_cdk::println!("sm header: {:?}", sm_header);

    let raw_connection_open_ack = get_ibc0_connection_open_ack();
    let proofs = conn_open_ack(raw_connection_open_ack).await?;
    ic_cdk::println!("proofs: {:?}", proofs);

    let raw_channel_open_init = get_ibc0_channel_open_init();
    chan_open_init(raw_channel_open_init).await?;

    let raw_update_client = get_ibc0_update_client3();
    let sm_header = update_client(raw_update_client).await?;
    let sm_header =
        RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
    ic_cdk::println!("sm header: {:?}", sm_header);

    let raw_chann_open_ack = get_ibc0_channel_open_ack();
    let proofs = chan_open_ack(raw_chann_open_ack).await?;
    ic_cdk::println!("proofs: {:?}", proofs);

    let raw_update_client = get_ibc0_update_client4();
    let sm_header = update_client(raw_update_client).await?;
    let sm_header =
        RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
    ic_cdk::println!("sm header: {:?}", sm_header);

    let raw_packet_ack = get_ibc0_ack();
    let proofs = ack_packet(raw_packet_ack).await?;
    ic_cdk::println!("proofs: {:?}", proofs);

    let raw_update_client = get_ibc0_update_client5();
    let sm_header = update_client(raw_update_client).await?;
    let sm_header =
        RawSmHeader::decode(sm_header.as_ref()).map_err(|_| "parse sm header error".to_string())?;
    ic_cdk::println!("sm header: {:?}", sm_header);

    let raw_packet_recv = get_ibc0_recv();
    let proofs = recv_packet(raw_packet_recv).await?;
    ic_cdk::println!("proofs: {:?}", proofs);

    Ok(())
}
