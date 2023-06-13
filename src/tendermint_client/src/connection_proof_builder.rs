use crate::prelude::*;
use crate::solomachine::client_state::{self, ClientState as SmClientState};
// use crate::solomachine::connection_state_data::ConnectionStateData;
use crate::solomachine::consensus_state::{self, ConsensusState as SmConsensusState, PublicKey};
// use crate::solomachine::datatype::DataType;
use crate::solomachine::header::Header as SmHeader;
use crate::solomachine::header_data;
use crate::solomachine::proofs;
use crate::solomachine::sign_bytes;
use crate::solomachine::utils;

use crate::tm_client_state::ClientState as TmClientState;
use ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::Height;

use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics23_commitment::commitment::CommitmentProofBytes;
use ibc::core::ics23_commitment::commitment::CommitmentRoot;
use ibc::timestamp::Timestamp;

use eyre::Result;
use ibc::core::ics24_host::identifier::ClientId;
use ibc::core::ics24_host::identifier::ConnectionId;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::solomachine::v1::ClientState as RawSmClientState;
use ibc_proto::ibc::lightclients::solomachine::v1::ConsensusState as RawSmConsesusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use tendermint::public_key;

use crate::types;
use ic_cdk::api::time;

use ibc_proto::ibc::lightclients::solomachine::v1::{
    ChannelStateData, ClientStateData, ConnectionStateData, ConsensusStateData, DataType,
    TimestampedSignatureData,
};

use ibc_proto::cosmos::tx::signing::v1beta1::signature_descriptor::{
    data::{Single, Sum},
    Data,
};

// 1. Step 1 ===============================
// let sequence = self.sequence_cnt;
// self.sequence_cnt ++;
// let (sign_bytes, time) = construct_solomachine_connection_sign_bytes(connection_id, connection_end, sequence).unwrap();
// let conn_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();
// return conn_proof
// ==========================================

// return connection sign bytes and time
pub fn construct_solomachine_connection_sign_bytes(
    connection_id: &ConnectionId,
    connection_end: &ConnectionEnd,
    sequence: u64,
    time: u64,
) -> Result<Vec<u8>, String> {
    let data = ConnectionStateData {
        path: ("/ibc/connections%2F".to_string() + connection_id.as_str()).into(),
        connection: Some(connection_end.clone().into()),
    }
    .encode_to_vec();
    // let time = time();
    let sign_bytes = utils::construct_sign_bytes(sequence, time, DataType::ConnectionState, data)?;

    Ok(sign_bytes)
}

pub fn build_solomachine_connection_proof(
    raw_signature: &[u8],
    time: u64,
) -> Result<CommitmentProofBytes, String> {
    let sig = Data {
        sum: Some(Sum::Single(Single {
            mode: 1,
            signature: raw_signature.to_vec(),
        })),
    }
    .encode_to_vec();

    let proof_init = TimestampedSignatureData {
        signature_data: sig,
        timestamp: time,
    }
    .encode_to_vec();

    CommitmentProofBytes::try_from(proof_init).map_err(|_| "Error::malformed_proof".to_string())
}

// 2. Step 2 ===============================
// if msg_type == types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck  {
//      let sequence = self.sequence_cnt;
//      self.sequence_cnt ++;
//      let (sign_bytes, time) = construct_solomachine_client_state_sign_bytes(...);
//      let client_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();
//      return client_proof
// } else {
//      let client_proof = None;
//      return client_proof
// }
// ==========================================

// return connection sign bytes and time
pub fn construct_solomachine_client_state_sign_bytes(
    message_type: types::ConnectionMsgType,
    client_id: &ClientId,
    sequence: u64,
    client_state: &SmClientState,
    time: u64,
) -> Result<Vec<u8>, String> {
    match message_type {
        types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck => {
            let data = ClientStateData {
                path: ("/ibc/clients%2F".to_string()
                    + client_id.as_str()
                    + &"%2FclientState".to_string())
                    .into(),
                client_state: Some(client_state.clone().into()),
            }
            .encode_to_vec();

            // let time = time();
            let sign_bytes =
                utils::construct_sign_bytes(sequence, time, DataType::ClientState, data)?;

            return Ok(sign_bytes);
        }
        _ => return Err("Other connection msg's proof should emplty".to_string()),
    }
}

pub fn build_solomachine_client_state_proof(
    message_type: types::ConnectionMsgType,
    raw_signature: &[u8],
    time: u64,
) -> Result<CommitmentProofBytes, String> {
    match message_type {
        types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck => {
            let sig = Data {
                sum: Some(Sum::Single(Single {
                    mode: 1,
                    signature: raw_signature.to_vec(),
                })),
            }
            .encode_to_vec();

            let proof_client = TimestampedSignatureData {
                signature_data: sig,
                timestamp: time,
            }
            .encode_to_vec();

            CommitmentProofBytes::try_from(proof_client)
                .map_err(|_| "Error::malformed_proof".to_string())
        }
        _ => return Err("Other connection msg's proof should emplty".to_string()),
    }
}

// 3. Step 3 ===============================
// if msg_type == types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck  {
//      let sequence = self.sequence_cnt;
//      self.sequence_cnt ++;
//      let (sign_bytes, time) = construct_solomachine_consensus_state_sign_bytes(msg_type, client_id, client_state, consensus_state, sequence).unwrap();
//      let consensus_state_proof = build_solomachine_consensus_proof(client_state, msg_type, raw_signature, time) .unwrap();
//      return consensus_state_proof
// } else {
//      let consensus_state_proof = None
//      return consensus_state_proof
// }
// ==========================================
pub fn construct_solomachine_consensus_state_sign_bytes(
    message_type: types::ConnectionMsgType,
    client_id: &ClientId,
    sequence: u64,
    client_state: &SmClientState,
    consensus_state: &SmConsensusState,
    time: u64,
) -> Result<Vec<u8>, String> {
    match message_type {
        types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck => {
            let data = ConsensusStateData {
                path: ("/ibc/clients%2F".to_string()
                    + client_id.as_str()
                    + &"%2FconsensusStates%2F0-".to_string()
                    + &client_state.latest_height().revision_height().to_string())
                    .into(),
                consensus_state: Some(consensus_state.clone().into()),
            }
            .encode_to_vec();

            // let time = time();
            let sign_bytes =
                utils::construct_sign_bytes(sequence, time, DataType::ConsensusState, data)?;

            return Ok(sign_bytes);
        }
        _ => return Err("Other connection msg's proof should emplty".to_string()),
    }
}

pub fn build_solomachine_consensus_state_proof(
    message_type: types::ConnectionMsgType,
    client_state: &SmClientState,
    raw_signature: &[u8],
    time: u64,
) -> Result<(CommitmentProofBytes, Height), String> {
    match message_type {
        types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck => {
            let sig = Data {
                sum: Some(Sum::Single(Single {
                    mode: 1,
                    signature: raw_signature.to_vec(),
                })),
            }
            .encode_to_vec();

            let proof_client = TimestampedSignatureData {
                signature_data: sig,
                timestamp: time,
            }
            .encode_to_vec();

            let proofs = CommitmentProofBytes::try_from(proof_client)
                .map_err(|_| "Error::malformed_proof".to_string())?;

            return Ok((proofs, client_state.latest_height()));
        }
        _ => return Err("Other connection msg's proof should emplty".to_string()),
    }
}
