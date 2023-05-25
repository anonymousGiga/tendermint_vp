use crate::prelude::*;
use crate::solomachine::client_state::{self, ClientState as SmClientState};
use crate::solomachine::consensus_state::{self, ConsensusState as SmConsensusState, PublicKey};
use crate::solomachine::datatype::DataType;
use crate::solomachine::header::Header as SmHeader;
use crate::solomachine::header_data;
use crate::solomachine::sign_bytes;
use crate::utils;

use crate::tm_client_state::ClientState as TmClientState;
use ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::Height;

use ibc::core::ics23_commitment::commitment::CommitmentProofBytes;
use ibc::core::ics23_commitment::commitment::CommitmentRoot;
use ibc::timestamp::Timestamp;

use eyre::Result;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::solomachine::v1::ClientState as RawSmClientState;
use ibc_proto::ibc::lightclients::solomachine::v1::ConsensusState as RawSmConsesusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use tendermint::public_key;

pub fn build_solomachine_client_state(
    client_state: &TmClientState,
    consensus_state: &TmConsensusState,
    pk: &[u8],
) -> Result<SmClientState, String> {
    // Build the client state.
    let pk = PublicKey(
        tendermint::PublicKey::from_raw_secp256k1(pk).ok_or("Parse pubkey error".to_string())?,
    );
    let timestamp: Timestamp = consensus_state.timestamp.into();
    Ok(SmClientState {
        sequence: client_state.latest_height.revision_height(),
        is_frozen: client_state.is_frozen(),
        consensus_state: SmConsensusState {
            public_key: pk,
            diversifier: "oct".to_string(),
            timestamp: timestamp.nanoseconds(),
            root: CommitmentRoot::from_bytes(&pk.to_bytes()),
        },
        allow_update_after_proposal: false,
    })
}

pub fn build_solomachine_consensus_state(
    pk: &[u8],
    consensus_state: &TmConsensusState,
) -> Result<SmConsensusState, String> {
    let pk = PublicKey::from_raw_secp256k1_data(pk)?;
    let timestamp: Timestamp = consensus_state.timestamp.into();
    Ok(SmConsensusState {
        public_key: pk,
        diversifier: "oct".to_string(),
        timestamp: timestamp.nanoseconds(),
        root: CommitmentRoot::from_bytes(&pk.to_bytes()),
    })
}

// return SmHeaderTemplate and sign_bytes
pub fn construct_solomachine_header(
    client_state: &TmClientState,
    consensus_state: &TmConsensusState,
    pk: &[u8],
) -> Result<(SmHeader, Vec<u8>), String> {
    let height = client_state.latest_height.revision_height();
    let timestamp: Timestamp = consensus_state.timestamp.into();
    let pk = PublicKey::from_raw_secp256k1_data(pk)?;
    let solomachine_header_template = SmHeader {
        sequence: height,
        timestamp: timestamp.nanoseconds(),
        signature: vec![],
        new_public_key: Some(pk),
        new_diversifier: "oct".to_string(),
    };

    let data = header_data::HeaderData {
        new_pub_key: Some(pk),
        new_diversifier: "oct".to_string(),
    }
    .encode_vec()
    .map_err(|_| "Encoding to 'Any' from 'HeaderData' error".to_string())?;
    let sign_bytes =
        utils::construct_sign_bytes(height, timestamp.nanoseconds(), DataType::Header, data)?;

    Ok((solomachine_header_template, sign_bytes))
}

pub fn build_solomachine_header(
    mut solomachine_header_template: SmHeader,
    raw_signature: &[u8],
) -> Result<SmHeader, String> {
    use ibc_proto::cosmos::tx::signing::v1beta1::signature_descriptor::{
        data::{Single, Sum},
        Data,
    };

    let sig = Data {
        sum: Some(Sum::Single(Single {
            mode: 1,
            signature: raw_signature.to_vec(),
        })),
    }
    .encode_to_vec();

    solomachine_header_template.signature = sig;
    Ok(solomachine_header_template)
}
