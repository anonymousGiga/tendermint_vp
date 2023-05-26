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
use ibc::core::ics04_channel::channel::{ChannelEnd, IdentifiedChannelEnd};
use ibc::core::ics24_host::identifier::ClientId;
use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ConnectionId, PortId};

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

// return channel sign bytes and time
pub fn construct_solomachine_channel_sign_bytes(
    port_id: &PortId,
    channel_id: &ChannelId,
    channel_end: &ChannelEnd,
    sequence: u64,
) -> Result<(Vec<u8>, u64), String> {
    let data = ChannelStateData {
        path: ("/ibc/channelEnds%2Fports%2F".to_string()
            + port_id.as_str()
            + &"%2Fchannels%2F".to_string()
            + channel_id.as_str())
        .into(),
        channel: Some(channel_end.clone().into()),
    }
    .encode_to_vec();

    let time = time();
    let sign_bytes = utils::construct_sign_bytes(sequence, time, DataType::ChannelState, data)?;

    Ok((sign_bytes, time))
}

pub fn build_solomachine_channel_proof(
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

//  fn build_channel_proofs(
//         &self,
//         port_id: &PortId,
//         channel_id: &ChannelId,
//         height: ICSHeight,
//     ) -> Result<Proofs, Error> {
//         // Collect all proofs as required
//         let (channel, maybe_channel_proof) = self.query_channel(
//             QueryChannelRequest {
//                 port_id: port_id.clone(),
//                 channel_id: channel_id.clone(),
//                 height: QueryHeight::Specific(height),
//             },
//             IncludeProof::No,
//         )?;

//         let mut buf = Vec::new();
//         let data = ChannelStateData {
//             path: ("/ibc/channelEnds%2Fports%2F".to_string()
//                 + port_id.as_str()
//                 + &"%2Fchannels%2F".to_string()
//                 + channel_id.as_str())
//             .into(),
//             channel: Some(channel.clone().into()),
//         };
//         println!("ys-debug: ChannelStateData: {:?}", data);
//         Message::encode(&data, &mut buf).unwrap();

//         let duration_since_epoch = SystemTime::now()
//             .duration_since(SystemTime::UNIX_EPOCH)
//             .unwrap();
//         let timestamp_nanos = duration_since_epoch.as_nanos() as u64; // u128

//         let sig_data = alice_sign_sign_bytes(
//             height.revision_height() + 1,
//             timestamp_nanos,
//             DataType::ChannelState.into(),
//             buf.to_vec(),
//         );

//         let timestamped = TimestampedSignatureData {
//             signature_data: sig_data,
//             timestamp: timestamp_nanos,
//         };
//         let mut channel_proof = Vec::new();
//         Message::encode(&timestamped, &mut channel_proof).unwrap();

//         let channel_proof_bytes =
//             CommitmentProofBytes::try_from(channel_proof).map_err(Error::malformed_proof)?;

//         Proofs::new(channel_proof_bytes, None, None, None, height.increment())
//             .map_err(Error::malformed_proof)
//     }
