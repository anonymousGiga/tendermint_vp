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
    PacketAcknowledgementData, PacketCommitmentData, TimestampedSignatureData,
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

pub fn construct_solomachine_recv_packet_sign_bytes(
    port_id: &PortId,
    channel_id: &ChannelId,
    packet: &[u8],
    sequence: u64,
    time: u64,
) -> Result<Vec<u8>, String> {
    let data = PacketCommitmentData {
        path: ("/ibc/commitments%2Fports%2F".to_string()
            + port_id.as_str()
            + "%2Fchannels%2F"
            + channel_id.as_str()
            + "%2Fsequences%2F"
            + &sequence.to_string())
            .into(),
        commitment: packet.clone().into(),
    }
    .encode_to_vec();

    // let time = time();
    let sign_bytes = utils::construct_sign_bytes(sequence, time, DataType::PacketCommitment, data)?;

    Ok(sign_bytes)
}

pub fn construct_solomachine_ack_packet_sign_bytes(
    port_id: &PortId,
    channel_id: &ChannelId,
    packet: Vec<u8>,
    sequence: u64,
    time: u64,
) -> Result<Vec<u8>, String> {
    let data = PacketAcknowledgementData {
        path: ("/ibc/acks%2Fports%2F".to_string()
            + port_id.as_str()
            + "%2Fchannels%2F"
            + channel_id.as_str()
            + "%2Fsequences%2F"
            + &sequence.to_string())
            .into(),
        acknowledgement: packet.clone().into(),
    }
    .encode_to_vec();

    // let time = time();
    let sign_bytes =
        utils::construct_sign_bytes(sequence, time, DataType::PacketAcknowledgement, data)?;

    Ok(sign_bytes)
}

pub fn build_solomachine_packet_proof(
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

//    fn build_packet_proofs(
//         &self,
//         packet_type: PacketMsgType,
//         port_id: PortId,
//         channel_id: ChannelId,
//         sequence: Sequence,
//         height: ICSHeight,
//     ) -> Result<Proofs, Error> {
//         let mut buf = Vec::new();
//         let (maybe_packet_proof, channel_proof) = match packet_type {
//             PacketMsgType::Recv => {
//                 let (packet, _maybe_packet_proof) = self.query_packet_commitment(
//                     QueryPacketCommitmentRequest {
//                         port_id: port_id.clone(),
//                         channel_id: channel_id.clone(),
//                         sequence,
//                         height: QueryHeight::Specific(height),
//                     },
//                     IncludeProof::No,
//                 )?;
//                 let data = PacketCommitmentData {
//                     path: ("/ibc/commitments%2Fports%2F".to_string()
//                         + port_id.as_str()
//                         + "%2Fchannels%2F"
//                         + channel_id.as_str()
//                         + "%2Fsequences%2F"
//                         + &sequence.to_string())
//                         .into(),
//                     commitment: packet.clone().into(),
//                 };
//                 println!("ys-debug: PacketCommitmentData: {:?}", data);
//                 Message::encode(&data, &mut buf).unwrap();

//                 let sig_data = super::super::foreign_client::alice_sign_sign_bytes(
//                     height.revision_height() + 1,
//                     9999,
//                     DataType::PacketCommitment.into(),
//                     buf.to_vec(),
//                 );

//                 let timestamped = TimestampedSignatureData {
//                     signature_data: sig_data,
//                     timestamp: 9999,
//                 };
//                 let mut packet_proof = Vec::new();
//                 Message::encode(&timestamped, &mut packet_proof).unwrap();

//                 (Some(packet_proof), None)
//             }
//             PacketMsgType::Ack => {
//                 let (packet, _maybe_packet_proof) = self.query_packet_acknowledgement(
//                     QueryPacketAcknowledgementRequest {
//                         port_id: port_id.clone(),
//                         channel_id: channel_id.clone(),
//                         sequence,
//                         height: QueryHeight::Specific(height),
//                     },
//                     IncludeProof::No,
//                 )?;
//                 let data = PacketAcknowledgementData {
//                     path: ("/ibc/acks%2Fports%2F".to_string()
//                         + port_id.as_str()
//                         + "%2Fchannels%2F"
//                         + channel_id.as_str()
//                         + "%2Fsequences%2F"
//                         + &sequence.to_string())
//                         .into(),
//                     acknowledgement: packet.clone().into(),
//                 };
//                 println!("ys-debug: PacketAcknowledgementData: {:?}", data);
//                 Message::encode(&data, &mut buf).unwrap();

//                 let sig_data = super::super::foreign_client::alice_sign_sign_bytes(
//                     height.revision_height() + 1,
//                     9999,
//                     DataType::PacketAcknowledgement.into(),
//                     buf.to_vec(),
//                 );

//                 let timestamped = TimestampedSignatureData {
//                     signature_data: sig_data,
//                     timestamp: 9999,
//                 };
//                 let mut packet_proof = Vec::new();
//                 Message::encode(&timestamped, &mut packet_proof).unwrap();

//                 (Some(packet_proof), None)
//             }
//             PacketMsgType::TimeoutUnordered => {
//                 // let (_, maybe_packet_proof) = self.query_packet_receipt(
//                 //     QueryPacketReceiptRequest {
//                 //         port_id,
//                 //         channel_id,
//                 //         sequence,
//                 //         height: QueryHeight::Specific(height),
//                 //     },
//                 //     IncludeProof::Yes,
//                 // )?;

//                 // (maybe_packet_proof, None)
//                 (None, None)
//             }
//             PacketMsgType::TimeoutOrdered => {
//                 // let (_, maybe_packet_proof) = self.query_next_sequence_receive(
//                 //     QueryNextSequenceReceiveRequest {
//                 //         port_id,
//                 //         channel_id,
//                 //         height: QueryHeight::Specific(height),
//                 //     },
//                 //     IncludeProof::Yes,
//                 // )?;

//                 // (maybe_packet_proof, None)
//                 (None, None)
//             }
//             PacketMsgType::TimeoutOnCloseUnordered => {
//                 // let channel_proof = {
//                 //     let (_, maybe_channel_proof) = self.query_channel(
//                 //         QueryChannelRequest {
//                 //             port_id: port_id.clone(),
//                 //             channel_id: channel_id.clone(),
//                 //             height: QueryHeight::Specific(height),
//                 //         },
//                 //         IncludeProof::Yes,
//                 //     )?;

//                 //     let Some(channel_merkle_proof) = maybe_channel_proof else {
//                 //         return Err(Error::queried_proof_not_found());
//                 //     };

//                 //     Some(
//                 //         CommitmentProofBytes::try_from(channel_merkle_proof)
//                 //             .map_err(Error::malformed_proof)?,
//                 //     )
//                 // };

//                 // let (_, maybe_packet_proof) = self.query_packet_receipt(
//                 //     QueryPacketReceiptRequest {
//                 //         port_id,
//                 //         channel_id,
//                 //         sequence,
//                 //         height: QueryHeight::Specific(height),
//                 //     },
//                 //     IncludeProof::Yes,
//                 // )?;

//                 // (maybe_packet_proof, channel_proof)
//                 (None, None)
//             }
//             PacketMsgType::TimeoutOnCloseOrdered => {
//                 // let channel_proof = {
//                 //     let (_, maybe_channel_proof) = self.query_channel(
//                 //         QueryChannelRequest {
//                 //             port_id: port_id.clone(),
//                 //             channel_id: channel_id.clone(),
//                 //             height: QueryHeight::Specific(height),
//                 //         },
//                 //         IncludeProof::Yes,
//                 //     )?;

//                 //     let Some(channel_merkle_proof) = maybe_channel_proof else {
//                 //         return Err(Error::queried_proof_not_found());
//                 //     };

//                 //     Some(
//                 //         CommitmentProofBytes::try_from(channel_merkle_proof)
//                 //             .map_err(Error::malformed_proof)?,
//                 //     )
//                 // };
//                 // let (_, maybe_packet_proof) = self.query_next_sequence_receive(
//                 //     QueryNextSequenceReceiveRequest {
//                 //         port_id,
//                 //         channel_id,
//                 //         height: QueryHeight::Specific(height),
//                 //     },
//                 //     IncludeProof::Yes,
//                 // )?;

//                 // (maybe_packet_proof, channel_proof)
//                 (None, None)
//             }
//         };

//         let Some(packet_proof) = maybe_packet_proof else {
//             return Err(Error::queried_proof_not_found());
//         };

//         let proofs = Proofs::new(
//             CommitmentProofBytes::try_from(packet_proof).map_err(Error::malformed_proof)?,
//             None,
//             None,
//             channel_proof,
//             height.increment(),
//         )
//         .map_err(Error::malformed_proof)?;

//         Ok(proofs)
//     }
