use crate::prelude::*;

use core::time::Duration;
// use num_traits::float::FloatCore;

use ibc::core::ics02_client::client_state::ClientState;
use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics04_channel::channel::ChannelEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ibc::core::ics04_channel::handler::recv_packet::RecvPacketResult;
use ibc::core::ics04_channel::handler::{ChannelIdState, ChannelResult};
use ibc::core::ics04_channel::msgs::acknowledgement::Acknowledgement;
use ibc::core::ics04_channel::{
    error::{ChannelError, PacketError},
    packet::Receipt,
};
use ibc::core::ics24_host::identifier::{ChannelId, ClientId, ConnectionId, PortId};
use ibc::timestamp::Timestamp;
use ibc::Height;

use hashbrown::HashMap;
use sha2::Digest;

use ibc::core::ics04_channel::packet::{PacketResult, Sequence};
use ibc::core::ics04_channel::timeout::TimeoutHeight;

pub struct ChannelStore {
    connection_channels: HashMap<ConnectionId, Vec<(PortId, ChannelId)>>,
    channel_ids_counter: u64,
    channels: HashMap<(PortId, ChannelId), ChannelEnd>,
    next_sequence_send: HashMap<(PortId, ChannelId), Sequence>,
    next_sequence_recv: HashMap<(PortId, ChannelId), Sequence>,
    next_sequence_ack: HashMap<(PortId, ChannelId), Sequence>,
    packet_receipts: HashMap<(PortId, ChannelId, Sequence), Receipt>,
    packet_acknowledgements: HashMap<(PortId, ChannelId, Sequence), AcknowledgementCommitment>,
    packet_commitments: HashMap<(PortId, ChannelId, Sequence), PacketCommitment>,
}

impl ChannelStore {
    pub fn new() -> Self {
        ChannelStore {
            connection_channels: HashMap::new(),
            channel_ids_counter: 0u64,
            channels: HashMap::new(),
            next_sequence_send: HashMap::new(),
            next_sequence_recv: HashMap::new(),
            next_sequence_ack: HashMap::new(),
            packet_receipts: HashMap::new(),
            packet_acknowledgements: HashMap::new(),
            packet_commitments: HashMap::new(),
        }
    }
}

impl ChannelStore {
    pub fn store_channel_result(&mut self, result: ChannelResult) -> Result<(), PacketError> {
        let connection_id = result.channel_end.connection_hops()[0].clone();

        // The handler processed this channel & some modifications occurred, store the new end.
        self.store_channel(
            result.port_id.clone(),
            result.channel_id.clone(),
            result.channel_end,
        )
        .map_err(PacketError::Channel)?;

        // The channel identifier was freshly brewed.
        // Increase counter & initialize seq. nrs.
        if matches!(result.channel_id_state, ChannelIdState::Generated) {
            self.increase_channel_counter();

            // Associate also the channel end to its connection.
            self.store_connection_channels(
                connection_id,
                result.port_id.clone(),
                result.channel_id.clone(),
            )
            .map_err(PacketError::Channel)?;

            // Initialize send, recv, and ack sequence numbers.
            self.store_next_sequence_send(
                result.port_id.clone(),
                result.channel_id.clone(),
                1.into(),
            )?;
            self.store_next_sequence_recv(
                result.port_id.clone(),
                result.channel_id.clone(),
                1.into(),
            )?;
            self.store_next_sequence_ack(result.port_id, result.channel_id, 1.into())?;
        }

        Ok(())
    }

    pub fn store_packet_result(&mut self, general_result: PacketResult) -> Result<(), PacketError> {
        match general_result {
            PacketResult::Send(res) => {
                self.store_next_sequence_send(
                    res.port_id.clone(),
                    res.channel_id.clone(),
                    res.seq_number,
                )?;

                self.store_packet_commitment(res.port_id, res.channel_id, res.seq, res.commitment)?;
            }
            PacketResult::Recv(res) => match res {
                RecvPacketResult::Ordered {
                    port_id,
                    channel_id,
                    next_seq_recv,
                } => self.store_next_sequence_recv(port_id, channel_id, next_seq_recv)?,
                RecvPacketResult::Unordered {
                    port_id,
                    channel_id,
                    sequence,
                    receipt,
                } => self.store_packet_receipt(port_id, channel_id, sequence, receipt)?,
                RecvPacketResult::NoOp => unreachable!(),
            },
            PacketResult::WriteAck(res) => {
                self.store_packet_acknowledgement(
                    res.port_id,
                    res.channel_id,
                    res.seq,
                    res.ack_commitment,
                )?;
            }
            PacketResult::Ack(res) => {
                self.delete_packet_commitment(&res.port_id, &res.channel_id, &res.seq)?;
                if let Some(s) = res.seq_number {
                    //Ordered Channel
                    self.store_next_sequence_ack(res.port_id, res.channel_id, s)?;
                }
            }
            PacketResult::Timeout(res) => {
                self.delete_packet_commitment(&res.port_id, &res.channel_id, &res.seq)?;
                if let Some(c) = res.channel {
                    // Ordered Channel: closes channel
                    self.store_channel(res.port_id, res.channel_id, c)
                        .map_err(PacketError::Channel)?;
                }
            }
        }
        Ok(())
    }

    fn store_packet_commitment(
        &mut self,
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
        commitment: PacketCommitment,
    ) -> Result<(), PacketError> {
        self.packet_commitments
            .insert((port_id, channel_id, sequence), commitment);

        Ok(())
    }

    fn delete_packet_commitment(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<(), PacketError> {
        let key = (port_id.clone(), channel_id.clone(), sequence.clone());
        self.packet_commitments.remove(&key);

        Ok(())
    }

    fn store_packet_receipt(
        &mut self,
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
        receipt: Receipt,
    ) -> Result<(), PacketError> {
        self.packet_receipts
            .insert((port_id, channel_id, sequence), receipt);

        Ok(())
    }

    fn store_packet_acknowledgement(
        &mut self,
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
        ack_commitment: AcknowledgementCommitment,
    ) -> Result<(), PacketError> {
        self.packet_acknowledgements
            .insert((port_id, channel_id, sequence), ack_commitment);

        Ok(())
    }

    fn delete_packet_acknowledgement(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<(), PacketError> {
        let key = (port_id.clone(), channel_id.clone(), sequence.clone());
        self.packet_acknowledgements.remove(&key);

        Ok(())
    }

    fn store_connection_channels(
        &mut self,
        conn_id: ConnectionId,
        port_id: PortId,
        channel_id: ChannelId,
    ) -> Result<(), ChannelError> {
        if let Some(channels) = self.connection_channels.get_mut(&conn_id) {
            channels.push((port_id, channel_id));
        } else {
            let mut channels = Vec::new();
            channels.push((port_id, channel_id));
            self.connection_channels.insert(conn_id, channels);
        }

        Ok(())
    }

    /// Stores the given channel_end at a path associated with the port_id and channel_id.
    fn store_channel(
        &mut self,
        port_id: PortId,
        channel_id: ChannelId,
        channel_end: ChannelEnd,
    ) -> Result<(), ChannelError> {
        self.channels.insert((port_id, channel_id), channel_end);

        Ok(())
    }

    fn store_next_sequence_send(
        &mut self,
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
    ) -> Result<(), PacketError> {
        self.next_sequence_send
            .insert((port_id, channel_id), sequence);
        Ok(())
    }

    fn store_next_sequence_recv(
        &mut self,
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
    ) -> Result<(), PacketError> {
        self.next_sequence_recv
            .insert((port_id, channel_id), sequence);

        Ok(())
    }

    fn store_next_sequence_ack(
        &mut self,
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
    ) -> Result<(), PacketError> {
        self.next_sequence_ack
            .insert((port_id, channel_id), sequence);

        Ok(())
    }

    /// Called upon channel identifier creation (Init or Try message processing).
    /// Increases the counter which keeps track of how many channels have been created.
    /// Should never fail.
    fn increase_channel_counter(&mut self) {
        self.channel_ids_counter = self
            .channel_ids_counter
            .checked_add(1)
            .expect(format!("increase channel counter overflow").as_str())
    }
}

impl ChannelStore {
    /// Returns a counter on the number of channel ids have been created thus far.
    /// The value of this counter should increase only via method
    /// `ChannelKeeper::increase_channel_counter`.
    pub fn channel_counter(&self) -> Result<u64, ChannelError> {
        Ok(self.channel_ids_counter)
    }

    pub fn channel_end(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ChannelEnd, ChannelError> {
        self.channels
            .get(&(port_id.clone(), channel_id.clone()))
            .map(|ce| ce.clone())
            .ok_or(ChannelError::ChannelNotFound {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            })
    }

    pub fn get_next_sequence_send(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<Sequence, PacketError> {
        self.next_sequence_send
            .get(&(port_id.clone(), channel_id.clone()))
            .map(|sq| sq.clone())
            .ok_or(PacketError::MissingNextSendSeq {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            })
    }

    pub fn get_next_sequence_recv(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<Sequence, PacketError> {
        self.next_sequence_recv
            .get(&(port_id.clone(), channel_id.clone()))
            .map(|sq| sq.clone())
            .ok_or(PacketError::MissingNextRecvSeq {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            })
            .map(Into::into)
    }

    pub fn get_next_sequence_ack(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<Sequence, PacketError> {
        self.next_sequence_ack
            .get(&(port_id.clone(), channel_id.clone()))
            .map(|sq| sq.clone())
            .ok_or(PacketError::MissingNextSendSeq {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            })
    }

    pub fn get_packet_commitment(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<PacketCommitment, PacketError> {
        self.packet_commitments
            .get(&(port_id.clone(), channel_id.clone(), sequence.clone()))
            .map(|pc| pc.clone())
            .ok_or(PacketError::PacketCommitmentNotFound {
                sequence: sequence.clone(),
            })
    }

    pub fn get_packet_receipt(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<Receipt, PacketError> {
        self.packet_receipts
            .get(&(port_id.clone(), channel_id.clone(), sequence.clone()))
            .map(|pc| pc.clone())
            .ok_or(PacketError::PacketReceiptNotFound {
                sequence: sequence.clone(),
            })
    }

    pub fn get_packet_acknowledgement(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<AcknowledgementCommitment, PacketError> {
        self.packet_acknowledgements
            .get(&(port_id.clone(), channel_id.clone(), sequence.clone()))
            .map(|ac| ac.clone())
            .ok_or(PacketError::PacketAcknowledgementNotFound {
                sequence: sequence.clone(),
            })
    }

    pub fn packet_commitment(
        &self,
        packet_data: &[u8],
        timeout_height: &TimeoutHeight,
        timeout_timestamp: &Timestamp,
    ) -> PacketCommitment {
        let mut hash_input = timeout_timestamp.nanoseconds().to_be_bytes().to_vec();

        let revision_number = timeout_height.commitment_revision_number().to_be_bytes();
        hash_input.append(&mut revision_number.to_vec());

        let revision_height = timeout_height.commitment_revision_height().to_be_bytes();
        hash_input.append(&mut revision_height.to_vec());

        let packet_data_hash = self.hash(packet_data);
        hash_input.append(&mut packet_data_hash.to_vec());

        self.hash(&hash_input).into()
    }

    fn hash(&self, value: &[u8]) -> Vec<u8> {
        sha2::Sha256::digest(value).to_vec()
    }

    pub fn ack_commitment(&self, ack: &Acknowledgement) -> AcknowledgementCommitment {
        self.hash(ack.as_ref()).into()
    }
}
