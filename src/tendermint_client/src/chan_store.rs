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

use ibc::core::ics04_channel::packet::Sequence;

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

impl ChannelStore {}
