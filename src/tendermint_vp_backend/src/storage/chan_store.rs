use candid::{CandidType, Decode, Deserialize, Encode};
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{
    BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable, Vec as StableVec,
};

use ibc::core::ics04_channel::packet::{PacketResult, Receipt, Sequence};

use ibc::core::ics04_channel::channel::ChannelEnd;
// use tendermint_client::tendermint_client::PortId;
use ibc::core::ics24_host::identifier::{ChannelId, ClientId, ConnectionId, PortId};
use std::str::FromStr;
use std::{borrow::Cow, cell::RefCell};
use tendermint_client::chan_store::ChannelStore;

use ibc_proto::ibc::core::connection::v1::{
    ConnectionEnd as RawConnectionEnd, Counterparty as RawCounterparty,
    IdentifiedConnection as RawIdentifiedConnection,
};

use ibc_proto::ibc::core::channel::v1::{
    Channel as RawChannel, IdentifiedChannel as RawIdentifiedChannel,
};

use hashbrown::HashMap;

use ibc_proto::ibc::lightclients::tendermint::v1::ClientState as RawTmClientState;
use ibc_proto::ibc::lightclients::tendermint::v1::ConsensusState as RawTmConsensusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

use super::storage_manager;
use super::utils::*;

const MAX_VALUE_SIZE: u32 = 16;
#[derive(CandidType, Deserialize)]
pub struct StableChannelStore {
    connection_channels_address: u8,
    channel_ids_counter: u64,
    channels_address: u8,
    next_sequence_send_address: u8,
    next_sequence_recv_address: u8,
    next_sequence_ack_address: u8,
    packet_receipts_address: u8,
    packet_acknowledgements_address: u8,
    packet_commitments_address: u8,
}

impl Storable for StableChannelStore {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for StableChannelStore {
    const MAX_SIZE: u32 = MAX_VALUE_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl From<ChannelStore> for StableChannelStore {
    fn from(value: ChannelStore) -> Self {
        let mut scs = StableChannelStore {
            connection_channels_address: 0u8,
            channel_ids_counter: value.channel_ids_counter,
            channels_address: 0u8,
            next_sequence_send_address: 0u8,
            next_sequence_recv_address: 0u8,
            next_sequence_ack_address: 0u8,
            packet_receipts_address: 0u8,
            packet_acknowledgements_address: 0u8,
            packet_commitments_address: 0u8,
        };

        storage_manager::MEMORY_MANAGER.with(|instance| {
            let mut instance = instance.borrow_mut();
            // connection_channels
            let mut map1: BTreeMap<StringData, u8, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.connection_channels_address = instance.1;
            instance.1 += 1;

            for (k, v) in value.connection_channels {
                let c = StringData(k.to_string());
                let vec: StableVec<TupleStringData, _> =
                    StableVec::init(instance.0.get(MemoryId::new(instance.1)))
                        .expect("Get vec memory error");

                map1.insert(c, instance.1);
                instance.1 += 1;

                let _ = v
                    .iter()
                    .map(|(port_id, chann_id)| {
                        vec.push(&&TupleStringData {
                            data1: port_id.as_str().to_string(),
                            data2: chann_id.as_str().to_string(),
                        })
                    })
                    .collect::<Vec<_>>();
            }

            // channels
            let mut map2: BTreeMap<TupleStringData, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.channels_address = instance.1;
            instance.1 += 1;

            for ((port_id, chann_id), chann_end) in value.channels {
                let k = TupleStringData {
                    data1: port_id.as_str().to_string(),
                    data2: chann_id.as_str().to_string(),
                };

                let v = VecData(RawChannel::from(chann_end).encode_to_vec());
                map2.insert(k, v);
            }

            // next_sequence_send
            let mut map3: BTreeMap<TupleStringData, u64, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.next_sequence_send_address = instance.1;
            instance.1 += 1;

            for ((port_id, chann_id), seq) in value.next_sequence_send {
                let k = TupleStringData {
                    data1: port_id.as_str().to_string(),
                    data2: chann_id.as_str().to_string(),
                };

                let v = u64::from(seq);
                map3.insert(k, v);
            }

            // next_sequence_recv
            let mut map4: BTreeMap<TupleStringData, u64, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.next_sequence_send_address = instance.1;
            instance.1 += 1;

            for ((port_id, chann_id), seq) in value.next_sequence_recv {
                let k = TupleStringData {
                    data1: port_id.as_str().to_string(),
                    data2: chann_id.as_str().to_string(),
                };

                let v = u64::from(seq);
                map4.insert(k, v);
            }

            // next_sequence_ack
            let mut map5: BTreeMap<TupleStringData, u64, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.next_sequence_send_address = instance.1;
            instance.1 += 1;

            for ((port_id, chann_id), seq) in value.next_sequence_ack {
                let k = TupleStringData {
                    data1: port_id.as_str().to_string(),
                    data2: chann_id.as_str().to_string(),
                };

                let v = u64::from(seq);
                map5.insert(k, v);
            }

            // packet_receipts
            let mut map6: BTreeMap<TupleData, u8, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.packet_receipts_address = instance.1;
            instance.1 += 1;

            for ((port_id, chann_id, seq), _receipt) in value.packet_receipts {
                let k = TupleData {
                    data1: port_id.as_str().to_string(),
                    data2: chann_id.as_str().to_string(),
                    data3: u64::from(seq),
                };

                let v = 1u8; // as all receipts are ok
                map6.insert(k, v);
            }

            // packet_ack
            let mut map7: BTreeMap<TupleData, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.packet_acknowledgements_address = instance.1;
            instance.1 += 1;

            for ((port_id, chann_id, seq), ack) in value.packet_acknowledgements {
                let k = TupleData {
                    data1: port_id.as_str().to_string(),
                    data2: chann_id.as_str().to_string(),
                    data3: u64::from(seq),
                };

                let v = VecData(ack.into_vec());

                map7.insert(k, v);
            }

            // packet_commitment
            let mut map8: BTreeMap<TupleData, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.packet_acknowledgements_address = instance.1;
            instance.1 += 1;

            for ((port_id, chann_id, seq), commitment) in value.packet_commitments {
                let k = TupleData {
                    data1: port_id.as_str().to_string(),
                    data2: chann_id.as_str().to_string(),
                    data3: u64::from(seq),
                };

                let v = VecData(commitment.into_vec());

                map8.insert(k, v);
            }
        });

        scs
    }
}

impl From<StableChannelStore> for ChannelStore {
    fn from(value: StableChannelStore) -> Self {
        // connection_channels
        let mut connection_channels = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<StringData, u8, _> = BTreeMap::init(
                instance
                    .0
                    .get(MemoryId::new(value.connection_channels_address)),
            );

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let conn_id: ConnectionId =
                        ConnectionId::from_str(&k.0).expect("Parse connection id error");

                    let st_vec: StableVec<TupleStringData, _> =
                        StableVec::init(instance.0.get(MemoryId::new(v)))
                            .expect("Get vec memory error");
                    let mut vec = Vec::new();

                    let _ = st_vec
                        .iter()
                        .map(|value| {
                            let port_id =
                                PortId::from_str(&value.data1).expect("Parse port id error");

                            let chan_id =
                                ChannelId::from_str(&value.data2).expect("Parse channel id error");

                            vec.push((port_id, chan_id))
                        })
                        .collect::<Vec<_>>();

                    connection_channels.insert(conn_id, vec);
                })
                .collect::<Vec<_>>();
        });

        // channels
        let mut channels = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<TupleStringData, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(value.channels_address)));

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let port_id = PortId::from_str(&k.data1).expect("Parse port id error");
                    let chann_id = ChannelId::from_str(&k.data2).expect("Parse channel id error");
                    let chan_end: ChannelEnd = RawChannel::decode(v.0.as_ref())
                        .expect("parse channel end error")
                        .try_into()
                        .expect("parse channel end error");

                    channels.insert((port_id, chann_id), chan_end);
                })
                .collect::<Vec<_>>();
        });

        // // next_sequence_send
        let mut next_sequence_send = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<TupleStringData, u64, _> = BTreeMap::init(
                instance
                    .0
                    .get(MemoryId::new(value.next_sequence_send_address)),
            );

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let port_id = PortId::from_str(&k.data1).expect("Parse port id error");
                    let chann_id = ChannelId::from_str(&k.data2).expect("Parse channel id error");
                    let sequence = Sequence::from(v);

                    next_sequence_send.insert((port_id, chann_id), sequence);
                })
                .collect::<Vec<_>>();
        });

        // // next_sequence_recv
        let mut next_sequence_recv = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<TupleStringData, u64, _> = BTreeMap::init(
                instance
                    .0
                    .get(MemoryId::new(value.next_sequence_recv_address)),
            );

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let port_id = PortId::from_str(&k.data1).expect("Parse port id error");
                    let chann_id = ChannelId::from_str(&k.data2).expect("Parse channel id error");
                    let sequence = Sequence::from(v);

                    next_sequence_recv.insert((port_id, chann_id), sequence);
                })
                .collect::<Vec<_>>();
        });

        // // next_sequence_ack
        let mut next_sequence_ack = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<TupleStringData, u64, _> = BTreeMap::init(
                instance
                    .0
                    .get(MemoryId::new(value.next_sequence_ack_address)),
            );

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let port_id = PortId::from_str(&k.data1).expect("Parse port id error");
                    let chann_id = ChannelId::from_str(&k.data2).expect("Parse channel id error");
                    let sequence = Sequence::from(v);

                    next_sequence_ack.insert((port_id, chann_id), sequence);
                })
                .collect::<Vec<_>>();
        });

        let mut packet_receipts = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<TupleData, u8, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(value.packet_receipts_address)));

            let _ = map
                .iter()
                .map(|(k, _v)| {
                    let port_id = PortId::from_str(&k.data1).expect("Parse port id error");
                    let chann_id = ChannelId::from_str(&k.data2).expect("Parse channel id error");
                    let sequence = Sequence::from(k.data3);
                    let receipt = Receipt::Ok;

                    packet_receipts.insert((port_id, chann_id, sequence), receipt);
                })
                .collect::<Vec<_>>();
        });

        let mut packet_acknowledgements = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<TupleData, VecData, _> = BTreeMap::init(
                instance
                    .0
                    .get(MemoryId::new(value.packet_acknowledgements_address)),
            );

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let port_id = PortId::from_str(&k.data1).expect("Parse port id error");
                    let chann_id = ChannelId::from_str(&k.data2).expect("Parse channel id error");
                    let sequence = Sequence::from(k.data3);
                    let ack: AcknowledgementCommitment = AcknowledgementCommitment::from(v.0);

                    packet_acknowledgements.insert((port_id, chann_id, sequence), ack);
                })
                .collect::<Vec<_>>();
        });

        let mut packet_commitments = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<TupleData, VecData, _> = BTreeMap::init(
                instance
                    .0
                    .get(MemoryId::new(value.packet_commitments_address)),
            );

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let port_id = PortId::from_str(&k.data1).expect("Parse port id error");
                    let chann_id = ChannelId::from_str(&k.data2).expect("Parse channel id error");
                    let sequence = Sequence::from(k.data3);
                    let commit = PacketCommitment::from(v.0);

                    packet_commitments.insert((port_id, chann_id, sequence), commit);
                })
                .collect::<Vec<_>>();
        });

        ChannelStore {
            connection_channels,
            channel_ids_counter: value.channel_ids_counter,
            channels,
            next_sequence_send,
            next_sequence_recv,
            next_sequence_ack,
            packet_receipts,
            packet_acknowledgements,
            packet_commitments,
        }
    }
}
