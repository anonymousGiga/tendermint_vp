use candid::{CandidType, Decode, Deserialize, Encode};
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{
    BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable, Vec as StableVec,
};
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

use ibc::core::ics24_host::identifier::{ClientId, ConnectionId};

use hashbrown::HashMap;

use ibc_proto::ibc::lightclients::tendermint::v1::ClientState as RawTmClientState;
use ibc_proto::ibc::lightclients::tendermint::v1::ConsensusState as RawTmConsensusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

use super::storage_manager;
use super::utils::*;

const MAX_VALUE_SIZE: u32 = 32;
#[derive(CandidType, Deserialize)]
struct StableChannelStore {
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
            channel_ids_counter: 0u64,
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

            // let mut map2: BTreeMap<StringData, u8, _> =
            //     BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            // scs.client_connections_address = instance.1;
            // instance.1 += 1;

            // for (k, v) in value.connections {
            //     let h = StringData(k.to_string());
            //     let cs = VecData(RawConnectionEnd::from(v).encode_to_vec());
            //     map1.insert(h, cs);
            // }

            // for (k, v) in value.client_connections {
            //     let c = StringData(k.to_string());
            //     let vec: StableVec<StringData, _> =
            //         StableVec::init(instance.0.get(MemoryId::new(instance.1)))
            //             .expect("Get vec memory error");
            //     map2.insert(c, instance.1);
            //     instance.1 += 1;

            //     let _ = v
            //         .iter()
            //         .map(|conn_id| vec.push(&StringData(conn_id.as_str().to_string())))
            //         .collect::<Vec<_>>();
            // }
        });

        scs
    }
}

// impl From<StableChannelStore> for ChannelStore{
//     fn from(value: StableChannelStore) -> Self {
//         let mut connections = HashMap::new();

//         storage_manager::MEMORY_MANAGER.with(|instance| {
//             let instance = instance.borrow();
//             let map: BTreeMap<StringData, VecData, _> =
//                 BTreeMap::init(instance.0.get(MemoryId::new(value.connections_address)));

//             let _ = map
//                 .iter()
//                 .map(|(k, v)| {
//                     let conn_id: ConnectionId =
//                         ConnectionId::from_str(&k.0).expect("Parse connection id error");
//                     let conn_end: ConnectionEnd = RawConnectionEnd::decode(v.0.as_ref())
//                         .expect("parse connecion end error")
//                         .try_into()
//                         .expect("parse connecion end error");

//                     connections.insert(conn_id, conn_end);
//                 })
//                 .collect::<Vec<_>>();
//         });

//         let mut client_connections = HashMap::new();

//         storage_manager::MEMORY_MANAGER.with(|instance| {
//             let instance = instance.borrow();
//             let map: BTreeMap<StringData, u8, _> = BTreeMap::init(
//                 instance
//                     .0
//                     .get(MemoryId::new(value.client_connections_address)),
//             );

//             let _ = map
//                 .iter()
//                 .map(|(k, v)| {
//                     let client_id: ClientId =
//                         ClientId::from_str(&k.0).expect("Parse client id error");
//                     let st_vec: StableVec<StringData, _> =
//                         StableVec::init(instance.0.get(MemoryId::new(v)))
//                             .expect("Get vec memory error");
//                     let mut vec = Vec::new();

//                     let _ = st_vec
//                         .iter()
//                         .map(|value| {
//                             let conn_id = ConnectionId::from_str(&value.0)
//                                 .expect("Parse conneciont id error");
//                             vec.push(conn_id)
//                         })
//                         .collect::<Vec<_>>();

//                     client_connections.insert(client_id, vec);
//                 })
//                 .collect::<Vec<_>>();
//         });

//         ConnectionStore {
//             connections,
//             client_connections,
//             connections_counter: value.connections_count,
//         }
//     }
// }
