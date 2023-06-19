use candid::{CandidType, Decode, Deserialize, Encode};
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{
    BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable, Vec as StableVec,
};
use std::str::FromStr;
use std::{borrow::Cow, cell::RefCell};
use tendermint_client::conn_store::ConnectionStore;

use ibc_proto::ibc::core::connection::v1::{
    ConnectionEnd as RawConnectionEnd, Counterparty as RawCounterparty,
    IdentifiedConnection as RawIdentifiedConnection,
};

use ibc::core::ics24_host::identifier::{ClientId, ConnectionId};

use hashbrown::HashMap;

use ibc_proto::ibc::lightclients::tendermint::v1::ClientState as RawTmClientState;
use ibc_proto::ibc::lightclients::tendermint::v1::ConsensusState as RawTmConsensusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

use super::storage_manager;
use super::utils::*;

const MAX_VALUE_SIZE: u32 = 16;
#[derive(CandidType, Deserialize)]
struct StableConnectionStore {
    connections_address: u8,
    client_connections_address: u8,
    connections_count: u64,
}

impl Storable for StableConnectionStore {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for StableConnectionStore {
    const MAX_SIZE: u32 = MAX_VALUE_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl From<ConnectionStore> for StableConnectionStore {
    fn from(value: ConnectionStore) -> Self {
        let mut scs = StableConnectionStore {
            connections_address: 0u8,
            client_connections_address: 0u8,
            connections_count: value
                .connection_counter()
                .expect("connection_counter error"),
        };

        storage_manager::MEMORY_MANAGER.with(|instance| {
            let mut instance = instance.borrow_mut();
            let mut map1: BTreeMap<StringData, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.connections_address = instance.1;
            instance.1 += 1;

            let mut map2: BTreeMap<StringData, u8, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            scs.client_connections_address = instance.1;
            instance.1 += 1;

            for (k, v) in value.connections {
                let h = StringData(k.to_string());
                let cs = VecData(RawConnectionEnd::from(v).encode_to_vec());
                map1.insert(h, cs);
            }

            for (k, v) in value.client_connections {
                let c = StringData(k.to_string());
                let vec: StableVec<StringData, _> =
                    StableVec::init(instance.0.get(MemoryId::new(instance.1)))
                        .expect("Get vec memory error");
                map2.insert(c, instance.1);
                instance.1 += 1;

                let _ = v
                    .iter()
                    .map(|conn_id| vec.push(&StringData(conn_id.as_str().to_string())))
                    .collect::<Vec<_>>();
            }
        });

        scs
    }
}

impl From<StableConnectionStore> for ConnectionStore {
    fn from(value: StableConnectionStore) -> Self {
        let mut connections = HashMap::new();

        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<StringData, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(value.connections_address)));

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let conn_id: ConnectionId =
                        ConnectionId::from_str(&k.0).expect("Parse connection id error");
                    let conn_end: ConnectionEnd = RawConnectionEnd::decode(v.0.as_ref())
                        .expect("parse connecion end error")
                        .try_into()
                        .expect("parse connecion end error");

                    connections.insert(conn_id, conn_end);
                })
                .collect::<Vec<_>>();
        });

        let mut client_connections = HashMap::new();

        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<StringData, u8, _> = BTreeMap::init(
                instance
                    .0
                    .get(MemoryId::new(value.client_connections_address)),
            );

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let client_id: ClientId =
                        ClientId::from_str(&k.0).expect("Parse client id error");
                    let st_vec: StableVec<StringData, _> =
                        StableVec::init(instance.0.get(MemoryId::new(v)))
                            .expect("Get vec memory error");
                    let mut vec = Vec::new();

                    let _ = st_vec
                        .iter()
                        .map(|value| {
                            let conn_id = ConnectionId::from_str(&value.0)
                                .expect("Parse conneciont id error");
                            vec.push(conn_id)
                        })
                        .collect::<Vec<_>>();

                    client_connections.insert(client_id, vec);
                })
                .collect::<Vec<_>>();
        });

        ConnectionStore {
            connections,
            client_connections,
            connections_counter: value.connections_count,
        }
    }
}
