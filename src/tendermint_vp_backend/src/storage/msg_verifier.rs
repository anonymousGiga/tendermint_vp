use candid::{CandidType, Decode, Deserialize, Encode};
use ibc::core::ics02_client::consensus_state;
use ibc::Height;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable};
use std::str::FromStr;
use std::{borrow::Cow, cell::RefCell};
use tendermint_client::chan_store::ChannelStore;
use tendermint_client::conn_store::ConnectionStore;
use tendermint_client::msg_verifier::MessageVerifier;
use tendermint_client::tendermint_client::TendermintClient;
use tendermint_client::tm_client_state::ClientState as TmClientState;

use ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};

use hashbrown::HashMap;
use ibc_proto::ibc::lightclients::tendermint::v1::ClientState as RawTmClientState;
use ibc_proto::ibc::lightclients::tendermint::v1::ConsensusState as RawTmConsensusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

use super::chan_store::*;
use super::conn_store::*;
use super::storage_manager;
use super::tendermint_client::*;
use super::utils::*;

const MAX_VALUE_SIZE: u32 = 64;

#[derive(CandidType, Deserialize)]
pub struct StableMessageVerifier {
    tendermint_clients_address: u8,
    client_ids_counter: u64,
    conn_store: StableConnectionStore,
    chan_store: StableChannelStore,
}

impl Storable for StableMessageVerifier {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for StableMessageVerifier {
    const MAX_SIZE: u32 = MAX_VALUE_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl From<MessageVerifier> for StableMessageVerifier {
    fn from(value: MessageVerifier) -> Self {
        let mut smv = StableMessageVerifier {
            tendermint_clients_address: 0u8,
            client_ids_counter: value.client_ids_counter,
            conn_store: StableConnectionStore::from(value.conn_store),
            chan_store: StableChannelStore::from(value.chan_store),
        };

        storage_manager::MEMORY_MANAGER.with(|instance| {
            let mut instance = instance.borrow_mut();
            let mut map: BTreeMap<StringData, StableTendermintClient, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            smv.tendermint_clients_address = instance.1;
            instance.1 += 1;

            for (k, v) in value.tendermint_clients {
                let client_id = StringData(k.as_str().to_string());
                map.insert(client_id, StableTendermintClient::from(v));
            }
        });

        smv
    }
}

impl From<StableMessageVerifier> for MessageVerifier {
    fn from(value: StableMessageVerifier) -> Self {
        let mut tendermint_clients = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<StringData, StableTendermintClient, _> = BTreeMap::init(
                instance
                    .0
                    .get(MemoryId::new(value.tendermint_clients_address)),
            );

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let client_id = ClientId::from_str(&k.0).expect("parse client id error");
                    let sss = TendermintClient::from(v);

                    tendermint_clients.insert(client_id, sss);
                })
                .collect::<Vec<_>>();
        });

        MessageVerifier {
            tendermint_clients,
            client_ids_counter: value.client_ids_counter,
            conn_store: ConnectionStore::from(value.conn_store),
            chan_store: ChannelStore::from(value.chan_store),
        }
    }
}
