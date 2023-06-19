use candid::{CandidType, Decode, Deserialize, Encode};
use ibc::core::ics02_client::consensus_state;
use ibc::Height;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable};
use std::str::FromStr;
use std::{borrow::Cow, cell::RefCell};
use tendermint_client::tendermint_client::TendermintClient;
use tendermint_client::tm_client_state::ClientState as TmClientState;

use ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};

use hashbrown::HashMap;
use ibc_proto::ibc::lightclients::tendermint::v1::ClientState as RawTmClientState;
use ibc_proto::ibc::lightclients::tendermint::v1::ConsensusState as RawTmConsensusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

use super::storage_manager;
use super::utils::*;

const MAX_VALUE_SIZE: u32 = 4096;

#[derive(CandidType, Deserialize)]
struct StableTendermintClient {
    client_id: String,
    addreass_offset: u8,
    client_state: Vec<u8>,
}

impl Storable for StableTendermintClient {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for StableTendermintClient {
    const MAX_SIZE: u32 = MAX_VALUE_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl From<TendermintClient> for StableTendermintClient {
    fn from(value: TendermintClient) -> Self {
        let mut stc = StableTendermintClient {
            client_id: value.client_id.as_str().to_string(),
            addreass_offset: 0u8,
            client_state: RawTmClientState::from(value.client_state).encode_to_vec(),
        };

        storage_manager::MEMORY_MANAGER.with(|instance| {
            let mut instance = instance.borrow_mut();
            let mut map: BTreeMap<StringData, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            stc.addreass_offset = instance.1;
            instance.1 += 1;
            for (k, v) in value.consensus_states {
                let h = StringData(k.to_string());
                let cs = VecData(RawTmConsensusState::from(v).encode_to_vec());

                map.insert(h, cs);
            }
        });

        stc
    }
}

impl From<StableTendermintClient> for TendermintClient {
    fn from(value: StableTendermintClient) -> Self {
        let client_id = ClientId::from_str(&value.client_id).expect("parse client id error");
        let client_state = RawTmClientState::decode(value.client_state.as_ref())
            .expect("parse client_state error")
            .try_into()
            .expect("parse client_state error");

        let mut consensus_states = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<StringData, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(value.addreass_offset)));

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let h: Height = Height::from_str(&k.0).expect("Parse height error");
                    let cs: TmConsensusState = RawTmConsensusState::decode(v.0.as_ref())
                        .expect("parse client_state error")
                        .try_into()
                        .expect("parse client_state error");

                    consensus_states.insert(h, cs);
                })
                .collect::<Vec<_>>();
        });

        TendermintClient {
            client_id,
            consensus_states,
            client_state,
        }
    }
}
