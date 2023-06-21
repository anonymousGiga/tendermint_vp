use candid::{CandidType, Decode, Deserialize, Encode};
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{
    BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable, Vec as StableVec,
};

use tendermint_client::solomachine::consensus_state::{
    self, ConsensusState as SmConsensusState, PublicKey,
};

use ibc::core::ics04_channel::packet::{PacketResult, Receipt, Sequence};

use ibc_proto::ibc::lightclients::solomachine::v1::ClientState as RawSmClientState;
use ibc_proto::ibc::lightclients::solomachine::v1::ConsensusState as RawSmConsensusState;
use ibc_proto::protobuf::Protobuf;

use ibc::core::ics04_channel::channel::ChannelEnd;
// use tendermint_client::tendermint_client::PortId;
use ibc::core::ics24_host::identifier::{ChannelId, ClientId, ConnectionId, PortId};
use std::str::FromStr;
use std::{borrow::Cow, cell::RefCell};

use tendermint_client::solomachine_store::{
    SequenceAndTimeStore, SoloMachineStateStore, SoloMachineStateStores,
};

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
use prost::Message;

use super::storage_manager;
use super::utils::*;

const MAX_VALUE_SIZE: u32 = 4096;
#[derive(CandidType, Deserialize)]
struct StableSoloMachineStateStore {
    client_state: Vec<u8>,
    consensus_state_address: u8,
}

impl Storable for StableSoloMachineStateStore {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for StableSoloMachineStateStore {
    const MAX_SIZE: u32 = MAX_VALUE_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl From<SoloMachineStateStore> for StableSoloMachineStateStore {
    fn from(value: SoloMachineStateStore) -> Self {
        let client_state = RawSmClientState::from(value.client_state).encode_to_vec();
        let mut sms = StableSoloMachineStateStore {
            client_state,
            consensus_state_address: 0u8,
        };

        storage_manager::MEMORY_MANAGER.with(|instance| {
            let mut instance = instance.borrow_mut();
            let mut map: BTreeMap<u64, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            sms.consensus_state_address = instance.1;
            instance.1 += 1;

            for (k, v) in value.consensus_state {
                let cs = VecData(RawSmConsensusState::from(v).encode_to_vec());
                map.insert(k, cs);
            }
        });

        sms
    }
}

impl From<StableSoloMachineStateStore> for SoloMachineStateStore {
    fn from(value: StableSoloMachineStateStore) -> Self {
        let client_state = RawSmClientState::decode(value.client_state.as_ref())
            .expect("parse sm client_state error")
            .try_into()
            .expect("parse sm client_state error");
        let mut consensus_state = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<u64, VecData, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(value.consensus_state_address)));

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let cs: SmConsensusState = RawSmConsensusState::decode(v.0.as_ref())
                        .expect("parse sm consenseus state error")
                        .try_into()
                        .expect("parse sm consenseus state error");

                    consensus_state.insert(k, cs);
                })
                .collect::<Vec<_>>();
        });

        SoloMachineStateStore {
            client_state,
            consensus_state,
        }
    }
}

const MAX_VALUES_SIZE: u32 = 2;
#[derive(CandidType, Deserialize)]
pub struct StableSoloMachineStateStores {
    solomachine_address: u8,
}

impl Storable for StableSoloMachineStateStores {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for StableSoloMachineStateStores {
    const MAX_SIZE: u32 = MAX_VALUES_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl From<SoloMachineStateStores> for StableSoloMachineStateStores {
    fn from(value: SoloMachineStateStores) -> Self {
        let mut sms = StableSoloMachineStateStores {
            solomachine_address: 0u8,
        };

        storage_manager::MEMORY_MANAGER.with(|instance| {
            let mut instance = instance.borrow_mut();
            let mut map: BTreeMap<StringData, StableSoloMachineStateStore, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            sms.solomachine_address = instance.1;
            instance.1 += 1;

            for (k, v) in value.solomachine {
                let client_id = StringData(k.as_str().to_string());
                map.insert(client_id, StableSoloMachineStateStore::from(v));
            }
        });

        sms
    }
}

impl From<StableSoloMachineStateStores> for SoloMachineStateStores {
    fn from(value: StableSoloMachineStateStores) -> Self {
        let mut solomachine = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<StringData, StableSoloMachineStateStore, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(value.solomachine_address)));

            let _ = map
                .iter()
                .map(|(k, v)| {
                    let client_id = ClientId::from_str(&k.0).expect("parse client id error");
                    let sss = SoloMachineStateStore::from(v);

                    solomachine.insert(client_id, sss);
                })
                .collect::<Vec<_>>();
        });

        SoloMachineStateStores { solomachine }
    }
}

#[derive(CandidType, Deserialize)]
pub struct StableSequenceAndTimeStore {
    sequence_time_address: u8,
}

impl Storable for StableSequenceAndTimeStore {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for StableSequenceAndTimeStore {
    const MAX_SIZE: u32 = MAX_VALUES_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl From<SequenceAndTimeStore> for StableSequenceAndTimeStore {
    fn from(value: SequenceAndTimeStore) -> Self {
        let mut sms = StableSequenceAndTimeStore {
            sequence_time_address: 0u8,
        };

        storage_manager::MEMORY_MANAGER.with(|instance| {
            let mut instance = instance.borrow_mut();
            let mut map: BTreeMap<u64, u64, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
            sms.sequence_time_address = instance.1;
            instance.1 += 1;

            for (k, v) in value.sequence_time {
                map.insert(k, v);
            }
        });

        sms
    }
}

impl From<StableSequenceAndTimeStore> for SequenceAndTimeStore {
    fn from(value: StableSequenceAndTimeStore) -> Self {
        let mut sequence_time = HashMap::new();
        storage_manager::MEMORY_MANAGER.with(|instance| {
            let instance = instance.borrow();
            let map: BTreeMap<u64, u64, _> =
                BTreeMap::init(instance.0.get(MemoryId::new(value.sequence_time_address)));

            let _ = map
                .iter()
                .map(|(k, v)| {
                    sequence_time.insert(k, v);
                })
                .collect::<Vec<_>>();
        });

        SequenceAndTimeStore { sequence_time }
    }
}
