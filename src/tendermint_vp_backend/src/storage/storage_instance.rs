use candid::{CandidType, Decode, Deserialize, Encode};
use ibc::core::ics02_client::consensus_state;
use ibc::Height;
use ic_cdk::export::Principal;
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{cell::Cell, BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable};
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

use tendermint_client::solomachine_store::{
    SequenceAndTimeStore, SoloMachineStateStore, SoloMachineStateStores,
};

use tendermint_client::solomachine_counter::SoloMachineCounter;

use super::chan_store::*;
use super::conn_store::*;
use super::msg_verifier::*;
use super::sm_stores::*;
use super::storage_manager;
use super::tendermint_client::*;
use super::utils::*;
use crate::TendermintInstance;

const MAX_VALUE_SIZE: u32 = 64;

#[derive(CandidType, Deserialize, Default)]
pub struct StableTendermintInstance {
    pub owner: Option<Principal>,
    // pub verifier: Option<StableMessageVerifier>,
    // pub solo_store: Option<StableSoloMachineStateStores>,
    // pub solo_counter: Option<u64>,
    pub sequence_times: Option<StableSequenceAndTimeStore>,
}

impl Storable for StableTendermintInstance {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for StableTendermintInstance {
    const MAX_SIZE: u32 = MAX_VALUE_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

impl From<TendermintInstance> for StableTendermintInstance {
    fn from(value: TendermintInstance) -> Self {
        // let verifier = value
        //     .verifier
        //     .and_then(|v| Some(StableMessageVerifier::from(v)));
        // let solo_store = value
        //     .solo_store
        //     .and_then(|v| Some(StableSoloMachineStateStores::from(v)));
        // let solo_counter = value.solo_counter.and_then(|v| Some(v.sequence_cnt()));
        let sequence_times = value
            .sequence_times
            .and_then(|v| Some(StableSequenceAndTimeStore::from(v)));

        let sti = StableTendermintInstance {
            owner: value.owner,
            // verifier,
            // solo_store,
            // solo_counter,
            sequence_times,
        };

        sti
    }
}

impl From<StableTendermintInstance> for TendermintInstance {
    fn from(value: StableTendermintInstance) -> Self {
        // let verifier = value.verifier.and_then(|v| Some(MessageVerifier::from(v)));
        // let solo_store = value
        //     .solo_store
        //     .and_then(|v| Some(SoloMachineStateStores::from(v)));
        // let solo_counter = value
        //     .solo_counter
        //     .and_then(|v| Some(SoloMachineCounter::new(v)));
        let sequence_times = value
            .sequence_times
            .and_then(|v| Some(SequenceAndTimeStore::from(v)));

        // TendermintInstance {
        //     owner: value.owner,
        //     verifier,
        //     solo_store,
        //     solo_counter,
        //     sequence_times,
        // }

        TendermintInstance {
            owner: value.owner,
            verifier: None,
            solo_store: None,
            solo_counter: None,
            // sequence_times: None,
            sequence_times,
        }
    }
}

pub fn presist(s: StableTendermintInstance) -> Result<(), String> {
    storage_manager::MEMORY_MANAGER.with(|instance| {
        let instance = instance.borrow();
        Cell::init(instance.0.get(MemoryId::new(instance.1)), s)
            .map_err(|_| "Get cell memory error!".to_string())
    })?;

    Ok(())
}

pub fn restore() -> Result<TendermintInstance, String> {
    let mut sti = storage_manager::MEMORY_MANAGER
        .with(|instance| {
            let instance = instance.borrow();
            Cell::init(
                instance.0.get(MemoryId::new(instance.1)),
                StableTendermintInstance::default(),
            )
        })
        .map_err(|_| "Get cell memory error!".to_string())?;
    let sti = sti
        .set(StableTendermintInstance::default())
        .map_err(|_| "Get cell data error!".to_string())?;

    Ok(TendermintInstance::from(sti))
}
