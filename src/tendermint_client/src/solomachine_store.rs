use crate::solomachine::client_state::{self, ClientState as SmClientState};
use crate::solomachine::consensus_state::{self, ConsensusState as SmConsensusState, PublicKey};
use ibc::core::ics24_host::identifier::ClientId;
// use crate::solomachine::datatype::DataType;
use crate::prelude::*;
use hashbrown::HashMap;

struct SoloMachineStateStore {
    client_state: SmClientState,
    consensus_state: HashMap<u64, SmConsensusState>,
}

pub struct SoloMachineStateStores {
    solomachine: HashMap<ClientId, SoloMachineStateStore>,
}

impl SoloMachineStateStores {
    pub fn new() -> Self {
        SoloMachineStateStores {
            solomachine: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        client_id: ClientId,
        sequence: u64,
        sm_client_state: SmClientState,
        sm_consensus_state: SmConsensusState,
    ) {
        if let Some(store) = self.solomachine.get_mut(&client_id) {
            store.client_state = sm_client_state;
            store.consensus_state.insert(sequence, sm_consensus_state);
        } else {
            let mut consensus_state = HashMap::new();
            consensus_state.insert(sequence, sm_consensus_state);

            let store = SoloMachineStateStore {
                client_state: sm_client_state,
                consensus_state,
            };

            self.solomachine.insert(client_id, store);
        }
    }

    pub fn get_client_state(&self, client_id: &ClientId) -> Result<SmClientState, String> {
        let solomachine = self
            .solomachine
            .get(client_id)
            .ok_or("No solo machine match".to_string())?;
        let cs = solomachine.client_state.clone();

        Ok(cs.clone())
    }

    pub fn get_consensus_state(
        &self,
        client_id: &ClientId,
        sequence: &u64,
    ) -> Result<SmConsensusState, String> {
        let solomachine = self
            .solomachine
            .get(client_id)
            .ok_or("No solo machine match".to_string())?;
        let cs = solomachine
            .consensus_state
            .get(sequence)
            .ok_or("No consensus state match this sequence".to_string())?;

        Ok(cs.clone())
    }
}

pub struct SequenceAndTimeStore {
    sequence_time: HashMap<u64, u64>,
}

impl SequenceAndTimeStore {
    pub fn new() -> Self {
        SequenceAndTimeStore {
            sequence_time: HashMap::new(),
        }
    }

    pub fn insert(&mut self, sequence: u64, time: u64) {
        ic_cdk::println!("insert (sequence: {:?}, time: {:?})", sequence, time);
        self.sequence_time.insert(sequence, time);
    }

    pub fn get_sequence_time(&self, sequence: u64) -> Result<u64, String> {
        self.sequence_time
            .get(&sequence)
            .map(|time| *time)
            .ok_or("Not found!".to_string())
    }
}
