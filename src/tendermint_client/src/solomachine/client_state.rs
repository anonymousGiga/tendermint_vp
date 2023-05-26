use super::consensus_state::ConsensusState;
use super::error::Error;
use super::SOLOMACHINE_CLIENT_STATE_TYPE_URL;
use crate::prelude::*;
use core::time::Duration;
use ibc::core::ics02_client::client_state::ClientState as Ics2ClientState;
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::error::ClientError as Ics02Error;
use ibc::core::ics23_commitment::commitment::CommitmentRoot;
use ibc::core::ics24_host::identifier::ChainId;
use ibc::Height;
// use cosmos_sdk_proto::{
//     self,
//     traits::{Message, MessageExt},
// };
use eyre::Result;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::solomachine::v1::ClientState as RawSmClientState;
use ibc_proto::ibc::lightclients::solomachine::v1::ConsensusState as RawSmConsesusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState {
    pub sequence: u64,
    pub is_frozen: bool,
    pub consensus_state: ConsensusState,
    pub allow_update_after_proposal: bool,
}

// impl Ics2ClientState for ClientState {
impl ClientState {
    pub fn chain_id(&self) -> ChainId {
        ChainId::new("ibc".to_string(), 1)
    }

    // fn client_type(&self) -> ClientType {
    //     ClientType::Solomachine
    // }

    pub fn latest_height(&self) -> Height {
        Height::new(0, self.sequence).unwrap()
    }

    pub fn frozen_height(&self) -> Option<Height> {
        if self.is_frozen {
            Some(Height::new(0, self.sequence).unwrap())
        } else {
            None
        }
    }

    // fn upgrade(
    //     &mut self,
    //     _upgrade_height: Height,
    //     _upgrade_options: &dyn CoreUpgradeOptions,
    //     _chain_id: ChainId,
    // ) {
    // }

    pub fn expired(&self, _elapsed: Duration) -> bool {
        false
    }
}

impl Protobuf<RawSmClientState> for ClientState {}

impl TryFrom<RawSmClientState> for ClientState {
    type Error = Error;

    fn try_from(raw: RawSmClientState) -> Result<Self, Self::Error> {
        let cs = raw.consensus_state.unwrap();
        let pk = cs.public_key.unwrap().try_into().unwrap();
        Ok(Self {
            sequence: raw.sequence,
            // is_frozen: value.is_frozen,
            is_frozen: (raw.frozen_sequence != 0),
            consensus_state: ConsensusState {
                public_key: pk,
                diversifier: cs.diversifier,
                timestamp: cs.timestamp,
                root: CommitmentRoot::from_bytes(&pk.to_bytes()),
            },
            allow_update_after_proposal: raw.allow_update_after_proposal,
        })
    }
}

impl From<ClientState> for RawSmClientState {
    fn from(value: ClientState) -> Self {
        let frozen_sequence = if value.is_frozen {
            value.sequence
        } else {
            0u64
        };
        Self {
            sequence: value.sequence,
            // is_frozen: value.is_frozen,
            frozen_sequence,
            consensus_state: Some(RawSmConsesusState {
                public_key: Some(value.consensus_state.public_key.into()),
                diversifier: value.consensus_state.diversifier,
                timestamp: value.consensus_state.timestamp,
            }),
            allow_update_after_proposal: value.allow_update_after_proposal,
        }
    }
}

impl Protobuf<Any> for ClientState {}

impl TryFrom<Any> for ClientState {
    type Error = Ics02Error;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_client_state<B: Buf>(buf: B) -> Result<ClientState, Error> {
            RawSmClientState::decode(buf)
                .map_err(Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            SOLOMACHINE_CLIENT_STATE_TYPE_URL => {
                decode_client_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::Other {
                description: raw.type_url,
            }),
        }
    }
}

impl From<ClientState> for Any {
    fn from(client_state: ClientState) -> Self {
        Any {
            type_url: SOLOMACHINE_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawSmClientState>::encode_vec(&client_state)
                .expect("encoding to `Any` from `SmClientState`"),
        }
    }
}
