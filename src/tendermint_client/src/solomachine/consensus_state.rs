use super::error::Error;
use super::SOLOMACHINE_CONSENSUS_STATE_TYPE_URL;
use crate::prelude::*;
use eyre::Result;
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics23_commitment::commitment::CommitmentRoot;
use ibc::timestamp::Timestamp;
use ibc_proto as proto;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::solomachine::v1::ConsensusState as RawConsensusState;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use serde::{Deserialize, Serialize};
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKey(pub tendermint::PublicKey);

impl PublicKey {
    /// Protobuf [`Any`] type URL for Ed25519 public keys
    pub const ED25519_TYPE_URL: &'static str = "/cosmos.crypto.ed25519.PubKey";

    /// Protobuf [`Any`] type URL for secp256k1 public keys
    pub const SECP256K1_TYPE_URL: &'static str = "/cosmos.crypto.secp256k1.PubKey";

    /// Get the type URL for this [`PublicKey`].
    pub fn type_url(&self) -> &'static str {
        match &self.0 {
            tendermint::PublicKey::Ed25519(_) => Self::ED25519_TYPE_URL,
            tendermint::PublicKey::Secp256k1(_) => Self::SECP256K1_TYPE_URL,
            // `tendermint::PublicKey` is `non_exhaustive`
            _ => unreachable!("unknown pubic key type"),
        }
    }

    /// Convert this [`PublicKey`] to a Protobuf [`Any`] type.
    pub fn to_any(&self) -> Result<Any> {
        let value = match self.0 {
            tendermint::PublicKey::Ed25519(_) => proto::cosmos::crypto::secp256k1::PubKey {
                key: self.to_bytes(),
            }
            .encode_to_vec(),
            tendermint::PublicKey::Secp256k1(_) => proto::cosmos::crypto::secp256k1::PubKey {
                key: self.to_bytes(),
            }
            .encode_to_vec(),
            _ => return Err(eyre::Report::from(Error::Other("Error".to_string()))),
        };

        Ok(Any {
            type_url: self.type_url().to_owned(),
            value,
        })
    }

    /// Serialize this [`PublicKey`] as a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl TryFrom<Any> for PublicKey {
    type Error = eyre::Report;

    fn try_from(any: Any) -> Result<PublicKey> {
        PublicKey::try_from(&any)
    }
}

impl TryFrom<&Any> for PublicKey {
    type Error = eyre::Report;

    fn try_from(any: &Any) -> Result<PublicKey> {
        let err = eyre::Report::from(Error::Other("Error".to_string()));
        match any.type_url.as_str() {
            Self::ED25519_TYPE_URL => proto::cosmos::crypto::ed25519::PubKey::decode(&*any.value)?
                .try_into()
                .map_err(|_| err),

            Self::SECP256K1_TYPE_URL => {
                proto::cosmos::crypto::secp256k1::PubKey::decode(&*any.value)?
                    .try_into()
                    .map_err(|_| err)
            }
            other => Err(err),
        }
    }
}

impl TryFrom<proto::cosmos::crypto::ed25519::PubKey> for PublicKey {
    type Error = eyre::Report;

    fn try_from(public_key: proto::cosmos::crypto::ed25519::PubKey) -> Result<PublicKey> {
        tendermint::public_key::PublicKey::from_raw_ed25519(&public_key.key)
            .map(Into::into)
            .ok_or_else(|| eyre::Report::from(Error::Other("Error".to_string())))
    }
}

impl TryFrom<proto::cosmos::crypto::secp256k1::PubKey> for PublicKey {
    type Error = eyre::Report;

    fn try_from(public_key: proto::cosmos::crypto::secp256k1::PubKey) -> Result<PublicKey> {
        tendermint::public_key::PublicKey::from_raw_secp256k1(&public_key.key)
            .map(Into::into)
            .ok_or_else(|| eyre::Report::from(Error::Other("Error".to_string())))
    }
}

impl From<PublicKey> for Any {
    fn from(public_key: PublicKey) -> Any {
        // This is largely a workaround for `tendermint::PublicKey` being
        // marked `non_exhaustive`.
        public_key.to_any().expect("unsupported algorithm")
    }
}

impl From<tendermint::PublicKey> for PublicKey {
    fn from(pk: tendermint::PublicKey) -> PublicKey {
        PublicKey(pk)
    }
}

impl From<PublicKey> for tendermint::PublicKey {
    fn from(pk: PublicKey) -> tendermint::PublicKey {
        pk.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusState {
    pub public_key: PublicKey,
    pub diversifier: String,
    pub timestamp: u64,
    pub root: CommitmentRoot,
}

impl ConsensusState {
    pub fn new(public_key: PublicKey, diversifier: String, timestamp: u64) -> Self {
        Self {
            public_key,
            diversifier,
            timestamp,
            root: CommitmentRoot::from_bytes(&public_key.to_bytes()),
        }
    }
}

// impl ibc::core::ics02_client::consensus_state::ConsensusState for ConsensusState {
//     fn root(&self) -> &CommitmentRoot {
//         &self.root
//     }

//     fn timestamp(&self) -> Timestamp {
//         Timestamp::from_nanoseconds(self.timestamp).unwrap()
//     }
// }

impl Protobuf<RawConsensusState> for ConsensusState {}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(raw: RawConsensusState) -> Result<Self, Self::Error> {
        let pk = raw.public_key.unwrap().try_into().unwrap();
        Ok(Self {
            public_key: pk,
            diversifier: raw.diversifier,
            timestamp: raw.timestamp,
            root: CommitmentRoot::from_bytes(&pk.to_bytes()),
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        RawConsensusState {
            public_key: Some(value.public_key.into()),
            diversifier: value.diversifier,
            timestamp: value.timestamp,
        }
    }
}

impl Protobuf<Any> for ConsensusState {}

impl TryFrom<Any> for ConsensusState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_consensus_state<B: Buf>(buf: B) -> Result<ConsensusState, Error> {
            RawConsensusState::decode(buf)
                .map_err(Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            SOLOMACHINE_CONSENSUS_STATE_TYPE_URL => {
                decode_consensus_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(ClientError::UnknownConsensusStateType {
                consensus_state_type: (raw.type_url),
            }),
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(consensus_state: ConsensusState) -> Self {
        Any {
            type_url: SOLOMACHINE_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawConsensusState>::encode_vec(&consensus_state)
                .expect("encoding to `Any` from `SmConsensusState`"),
        }
    }
}
