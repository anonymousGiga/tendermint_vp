use crate::prelude::*;
use crate::utils::IntoResult;
use core::convert::{TryFrom, TryInto};
use core::time::Duration;

use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::Height as RawHeight;
use ibc_proto::ibc::core::commitment::v1::{MerklePath, MerkleProof as RawMerkleProof};
use ibc_proto::ibc::lightclients::tendermint::v1::{
    ClientState as RawTmClientState, ConsensusState as RawTmConsensusState,
};
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use tendermint::chain::id::MAX_LENGTH as MaxChainIdLen;
use tendermint::chain::Id as TmChainId;
use tendermint::trust_threshold::TrustThresholdFraction as TendermintTrustThresholdFraction;
use tendermint_light_client_verifier::options::Options;
use tendermint_light_client_verifier::types::{TrustedBlockState, UntrustedBlockState};
use tendermint_light_client_verifier::{ProdVerifier, Verifier};

use ibc::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc::clients::ics07_tendermint::error::Error;
use ibc::clients::ics07_tendermint::header::{Header as TmHeader, Header};
use ibc::clients::ics07_tendermint::misbehaviour::Misbehaviour as TmMisbehaviour;
use ibc::core::ics02_client::client_state::{ClientState as Ics2ClientState, UpdatedState};
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::core::ics02_client::context::ClientReader;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics02_client::trust_threshold::TrustThreshold;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use ibc::core::ics04_channel::context::ChannelReader;
use ibc::core::ics04_channel::packet::Sequence;
use ibc::core::ics23_commitment::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use ibc::core::ics23_commitment::merkle::{apply_prefix, MerkleProof};
use ibc::core::ics23_commitment::specs::ProofSpecs;
use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc::core::ics24_host::path::{
    AcksPath, ChannelEndsPath, ClientConsensusStatePath, ClientStatePath, ClientUpgradePath,
    CommitmentsPath, ConnectionsPath, ReceiptsPath, SeqRecvsPath,
};
use ibc::core::ics24_host::Path;
use ibc::timestamp::{Timestamp, ZERO_DURATION};
use ibc::Height;

pub const TENDERMINT_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.tendermint.v1.ClientState";

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientState {
    pub chain_id: ChainId,
    pub trust_level: TrustThreshold,
    pub trusting_period: Duration,
    pub unbonding_period: Duration,
    pub max_clock_drift: Duration,
    pub latest_height: Height,
    pub proof_specs: ProofSpecs,
    pub upgrade_path: Vec<String>,
    pub allow_update: AllowUpdate,
    pub frozen_height: Option<Height>,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub verifier: ProdVerifier,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AllowUpdate {
    pub after_expiry: bool,
    pub after_misbehaviour: bool,
}

impl ClientState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        trust_level: TrustThreshold,
        trusting_period: Duration,
        unbonding_period: Duration,
        max_clock_drift: Duration,
        latest_height: Height,
        proof_specs: ProofSpecs,
        upgrade_path: Vec<String>,
        allow_update: AllowUpdate,
        frozen_height: Option<Height>,
    ) -> Result<ClientState, Error> {
        if chain_id.as_str().len() > MaxChainIdLen {
            return Err(Error::ChainIdTooLong {
                chain_id: chain_id.clone(),
                len: chain_id.as_str().len(),
                max_len: MaxChainIdLen,
            });
        }

        // `TrustThreshold` is guaranteed to be in the range `[0, 1)`, but a `TrustThreshold::ZERO`
        // value is invalid in this context
        if trust_level == TrustThreshold::ZERO {
            return Err(Error::InvalidTrustThreshold {
                reason: "ClientState trust-level cannot be zero".to_string(),
            });
        }

        let _ = TendermintTrustThresholdFraction::new(
            trust_level.numerator(),
            trust_level.denominator(),
        )
        .map_err(Error::InvalidTendermintTrustThreshold)?;

        // Basic validation of trusting period and unbonding period: each should be non-zero.
        if trusting_period <= Duration::new(0, 0) {
            return Err(Error::InvalidTrustThreshold {
                reason: format!(
                    "ClientState trusting period ({trusting_period:?}) must be greater than zero"
                ),
            });
        }

        if unbonding_period <= Duration::new(0, 0) {
            return Err(Error::InvalidTrustThreshold {
                reason: format!(
                    "ClientState unbonding period ({unbonding_period:?}) must be greater than zero"
                ),
            });
        }

        if trusting_period >= unbonding_period {
            return Err(Error::InvalidTrustThreshold {
                reason: format!(
                "ClientState trusting period ({trusting_period:?}) must be smaller than unbonding period ({unbonding_period:?})"
            ),
            });
        }

        if max_clock_drift <= Duration::new(0, 0) {
            return Err(Error::InvalidMaxClockDrift {
                reason: "ClientState max-clock-drift must be greater than zero".to_string(),
            });
        }

        if latest_height.revision_number() != chain_id.version() {
            return Err(Error::InvalidLatestHeight {
                reason: "ClientState latest-height revision number must match chain-id version"
                    .to_string(),
            });
        }

        // Disallow empty proof-specs
        if proof_specs.is_empty() {
            return Err(Error::Validation {
                reason: "ClientState proof-specs cannot be empty".to_string(),
            });
        }

        // `upgrade_path` itself may be empty, but if not then each key must be non-empty
        for (idx, key) in upgrade_path.iter().enumerate() {
            if key.trim().is_empty() {
                return Err(Error::Validation {
                    reason: format!(
                        "ClientState upgrade-path key at index {idx:?} cannot be empty"
                    ),
                });
            }
        }

        Ok(Self {
            chain_id,
            trust_level,
            trusting_period,
            unbonding_period,
            max_clock_drift,
            latest_height,
            proof_specs,
            upgrade_path,
            allow_update,
            frozen_height,
            verifier: ProdVerifier::default(),
        })
    }

    pub fn with_header(self, h: TmHeader) -> Result<Self, Error> {
        Ok(ClientState {
            latest_height: Height::new(
                self.latest_height.revision_number(),
                h.signed_header.header.height.into(),
            )
            .map_err(|_| Error::InvalidHeaderHeight {
                height: h.signed_header.header.height.value(),
            })?,
            ..self
        })
    }

    pub fn with_frozen_height(self, h: Height) -> Self {
        Self {
            frozen_height: Some(h),
            ..self
        }
    }

    /// Get the refresh time to ensure the state does not expire
    pub fn refresh_time(&self) -> Option<Duration> {
        Some(2 * self.trusting_period / 3)
    }

    /// Helper method to produce a [`Options`] struct for use in
    /// Tendermint-specific light client verification.
    pub fn as_light_client_options(&self) -> Result<Options, Error> {
        Ok(Options {
            trust_threshold: self.trust_level.try_into().map_err(|e: ClientError| {
                Error::InvalidTrustThreshold {
                    reason: e.to_string(),
                }
            })?,
            trusting_period: self.trusting_period,
            clock_drift: self.max_clock_drift,
        })
    }

    /// Verify the time and height delays
    pub fn verify_delay_passed(
        current_time: Timestamp,
        current_height: Height,
        processed_time: Timestamp,
        processed_height: Height,
        delay_period_time: Duration,
        delay_period_blocks: u64,
    ) -> Result<(), Error> {
        let earliest_time =
            (processed_time + delay_period_time).map_err(Error::TimestampOverflow)?;
        if !(current_time == earliest_time || current_time.after(&earliest_time)) {
            return Err(Error::NotEnoughTimeElapsed {
                current_time,
                earliest_time,
            });
        }

        let earliest_height = processed_height.add(delay_period_blocks);
        if current_height < earliest_height {
            return Err(Error::NotEnoughBlocksElapsed {
                current_height,
                earliest_height,
            });
        }

        Ok(())
    }

    /// Verify that the client is at a sufficient height and unfrozen at the given height
    pub fn verify_height(&self, height: Height) -> Result<(), Error> {
        if self.latest_height < height {
            return Err(Error::InsufficientHeight {
                latest_height: self.latest_height,
                target_height: height,
            });
        }

        match self.frozen_height {
            Some(frozen_height) if frozen_height <= height => Err(Error::ClientFrozen {
                frozen_height,
                target_height: height,
            }),
            _ => Ok(()),
        }
    }

    fn check_header_validator_set(
        trusted_consensus_state: &TmConsensusState,
        header: &Header,
    ) -> Result<(), ClientError> {
        let trusted_val_hash = header.trusted_validator_set.hash();

        if trusted_consensus_state.next_validators_hash != trusted_val_hash {
            return Err(Error::MisbehaviourTrustedValidatorHashMismatch {
                trusted_validator_set: header.trusted_validator_set.validators().clone(),
                next_validators_hash: trusted_consensus_state.next_validators_hash,
                trusted_val_hash,
            }
            .into());
        }

        Ok(())
    }

    pub fn check_header_and_validator_set(
        &self,
        header: &Header,
        consensus_state: &TmConsensusState,
        current_timestamp: Timestamp,
    ) -> Result<(), ClientError> {
        Self::check_header_validator_set(consensus_state, header)?;

        let duration_since_consensus_state = current_timestamp
            .duration_since(&consensus_state.timestamp())
            .ok_or_else(|| ClientError::InvalidConsensusStateTimestamp {
                time1: consensus_state.timestamp(),
                time2: current_timestamp,
            })?;

        if duration_since_consensus_state >= self.trusting_period {
            return Err(Error::ConsensusStateTimestampGteTrustingPeriod {
                duration_since_consensus_state,
                trusting_period: self.trusting_period,
            }
            .into());
        }

        let untrusted_state = header_as_untrusted_block_state(&header);
        let chain_id = self.chain_id.clone().into();
        let trusted_state = header_as_trusted_block_state(&header, consensus_state, &chain_id)?;
        let options = self.as_light_client_options()?;

        self.verifier
            .validate_against_trusted(
                &untrusted_state,
                &trusted_state,
                &options,
                current_timestamp.into_tm_time().unwrap(),
            )
            .into_result()?;

        Ok(())
    }

    pub fn verify_header_commit_against_trusted(
        &self,
        header: &Header,
        consensus_state: &TmConsensusState,
    ) -> Result<(), ClientError> {
        let untrusted_state = header_as_untrusted_block_state(header);
        let chain_id = self.chain_id.clone().into();
        let trusted_state = header_as_trusted_block_state(header, consensus_state, &chain_id)?;
        let options = self.as_light_client_options()?;

        self.verifier
            .verify_commit_against_trusted(&untrusted_state, &trusted_state, &options)
            .into_result()?;

        Ok(())
    }

    pub fn verify_connection_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        connection_id: &ConnectionId,
        expected_connection_end: &ConnectionEnd,
    ) -> Result<(), ClientError> {
        self.verify_height(height)?;

        let path = ConnectionsPath(connection_id.clone());
        let value = expected_connection_end
            .encode_vec()
            .map_err(ClientError::InvalidConnectionEnd)?;
        verify_membership(self, prefix, proof, root, path, value)
    }

    pub fn verify_client_full_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        client_id: &ClientId,
        expected_client_state: Any,
    ) -> Result<(), ClientError> {
        self.verify_height(height)?;

        let path = ClientStatePath(client_id.clone());
        let value = expected_client_state.encode_to_vec();
        verify_membership(self, prefix, proof, root, path, value)
    }

    pub fn verify_client_consensus_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        client_id: &ClientId,
        consensus_height: Height,
        expected_consensus_state: &dyn ConsensusState,
    ) -> Result<(), ClientError> {
        self.verify_height(height)?;

        let path = ClientConsensusStatePath {
            client_id: client_id.clone(),
            epoch: consensus_height.revision_number(),
            height: consensus_height.revision_height(),
        };
        let value = expected_consensus_state
            .encode_vec()
            .map_err(ClientError::InvalidAnyConsensusState)?;

        verify_membership(self, prefix, proof, root, path, value)
    }
}

impl ClientState {
    pub fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    // fn client_type(&self) -> ClientType {
    //     tm_client_type()
    // }

    // pub fn latest_height(&self) -> Height {
    //     self.latest_height
    // }

    // pub fn frozen_height(&self) -> Option<Height> {
    //     self.frozen_height
    // }

    pub fn zero_custom_fields(&mut self) {
        // Reset custom fields to zero values
        self.trusting_period = ZERO_DURATION;
        self.trust_level = TrustThreshold::ZERO;
        self.allow_update.after_expiry = false;
        self.allow_update.after_misbehaviour = false;
        self.frozen_height = None;
        self.max_clock_drift = ZERO_DURATION;
    }
}

fn header_as_untrusted_block_state(h: &Header) -> UntrustedBlockState<'_> {
    UntrustedBlockState {
        signed_header: &h.signed_header,
        validators: &h.validator_set,
        next_validators: None,
    }
}

fn header_as_trusted_block_state<'a>(
    h: &'a Header,
    consensus_state: &TmConsensusState,
    chain_id: &'a TmChainId,
) -> Result<TrustedBlockState<'a>, Error> {
    Ok(TrustedBlockState {
        chain_id,
        header_time: consensus_state.timestamp,
        height: h.trusted_height.revision_height().try_into().map_err(|_| {
            Error::InvalidHeaderHeight {
                height: h.trusted_height.revision_height(),
            }
        })?,
        next_validators: &h.trusted_validator_set,
        next_validators_hash: consensus_state.next_validators_hash,
    })
}

fn verify_membership(
    client_state: &ClientState,
    prefix: &CommitmentPrefix,
    proof: &CommitmentProofBytes,
    root: &CommitmentRoot,
    path: impl Into<Path>,
    value: Vec<u8>,
) -> Result<(), ClientError> {
    let merkle_path = apply_prefix(prefix, vec![path.into().to_string()]);
    let merkle_proof: MerkleProof = RawMerkleProof::try_from(proof.clone())
        .map_err(ClientError::InvalidCommitmentProof)?
        .into();

    merkle_proof
        .verify_membership(
            &client_state.proof_specs,
            root.clone().into(),
            merkle_path,
            value,
            0,
        )
        .map_err(ClientError::Ics23Verification)
}

fn verify_non_membership(
    client_state: &ClientState,
    prefix: &CommitmentPrefix,
    proof: &CommitmentProofBytes,
    root: &CommitmentRoot,
    path: impl Into<Path>,
) -> Result<(), ClientError> {
    let merkle_path = apply_prefix(prefix, vec![path.into().to_string()]);
    let merkle_proof: MerkleProof = RawMerkleProof::try_from(proof.clone())
        .map_err(ClientError::InvalidCommitmentProof)?
        .into();

    merkle_proof
        .verify_non_membership(&client_state.proof_specs, root.clone().into(), merkle_path)
        .map_err(ClientError::Ics23Verification)
}

impl Protobuf<RawTmClientState> for ClientState {}

impl TryFrom<RawTmClientState> for ClientState {
    type Error = Error;

    fn try_from(raw: RawTmClientState) -> Result<Self, Self::Error> {
        let chain_id = ChainId::from_string(raw.chain_id.as_str());

        let trust_level = {
            let trust_level = raw
                .trust_level
                .clone()
                .ok_or(Error::MissingTrustingPeriod)?;
            trust_level
                .try_into()
                .map_err(|e| Error::InvalidTrustThreshold {
                    reason: format!("{e}"),
                })?
        };

        let trusting_period = raw
            .trusting_period
            .ok_or(Error::MissingTrustingPeriod)?
            .try_into()
            .map_err(|_| Error::MissingTrustingPeriod)?;

        let unbonding_period = raw
            .unbonding_period
            .ok_or(Error::MissingUnbondingPeriod)?
            .try_into()
            .map_err(|_| Error::MissingUnbondingPeriod)?;

        let max_clock_drift = raw
            .max_clock_drift
            .ok_or(Error::NegativeMaxClockDrift)?
            .try_into()
            .map_err(|_| Error::NegativeMaxClockDrift)?;

        let latest_height = raw
            .latest_height
            .ok_or(Error::MissingLatestHeight)?
            .try_into()
            .map_err(|_| Error::MissingLatestHeight)?;

        // In `RawClientState`, a `frozen_height` of `0` means "not frozen".
        // See:
        // https://github.com/cosmos/ibc-go/blob/8422d0c4c35ef970539466c5bdec1cd27369bab3/modules/light-clients/07-tendermint/types/client_state.go#L74
        let frozen_height = raw
            .frozen_height
            .and_then(|raw_height| raw_height.try_into().ok());

        // We use set this deprecated field just so that we can properly convert
        // it back in its raw form
        #[allow(deprecated)]
        let allow_update = AllowUpdate {
            after_expiry: raw.allow_update_after_expiry,
            after_misbehaviour: raw.allow_update_after_misbehaviour,
        };

        let client_state = ClientState::new(
            chain_id,
            trust_level,
            trusting_period,
            unbonding_period,
            max_clock_drift,
            latest_height,
            raw.proof_specs.into(),
            raw.upgrade_path,
            allow_update,
            frozen_height,
        )?;

        Ok(client_state)
    }
}

impl From<ClientState> for RawTmClientState {
    fn from(value: ClientState) -> Self {
        #[allow(deprecated)]
        Self {
            chain_id: value.chain_id.to_string(),
            trust_level: Some(value.trust_level.into()),
            trusting_period: Some(value.trusting_period.into()),
            unbonding_period: Some(value.unbonding_period.into()),
            max_clock_drift: Some(value.max_clock_drift.into()),
            frozen_height: Some(value.frozen_height.map(|height| height.into()).unwrap_or(
                RawHeight {
                    revision_number: 0,
                    revision_height: 0,
                },
            )),
            latest_height: Some(value.latest_height.into()),
            proof_specs: value.proof_specs.into(),
            upgrade_path: value.upgrade_path,
            allow_update_after_expiry: value.allow_update.after_expiry,
            allow_update_after_misbehaviour: value.allow_update.after_misbehaviour,
        }
    }
}

impl Protobuf<Any> for ClientState {}

impl TryFrom<Any> for ClientState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_client_state<B: Buf>(buf: B) -> Result<ClientState, Error> {
            RawTmClientState::decode(buf)
                .map_err(Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            TENDERMINT_CLIENT_STATE_TYPE_URL => {
                decode_client_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(ClientError::UnknownClientStateType {
                client_state_type: raw.type_url,
            }),
        }
    }
}

impl From<ClientState> for Any {
    fn from(client_state: ClientState) -> Self {
        Any {
            type_url: TENDERMINT_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawTmClientState>::encode_vec(&client_state)
                .expect("encoding to `Any` from `TmClientState`"),
        }
    }
}
