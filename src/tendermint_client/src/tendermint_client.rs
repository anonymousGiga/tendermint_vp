use crate::prelude::*;

// use tendermint_light_client_verifier::types::{TrustedBlockState, UntrustedBlockState};

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
use tendermint::trust_threshold::TrustThresholdFraction as TendermintTrustThresholdFraction;
use tendermint_light_client_verifier::options::Options;
use tendermint_light_client_verifier::types::{TrustedBlockState, UntrustedBlockState};
pub use tendermint_light_client_verifier::{types::Time, ProdVerifier, Verdict, Verifier};

pub use ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
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
pub use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc::core::ics24_host::path::{
    AcksPath, ChannelEndsPath, ClientConsensusStatePath, ClientStatePath, ClientUpgradePath,
    CommitmentsPath, ConnectionsPath, ReceiptsPath, SeqRecvsPath,
};
use ibc::core::ics24_host::Path;
use ibc::timestamp::{Timestamp, ZERO_DURATION};
use ibc::Height;

pub use crate::tm_client_state::ClientState as TmClientState;
use crate::utils::IntoResult;
pub use hashbrown::HashMap;

// pub(crate) const TENDERMINT_CLIENT_TYPE: &str = "tendermint-vp-client";
// pub(crate) const TENDERMINT_CLIENT_TYPE: &str = "06-solomachine";
pub(crate) const TENDERMINT_CLIENT_TYPE: &str = "07-tendermint";

pub fn client_type() -> ClientType {
    ClientType::new(TENDERMINT_CLIENT_TYPE.to_string())
}

pub struct TendermintClient {
    pub client_id: ClientId,
    pub consensus_states: HashMap<Height, TmConsensusState>,
    pub client_state: TmClientState,
    // latest_height: Height,
    // frozen_height: Option<Height>,

    // max_clock_drift: Duration,
    // allow_update: AllowUpdate,
    // verifier: ProdVerifier,
}

impl TendermintClient {
    // MsgCreateClient
    pub fn new(
        client_id: ClientId,
        consensus_state: TmConsensusState,
        client_state: TmClientState,
        // max_clock_drift: Duration,
        // allow_update: AllowUpdate,
    ) -> Self {
        let mut consensus_states: HashMap<Height, TmConsensusState> = HashMap::new();

        consensus_states.insert(client_state.latest_height, consensus_state);
        ic_cdk::println!("insert: {:?} ", client_state.latest_height);
        ic_cdk::println!("new chain_id: ====== {:?}", client_state.chain_id());

        // let latest_height = client_state.latest_height;
        // let frozen_height = client_state.frozen_height;
        TendermintClient {
            client_id,
            consensus_states,
            client_state,
            // latest_height,
            // frozen_height,
            // verifier: ProdVerifier::default(),
        }
    }

    // MsgUpdateClient
    pub fn check_header_and_update_state(
        &mut self,
        header: Any,
        now: Time,
    ) -> Result<TmConsensusState, ClientError> {
        let header = Header::try_from(header)?;
        ic_cdk::println!("1 +++++++++++++++++ ");
        ic_cdk::println!("header.signed_header ====== {:?}", header.signed_header);
        ic_cdk::println!("header.validator ====== {:?}", header.validator_set);
        ic_cdk::println!("header.trusted_height ====== {:?}", header.trusted_height);
        ic_cdk::println!(
            "header.trusted_validator_set ====== {:?}",
            header.trusted_validator_set
        );

        // ic_cdk::println!("header  ====== {:?}", header);

        if header.height().revision_number() != self.client_state.chain_id().version() {
            return Err(ClientError::ClientSpecific {
                description: Error::MismatchedRevisions {
                    current_revision: self.client_state.chain_id().version(),
                    update_revision: header.height().revision_number(),
                }
                .to_string(),
            });
        }
        ic_cdk::println!("2 +++++++++++++++++ ");

        let header_consensus_state = TmConsensusState::from(header.clone());
        if let Some(cs) = self.consensus_states.get(&header.height()) {
            if *cs == header_consensus_state {
                // Header is already installed and matches the incoming
                // header (already verified)
                return Ok(header_consensus_state.clone());
            }
        }
        ic_cdk::println!("3 +++++++++++++++++ ");

        let trusted_consensus_state = self.consensus_states.get(&header.trusted_height).ok_or(
            ClientError::ConsensusStateNotFound {
                client_id: self.client_id.clone(),
                height: header.trusted_height,
            },
        )?;
        ic_cdk::println!("4 +++++++++++++++++ ");

        let trusted_state = TrustedBlockState {
            chain_id: &self.client_state.chain_id.clone().into(),
            header_time: trusted_consensus_state.timestamp,
            height: header
                .trusted_height
                .revision_height()
                .try_into()
                .map_err(|_| ClientError::ClientSpecific {
                    description: Error::InvalidHeaderHeight {
                        height: header.trusted_height.revision_height(),
                    }
                    .to_string(),
                })?,
            next_validators: &header.trusted_validator_set,
            next_validators_hash: trusted_consensus_state.next_validators_hash,
        };
        ic_cdk::println!("chain id: {:?}", self.client_state.chain_id);
        ic_cdk::println!("5 +++++++++++++++++ ");

        let untrusted_state = UntrustedBlockState {
            signed_header: &header.signed_header,
            validators: &header.validator_set,
            // NB: This will skip the
            // VerificationPredicates::next_validators_match check for the
            // untrusted state.
            next_validators: None,
        };
        ic_cdk::println!("6 +++++++++++++++++ ");

        let options = self.client_state.as_light_client_options()?;
        ic_cdk::println!("7 +++++++++++++++++ ");

        // -----------for test---------------
        use core::str::FromStr;
        // let now = Time::from_str("2023-06-01T02:15:51.562920032Z").unwrap();
        let now = header.signed_header.header.time;
        // ----------------------------------

        // let r = self.client_state
        self.client_state
            .verifier
            .verify(untrusted_state, trusted_state, &options, now)
            .into_result()?;
        // .into_result();
        // if let Err(e) = r {
        //     ic_cdk::println!("error: {:?}", e);
        // }
        ic_cdk::println!("8 +++++++++++++++++ ");

        // If the header has verified, but its corresponding consensus state
        // differs from the existing consensus state for that height, should freeze and report.
        if let Some(cs) = self.consensus_states.get(&header.height()) {
            if *cs != header_consensus_state {
                // self.frozen_height = Some(header.height());
                self.client_state = self
                    .client_state
                    .clone()
                    .with_frozen_height(header.height());

                return Err(ClientError::Other {
                    description: "May be a misbehaviour".to_string(),
                });
            }
        }
        ic_cdk::println!("9 +++++++++++++++++ ");

        // Monotonicity checks for timestamps for in-the-middle updates
        // (cs-new, cs-next, cs-latest)
        if header.height() < self.client_state.latest_height {
            let maybe_next_cs = self.next_consensus_state(&header.height())?;

            if let Some(next_cs) = maybe_next_cs {
                // New (untrusted) header timestamp cannot occur after next
                // consensus state's height
                if header.signed_header.header().time > next_cs.timestamp {
                    return Err(ClientError::ClientSpecific {
                        description: Error::HeaderTimestampTooHigh {
                            actual: header.signed_header.header().time.to_string(),
                            max: next_cs.timestamp.to_string(),
                        }
                        .to_string(),
                    });
                }
            }
        }
        ic_cdk::println!("10 +++++++++++++++++ ");

        // (cs-trusted, cs-prev, cs-new)
        if header.trusted_height < header.height() {
            let maybe_prev_cs = self.prev_consensus_state(&header.height())?;

            if let Some(prev_cs) = maybe_prev_cs {
                // New (untrusted) header timestamp cannot occur before the
                // previous consensus state's height
                if header.signed_header.header().time < prev_cs.timestamp {
                    return Err(ClientError::ClientSpecific {
                        description: Error::HeaderTimestampTooLow {
                            actual: header.signed_header.header().time.to_string(),
                            min: prev_cs.timestamp.to_string(),
                        }
                        .to_string(),
                    });
                }
            }
        }
        ic_cdk::println!("11 +++++++++++++++++ ");

        // update client state and consensus state
        let height = header.height();
        self.client_state = self.client_state.clone().with_header(header.clone())?;
        // self.latest_height = height;
        let cs = TmConsensusState::from(header);
        self.consensus_states.insert(height, cs.clone());
        ic_cdk::println!("insert consensus_states, hegiht: {:?}", height);

        Ok(cs)
    }

    // MsgSubmitMisbehaviour
    pub fn check_misbehaviour_and_update_state(
        &mut self,
        misbehaviour: Any,
        now: Timestamp,
    ) -> Result<(), ClientError> {
        let misbehaviour = TmMisbehaviour::try_from(misbehaviour)?;
        let header_1 = misbehaviour.header1();
        let header_2 = misbehaviour.header2();

        if header_1.height() == header_2.height() {
            // Fork
            if header_1.signed_header.commit.block_id.hash
                == header_2.signed_header.commit.block_id.hash
            {
                return Err(Error::MisbehaviourHeadersBlockHashesEqual.into());
            }
        } else {
            // BFT time violation
            if header_1.signed_header.header.time > header_2.signed_header.header.time {
                return Err(Error::MisbehaviourHeadersNotAtSameHeight.into());
            }
        }

        let consensus_state_1 = self.consensus_states.get(&header_1.trusted_height).ok_or(
            ClientError::ConsensusStateNotFound {
                client_id: self.client_id.clone(),
                height: header_1.trusted_height,
            },
        )?;

        let consensus_state_2 = self.consensus_states.get(&header_2.trusted_height).ok_or(
            ClientError::ConsensusStateNotFound {
                client_id: self.client_id.clone(),
                height: header_2.trusted_height,
            },
        )?;

        let chain_id = self
            .client_state
            .chain_id
            .clone()
            .with_version(header_1.height().revision_number());
        if !misbehaviour.chain_id_matches(&chain_id) {
            return Err(Error::MisbehaviourHeadersChainIdMismatch {
                header_chain_id: header_1.signed_header.header.chain_id.to_string(),
                chain_id: self.client_state.chain_id.to_string(),
            }
            .into());
        }

        self.client_state
            .check_header_and_validator_set(header_1, &consensus_state_1, now)?;
        self.client_state
            .check_header_and_validator_set(header_2, &consensus_state_2, now)?;

        self.client_state
            .verify_header_commit_against_trusted(header_1, &consensus_state_1)?;
        self.client_state
            .verify_header_commit_against_trusted(header_2, &consensus_state_2)?;

        // Update client state
        // self.frozen_height = Some(Height::new(0, 1).unwrap());
        self.client_state = self
            .client_state
            .clone()
            .with_frozen_height(Height::new(0, 1).unwrap());

        Ok(())
    }

    // MsgUpgradeClient
    pub fn check_upgrade_client_and_update_state(
        &mut self,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
        proof_upgrade_client: RawMerkleProof,
        proof_upgrade_consensus_state: RawMerkleProof,
        root: &CommitmentRoot,
    ) -> Result<(), ClientError> {
        self.verify_upgrade_client(
            upgraded_client_state.clone(),
            upgraded_consensus_state.clone(),
            proof_upgrade_client,
            proof_upgrade_consensus_state,
            root,
        )?;
        self.update_state_with_upgrade_client(upgraded_client_state, upgraded_consensus_state)?;
        Ok(())
    }
}

impl TendermintClient {
    fn next_consensus_state(
        &self,
        height: &Height,
    ) -> Result<Option<TmConsensusState>, ClientError> {
        let mut heights: Vec<Height> = self.consensus_states.keys().cloned().collect();
        heights.sort();

        // Search for next state.
        for h in heights {
            if h > *height {
                // unwrap should never happen, as the consensus state for h must exist
                return Ok(Some(
                    self.consensus_states
                        .get(&h)
                        .expect("Shoud not happen")
                        .clone(),
                ));
            }
        }
        Ok(None)
    }

    fn prev_consensus_state(
        &self,
        height: &Height,
    ) -> Result<Option<TmConsensusState>, ClientError> {
        // Get the consensus state heights and sort them in descending order.
        let mut heights: Vec<Height> = self.consensus_states.keys().cloned().collect();
        heights.sort_by(|a, b| b.cmp(a));

        // Search for previous state.
        for h in heights {
            if h < *height {
                // unwrap should never happen, as the consensus state for h must exist
                return Ok(Some(
                    self.consensus_states
                        .get(&h)
                        .expect("Should not happen")
                        .clone(),
                ));
            }
        }
        Ok(None)
    }

    fn verify_upgrade_client(
        &self,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
        proof_upgrade_client: RawMerkleProof,
        proof_upgrade_consensus_state: RawMerkleProof,
        root: &CommitmentRoot,
    ) -> Result<(), ClientError> {
        // Make sure that the client type is of Tendermint type `ClientState`
        let mut upgraded_tm_client_state = TmClientState::try_from(upgraded_client_state)?;

        // Make sure that the consensus type is of Tendermint type `ConsensusState`
        let upgraded_tm_cons_state = TmConsensusState::try_from(upgraded_consensus_state)?;

        // Note: verification of proofs that unmarshalled correctly has been done
        // while decoding the proto message into a `MsgEnvelope` domain type
        let merkle_proof_upgrade_client = MerkleProof::from(proof_upgrade_client);
        let merkle_proof_upgrade_cons_state = MerkleProof::from(proof_upgrade_consensus_state);

        // Make sure the latest height of the current client is not greater then
        // the upgrade height This condition checks both the revision number and
        // the height
        if self.client_state.latest_height >= upgraded_tm_client_state.latest_height {
            return Err(ClientError::LowUpgradeHeight {
                upgraded_height: self.client_state.latest_height,
                client_height: upgraded_tm_client_state.latest_height,
            });
        }

        // Check to see if the upgrade path is set
        let mut upgrade_path = self.client_state.upgrade_path.clone();
        if upgrade_path.pop().is_none() {
            return Err(ClientError::ClientSpecific {
                description: "cannot upgrade client as no upgrade path has been set".to_string(),
            });
        };

        let last_height = self.client_state.latest_height.revision_height();

        // Construct the merkle path for the client state
        let mut client_upgrade_path = upgrade_path.clone();
        client_upgrade_path.push(ClientUpgradePath::UpgradedClientState(last_height).to_string());

        let client_upgrade_merkle_path = MerklePath {
            key_path: client_upgrade_path,
        };

        upgraded_tm_client_state.zero_custom_fields();
        let client_state_value =
            Protobuf::<RawTmClientState>::encode_vec(&upgraded_tm_client_state)
                .map_err(ClientError::Encode)?;

        // Verify the proof of the upgraded client state
        merkle_proof_upgrade_client
            .verify_membership(
                &self.client_state.proof_specs,
                root.clone().into(),
                client_upgrade_merkle_path,
                client_state_value,
                0,
            )
            .map_err(ClientError::Ics23Verification)?;

        // Construct the merkle path for the consensus state
        let mut cons_upgrade_path = upgrade_path;
        cons_upgrade_path
            .push(ClientUpgradePath::UpgradedClientConsensusState(last_height).to_string());
        let cons_upgrade_merkle_path = MerklePath {
            key_path: cons_upgrade_path,
        };

        let cons_state_value = Protobuf::<RawTmConsensusState>::encode_vec(&upgraded_tm_cons_state)
            .map_err(ClientError::Encode)?;

        // Verify the proof of the upgraded consensus state
        merkle_proof_upgrade_cons_state
            .verify_membership(
                &self.client_state.proof_specs,
                root.clone().into(),
                cons_upgrade_merkle_path,
                cons_state_value,
                0,
            )
            .map_err(ClientError::Ics23Verification)?;

        Ok(())
    }

    fn update_state_with_upgrade_client(
        &mut self,
        upgraded_client_state: Any,
        upgraded_consensus_state: Any,
    ) -> Result<(), ClientError> {
        let upgraded_tm_client_state = TmClientState::try_from(upgraded_client_state)?;
        let upgraded_tm_cons_state = TmConsensusState::try_from(upgraded_consensus_state)?;

        // Frozen height is set to None fo the new client state
        let new_frozen_height = None;

        // Construct new client state and consensus state relayer chosen client
        // parameters are ignored. All chain-chosen parameters come from
        // committed client, all client-chosen parameters come from current
        // client.
        let new_client_state = TmClientState::new(
            upgraded_tm_client_state.chain_id,
            self.client_state.trust_level,
            self.client_state.trusting_period,
            upgraded_tm_client_state.unbonding_period,
            self.client_state.max_clock_drift,
            upgraded_tm_client_state.latest_height,
            upgraded_tm_client_state.proof_specs,
            upgraded_tm_client_state.upgrade_path,
            self.client_state.allow_update,
            new_frozen_height,
        )?;

        // The new consensus state is merely used as a trusted kernel against
        // which headers on the new chain can be verified. The root is just a
        // stand-in sentinel value as it cannot be known in advance, thus no
        // proof verification will pass. The timestamp and the
        // NextValidatorsHash of the consensus state is the blocktime and
        // NextValidatorsHash of the last block committed by the old chain. This
        // will allow the first block of the new chain to be verified against
        // the last validators of the old chain so long as it is submitted
        // within the TrustingPeriod of this client.
        // NOTE: We do not set processed time for this consensus state since
        // this consensus state should not be used for packet verification as
        // the root is empty. The next consensus state submitted using update
        // will be usable for packet-verification.
        let sentinel_root = "sentinel_root".as_bytes().to_vec();
        let new_consensus_state = TmConsensusState::new(
            sentinel_root.into(),
            upgraded_tm_cons_state.timestamp,
            upgraded_tm_cons_state.next_validators_hash,
        );

        // update client_state and consensus_state
        self.client_state = new_client_state;
        self.consensus_states
            .insert(self.client_state.latest_height, new_consensus_state);

        Ok(())
    }
}
