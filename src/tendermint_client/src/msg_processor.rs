use crate::prelude::*;
use ibc::core::ics02_client::handler::ClientResult;

use crate::chan_store::*;
use crate::conn_store::*;
use crate::tendermint_client::*;
// use hashbrown::HashMap;

// use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc::core::ics02_client::msgs::ClientMsg;
use ibc::core::ics03_connection::msgs::conn_open_init::*;

use ibc::core::ics03_connection::connection::State as ConnectionState;
use ibc::core::ics03_connection::connection::{ConnectionEnd, Counterparty, State};
use ibc::core::ics03_connection::context::ConnectionReader;
use ibc::core::ics03_connection::error::ConnectionError;
use ibc::core::ics03_connection::events::OpenInit;
use ibc::core::ics03_connection::handler::ConnectionResult;
use ibc::core::ics03_connection::msgs::conn_open_ack::MsgConnectionOpenAck;
use ibc::core::ics03_connection::msgs::conn_open_confirm::MsgConnectionOpenConfirm;
use ibc::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
use ibc::core::ics03_connection::msgs::conn_open_try::MsgConnectionOpenTry;
use ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc::core::ics24_host::identifier::ConnectionId;

use ibc::core::ics04_channel::channel::{
    ChannelEnd, Counterparty as ChCounterparty, State as ChState,
};
use ibc::core::ics04_channel::context::ChannelReader;
use ibc::core::ics04_channel::error::ChannelError;
use ibc::core::ics04_channel::handler::{ChannelIdState, ChannelResult};
use ibc::core::ics04_channel::msgs::chan_close_init::MsgChannelCloseInit;
use ibc::core::ics04_channel::msgs::chan_open_ack::MsgChannelOpenAck;
use ibc::core::ics04_channel::msgs::chan_open_confirm::MsgChannelOpenConfirm;
use ibc::core::ics04_channel::msgs::chan_open_init::MsgChannelOpenInit;
use ibc::core::ics04_channel::msgs::chan_open_try::MsgChannelOpenTry;
use ibc::core::ics04_channel::Version;
use ibc::core::ics24_host::identifier::ChannelId;

use ibc::events::IbcEvent;
use ibc::handler::{HandlerOutput, HandlerResult};
use ibc::Height;

pub const DEFAULT_COMMITMENT_PREFIX: &str = "ibc";

pub struct MessageProcessor {
    tendermint_clients: HashMap<ClientId, TendermintClient>,
    conn_store: ConnectionStore,
    chan_store: ChannelStore,
}

impl MessageProcessor {
    pub fn new() -> Self {
        MessageProcessor {
            tendermint_clients: HashMap::new(),
            conn_store: ConnectionStore::new(),
            chan_store: ChannelStore::new(),
        }
    }
}

// Process client messages
impl MessageProcessor {
    pub fn create_client() {}
    pub fn update_client() {}
    pub fn upgrade_client() {}
    pub fn misbehaviour() {}
}

// Process connection messages
impl MessageProcessor {
    pub fn conn_open_init(&mut self, msg: MsgConnectionOpenInit) -> Result<(), String> {
        // verify
        let versions = if let Some(version) = msg.version {
            vec![version]
        } else {
            self.conn_store.get_compatible_versions()
        };

        // construct
        let conn_end_on_a = ConnectionEnd::new(
            State::Init,
            msg.client_id_on_a.clone(),
            Counterparty::new(
                msg.counterparty.client_id().clone(),
                None,
                msg.counterparty.prefix().clone(),
            ),
            versions,
            msg.delay_period,
        );

        let conn_id_on_a = ConnectionId::new(
            self.conn_store
                .connection_counter()
                .map_err(|_| "Get connection counter error?")?,
        );
        let client_id_on_b = msg.counterparty.client_id().clone();

        // store
        self.conn_store.increase_connection_counter();
        self.store_connection(conn_id_on_a.clone(), conn_end_on_a)?;
        self.store_connection_to_client(conn_id_on_a, client_id_on_b)?;

        Ok(())
    }

    pub fn conn_open_try(&mut self, msg: MsgConnectionOpenTry) -> Result<(), String> {
        // verify
        let conn_id_on_b = ConnectionId::new(
            self.conn_store
                .connection_counter()
                .map_err(|_| "Get conn_store counter error".to_string())?,
        );

        let version_on_b = self
            .conn_store
            .pick_version(
                &self.conn_store.get_compatible_versions(),
                &msg.versions_on_a,
            )
            .map_err(|_| "Get version error".to_string())?;

        let conn_end_on_b = ConnectionEnd::new(
            State::TryOpen,
            msg.client_id_on_b.clone(),
            msg.counterparty.clone(),
            vec![version_on_b],
            msg.delay_period,
        );

        let client_id_on_a = msg.counterparty.client_id();
        let conn_id_on_a = conn_end_on_b
            .counterparty()
            .connection_id()
            .ok_or("ConnectionError::InvalidCounterparty".to_string())?;

        // Verify proofs
        {
            let client_state_of_a_on_b = self.client_state(conn_end_on_b.client_id())?;
            let consensus_state_of_a_on_b =
                self.client_consensus_state(&msg.client_id_on_b, &msg.proofs_height_on_a)?;

            let prefix_on_a = conn_end_on_b.counterparty().prefix();
            let prefix_on_b = self.commitment_prefix();

            {
                let versions_on_a = msg.versions_on_a;
                let expected_conn_end_on_a = ConnectionEnd::new(
                    State::Init,
                    client_id_on_a.clone(),
                    Counterparty::new(msg.client_id_on_b.clone(), None, prefix_on_b),
                    versions_on_a,
                    msg.delay_period,
                );

                client_state_of_a_on_b
                    .verify_connection_state(
                        msg.proofs_height_on_a,
                        prefix_on_a,
                        &msg.proof_conn_end_on_a,
                        &consensus_state_of_a_on_b.root,
                        conn_id_on_a,
                        &expected_conn_end_on_a,
                    )
                    .map_err(|_| "ConnectionError::VerifyConnectionState".to_string())?;
            }

            client_state_of_a_on_b
                .verify_client_full_state(
                    msg.proofs_height_on_a,
                    prefix_on_a,
                    &msg.proof_client_state_of_b_on_a,
                    &consensus_state_of_a_on_b.root,
                    client_id_on_a,
                    msg.client_state_of_b_on_a,
                )
                .map_err(|_| "ConnectionError::ClientStateVerificationFailure".to_string())?;

            // let expected_consensus_state_of_b_on_a =
            //     ctx_b.host_consensus_state(&msg.consensus_height_of_b_on_a)?;
            // client_state_of_a_on_b
            //     .verify_client_consensus_state(
            //         msg.proofs_height_on_a,
            //         prefix_on_a,
            //         &msg.proof_consensus_state_of_b_on_a,
            //         consensus_state_of_a_on_b.root(),
            //         client_id_on_a,
            //         msg.consensus_height_of_b_on_a,
            //         expected_consensus_state_of_b_on_a.as_ref(),
            //     )
            //     .map_err(|e| ConnectionError::ConsensusStateVerificationFailure {
            //         height: msg.proofs_height_on_a,
            //         client_error: e,
            //     })?;
        }

        // store
        self.conn_store.increase_connection_counter();
        self.store_connection_to_client(conn_id_on_b.clone(), conn_end_on_b.client_id().clone())?;
        self.store_connection(conn_id_on_b, conn_end_on_b)?;

        Ok(())
    }

    pub fn conn_open_ack(&mut self, msg: MsgConnectionOpenAck) -> Result<(), String> {
        let conn_end_on_a = self.connection_end(&msg.conn_id_on_a)?;
        if !(conn_end_on_a.state_matches(&State::Init)
            && conn_end_on_a.versions().contains(&msg.version))
        {
            return Err("ConnectionError::ConnectionMismatch".to_string());
        }

        let client_id_on_a = conn_end_on_a.client_id();
        let client_id_on_b = conn_end_on_a.counterparty().client_id();

        // Proof verification.
        {
            let client_state_of_b_on_a = self.client_state(client_id_on_a)?;
            let consensus_state_of_b_on_a =
                self.client_consensus_state(conn_end_on_a.client_id(), &msg.proofs_height_on_b)?;

            let prefix_on_a = self.commitment_prefix();
            let prefix_on_b = conn_end_on_a.counterparty().prefix();

            {
                let expected_conn_end_on_b = ConnectionEnd::new(
                    State::TryOpen,
                    client_id_on_b.clone(),
                    Counterparty::new(
                        client_id_on_a.clone(),
                        Some(msg.conn_id_on_a.clone()),
                        prefix_on_a,
                    ),
                    vec![msg.version.clone()],
                    conn_end_on_a.delay_period(),
                );

                client_state_of_b_on_a
                    .verify_connection_state(
                        msg.proofs_height_on_b,
                        prefix_on_b,
                        &msg.proof_conn_end_on_b,
                        &consensus_state_of_b_on_a.root,
                        &msg.conn_id_on_b,
                        &expected_conn_end_on_b,
                    )
                    .map_err(|_| "ConnectionError::VerifyConnectionState".to_string())?;
            }

            client_state_of_b_on_a
                .verify_client_full_state(
                    msg.proofs_height_on_b,
                    prefix_on_b,
                    &msg.proof_client_state_of_a_on_b,
                    &consensus_state_of_b_on_a.root,
                    client_id_on_b,
                    msg.client_state_of_a_on_b,
                )
                .map_err(|_| "ConnectionError::ClientStateVerificationFailure".to_string())?;
        }

        // Store
        let new_conn_end_on_a = {
            let mut counterparty = conn_end_on_a.counterparty().clone();
            counterparty.connection_id = Some(msg.conn_id_on_b.clone());

            let mut new_conn_end_on_a = conn_end_on_a;
            new_conn_end_on_a.set_state(State::Open);
            new_conn_end_on_a.set_version(msg.version.clone());
            new_conn_end_on_a.set_counterparty(counterparty);
            new_conn_end_on_a
        };

        self.store_connection(msg.conn_id_on_a, new_conn_end_on_a)?;

        Ok(())
    }

    pub fn conn_open_confirm(&mut self, msg: MsgConnectionOpenConfirm) -> Result<(), String> {
        let conn_end_on_b = self.connection_end(&msg.conn_id_on_b)?;
        if !conn_end_on_b.state_matches(&State::TryOpen) {
            return Err("ConnectionError::ConnectionMismatch".to_string());
        }
        let client_id_on_a = conn_end_on_b.counterparty().client_id();
        let client_id_on_b = conn_end_on_b.client_id();
        let conn_id_on_a = conn_end_on_b
            .counterparty()
            .connection_id()
            .ok_or("ConnectionError::InvalidCounterparty".to_string())?;

        // Verify proofs
        {
            let client_state_of_a_on_b = self.client_state(client_id_on_b)?;
            let consensus_state_of_a_on_b =
                self.client_consensus_state(client_id_on_b, &msg.proof_height_on_a)?;

            let prefix_on_a = conn_end_on_b.counterparty().prefix();
            let prefix_on_b = self.commitment_prefix();

            let expected_conn_end_on_a = ConnectionEnd::new(
                State::Open,
                client_id_on_a.clone(),
                Counterparty::new(
                    client_id_on_b.clone(),
                    Some(msg.conn_id_on_b.clone()),
                    prefix_on_b,
                ),
                conn_end_on_b.versions().to_vec(),
                conn_end_on_b.delay_period(),
            );

            client_state_of_a_on_b
                .verify_connection_state(
                    msg.proof_height_on_a,
                    prefix_on_a,
                    &msg.proof_conn_end_on_a,
                    &consensus_state_of_a_on_b.root,
                    conn_id_on_a,
                    &expected_conn_end_on_a,
                )
                .map_err(|_| "ConnectionError::VerifyConnectionState".to_string())?;
        }

        // store
        let new_conn_end_on_b = {
            let mut new_conn_end_on_b = conn_end_on_b;

            new_conn_end_on_b.set_state(State::Open);
            new_conn_end_on_b
        };

        self.store_connection(msg.conn_id_on_b, new_conn_end_on_b)?;

        Ok(())
    }

    // chann
}

// Process channel messages
impl MessageProcessor {
    pub fn chan_open_init(&mut self, msg: &MsgChannelOpenInit) -> Result<(), ChannelError> {
        // verify
        if msg.connection_hops_on_a.len() != 1 {
            return Err(ChannelError::InvalidConnectionHopsLength {
                expected: 1,
                actual: msg.connection_hops_on_a.len(),
            });
        }

        // An IBC connection running on the local (host) chain should exist.
        let conn_end_on_a = self.connection_end2(&msg.connection_hops_on_a[0])?;

        let conn_version = match conn_end_on_a.versions() {
            [version] => version,
            _ => return Err(ChannelError::InvalidVersionLengthConnection),
        };

        let channel_feature = msg.ordering.to_string();
        if !conn_version.is_supported_feature(channel_feature) {
            return Err(ChannelError::ChannelFeatureNotSuportedByConnection);
        }

        let chan_end_on_a = ChannelEnd::new(
            ChState::Init,
            msg.ordering,
            ChCounterparty::new(msg.port_id_on_b.clone(), None),
            msg.connection_hops_on_a.clone(),
            msg.version_proposal.clone(),
        );

        let chan_id_on_a = ChannelId::new(self.chan_store.channel_counter()?);

        let result = ChannelResult {
            port_id: msg.port_id_on_a.clone(),
            channel_id: chan_id_on_a,
            channel_end: chan_end_on_a,
            channel_id_state: ChannelIdState::Generated,
        };

        // modify version, need check
        // +++++++++++
        // TODO
        // +++++++++++
        // +++++++++++
        // +++++++++++
        // +++++++++++
        // +++++++++++
        // +++++++++++

        // store
        self.chan_store
            .store_channel_result(result)
            .map_err(|_| ChannelError::Other {
                description: "Store channel error!".to_string(),
            })?;

        Ok(())
    }

    pub fn chan_open_try(&mut self, msg: &MsgChannelOpenTry) -> Result<(), ChannelError> {
        // An IBC connection running on the local (host) chain should exist.
        if msg.connection_hops_on_b.len() != 1 {
            return Err(ChannelError::InvalidConnectionHopsLength {
                expected: 1,
                actual: msg.connection_hops_on_b.len(),
            });
        }

        let conn_end_on_b = self.connection_end2(&msg.connection_hops_on_b[0])?;
        if !conn_end_on_b.state_matches(&ConnectionState::Open) {
            return Err(ChannelError::ConnectionNotOpen {
                connection_id: msg.connection_hops_on_b[0].clone(),
            });
        }

        let conn_version = match conn_end_on_b.versions() {
            [version] => version,
            _ => return Err(ChannelError::InvalidVersionLengthConnection),
        };

        let channel_feature = msg.ordering.to_string();
        if !conn_version.is_supported_feature(channel_feature) {
            return Err(ChannelError::ChannelFeatureNotSuportedByConnection);
        }

        // Verify proofs
        {
            let client_id_on_b = conn_end_on_b.client_id();
            let client_state_of_a_on_b = self.client_state2(client_id_on_b)?;
            let consensus_state_of_a_on_b =
                self.client_consensus_state2(client_id_on_b, &msg.proof_height_on_a)?;
            let prefix_on_a = conn_end_on_b.counterparty().prefix();
            let port_id_on_a = &&msg.port_id_on_a;
            let chan_id_on_a = msg.chan_id_on_a.clone();
            let conn_id_on_a = conn_end_on_b.counterparty().connection_id().ok_or(
                ChannelError::UndefinedConnectionCounterparty {
                    connection_id: msg.connection_hops_on_b[0].clone(),
                },
            )?;

            // The client must not be frozen.
            if client_state_of_a_on_b.is_frozen() {
                return Err(ChannelError::FrozenClient {
                    client_id: client_id_on_b.clone(),
                });
            }

            let expected_chan_end_on_a = ChannelEnd::new(
                ChState::Init,
                msg.ordering,
                ChCounterparty::new(msg.port_id_on_b.clone(), None),
                vec![conn_id_on_a.clone()],
                msg.version_supported_on_a.clone(),
            );

            // Verify the proof for the channel state against the expected channel end.
            // A counterparty channel id of None in not possible, and is checked by validate_basic in msg.
            client_state_of_a_on_b
                .verify_channel_state(
                    msg.proof_height_on_a,
                    prefix_on_a,
                    &msg.proof_chan_end_on_a,
                    &consensus_state_of_a_on_b.root,
                    port_id_on_a,
                    &chan_id_on_a,
                    &expected_chan_end_on_a,
                )
                .map_err(ChannelError::VerifyChannelFailed)?;
        }

        let chan_end_on_b = ChannelEnd::new(
            ChState::TryOpen,
            msg.ordering,
            ChCounterparty::new(msg.port_id_on_a.clone(), Some(msg.chan_id_on_a.clone())),
            msg.connection_hops_on_b.clone(),
            // Note: This will be rewritten by the module callback
            Version::empty(),
        );

        let chan_id_on_b = ChannelId::new(self.chan_store.channel_counter()?);

        let result = ChannelResult {
            port_id: msg.port_id_on_b.clone(),
            channel_id: chan_id_on_b,
            channel_end: chan_end_on_b,
            channel_id_state: ChannelIdState::Generated,
        };

        // store
        self.chan_store
            .store_channel_result(result)
            .map_err(|_| ChannelError::Other {
                description: "Store channel error!".to_string(),
            })?;

        Ok(())
    }

    pub fn chan_open_ack(&mut self, msg: &MsgChannelOpenAck) -> Result<(), ChannelError> {
        let chan_end_on_a = self
            .chan_store
            .channel_end(&msg.port_id_on_a, &msg.chan_id_on_a)?;

        // Validate that the channel end is in a state where it can be ack.
        if !chan_end_on_a.state_matches(&ChState::Init) {
            return Err(ChannelError::InvalidChannelState {
                channel_id: msg.chan_id_on_a.clone(),
                state: chan_end_on_a.state,
            });
        }

        // An OPEN IBC connection running on the local (host) chain should exist.

        if chan_end_on_a.connection_hops().len() != 1 {
            return Err(ChannelError::InvalidConnectionHopsLength {
                expected: 1,
                actual: chan_end_on_a.connection_hops().len(),
            });
        }

        let conn_end_on_a = self.connection_end2(&chan_end_on_a.connection_hops()[0])?;

        if !conn_end_on_a.state_matches(&ConnectionState::Open) {
            return Err(ChannelError::ConnectionNotOpen {
                connection_id: chan_end_on_a.connection_hops()[0].clone(),
            });
        }

        // Verify proofs
        {
            let client_id_on_a = conn_end_on_a.client_id();
            let client_state_of_b_on_a = self.client_state2(client_id_on_a)?;
            let consensus_state_of_b_on_a =
                self.client_consensus_state2(client_id_on_a, &msg.proof_height_on_b)?;
            let prefix_on_b = conn_end_on_a.counterparty().prefix();
            let port_id_on_b = &chan_end_on_a.counterparty().port_id;
            let conn_id_on_b = conn_end_on_a.counterparty().connection_id().ok_or(
                ChannelError::UndefinedConnectionCounterparty {
                    connection_id: chan_end_on_a.connection_hops()[0].clone(),
                },
            )?;

            // The client must not be frozen.
            if client_state_of_b_on_a.is_frozen() {
                return Err(ChannelError::FrozenClient {
                    client_id: client_id_on_a.clone(),
                });
            }

            let expected_chan_end_on_b = ChannelEnd::new(
                ChState::TryOpen,
                // Note: Both ends of a channel must have the same ordering, so it's
                // fine to use A's ordering here
                *chan_end_on_a.ordering(),
                ChCounterparty::new(msg.port_id_on_a.clone(), Some(msg.chan_id_on_a.clone())),
                vec![conn_id_on_b.clone()],
                msg.version_on_b.clone(),
            );

            // Verify the proof for the channel state against the expected channel end.
            // A counterparty channel id of None in not possible, and is checked by validate_basic in msg.
            client_state_of_b_on_a
                .verify_channel_state(
                    msg.proof_height_on_b,
                    prefix_on_b,
                    &msg.proof_chan_end_on_b,
                    &consensus_state_of_b_on_a.root,
                    port_id_on_b,
                    &msg.chan_id_on_b,
                    &expected_chan_end_on_b,
                )
                .map_err(ChannelError::VerifyChannelFailed)?;
        }

        // Transition the channel end to the new state & pick a version.
        let new_chan_end_on_a = {
            let mut chan_end_on_a = chan_end_on_a;

            chan_end_on_a.set_state(ChState::Open);
            chan_end_on_a.set_version(msg.version_on_b.clone());
            chan_end_on_a.set_counterparty_channel_id(msg.chan_id_on_b.clone());

            chan_end_on_a
        };

        let result = ChannelResult {
            port_id: msg.port_id_on_a.clone(),
            channel_id: msg.chan_id_on_a.clone(),
            channel_id_state: ChannelIdState::Reused,
            channel_end: new_chan_end_on_a,
        };

        // store
        self.chan_store
            .store_channel_result(result)
            .map_err(|_| ChannelError::Other {
                description: "Store channel error!".to_string(),
            })?;

        Ok(())
    }

    pub fn chan_open_confirm(&mut self, msg: &MsgChannelOpenConfirm) -> Result<(), ChannelError> {
        let mut chan_end_on_b = self
            .chan_store
            .channel_end(&msg.port_id_on_b, &msg.chan_id_on_b)?;

        // Validate that the channel end is in a state where it can be confirmed.
        if !chan_end_on_b.state_matches(&ChState::TryOpen) {
            return Err(ChannelError::InvalidChannelState {
                channel_id: msg.chan_id_on_b.clone(),
                state: chan_end_on_b.state,
            });
        }

        // An OPEN IBC connection running on the local (host) chain should exist.
        if chan_end_on_b.connection_hops().len() != 1 {
            return Err(ChannelError::InvalidConnectionHopsLength {
                expected: 1,
                actual: chan_end_on_b.connection_hops().len(),
            });
        }

        let conn_end_on_b = self.connection_end2(&chan_end_on_b.connection_hops()[0])?;

        if !conn_end_on_b.state_matches(&ConnectionState::Open) {
            return Err(ChannelError::ConnectionNotOpen {
                connection_id: chan_end_on_b.connection_hops()[0].clone(),
            });
        }

        // Verify proofs
        {
            let client_id_on_b = conn_end_on_b.client_id();
            let client_state_of_a_on_b = self.client_state2(client_id_on_b)?;
            let consensus_state_of_a_on_b =
                self.client_consensus_state2(client_id_on_b, &msg.proof_height_on_a)?;
            let prefix_on_a = conn_end_on_b.counterparty().prefix();
            let port_id_on_a = &chan_end_on_b.counterparty().port_id;
            let chan_id_on_a = chan_end_on_b
                .counterparty()
                .channel_id()
                .ok_or(ChannelError::InvalidCounterpartyChannelId)?;
            let conn_id_on_a = conn_end_on_b.counterparty().connection_id().ok_or(
                ChannelError::UndefinedConnectionCounterparty {
                    connection_id: chan_end_on_b.connection_hops()[0].clone(),
                },
            )?;

            // The client must not be frozen.
            if client_state_of_a_on_b.is_frozen() {
                return Err(ChannelError::FrozenClient {
                    client_id: client_id_on_b.clone(),
                });
            }

            let expected_chan_end_on_a = ChannelEnd::new(
                ChState::Open,
                *chan_end_on_b.ordering(),
                ChCounterparty::new(msg.port_id_on_b.clone(), Some(msg.chan_id_on_b.clone())),
                vec![conn_id_on_a.clone()],
                chan_end_on_b.version.clone(),
            );

            // Verify the proof for the channel state against the expected channel end.
            // A counterparty channel id of None in not possible, and is checked in msg.
            client_state_of_a_on_b
                .verify_channel_state(
                    msg.proof_height_on_a,
                    prefix_on_a,
                    &msg.proof_chan_end_on_a,
                    &consensus_state_of_a_on_b.root,
                    port_id_on_a,
                    chan_id_on_a,
                    &expected_chan_end_on_a,
                )
                .map_err(ChannelError::VerifyChannelFailed)?;
        }

        // Transition the channel end to the new state.
        chan_end_on_b.set_state(ChState::Open);

        let result = ChannelResult {
            port_id: msg.port_id_on_b.clone(),
            channel_id: msg.chan_id_on_b.clone(),
            channel_id_state: ChannelIdState::Reused,
            channel_end: chan_end_on_b,
        };

        // store
        self.chan_store
            .store_channel_result(result)
            .map_err(|_| ChannelError::Other {
                description: "Store channel error!".to_string(),
            })?;

        Ok(())
    }

    pub fn chan_close_init(&mut self, msg: &MsgChannelCloseInit) -> Result<(), ChannelError> {
        let chan_end_on_a = self
            .chan_store
            .channel_end(&msg.port_id_on_a, &msg.chan_id_on_a)?;

        // Validate that the channel end is in a state where it can be closed.
        if chan_end_on_a.state_matches(&ChState::Closed) {
            return Err(ChannelError::InvalidChannelState {
                channel_id: msg.chan_id_on_a.clone(),
                state: chan_end_on_a.state,
            });
        }

        // An OPEN IBC connection running on the local (host) chain should exist.
        if chan_end_on_a.connection_hops().len() != 1 {
            return Err(ChannelError::InvalidConnectionHopsLength {
                expected: 1,
                actual: chan_end_on_a.connection_hops().len(),
            });
        }

        let conn_end_on_a = self.connection_end2(&chan_end_on_a.connection_hops()[0])?;

        if !conn_end_on_a.state_matches(&ConnectionState::Open) {
            return Err(ChannelError::ConnectionNotOpen {
                connection_id: chan_end_on_a.connection_hops()[0].clone(),
            });
        }

        let new_chan_end_on_a = {
            let mut chan_end_on_a = chan_end_on_a;
            chan_end_on_a.set_state(ChState::Closed);
            chan_end_on_a
        };

        let result = ChannelResult {
            port_id: msg.port_id_on_a.clone(),
            channel_id: msg.chan_id_on_a.clone(),
            channel_id_state: ChannelIdState::Reused,
            channel_end: new_chan_end_on_a,
        };

        // store
        self.chan_store
            .store_channel_result(result)
            .map_err(|_| ChannelError::Other {
                description: "Store channel error!".to_string(),
            })?;
        Ok(())
    }
}

impl MessageProcessor {
    fn commitment_prefix(&self) -> CommitmentPrefix {
        CommitmentPrefix::try_from(DEFAULT_COMMITMENT_PREFIX.as_bytes().to_vec())
            .unwrap_or_default()
    }

    /// Returns the ConsensusState that the given client stores at a specific height.
    fn client_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<TmConsensusState, String> {
        let cs = self
            .tendermint_clients
            .get(client_id)
            .ok_or("Not found client".to_string())?
            .consensus_states
            .get(height)
            .ok_or("Not found consensus state".to_string())?;
        Ok(cs.clone())
    }

    fn client_consensus_state2(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<TmConsensusState, ChannelError> {
        let cs = self
            .tendermint_clients
            .get(client_id)
            .ok_or(ChannelError::Other {
                description: "Not found consensus state".to_string(),
            })?
            .consensus_states
            .get(height)
            .ok_or(ChannelError::Other {
                description: "Not found consensus state".to_string(),
            })?;
        Ok(cs.clone())
    }
    fn client_state(&self, client_id: &ClientId) -> Result<TmClientState, String> {
        let cs = self
            .tendermint_clients
            .get(client_id)
            .ok_or("Not found client!".to_string())?
            .client_state
            .clone();
        Ok(cs)
    }

    fn client_state2(&self, client_id: &ClientId) -> Result<TmClientState, ChannelError> {
        let cs = self
            .tendermint_clients
            .get(client_id)
            .ok_or(ChannelError::Other {
                description: "Not found client state".to_string(),
            })?
            .client_state
            .clone();
        Ok(cs)
    }

    fn connection_end(&self, conn_id: &ConnectionId) -> Result<ConnectionEnd, String> {
        self.conn_store
            .connection_end(&conn_id)
            .map_err(|_| "ConnectionMismatch".to_string())
    }

    fn connection_end2(&self, conn_id: &ConnectionId) -> Result<ConnectionEnd, ChannelError> {
        self.conn_store
            .connection_end(&conn_id)
            .map_err(ChannelError::Connection)
    }

    fn store_connection(
        &mut self,
        connection_id: ConnectionId,
        connection_end: ConnectionEnd,
    ) -> Result<(), String> {
        self.conn_store
            .store_connection(connection_id, connection_end)
            .map_err(|_| "Store conn_id and conn_end error".to_string())
    }

    fn store_connection_to_client(
        &mut self,
        connection_id: ConnectionId,
        client_id: ClientId,
    ) -> Result<(), String> {
        self.conn_store
            .store_connection_to_client(connection_id, client_id)
            .map_err(|_| "Store conn_id and client_id error".to_string())
    }
}
