use crate::prelude::*;

use crate::chan_store::*;
use crate::conn_store::*;
use crate::solomachine::consensus_state;
use crate::tendermint_client;
use crate::tendermint_client::*;
use ibc::timestamp::Timestamp;

// use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc::core::ics02_client::client_state::ClientState;
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::core::ics02_client::context::ClientReader;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics02_client::events::CreateClient;
use ibc::core::ics02_client::handler::ClientResult;
use ibc::core::ics02_client::msgs::create_client::MsgCreateClient;
use ibc::core::ics02_client::msgs::misbehaviour::MsgSubmitMisbehaviour;
use ibc::core::ics02_client::msgs::update_client::MsgUpdateClient;
use ibc::core::ics02_client::msgs::upgrade_client::MsgUpgradeClient;
use ibc::core::ics02_client::msgs::ClientMsg;
use ibc::core::ics24_host::identifier::ClientId;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::MsgCreateClient as RawMsgCreateClient;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

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

use ibc::core::ics04_channel::channel::Order;
use ibc::core::ics04_channel::channel::{
    ChannelEnd, Counterparty as ChCounterparty, State as ChState,
};
use ibc::core::ics04_channel::context::ChannelReader;
use ibc::core::ics04_channel::error::ChannelError;
use ibc::core::ics04_channel::error::PacketError;
use ibc::core::ics04_channel::handler::acknowledgement::AckPacketResult;
use ibc::core::ics04_channel::handler::recv_packet::RecvPacketResult;
use ibc::core::ics04_channel::handler::timeout::TimeoutPacketResult;
use ibc::core::ics04_channel::handler::{ChannelIdState, ChannelResult};
use ibc::core::ics04_channel::msgs::acknowledgement::MsgAcknowledgement;
use ibc::core::ics04_channel::msgs::chan_close_init::MsgChannelCloseInit;
use ibc::core::ics04_channel::msgs::chan_open_ack::MsgChannelOpenAck;
use ibc::core::ics04_channel::msgs::chan_open_confirm::MsgChannelOpenConfirm;
use ibc::core::ics04_channel::msgs::chan_open_init::MsgChannelOpenInit;
use ibc::core::ics04_channel::msgs::chan_open_try::MsgChannelOpenTry;
use ibc::core::ics04_channel::msgs::recv_packet::MsgRecvPacket;
use ibc::core::ics04_channel::msgs::timeout::MsgTimeout;
use ibc::core::ics04_channel::msgs::timeout_on_close::MsgTimeoutOnClose;
use ibc::core::ics04_channel::packet::{PacketResult, Receipt, Sequence};
use ibc::core::ics04_channel::Version;
use ibc::core::ics24_host::identifier::ChannelId;

use ibc::events::IbcEvent;
use ibc::handler::{HandlerOutput, HandlerResult};
use ibc::timestamp::Expiry;
use ibc::Height;

pub const DEFAULT_COMMITMENT_PREFIX: &str = "ibc";

pub struct MessageVerifier {
    tendermint_clients: HashMap<ClientId, TendermintClient>,
    client_ids_counter: u64,
    conn_store: ConnectionStore,
    chan_store: ChannelStore,
    pub sequence_cnt: u64,
}

impl MessageVerifier {
    pub fn new() -> Self {
        MessageVerifier {
            tendermint_clients: HashMap::new(),
            client_ids_counter: 0u64,
            conn_store: ConnectionStore::new(),
            chan_store: ChannelStore::new(),
            sequence_cnt: 1u64,
        }
    }
}

// Process client messages
impl MessageVerifier {
    pub fn create_client(
        &mut self,
        msg: MsgCreateClient,
    ) -> Result<(TmClientState, TmConsensusState), String> {
        let MsgCreateClient {
            client_state,
            consensus_state,
            signer: _,
        } = msg;

        let client_state = self.decode_client_state(client_state)?;
        let client_type = tendermint_client::client_type();
        let client_id = ClientId::new(client_type.clone(), self.client_ids_counter)
            .map_err(|_| "ClientError::ClientIdentifierConstructor".to_string())?;
        let consensus_state = TmConsensusState::try_from(consensus_state)
            .map_err(|_| "Parse consensus_state error".to_string())?;
        let tc = tendermint_client::TendermintClient::new(
            client_id.clone(),
            consensus_state.clone(),
            client_state.clone(),
        );

        // store
        self.tendermint_clients.insert(client_id, tc);
        self.increase_client_counter();

        Ok((client_state, consensus_state))
    }

    pub fn update_client(
        &mut self,
        msg: MsgUpdateClient,
        now: Time,
    ) -> Result<TmConsensusState, String> {
        let MsgUpdateClient {
            client_id,
            header,
            signer: _,
        } = msg;

        let client_state = self.client_state(&client_id)?;

        if client_state.is_frozen() {
            return Err("ClientError::ClientFrozen".to_string());
        }

        let tc = self
            .tendermint_clients
            .get_mut(&client_id)
            .ok_or("No tendermint client match".to_string())?;

        tc.check_header_and_update_state(header, now)
            .map_err(|_| "update client error".to_string())
    }

    pub fn upgrade_client(&mut self, msg: MsgUpgradeClient) -> Result<(), String> {
        let MsgUpgradeClient { client_id, .. } = msg;

        let old_client_state = self.client_state(&client_id)?;
        if old_client_state.is_frozen() {
            return Err("ClientError::ClientFrozen".to_string());
        }

        let old_consensus_state =
            self.client_consensus_state(&client_id, &old_client_state.latest_height)?;

        let tc = self
            .tendermint_clients
            .get_mut(&client_id)
            .ok_or("No tendermint client match".to_string())?;

        tc.check_upgrade_client_and_update_state(
            msg.client_state.clone(),
            msg.consensus_state.clone(),
            msg.proof_upgrade_client.clone(),
            msg.proof_upgrade_consensus_state.clone(),
            old_consensus_state.root(),
        )
        .map_err(|_| "Upgrade client error".to_string())
    }

    pub fn misbehaviour(&mut self, msg: MsgSubmitMisbehaviour, now: Time) -> Result<(), String> {
        let MsgSubmitMisbehaviour {
            client_id,
            misbehaviour,
            signer: _,
        } = msg;

        let client_state = self.client_state(&client_id)?;
        if client_state.is_frozen() {
            return Err("ClientError::ClientFrozen { client_id }".to_string());
        }

        let tc = self
            .tendermint_clients
            .get_mut(&client_id)
            .ok_or("No tendermint client match".to_string())?;

        tc.check_misbehaviour_and_update_state(misbehaviour, now.into())
            .map_err(|_| "Check misbehaviour error".to_string())
    }
}

// Process connection messages
impl MessageVerifier {
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

    pub fn conn_open_try(
        &mut self,
        msg: MsgConnectionOpenTry,
        conn_end: ConnectionEnd,
    ) -> Result<
        (
            TmClientState,
            TmConsensusState,
            ConnectionId,
            ConnectionEnd,
            ClientId,
        ),
        String,
    > {
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

        let client_state_of_a_on_b = self.client_state(conn_end_on_b.client_id())?;
        let consensus_state_of_a_on_b =
            self.client_consensus_state(&msg.client_id_on_b, &msg.proofs_height_on_a)?;

        // Verify proofs
        {
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
        }

        // store
        self.conn_store.increase_connection_counter();
        self.store_connection_to_client(conn_id_on_b.clone(), conn_end_on_b.client_id().clone())?;
        self.store_connection(conn_id_on_b, conn_end_on_b.clone())?;

        Ok((
            client_state_of_a_on_b,
            consensus_state_of_a_on_b,
            conn_id_on_a.clone(),
            conn_end,
            client_id_on_a.clone(),
        ))
    }

    pub fn conn_open_ack(
        &mut self,
        msg: MsgConnectionOpenAck,
    ) -> Result<(TmClientState, TmConsensusState), String> {
        let conn_end_on_a = self.connection_end(&msg.conn_id_on_a)?;
        if !(conn_end_on_a.state_matches(&State::Init)
            && conn_end_on_a.versions().contains(&msg.version))
        {
            return Err("ConnectionError::ConnectionMismatch".to_string());
        }

        let client_id_on_a = conn_end_on_a.client_id();
        let client_id_on_b = conn_end_on_a.counterparty().client_id();

        let client_state_of_b_on_a = self.client_state(client_id_on_a)?;
        let consensus_state_of_b_on_a =
            self.client_consensus_state(conn_end_on_a.client_id(), &msg.proofs_height_on_b)?;

        // Proof verification.
        {
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

        Ok((client_state_of_b_on_a, consensus_state_of_b_on_a))
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
impl MessageVerifier {
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

// For Packet Message
impl MessageVerifier {
    pub fn recv_packet(&mut self, msg: &MsgRecvPacket) -> Result<(), PacketError> {
        let chan_end_on_b = self
            .chan_store
            .channel_end(&msg.packet.port_on_b, &msg.packet.chan_on_b)
            .map_err(PacketError::Channel)?;

        if !chan_end_on_b.state_matches(&ChState::Open) {
            return Err(PacketError::InvalidChannelState {
                channel_id: msg.packet.chan_on_a.clone(),
                state: chan_end_on_b.state,
            });
        }

        let counterparty = ChCounterparty::new(
            msg.packet.port_on_a.clone(),
            Some(msg.packet.chan_on_a.clone()),
        );

        if !chan_end_on_b.counterparty_matches(&counterparty) {
            return Err(PacketError::InvalidPacketCounterparty {
                port_id: msg.packet.port_on_a.clone(),
                channel_id: msg.packet.chan_on_a.clone(),
            });
        }

        let conn_id_on_b = &chan_end_on_b.connection_hops()[0];
        let conn_end_on_b = self
            .connection_end2(conn_id_on_b)
            .map_err(PacketError::Channel)?;

        if !conn_end_on_b.state_matches(&ConnectionState::Open) {
            return Err(PacketError::ConnectionNotOpen {
                connection_id: chan_end_on_b.connection_hops()[0].clone(),
            });
        }

        // let latest_height = ChannelReader::host_height(ctx_b).map_err(PacketError::Channel)?;
        // if msg.packet.timeout_height_on_b.has_expired(latest_height) {
        //     return Err(PacketError::LowPacketHeight {
        //         chain_height: latest_height,
        //         timeout_height: msg.packet.timeout_height_on_b,
        //     });
        // }

        // let latest_timestamp =
        //     ChannelReader::host_timestamp(ctx_b).map_err(PacketError::Channel)?;
        // if let Expiry::Expired = latest_timestamp.check_expiry(&msg.packet.timeout_timestamp_on_b) {
        //     return Err(PacketError::LowPacketTimestamp);
        // }

        // Verify proofs
        {
            let client_id_on_b = conn_end_on_b.client_id();
            let client_state_of_a_on_b = self
                .client_state2(client_id_on_b)
                .map_err(PacketError::Channel)?;

            // The client must not be frozen.
            if client_state_of_a_on_b.is_frozen() {
                return Err(PacketError::FrozenClient {
                    client_id: client_id_on_b.clone(),
                });
            }

            let consensus_state_of_a_on_b = self
                .client_consensus_state2(client_id_on_b, &msg.proof_height_on_a)
                .map_err(PacketError::Channel)?;

            let expected_commitment_on_a = self.chan_store.packet_commitment(
                &msg.packet.data,
                &msg.packet.timeout_height_on_b,
                &msg.packet.timeout_timestamp_on_b,
            );
            // Verify the proof for the packet against the chain store.
            client_state_of_a_on_b
                .verify_packet_data(
                    // ctx_b,
                    msg.proof_height_on_a,
                    &conn_end_on_b,
                    &msg.proof_commitment_on_a,
                    consensus_state_of_a_on_b.root(),
                    &msg.packet.port_on_a,
                    &msg.packet.chan_on_a,
                    msg.packet.sequence,
                    expected_commitment_on_a,
                )
                .map_err(|e| ChannelError::PacketVerificationFailed {
                    sequence: msg.packet.sequence,
                    client_error: e,
                })
                .map_err(PacketError::Channel)?;
        }

        let result = if chan_end_on_b.order_matches(&Order::Ordered) {
            let next_seq_recv = self
                .chan_store
                .get_next_sequence_recv(&msg.packet.port_on_b, &msg.packet.chan_on_b)?;
            if msg.packet.sequence > next_seq_recv {
                return Err(PacketError::InvalidPacketSequence {
                    given_sequence: msg.packet.sequence,
                    next_sequence: next_seq_recv,
                });
            }

            if msg.packet.sequence < next_seq_recv {
                PacketResult::Recv(RecvPacketResult::NoOp)
            } else {
                PacketResult::Recv(RecvPacketResult::Ordered {
                    port_id: msg.packet.port_on_b.clone(),
                    channel_id: msg.packet.chan_on_b.clone(),
                    next_seq_recv: next_seq_recv.increment(),
                })
            }
        } else {
            let packet_rec = self.chan_store.get_packet_receipt(
                &msg.packet.port_on_b,
                &msg.packet.chan_on_b,
                &msg.packet.sequence,
            );

            match packet_rec {
                Ok(_receipt) => PacketResult::Recv(RecvPacketResult::NoOp),
                Err(PacketError::PacketReceiptNotFound { sequence })
                    if sequence == msg.packet.sequence =>
                {
                    // store a receipt that does not contain any data
                    PacketResult::Recv(RecvPacketResult::Unordered {
                        port_id: msg.packet.port_on_b.clone(),
                        channel_id: msg.packet.chan_on_b.clone(),
                        sequence: msg.packet.sequence,
                        receipt: Receipt::Ok,
                    })
                }
                Err(e) => return Err(e),
            }
        };

        // store
        self.chan_store.store_packet_result(result)
    }

    // PacketMsg::Ack(msg) => acknowledgement::process(ctx, msg),
    pub fn acknowledgement(&mut self, msg: &MsgAcknowledgement) -> Result<(), PacketError> {
        let packet = &msg.packet;
        let chan_end_on_a = self
            .chan_store
            .channel_end(&packet.port_on_a, &packet.chan_on_a)
            .map_err(PacketError::Channel)?;

        if !chan_end_on_a.state_matches(&ChState::Open) {
            return Err(PacketError::ChannelClosed {
                channel_id: packet.chan_on_a.clone(),
            });
        }

        let counterparty =
            ChCounterparty::new(packet.port_on_b.clone(), Some(packet.chan_on_b.clone()));

        if !chan_end_on_a.counterparty_matches(&counterparty) {
            return Err(PacketError::InvalidPacketCounterparty {
                port_id: packet.port_on_b.clone(),
                channel_id: packet.chan_on_b.clone(),
            });
        }

        let conn_id_on_a = &chan_end_on_a.connection_hops()[0];
        let conn_end_on_a = self
            .connection_end2(conn_id_on_a)
            .map_err(PacketError::Channel)?;

        if !conn_end_on_a.state_matches(&ConnectionState::Open) {
            return Err(PacketError::ConnectionNotOpen {
                connection_id: chan_end_on_a.connection_hops()[0].clone(),
            });
        }

        // Verify packet commitment
        let packet_commitment = self.chan_store.get_packet_commitment(
            &packet.port_on_a,
            &packet.chan_on_a,
            &packet.sequence,
        )?;

        if packet_commitment
            != self.chan_store.packet_commitment(
                &packet.data,
                &packet.timeout_height_on_b,
                &packet.timeout_timestamp_on_b,
            )
        {
            return Err(PacketError::IncorrectPacketCommitment {
                sequence: packet.sequence,
            });
        }

        // Verify proofs
        {
            let client_id_on_a = conn_end_on_a.client_id();
            let client_state_on_a = self
                .client_state2(client_id_on_a)
                .map_err(PacketError::Channel)?;

            // The client must not be frozen.
            if client_state_on_a.is_frozen() {
                return Err(PacketError::FrozenClient {
                    client_id: client_id_on_a.clone(),
                });
            }

            let consensus_state = self
                .client_consensus_state2(client_id_on_a, &msg.proof_height_on_b)
                .map_err(PacketError::Channel)?;

            let ack_commitment = self.chan_store.ack_commitment(&msg.acknowledgement);

            // Verify the proof for the packet against the chain store.
            client_state_on_a
                .verify_packet_acknowledgement(
                    msg.proof_height_on_b,
                    &conn_end_on_a,
                    &msg.proof_acked_on_b,
                    consensus_state.root(),
                    &packet.port_on_b,
                    &packet.chan_on_b,
                    packet.sequence,
                    ack_commitment,
                )
                .map_err(|e| ChannelError::PacketVerificationFailed {
                    sequence: packet.sequence,
                    client_error: e,
                })
                .map_err(PacketError::Channel)?;
        }

        let result = if chan_end_on_a.order_matches(&Order::Ordered) {
            let next_seq_ack = self
                .chan_store
                .get_next_sequence_ack(&packet.port_on_a, &packet.chan_on_a)?;

            if packet.sequence != next_seq_ack {
                return Err(PacketError::InvalidPacketSequence {
                    given_sequence: packet.sequence,
                    next_sequence: next_seq_ack,
                });
            }

            PacketResult::Ack(AckPacketResult {
                port_id: packet.port_on_a.clone(),
                channel_id: packet.chan_on_a.clone(),
                seq: packet.sequence,
                seq_number: Some(next_seq_ack.increment()),
            })
        } else {
            PacketResult::Ack(AckPacketResult {
                port_id: packet.port_on_a.clone(),
                channel_id: packet.chan_on_a.clone(),
                seq: packet.sequence,
                seq_number: None,
            })
        };

        // store
        self.chan_store.store_packet_result(result)
    }

    // PacketMsg::Timeout(msg) => timeout::process(ctx, msg),
    pub fn timeout(&mut self, msg: &MsgTimeout) -> Result<(), PacketError> {
        let mut chan_end_on_a = self
            .chan_store
            .channel_end(&msg.packet.port_on_a, &msg.packet.chan_on_a)
            .map_err(PacketError::Channel)?;

        if !chan_end_on_a.state_matches(&ChState::Open) {
            return Err(PacketError::ChannelClosed {
                channel_id: msg.packet.chan_on_a.clone(),
            });
        }

        let counterparty = ChCounterparty::new(
            msg.packet.port_on_b.clone(),
            Some(msg.packet.chan_on_b.clone()),
        );

        if !chan_end_on_a.counterparty_matches(&counterparty) {
            return Err(PacketError::InvalidPacketCounterparty {
                port_id: msg.packet.port_on_b.clone(),
                channel_id: msg.packet.chan_on_b.clone(),
            });
        }

        let conn_id_on_a = chan_end_on_a.connection_hops()[0].clone();
        let conn_end_on_a = self
            .connection_end2(&conn_id_on_a)
            .map_err(PacketError::Channel)?;

        //verify packet commitment
        let commitment_on_a = self.chan_store.get_packet_commitment(
            &msg.packet.port_on_a,
            &msg.packet.chan_on_a,
            &msg.packet.sequence,
        )?;

        let expected_commitment_on_a = self.chan_store.packet_commitment(
            &msg.packet.data,
            &msg.packet.timeout_height_on_b,
            &msg.packet.timeout_timestamp_on_b,
        );
        if commitment_on_a != expected_commitment_on_a {
            return Err(PacketError::IncorrectPacketCommitment {
                sequence: msg.packet.sequence,
            });
        }

        // Verify proofs
        {
            let client_id_on_a = conn_end_on_a.client_id();
            let client_state_of_b_on_a = self
                .client_state2(client_id_on_a)
                .map_err(PacketError::Channel)?;

            // check that timeout height or timeout timestamp has passed on the other end
            if msg
                .packet
                .timeout_height_on_b
                .has_expired(msg.proof_height_on_b)
            {
                return Err(PacketError::PacketTimeoutHeightNotReached {
                    timeout_height: msg.packet.timeout_height_on_b,
                    chain_height: msg.proof_height_on_b,
                });
            }

            let consensus_state_of_b_on_a = self
                .client_consensus_state2(client_id_on_a, &msg.proof_height_on_b)
                .map_err(PacketError::Channel)?;
            let timestamp_of_b = consensus_state_of_b_on_a.timestamp();

            if let Expiry::Expired = msg
                .packet
                .timeout_timestamp_on_b
                .check_expiry(&timestamp_of_b)
            {
                return Err(PacketError::PacketTimeoutTimestampNotReached {
                    timeout_timestamp: msg.packet.timeout_timestamp_on_b,
                    chain_timestamp: timestamp_of_b,
                });
            }
            let next_seq_recv_verification_result = if chan_end_on_a.order_matches(&Order::Ordered)
            {
                if msg.packet.sequence < msg.next_seq_recv_on_b {
                    return Err(PacketError::InvalidPacketSequence {
                        given_sequence: msg.packet.sequence,
                        next_sequence: msg.next_seq_recv_on_b,
                    });
                }
                client_state_of_b_on_a.verify_next_sequence_recv(
                    msg.proof_height_on_b,
                    &conn_end_on_a,
                    &msg.proof_unreceived_on_b,
                    consensus_state_of_b_on_a.root(),
                    &msg.packet.port_on_b,
                    &msg.packet.chan_on_b,
                    msg.packet.sequence,
                )
            } else {
                client_state_of_b_on_a.verify_packet_receipt_absence(
                    msg.proof_height_on_b,
                    &conn_end_on_a,
                    &msg.proof_unreceived_on_b,
                    consensus_state_of_b_on_a.root(),
                    &msg.packet.port_on_b,
                    &msg.packet.chan_on_b,
                    msg.packet.sequence,
                )
            };
            next_seq_recv_verification_result
                .map_err(|e| ChannelError::PacketVerificationFailed {
                    sequence: msg.next_seq_recv_on_b,
                    client_error: e,
                })
                .map_err(PacketError::Channel)?;
        }

        let packet_res_chan = if chan_end_on_a.order_matches(&Order::Ordered) {
            // output.emit(IbcEvent::ChannelClosed(ChannelClosed::new(
            //     msg.packet.port_on_a.clone(),
            //     msg.packet.chan_on_a.clone(),
            //     chan_end_on_a.counterparty().port_id.clone(),
            //     chan_end_on_a.counterparty().channel_id.clone(),
            //     conn_id_on_a,
            //     chan_end_on_a.ordering,
            // )));
            chan_end_on_a.state = ChState::Closed;
            Some(chan_end_on_a)
        } else {
            None
        };

        let result = PacketResult::Timeout(TimeoutPacketResult {
            port_id: msg.packet.port_on_a.clone(),
            channel_id: msg.packet.chan_on_a.clone(),
            seq: msg.packet.sequence,
            channel: packet_res_chan,
        });

        // store
        self.chan_store.store_packet_result(result)
    }

    // PacketMsg::TimeoutOnClose(msg) => timeout_on_close::process(ctx, msg),
    pub fn timeout_on_close(&mut self, msg: &MsgTimeoutOnClose) -> Result<(), PacketError> {
        let packet = &msg.packet;
        let chan_end_on_a = self
            .chan_store
            .channel_end(&packet.port_on_a, &packet.chan_on_a)
            .map_err(PacketError::Channel)?;

        let counterparty =
            ChCounterparty::new(packet.port_on_b.clone(), Some(packet.chan_on_b.clone()));

        if !chan_end_on_a.counterparty_matches(&counterparty) {
            return Err(PacketError::InvalidPacketCounterparty {
                port_id: packet.port_on_b.clone(),
                channel_id: packet.chan_on_b.clone(),
            });
        }

        //verify the packet was sent, check the store
        let commitment_on_a = self.chan_store.get_packet_commitment(
            &packet.port_on_a,
            &packet.chan_on_a,
            &packet.sequence,
        )?;

        let expected_commitment_on_a = self.chan_store.packet_commitment(
            &packet.data,
            &packet.timeout_height_on_b,
            &packet.timeout_timestamp_on_b,
        );
        if commitment_on_a != expected_commitment_on_a {
            return Err(PacketError::IncorrectPacketCommitment {
                sequence: packet.sequence,
            });
        }

        let conn_id_on_a = chan_end_on_a.connection_hops()[0].clone();
        let conn_end_on_a = self
            .connection_end2(&conn_id_on_a)
            .map_err(PacketError::Channel)?;

        // Verify proofs
        {
            let client_id_on_a = conn_end_on_a.client_id();
            let client_state_of_b_on_a = self
                .client_state2(client_id_on_a)
                .map_err(PacketError::Channel)?;

            // The client must not be frozen.
            if client_state_of_b_on_a.is_frozen() {
                return Err(PacketError::FrozenClient {
                    client_id: client_id_on_a.clone(),
                });
            }

            let consensus_state_of_b_on_a = self
                .client_consensus_state2(client_id_on_a, &msg.proof_height_on_b)
                .map_err(PacketError::Channel)?;
            let prefix_on_b = conn_end_on_a.counterparty().prefix();
            let port_id_on_b = &chan_end_on_a.counterparty().port_id;
            let chan_id_on_b =
                chan_end_on_a
                    .counterparty()
                    .channel_id()
                    .ok_or(PacketError::Channel(
                        ChannelError::InvalidCounterpartyChannelId,
                    ))?;
            let conn_id_on_b = conn_end_on_a.counterparty().connection_id().ok_or(
                PacketError::UndefinedConnectionCounterparty {
                    connection_id: chan_end_on_a.connection_hops()[0].clone(),
                },
            )?;
            let expected_conn_hops_on_b = vec![conn_id_on_b.clone()];
            let expected_counterparty =
                ChCounterparty::new(packet.port_on_a.clone(), Some(packet.chan_on_a.clone()));
            let expected_chan_end_on_b = ChannelEnd::new(
                ChState::Closed,
                *chan_end_on_a.ordering(),
                expected_counterparty,
                expected_conn_hops_on_b,
                chan_end_on_a.version().clone(),
            );

            // Verify the proof for the channel state against the expected channel end.
            // A counterparty channel id of None in not possible, and is checked by validate_basic in msg.
            client_state_of_b_on_a
                .verify_channel_state(
                    msg.proof_height_on_b,
                    prefix_on_b,
                    &msg.proof_unreceived_on_b,
                    consensus_state_of_b_on_a.root(),
                    port_id_on_b,
                    chan_id_on_b,
                    &expected_chan_end_on_b,
                )
                .map_err(ChannelError::VerifyChannelFailed)
                .map_err(PacketError::Channel)?;

            let next_seq_recv_verification_result = if chan_end_on_a.order_matches(&Order::Ordered)
            {
                if packet.sequence < msg.next_seq_recv_on_b {
                    return Err(PacketError::InvalidPacketSequence {
                        given_sequence: packet.sequence,
                        next_sequence: msg.next_seq_recv_on_b,
                    });
                }
                client_state_of_b_on_a.verify_next_sequence_recv(
                    msg.proof_height_on_b,
                    &conn_end_on_a,
                    &msg.proof_unreceived_on_b,
                    consensus_state_of_b_on_a.root(),
                    &packet.port_on_b,
                    &packet.chan_on_b,
                    packet.sequence,
                )
            } else {
                client_state_of_b_on_a.verify_packet_receipt_absence(
                    msg.proof_height_on_b,
                    &conn_end_on_a,
                    &msg.proof_unreceived_on_b,
                    consensus_state_of_b_on_a.root(),
                    &packet.port_on_b,
                    &packet.chan_on_b,
                    packet.sequence,
                )
            };
            next_seq_recv_verification_result
                .map_err(|e| ChannelError::PacketVerificationFailed {
                    sequence: msg.next_seq_recv_on_b,
                    client_error: e,
                })
                .map_err(PacketError::Channel)?;
        };

        let packet_res_chan = if chan_end_on_a.order_matches(&Order::Ordered) {
            // output.emit(IbcEvent::ChannelClosed(ChannelClosed::new(
            //     msg.packet.port_on_a.clone(),
            //     msg.packet.chan_on_a.clone(),
            //     chan_end_on_a.counterparty().port_id.clone(),
            //     chan_end_on_a.counterparty().channel_id.clone(),
            //     conn_id_on_a,
            //     chan_end_on_a.ordering,
            // )));
            Some(chan_end_on_a)
        } else {
            None
        };

        let result = PacketResult::Timeout(TimeoutPacketResult {
            port_id: packet.port_on_a.clone(),
            channel_id: packet.chan_on_a.clone(),
            seq: packet.sequence,
            channel: packet_res_chan,
        });

        // store
        self.chan_store.store_packet_result(result)
    }
}

impl MessageVerifier {
    fn increase_client_counter(&mut self) {
        self.client_ids_counter = self
            .client_ids_counter
            .checked_add(1)
            .expect("increase client counter overflow");
    }

    fn decode_client_state(&self, client_state: Any) -> Result<TmClientState, String> {
        TmClientState::try_from(client_state.clone())
            .map_err(|_| "ClientError::UnknownClientStateType".to_string())
    }

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
