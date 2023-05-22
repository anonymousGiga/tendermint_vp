use crate::prelude::*;
use ibc::core::ics02_client::handler::ClientResult;

use crate::conn_store::*;
use crate::tendermint_client::*;
// use hashbrown::HashMap;

// use ibc::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use ibc::core::ics02_client::msgs::ClientMsg;
use ibc::core::ics03_connection::msgs::conn_open_init::*;

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
use ibc::events::IbcEvent;
use ibc::handler::{HandlerOutput, HandlerResult};
use ibc::Height;

pub const DEFAULT_COMMITMENT_PREFIX: &str = "ibc";

pub struct MessageProcessor {
    tendermint_clients: HashMap<ClientId, TendermintClient>,
    conn_store: ConnectionStore,
    // chan_store: ChannStore,
}

impl MessageProcessor {
    pub fn new() -> Self {
        MessageProcessor {
            tendermint_clients: HashMap::new(),
            conn_store: ConnectionStore::new(),
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

    fn client_state(&self, client_id: &ClientId) -> Result<TmClientState, String> {
        let cs = self
            .tendermint_clients
            .get(client_id)
            .ok_or("Not found client!".to_string())?
            .client_state
            .clone();
        Ok(cs)
    }

    fn connection_end(&self, conn_id: &ConnectionId) -> Result<ConnectionEnd, String> {
        self.conn_store
            .connection_end(&conn_id)
            .map_err(|_| "ConnectionMismatch".to_string())
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
