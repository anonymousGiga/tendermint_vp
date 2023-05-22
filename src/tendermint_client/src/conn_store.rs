use crate::prelude::*;
use ibc::core::ics02_client::client_state::ClientState;
use ibc::core::ics02_client::consensus_state::ConsensusState;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc::core::ics03_connection::error::ConnectionError;
use ibc::core::ics03_connection::handler::ConnectionResult;
use ibc::core::ics03_connection::version::{get_compatible_versions, pick_version, Version};
use ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use ibc::core::ics24_host::identifier::{ClientId, ConnectionId};
use ibc::Height;
use ibc_proto::google::protobuf::Any;

use hashbrown::HashMap;

pub struct ConnectionStore {
    connections: HashMap<ConnectionId, ConnectionEnd>,
    client_connections: HashMap<ClientId, Vec<ConnectionId>>,
    connections_counter: u64,
}

impl ConnectionStore {
    pub fn new() -> Self {
        ConnectionStore {
            connections: HashMap::new(),
            client_connections: HashMap::new(),
            connections_counter: 0u64,
        }
    }
}

impl ConnectionStore {
    /// Stores the given connection_end at a path associated with the connection_id.
    pub fn store_connection(
        &mut self,
        connection_id: ConnectionId,
        connection_end: ConnectionEnd,
    ) -> Result<(), ConnectionError> {
        self.connections.insert(connection_id, connection_end);
        Ok(())
    }

    /// Stores the given connection_id at a path associated with the client_id.
    pub fn store_connection_to_client(
        &mut self,
        connection_id: ConnectionId,
        client_id: ClientId,
    ) -> Result<(), ConnectionError> {
        if let Some(connections) = self.client_connections.get_mut(&client_id) {
            connections.push(connection_id);
        } else {
            let connections = vec![connection_id];
            self.client_connections.insert(client_id, connections);
        }
        Ok(())
    }

    /// Called upon connection identifier creation (Init or Try process).
    /// Increases the counter which keeps track of how many connections have been created.
    /// Should never fail.
    pub fn increase_connection_counter(&mut self) {
        self.connections_counter = self
            .connections_counter
            .checked_add(1)
            .expect("increase connection counter overflow");
    }
}

impl ConnectionStore {
    pub fn get_compatible_versions(&self) -> Vec<Version> {
        get_compatible_versions()
    }

    /// Function required by ICS 03. Returns one version out of the supplied list of versions, which the
    /// connection handshake protocol prefers.
    pub fn pick_version(
        &self,
        supported_versions: &[Version],
        counterparty_candidate_versions: &[Version],
    ) -> Result<Version, ConnectionError> {
        pick_version(supported_versions, counterparty_candidate_versions)
    }

    /// Returns the ConnectionEnd for the given identifier `conn_id`.
    pub fn connection_end(&self, conn_id: &ConnectionId) -> Result<ConnectionEnd, ConnectionError> {
        self.connections.get(conn_id).map(|c| c.clone()).ok_or(
            ConnectionError::ConnectionMismatch {
                connection_id: conn_id.clone(),
            },
        )
    }

    /// Returns a counter on how many connections have been created thus far.
    /// The value of this counter should increase only via method
    /// `ConnectionKeeper::increase_connection_counter`.
    pub fn connection_counter(&self) -> Result<u64, ConnectionError> {
        Ok(self.connections_counter)
    }
}
