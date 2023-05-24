pub mod client_state;
pub mod consensus_state;
pub mod error;
pub mod header;

pub const SOLOMACHINE_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.solomachine.v2.ClientState";
pub const SOLOMACHINE_CONSENSUS_STATE_TYPE_URL: &str =
    "/ibc.lightclients.solomachine.v2.ConsensusState";
pub const SOLOMACHINE_HEADER_TYPE_URL: &str = "/ibc.lightclients.solomachine.v2.Header";
