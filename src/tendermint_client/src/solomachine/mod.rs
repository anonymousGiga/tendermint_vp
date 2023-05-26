pub mod client_state;
pub mod connection_state_data;
pub mod consensus_state;
pub mod datatype;
pub mod error;
pub mod header;
pub mod header_data;
pub mod misbehaviour;
pub mod proofs;
pub mod sign_bytes;
pub mod signature_and_data;
pub mod utils;

pub const SOLOMACHINE_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.solomachine.v1.ClientState";
pub const SOLOMACHINE_CONSENSUS_STATE_TYPE_URL: &str =
    "/ibc.lightclients.solomachine.v1.ConsensusState";
pub const SOLOMACHINE_HEADER_TYPE_URL: &str = "/ibc.lightclients.solomachine.v1.Header";
