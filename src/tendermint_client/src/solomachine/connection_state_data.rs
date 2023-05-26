use super::error::Error;
use crate::prelude::*;
use ibc::core::ics03_connection::connection::ConnectionEnd;
use ibc_proto::ibc::lightclients::solomachine::v1::ConnectionStateData as RawConnectionStateData;
use ibc_proto::protobuf::Protobuf;

/// ConnectionStateData returns the SignBytes data for connection state
/// verification.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, PartialEq)]
pub struct ConnectionStateData {
    pub path: Vec<u8>,
    pub connection: Option<ConnectionEnd>,
}

impl Protobuf<RawConnectionStateData> for ConnectionStateData {}

impl TryFrom<RawConnectionStateData> for ConnectionStateData {
    type Error = Error;

    fn try_from(raw: RawConnectionStateData) -> Result<Self, Self::Error> {
        let connection = raw
            .connection
            .ok_or(Error::ConnectionEndIsEmpty)?
            .try_into()
            .map_err(Error::ConnectionError)?;
        Ok(Self {
            path: raw.path,
            connection: Some(connection),
        })
    }
}

impl From<ConnectionStateData> for RawConnectionStateData {
    fn from(value: ConnectionStateData) -> Self {
        Self {
            path: value.path,
            connection: Some(value.connection.unwrap().into()),
        }
    }
}
