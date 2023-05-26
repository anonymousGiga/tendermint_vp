// use super::datatype::DataType;
use ibc_proto::ibc::lightclients::solomachine::v1::DataType;
use ibc_proto::ibc::lightclients::solomachine::v1::SignBytes;

use super::sign_bytes;
use crate::prelude::*;
use ibc::clients::ics07_tendermint::error::Error;
use ibc_proto::protobuf::Protobuf;
use prost::Message;

pub(crate) fn construct_sign_bytes(
    sequence: u64,
    timestamp: u64,
    data_type: DataType,
    data: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let sign_bytes = SignBytes {
        sequence,
        timestamp,
        diversifier: "oct".to_string(),
        data_type: data_type.into(),
        data,
    };

    Ok(sign_bytes.encode_to_vec())
}
