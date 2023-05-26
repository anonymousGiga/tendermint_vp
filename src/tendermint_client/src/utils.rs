use crate::prelude::*;
use crate::solomachine::datatype::DataType;
use crate::solomachine::sign_bytes;
use ibc::clients::ics07_tendermint::error::Error;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use tendermint_light_client_verifier::{types::Time, ProdVerifier, Verdict, Verifier};
pub trait IntoResult<T, E> {
    fn into_result(self) -> Result<T, E>;
}

impl IntoResult<(), Error> for Verdict {
    fn into_result(self) -> Result<(), Error> {
        match self {
            Verdict::Success => Ok(()),
            Verdict::NotEnoughTrust(reason) => Err(Error::NotEnoughTrustedValsSigned { reason }),
            Verdict::Invalid(detail) => Err(Error::VerificationError { detail }),
        }
    }
}
