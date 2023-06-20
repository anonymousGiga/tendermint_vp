use candid::{CandidType, Decode, Deserialize, Encode};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable};
use std::{borrow::Cow, cell::RefCell};
use tendermint_client::tendermint_client::TendermintClient;

const MAX_STR_DATA_SIZE: u32 = 16;
const MAX_VEC_DATA_SIZE: u32 = 4096;
const MAX_TUPLE_DATA_SIZE: u32 = 4096;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct StringData(pub String);

impl Storable for StringData {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        // String already implements `Storable`.
        self.0.to_bytes()
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self(String::from_bytes(bytes))
    }
}

impl BoundedStorable for StringData {
    const MAX_SIZE: u32 = MAX_STR_DATA_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

#[derive(CandidType, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TupleStringData {
    pub data1: String,
    pub data2: String,
}

impl Storable for TupleStringData {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for TupleStringData {
    const MAX_SIZE: u32 = MAX_TUPLE_DATA_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

pub struct VecData(pub Vec<u8>);

impl Storable for VecData {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        // Vec<u8> already implements `Storable`.
        self.0.to_bytes()
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Self(<Vec<u8>>::from_bytes(bytes))
    }
}

impl BoundedStorable for VecData {
    const MAX_SIZE: u32 = MAX_VEC_DATA_SIZE;
    const IS_FIXED_SIZE: bool = false;
}

#[derive(CandidType, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TupleData {
    pub data1: String,
    pub data2: String,
    pub data3: u64,
}

impl Storable for TupleData {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for TupleData {
    const MAX_SIZE: u32 = MAX_TUPLE_DATA_SIZE;
    const IS_FIXED_SIZE: bool = false;
}
