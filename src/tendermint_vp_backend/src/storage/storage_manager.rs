use candid::{CandidType, Decode, Deserialize, Encode};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, DefaultMemoryImpl, StableBTreeMap, Storable};
use std::{borrow::Cow, cell::RefCell};

thread_local! {
    // The memory manager is used for simulating multiple memories. Given a `MemoryId` it can
    // return a memory that can be used by stable structures.
    pub static MEMORY_MANAGER: RefCell<(MemoryManager<DefaultMemoryImpl>, u8)> =
        RefCell::new((MemoryManager::init(DefaultMemoryImpl::default()), 0u8));

    // // Initialize a `StableBTreeMap` with `MemoryId(0)`.
    // static MAP: RefCell<StableBTreeMap<UserName, UserData, Memory>> = RefCell::new(
    //     StableBTreeMap::init(
    //         MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
    //     )
    // );
}

pub fn alloc_memory() {
    use ic_stable_structures::{
        BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable, Vec as StableVec,
    };
    MEMORY_MANAGER.with(|instance| {
        let mut instance = instance.borrow_mut();
        let mut map: BTreeMap<u64, u64, _> =
            BTreeMap::init(instance.0.get(MemoryId::new(instance.1)));
        instance.1 += 1;

        ic_cdk::println!("============== instance.cnt = {:?}", instance.1);

        for i in 0..111 {
            map.insert(i, i);
        }
    });
}

pub fn restore_from_memory(id: u8) {
    use hashbrown::HashMap;
    use ic_stable_structures::{
        BTreeMap, BoundedStorable, DefaultMemoryImpl, Storable, Vec as StableVec,
    };

    let mut sequence_time = HashMap::new();
    MEMORY_MANAGER.with(|instance| {
        let instance = instance.borrow();
        let map: BTreeMap<u64, u64, _> = BTreeMap::init(instance.0.get(MemoryId::new(id)));

        let _ = map
            .iter()
            .map(|(k, v)| {
                sequence_time.insert(k, v);
            })
            .collect::<Vec<_>>();
    });

    for (k, v) in sequence_time {
        ic_cdk::println!("restore k: {:?}, v: {:?}", k, v);
    }
}
