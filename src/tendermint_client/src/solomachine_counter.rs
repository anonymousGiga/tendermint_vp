use super::prelude::*;
pub struct SoloMachineCounter {
    sequence_cnt: u64,
}

impl SoloMachineCounter {
    pub fn new(sequence_cnt: u64) -> Self {
        SoloMachineCounter {
            sequence_cnt,
        }
    }

    pub fn sequence_cnt(&self) -> u64 {
        self.sequence_cnt
    }

    pub fn increase_sequence(&mut self) -> Result<(), String> {
        self.sequence_cnt = self.sequence_cnt.checked_add(1u64).ok_or("increase sequence error".to_string())?;
        Ok(())
    }
}

