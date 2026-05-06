#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Serialize, Deserialize)]
pub struct DecisionRecord {
    timestamp: u64,
    decision: String,
    context_hash: [u8; 32],
    prev_hash: [u8; 32],
    kind: String,
}

impl DecisionRecord {
    pub fn new(timestamp: u64, decision: String, kind: String) -> DecisionRecord {
        DecisionRecord {
            timestamp,
            decision,
            context_hash: [0u8; 32], //placeholder
            prev_hash: [0u8; 32],
            kind,
        }
    }

    pub fn summarize(&self) -> String {
        format!(
            "Decision of type {} at {} : {}",
            self.kind, self.timestamp, self.decision
        )
    }

    pub fn is_genesis(&self) -> bool {
        self.prev_hash == [0u8; 32]
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();

        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.decision.as_bytes());
        hasher.update(self.kind.as_bytes());
        let result: [u8; 32] = hasher.finalize().into();
        result
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DecisionChain {
    records: Vec<DecisionRecord>,
}

impl DecisionChain {
    pub fn new() -> DecisionChain {
        DecisionChain {
            records: Vec::new(),
        }
    }

    pub fn append(&mut self, mut record: DecisionRecord) {
        if let Some(prev_hash) = self.records.last() {
            record.prev_hash = prev_hash.compute_hash()
        }
        self.records.push(record);
    }

    pub fn verify(&self) -> bool {
        for (index, record) in self.records.iter().enumerate() {
            if index == 0 {
                continue;
            }
            let expected_hash = { &self.records[index - 1] }.compute_hash();
            if record.prev_hash != expected_hash {
                return false;
            }
        }
        true
    }

    pub fn iter(&self) -> std::slice::Iter<'_, DecisionRecord> {
        self.records.iter()
    }
}
