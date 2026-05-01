#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Serialize, Deserialize)]
pub struct DecisionRecord {
    timestamp: u64,
    decision: String,
    context_hash: Vec<u8>,
    prev_hash: Vec<u8>,
    kind: DecisionKind,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DecisionKind {
    Navigate,
    Classify,
    Abort,
}

impl DecisionRecord {
    pub fn new(timestamp: u64, decision: String, kind: DecisionKind) -> DecisionRecord {
        DecisionRecord {
            timestamp,
            decision,
            context_hash: Vec::new(),
            prev_hash: Vec::new(),
            kind,
        }
    }

    pub fn summarize(&self) -> String {
        let kind_of = match self.kind {
            DecisionKind::Navigate => "Navigate",
            DecisionKind::Classify => "Classify",
            DecisionKind::Abort => "Abort",
        };
        format!(
            "Decision of type {} at {} : {}",
            kind_of, self.timestamp, self.decision
        )
    }

    pub fn is_genesis(&self) -> bool {
        self.prev_hash.is_empty()
    }

    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha3_256::new();

        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.decision.as_bytes());

        let result: Vec<u8> = hasher.finalize().to_vec();
        result
    }
}

#[derive(Debug,Serialize,Deserialize)]
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
}
