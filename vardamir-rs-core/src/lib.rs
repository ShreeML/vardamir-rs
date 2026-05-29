use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
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

    pub fn prev_hash(&self) -> &[u8; 32] {
        &self.prev_hash
    }

    pub fn context_hash(&self) -> &[u8; 32] {
        &self.context_hash
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn decision(&self) -> &str {
        &self.decision
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }
}

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
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

    pub fn push_raw(&mut self, record: DecisionRecord) {
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

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    pub fn tamper_record(&mut self, index: usize, new_kind: String) {
        self.records[index].kind = new_kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_genesis() {
        let mut chain = DecisionChain::new();
        let record_1 = DecisionRecord::new(1200, "Turn Left".to_string(), "Navigation".to_string());
        assert!(record_1.is_genesis());
        chain.append(record_1);

        let record_2 = DecisionRecord::new(
            1202,
            "Located Target".to_string(),
            "Identification".to_string(),
        );
        chain.append(record_2);

        let mut iter = chain.iter();
        iter.next();
        let record_2 = iter.next().unwrap();
        assert!(!record_2.is_genesis());
    }

    #[test]
    fn test_compute_hash() {
        let record_1 = DecisionRecord::new(1200, "Turn Left".to_string(), "Navigation".to_string());
        let record_2 = DecisionRecord::new(
            1202,
            "Located Target".to_string(),
            "Identification".to_string(),
        );
        let record_3 = DecisionRecord::new(
            1202,
            "Located Target".to_string(),
            "Identification".to_string(),
        );
        assert_eq!(record_2.compute_hash(), record_3.compute_hash());
        assert_ne!(record_1.compute_hash(), record_2.compute_hash());
    }

    #[test]
    fn test_append() {
        let mut chain = DecisionChain::new();
        let record_1 = DecisionRecord::new(1200, "Turn Left".to_string(), "Navigation".to_string());
        let hash = record_1.compute_hash();
        chain.append(record_1);

        let record_2 = DecisionRecord::new(
            1202,
            "Located Target".to_string(),
            "Identification".to_string(),
        );
        chain.append(record_2);

        let mut iter = chain.iter();
        iter.next();
        let record_2 = iter.next().unwrap();
        assert_eq!(hash, record_2.prev_hash);
    }

    #[test]
    fn test_verify() {
        let mut chain = DecisionChain::new();
        let record_1 = DecisionRecord::new(1200, "Turn Left".to_string(), "Navigation".to_string());
        chain.append(record_1);

        let record_2 = DecisionRecord::new(
            1202,
            "Located Target".to_string(),
            "Identification".to_string(),
        );
        chain.append(record_2);

        let record_3 = DecisionRecord::new(
            1204,
            "Preparing systems".to_string(),
            "Preparation".to_string(),
        );
        chain.append(record_3);

        assert!(chain.verify());
        chain.tamper_record(1, "tampered".to_string());
        assert!(!chain.verify());
    }

    #[test]
    fn test_push_raw() {
        let mut chain = DecisionChain::new();
        let record_1 = DecisionRecord::new(1200, "Turn Left".to_string(), "Navigation".to_string());
        chain.append(record_1);

        let record_2 = DecisionRecord::new(
            1202,
            "Located Target".to_string(),
            "Identification".to_string(),
        );
        let hash = record_2.prev_hash().clone();
        chain.push_raw(record_2);

        let mut iter = chain.iter();
        iter.next();
        let pushed = iter.next().unwrap();

        assert_eq!(&hash, pushed.prev_hash())
    }
}
