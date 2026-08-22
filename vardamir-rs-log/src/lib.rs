#![allow(dead_code)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use vardamir_rs_attest::AttestationKey;
use vardamir_rs_core::{DecisionChain, DecisionRecord, VardamirError};

extern crate alloc;
pub use alloc::format;
pub use alloc::string::String;

pub const MAGIC: &[u8; 4] = b"VDMR";
pub const VERSION: u16 = 1;
pub const FILE_HEADER_SIZE: usize = 8;
pub const RECORD_HEADER_SIZE: usize = 16; // length(8) + crc(8); signature(32) comes after the data

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Checkpoint {
    record_count: u64,
    last_hash: [u8; 32],
    time: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum LogEntry {
    Decision(DecisionRecord),
    Checkpoint(Checkpoint),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum ScanOutcome {
    Clean {
        record_count: u64,
        last_hash: [u8; 32],
    },
    Corrupted {
        record_count: u64,
        last_hash: [u8; 32],
    },
}

pub struct LogWriter {
    file: BufWriter<File>,
    record_count: u64,
    last_hash: [u8; 32],
    last_time: u64,
}

fn fallback_path(original: &str) -> String {
    let mut unavailabilty = std::path::Path::new(original).exists();
    let mut n = 1;
    let mut path: String = original.into();

    if !unavailabilty {
        path = original.into();
    }
    while unavailabilty {
        path = format!("{original}.recovered{n}");
        unavailabilty = std::path::Path::new(&path).exists();
        n += 1;
    }
    path
}

fn scan_existing(file: &mut File) -> Result<ScanOutcome, VardamirError> {
    file.seek(SeekFrom::Start(FILE_HEADER_SIZE as u64))?;

    let mut record_count: u64 = 0;
    let mut last_hash: [u8; 32] = [0u8; 32];
    let mut corrupted = false;

    loop {
        let mut length = [0u8; 8];
        match file.read_exact(&mut length) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(_) => {
                return Err(VardamirError::InvalidData(
                    "Failed to read record length".into(),
                ));
            }
        }
        let length = u64::from_be_bytes(length);
        if length > 1_000_000 {
            return Err(VardamirError::InvalidData("Record too large".into()));
        }

        let mut checksum = [0u8; 8];
        file.read_exact(&mut checksum)?;
        let checksum = u64::from_be_bytes(checksum);

        let mut bytes = vec![0u8; length as usize];
        file.read_exact(&mut bytes)?;

        let crc = crc32fast::hash(&bytes) as u64;

        if crc != checksum {
            corrupted = true;
            break;
        }

        let mut signature = [0u8; 32];
        file.read_exact(&mut signature)
            .map_err(|_| VardamirError::InvalidData(String::from("Failed to read signature")))?;

        let record: DecisionRecord =
            bincode::deserialize(&bytes).map_err(|_| VardamirError::SerializationError)?;

        last_hash = record.compute_hash();
        record_count += 1;
    }
    if corrupted {
        return Ok(ScanOutcome::Corrupted {
            record_count,
            last_hash,
        });
    }
    Ok(ScanOutcome::Clean {
        record_count,
        last_hash,
    })
}

impl LogWriter {
    pub fn create(path: &str) -> Result<(Self, String), VardamirError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)?;

        let mut needs_header = file.metadata()?.len();

        let mut actual_path: String = path.into();

        let (record_count, last_hash) = if needs_header == 0 {
            (0, [0u8; 32])
        } else {
            match scan_existing(&mut file) {
                Ok(ScanOutcome::Clean {
                    record_count,
                    last_hash,
                }) => {
                    actual_path = path.into();
                    (record_count, last_hash)
                }
                Ok(ScanOutcome::Corrupted {
                    record_count,
                    last_hash,
                }) => {
                    actual_path = fallback_path(path);
                    file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .read(true)
                        .open(&actual_path)?;
                    needs_header = 0;
                    (record_count, last_hash)
                }
                Err(e) => return Err(e),
            }
        };

        let mut writer = LogWriter {
            file: BufWriter::with_capacity(8192, file),
            record_count,
            last_hash,
            last_time: 0,
        };

        if needs_header == 0 {
            writer.write_file_header()?;
        }
        Ok((writer, actual_path))
    }

    fn write_file_header(&mut self) -> Result<(), VardamirError> {
        self.file.write_all(MAGIC)?;
        self.file.write_all(&VERSION.to_be_bytes())?;
        self.file.write_all(&[0u8; 2])?;

        Ok(())
    }

    pub fn write_record(
        &mut self,
        record: &DecisionRecord,
        key: &AttestationKey,
    ) -> Result<(), VardamirError> {
        let bytes = bincode::serialize(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let len = bytes.len() as u64;
        let checksum = crc32fast::hash(&bytes) as u64;

        self.file.write_all(&len.to_be_bytes())?;
        self.file.write_all(&checksum.to_be_bytes())?;

        self.file.write_all(&bytes)?;

        let signature = key.sign(&bytes);
        self.file.write_all(&signature)?;

        self.file.flush()?;

        self.record_count += 1;
        self.last_hash = record.compute_hash();

        Ok(())
    }

    pub fn write_chain(
        &mut self,
        chain: &DecisionChain,
        keys: &[AttestationKey],
    ) -> Result<(), VardamirError> {
        if chain.len() != keys.len() {
            return Err(VardamirError::InvalidData(String::from(
                "Number of keys must match number of records",
            )));
        }

        for (record, key) in chain.iter().zip(keys) {
            self.write_record(record, key)?;
        }
        Ok(())
    }
}

pub struct LogReader {
    file: BufReader<File>,
}

impl LogReader {
    pub fn open(path: &str) -> Result<Self, VardamirError> {
        let file = OpenOptions::new().read(true).open(path)?;
        let mut reader = LogReader {
            file: BufReader::with_capacity(8192, file),
        };
        reader.verify_file_header()?;
        Ok(reader)
    }

    pub fn verify_file_header(&mut self) -> Result<(), VardamirError> {
        let mut magic = [0u8; 4];
        self.file.read_exact(&mut magic)?;

        if &magic != MAGIC {
            return Err(VardamirError::InvalidData(String::from(
                "not a valid Vardamir log - magic number mismatch",
            )));
        }

        let mut version = [0u8; 2];
        self.file.read_exact(&mut version)?;
        let version = u16::from_be_bytes(version);

        if version > VERSION {
            return Err(VardamirError::InvalidData(format!(
                "Invalid VDMR logs version: {version}"
            )));
        }

        let mut padding = [0u8; 2];
        self.file.read_exact(&mut padding)?;

        Ok(())
    }

    pub fn record_reader(
        &mut self,
        key: &AttestationKey,
    ) -> Result<Option<DecisionRecord>, VardamirError> {
        let mut length = [0u8; 8];
        match self.file.read_exact(&mut length) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(_) => {
                return Err(VardamirError::InvalidData(
                    "Failed to read record length".into(),
                ));
            }
        }
        let length = u64::from_be_bytes(length);
        if length > 1_000_000 {
            return Err(VardamirError::InvalidData("Record too large".into()));
        }

        let mut checksum = [0u8; 8];
        self.file.read_exact(&mut checksum)?;
        let checksum = u64::from_be_bytes(checksum);

        let mut bytes = vec![0u8; length as usize];
        self.file.read_exact(&mut bytes)?;

        let crc = crc32fast::hash(&bytes) as u64;

        if crc != checksum {
            return Err(VardamirError::CorruptionDetected);
        }

        let mut signature = [0u8; 32];
        self.file
            .read_exact(&mut signature)
            .map_err(|_| VardamirError::InvalidData(String::from("Failed to read signature")))?;

        if !key.verify(&bytes, &signature) {
            return Err(VardamirError::SignatureVerificationFailed);
        };

        let record: DecisionRecord =
            bincode::deserialize(&bytes).map_err(|_| VardamirError::SerializationError)?;

        Ok(Some(record))
    }

    pub fn read_all(&mut self, keys: &[AttestationKey]) -> Result<DecisionChain, VardamirError> {
        let mut records = DecisionChain::new();
        let mut key_index = 0;

        while key_index < keys.len() {
            match self.record_reader(&keys[key_index]) {
                Ok(Some(record)) => {
                    records.append(record);
                    key_index += 1;
                }
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }

        if !records.verify() {
            return Err(VardamirError::ChainVerificationFailed);
        }

        if records.len() != key_index {
            return Err(VardamirError::InvalidData(alloc::format!(
                "Mismatch: {} records read, but used {} keys",
                records.len(),
                key_index
            )));
        }

        Ok(records)
    }
}

pub fn recover(path: &str) -> Result<(), VardamirError> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;

    file.seek(SeekFrom::Start(FILE_HEADER_SIZE as u64))?;

    loop {
        let safe_point = file.stream_position()?;
        let mut length = [0u8; 8];

        if let Err(e) = file.read_exact(&mut length) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(());
            }
            return Err(e.into());
        }

        let length = u64::from_be_bytes(length);

        if length == 0 || length > 1_000_000 {
            file.set_len(safe_point)?;
            return Ok(());
        }

        let mut crc = [0u8; 8];
        file.read_exact(&mut crc)?;
        let crc = u64::from_be_bytes(crc);

        let mut bytes = vec![0u8; length as usize];
        file.read_exact(&mut bytes)?;

        let crc_expected = crc32fast::hash(&bytes) as u64;

        if crc_expected != crc {
            file.set_len(safe_point)?;
            return Ok(());
        }

        let mut signature = [0u8; 32];
        if file.read_exact(&mut signature).is_err() {
            file.set_len(safe_point)?;
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vardamir_rs_attest::{DeviceIdentity, ModelCommitment};
    use vardamir_rs_core::{DecisionChain, DecisionRecord};

    #[test]
    fn test_write_and_read() {
        let mut chain = DecisionChain::new();
        chain.append(DecisionRecord::new(
            1200,
            String::from("Turn Left"),
            String::from("Navigation"),
        ));
        chain.append(DecisionRecord::new(
            1202,
            String::from("Located Target"),
            String::from("Identification"),
        ));
        chain.append(DecisionRecord::new(
            1204,
            String::from("Preparing systems"),
            String::from("Preparation"),
        ));

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key1 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key2 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v2");
        let key3 = AttestationKey::derive(&identity, &commitment);

        let keys = vec![key1.clone(), key2.clone(), key3.clone()];

        let path = format!("test_read_and_write_{}.vdmr", std::process::id());
        let (mut writer, _actual_path) =
            LogWriter::create(&path).expect("failed to create LogWriter");

        writer
            .write_chain(&chain, &keys)
            .expect("failed to write chain");

        let mut reader = LogReader::open(&path).expect("failed to open LogReader");
        let log = reader.read_all(&keys).expect("failed to read all records");

        assert_eq!(chain, log);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_catches_tampering() {
        let mut chain = DecisionChain::new();
        chain.append(DecisionRecord::new(
            1200,
            String::from("Turn Left"),
            String::from("Navigation"),
        ));
        chain.append(DecisionRecord::new(
            1202,
            String::from("Located Target"),
            String::from("Identification"),
        ));
        chain.append(DecisionRecord::new(
            1204,
            String::from("Preparing systems"),
            String::from("Preparation"),
        ));

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key1 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([5u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key2 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([3u8; 32]);
        let commitment = ModelCommitment::from_string("model_v2");
        let key3 = AttestationKey::derive(&identity, &commitment);

        let keys = vec![key1.clone(), key2.clone(), key3.clone()];

        let path = format!("tampering_{}.vdmr", std::process::id());
        let (mut writer, _actual_path) =
            LogWriter::create(&path).expect("failed to create LogWriter");
        writer
            .write_chain(&chain, &keys)
            .expect("failed to write chain");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("failed to open file for tampering");
        file.seek(SeekFrom::Start(
            FILE_HEADER_SIZE as u64 + RECORD_HEADER_SIZE as u64 + 48 + 8 + 8 + 20,
        ))
        .expect("failed to seek to tamper position");
        file.write_all(b"t").expect("failed to write tampered byte");

        let mut reader = LogReader::open(&path).expect("failed to open LogReader after tamper");
        let result = reader.read_all(&keys);
        assert!(
            result.is_err(),
            "expected Err due to CRC mismatch but got Ok"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_bad_tail() {
        let mut chain = DecisionChain::new();
        chain.append(DecisionRecord::new(
            1200,
            String::from("Turn Left"),
            String::from("Navigation"),
        ));
        chain.append(DecisionRecord::new(
            1202,
            String::from("Located Target"),
            String::from("Identification"),
        ));
        chain.append(DecisionRecord::new(
            1204,
            String::from("Preparing systems"),
            String::from("Preparation"),
        ));

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key1 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key2 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v2");
        let key3 = AttestationKey::derive(&identity, &commitment);

        let keys = vec![key1.clone(), key2.clone(), key3.clone()];

        let path = format!("bad_tail_{}.vdmr", std::process::id());
        let (mut writer, _actual_path) =
            LogWriter::create(&path).expect("failed to create LogWriter");
        writer
            .write_chain(&chain, &keys)
            .expect("failed to write chain");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("failed to open file for bad tail injection");
        file.seek(SeekFrom::End(0))
            .expect("failed to seek to end of file");
        file.write_all(b"test")
            .expect("failed to write garbage tail");

        recover(&path).expect("failed to recover log file");

        let mut reader = LogReader::open(&path).expect("failed to open LogReader after recovery");
        let log = reader
            .read_all(&keys)
            .expect("failed to read all records after recovery");

        assert_eq!(chain, log);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_path_usage() {
        let path = format!("path_{}_.vdmr", std::process::id());
        let (writer, actual_path) = LogWriter::create(&path).expect("failed to create LogWriter");

        assert_eq!(actual_path, path);
        assert_eq!(writer.record_count, 0);
        assert_eq!(writer.last_hash, [0u8; 32]);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_fresh_file() {
        let mut chain = DecisionChain::new();
        chain.append(DecisionRecord::new(
            1200,
            String::from("Turn Left"),
            String::from("Navigation"),
        ));
        chain.append(DecisionRecord::new(
            1202,
            String::from("Located Target"),
            String::from("Identification"),
        ));
        chain.append(DecisionRecord::new(
            1204,
            String::from("Preparing systems"),
            String::from("Preparation"),
        ));

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key1 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key2 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v2");
        let key3 = AttestationKey::derive(&identity, &commitment);

        let keys = vec![key1.clone(), key2.clone(), key3.clone()];

        let path = format!("fresh_{}.vdmr", std::process::id());
        let (mut writer, _actual_path) =
            LogWriter::create(&path).expect("failed to create LogWriter");
        writer
            .write_chain(&chain, &keys)
            .expect("failed to write chain");
        let last_hash = writer.last_hash;
        let record_count = writer.record_count;

        let (writer, _actual_path) = LogWriter::create(&path).expect("failed to create LogWriter");

        assert_eq!(writer.last_hash, last_hash);
        assert_eq!(writer.record_count, record_count);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_corrupted_file() {
        let mut chain = DecisionChain::new();
        chain.append(DecisionRecord::new(
            1200,
            String::from("Turn Left"),
            String::from("Navigation"),
        ));
        chain.append(DecisionRecord::new(
            1202,
            String::from("Located Target"),
            String::from("Identification"),
        ));
        chain.append(DecisionRecord::new(
            1204,
            String::from("Preparing systems"),
            String::from("Preparation"),
        ));

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key1 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([5u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key2 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([3u8; 32]);
        let commitment = ModelCommitment::from_string("model_v2");
        let key3 = AttestationKey::derive(&identity, &commitment);

        let keys = vec![key1.clone(), key2.clone(), key3.clone()];

        let path = format!("corrupted_{}.vdmr", std::process::id());
        let (mut writer, _actual_path) =
            LogWriter::create(&path).expect("failed to create LogWriter");
        writer
            .write_chain(&chain, &keys)
            .expect("failed to write chain");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("failed to open file for tampering");
        file.seek(SeekFrom::Start(
            FILE_HEADER_SIZE as u64 + RECORD_HEADER_SIZE as u64 + 48 + 8 + 8 + 20,
        ))
        .expect("failed to seek to tamper position");
        file.write_all(b"t").expect("failed to write tampered byte");

        let (_writer, actual_path) = LogWriter::create(&path).expect("failed to create LogWriter");

        assert_ne!(path, actual_path);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_fallback_collision() {
        let mut chain = DecisionChain::new();
        chain.append(DecisionRecord::new(
            1200,
            String::from("Turn Left"),
            String::from("Navigation"),
        ));
        chain.append(DecisionRecord::new(
            1202,
            String::from("Located Target"),
            String::from("Identification"),
        ));
        chain.append(DecisionRecord::new(
            1204,
            String::from("Preparing systems"),
            String::from("Preparation"),
        ));

        let identity = DeviceIdentity::new([1u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key1 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([5u8; 32]);
        let commitment = ModelCommitment::from_string("model_v1");
        let key2 = AttestationKey::derive(&identity, &commitment);

        let identity = DeviceIdentity::new([3u8; 32]);
        let commitment = ModelCommitment::from_string("model_v2");
        let key3 = AttestationKey::derive(&identity, &commitment);

        let keys = vec![key1.clone(), key2.clone(), key3.clone()];

        let path = format!("fallback_{}.vdmr", std::process::id());
        let (mut writer, _actual_path) =
            LogWriter::create(&path).expect("failed to create LogWriter");
        writer
            .write_chain(&chain, &keys)
            .expect("failed to write chain");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("failed to open file for tampering");
        file.seek(SeekFrom::Start(
            FILE_HEADER_SIZE as u64 + RECORD_HEADER_SIZE as u64 + 48 + 8 + 8 + 20,
        ))
        .expect("failed to seek to tamper position");
        file.write_all(b"t").expect("failed to write tampered byte");

        let (_writer, actual_path_1) =
            LogWriter::create(&path).expect("failed to create LogWriter");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("failed to open file for tampering");
        file.seek(SeekFrom::Start(
            FILE_HEADER_SIZE as u64 + RECORD_HEADER_SIZE as u64 + 48 + 8 + 8 + 21,
        ))
        .expect("failed to seek to tamper position");
        file.write_all(b"t").expect("failed to write tampered byte");

        let (_writer, actual_path_2) =
            LogWriter::create(&path).expect("failed to create LogWriter");

        assert_ne!(actual_path_1, actual_path_2);

        std::fs::remove_file(path).ok();
    }
}
