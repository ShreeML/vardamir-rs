use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use vardamir_rs_attest::AttestationKey;
use vardamir_rs_core::{DecisionChain, DecisionRecord};

pub const MAGIC: &[u8; 4] = b"VDMR";
pub const VERSION: u16 = 1;
pub const FILE_HEADER_SIZE: usize = 8;
pub const RECORD_HEADER_SIZE: usize = 16; // length(8) + crc(8); signature(32) comes after the data

pub struct LogWriter {
    file: BufWriter<File>,
}

impl LogWriter {
    pub fn create(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        let needs_header = file.metadata()?.len();

        let mut writer = LogWriter {
            file: BufWriter::with_capacity(8192, file),
        };

        if needs_header == 0 {
            writer.write_file_header()?;
        }
        Ok(writer)
    }

    fn write_file_header(&mut self) -> std::io::Result<()> {
        self.file.write_all(MAGIC)?;
        self.file.write_all(&VERSION.to_be_bytes())?;
        self.file.write_all(&[0u8; 2])?;

        Ok(())
    }

    pub fn write_record(
        &mut self,
        record: &DecisionRecord,
        key: &AttestationKey,
    ) -> std::io::Result<()> {
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
        Ok(())
    }

    pub fn write_chain(
        &mut self,
        chain: &DecisionChain,
        keys: &[AttestationKey],
    ) -> std::io::Result<()> {
        if chain.len() != keys.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Number of keys must match number of records",
            ));
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
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).open(path)?;
        let mut reader = LogReader {
            file: BufReader::with_capacity(8192, file),
        };
        reader.verify_file_header()?;
        Ok(reader)
    }

    pub fn verify_file_header(&mut self) -> std::io::Result<()> {
        let mut magic = [0u8; 4];
        self.file.read_exact(&mut magic)?;

        if &magic != MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a valid Vardamir log - magic number mismatch",
            ));
        }

        let mut version = [0u8; 2];
        self.file.read_exact(&mut version)?;
        let version = u16::from_be_bytes(version);

        if version > VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid VDMR logs version: {version}"),
            ));
        }

        let mut padding = [0u8; 2];
        self.file.read_exact(&mut padding)?;

        Ok(())
    }

    pub fn record_reader(
        &mut self,
        key: &AttestationKey,
    ) -> std::io::Result<Option<DecisionRecord>> {
        let mut length = [0u8; 8];
        match self.file.read_exact(&mut length) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let length = u64::from_be_bytes(length);

        let mut checksum = [0u8; 8];
        self.file.read_exact(&mut checksum)?;
        let checksum = u64::from_be_bytes(checksum);

        let mut bytes = vec![0u8; length as usize];
        self.file.read_exact(&mut bytes)?;

        let crc = crc32fast::hash(&bytes) as u64;

        if crc != checksum {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CRC32 checksum mismatch - record is corrupted",
            ));
        }

        let mut signature = [0u8; 32];
        self.file.read_exact(&mut signature)?;

        if !key.verify(&bytes, &signature) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Key verification failed - record may have been corrupted with",
            ));
        };

        let record: DecisionRecord = bincode::deserialize(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Some(record))
    }

    pub fn read_all(&mut self, keys: &[AttestationKey]) -> std::io::Result<DecisionChain> {
        let mut records = DecisionChain::new();
        let mut key_index = 0;

        while key_index < keys.len() {
            match self.record_reader(&keys[key_index]) {
                Ok(Some(record)) => {
                    records.append(record);
                    key_index += 1;
                }
                Ok(None) => break,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }

        if !records.verify() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Chain verification failed - records may have been tampered with",
            ));
        }

        if records.len() != key_index {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Mismatch: {} records read, but used {} keys",
                    records.len(),
                    key_index
                ),
            ));
        }

        Ok(records)
    }
}

pub fn recover(path: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;

    file.seek(SeekFrom::Start(FILE_HEADER_SIZE as u64))?;

    loop {
        let safe_point = file.stream_position()?;
        let mut length = [0u8; 8];

        if let Err(e) = file.read_exact(&mut length) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(());
            }
            return Err(e);
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
            "Turn Left".to_string(),
            "Navigation".to_string(),
        ));
        chain.append(DecisionRecord::new(
            1202,
            "Located Target".to_string(),
            "Identification".to_string(),
        ));
        chain.append(DecisionRecord::new(
            1204,
            "Preparing all systems".to_string(),
            "Preparation".to_string(),
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
        let mut writer = LogWriter::create(&path).expect("failed to create LogWriter");

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
            "Turn Left".to_string(),
            "Navigation".to_string(),
        ));
        chain.append(DecisionRecord::new(
            1202,
            "Located Target".to_string(),
            "Identification".to_string(),
        ));
        chain.append(DecisionRecord::new(
            1204,
            "Preparing all systems".to_string(),
            "Preparation".to_string(),
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
        let mut writer = LogWriter::create(&path).expect("failed to create LogWriter");
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
            "Turn Left".to_string(),
            "Navigation".to_string(),
        ));
        chain.append(DecisionRecord::new(
            1202,
            "Located Target".to_string(),
            "Identification".to_string(),
        ));
        chain.append(DecisionRecord::new(
            1204,
            "Preparing all systems".to_string(),
            "Preparation".to_string(),
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
        let mut writer = LogWriter::create(&path).expect("failed to create LogWriter");
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
}
