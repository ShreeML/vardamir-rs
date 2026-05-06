#![allow(dead_code)]
#![allow(unused_imports)]

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use vardamir_rs_core::{DecisionChain, DecisionRecord};

pub const MAGIC: &[u8; 4] = b"VDMR";
pub const VERSION: u16 = 1;
pub const FILE_HEADER_SIZE: usize = 8;
pub const RECORD_HEADER_SIZE: usize = 16;

pub struct LogWriter {
    file: BufWriter<File>,
}

impl LogWriter {
    pub fn create(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(path)?;

        let mut writer = LogWriter {
            file: BufWriter::with_capacity(8192, file),
        };
        writer.write_file_header()?;
        Ok(writer)
    }

    fn write_file_header(&mut self) -> std::io::Result<()> {
        self.file.write_all(MAGIC)?;
        self.file.write_all(&VERSION.to_be_bytes())?;
        self.file.write_all(&[0u8; 2])?;

        Ok(())
    }

    pub fn write_record(&mut self, record: &DecisionRecord) -> std::io::Result<()> {
        let bytes = bincode::serialize(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let len = bytes.len() as u64;
        let checksum = crc32fast::hash(&bytes) as u64;

        self.file.write_all(&len.to_be_bytes())?;
        self.file.write_all(&checksum.to_be_bytes())?;

        self.file.write_all(&bytes)?;
        self.file.flush()?;
        Ok(())
    }

    pub fn write_chain(&mut self, chain: &DecisionChain) -> std::io::Result<()> {
        for record in chain.iter() {
            self.write_record(record)?;
        }
        Ok(())
    }
}

pub struct LogReader {
    file: BufReader<File>,
}

impl LogReader {
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)?;
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

    pub fn record_reader(&mut self) -> std::io::Result<Option<DecisionRecord>> {
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
        let record: DecisionRecord = bincode::deserialize(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Some(record))
    }

    pub fn read_all(&mut self) -> std::io::Result<Vec<DecisionRecord>>{
        let mut records  = vec![];
        loop{
            match self.record_reader(){
            Ok(Some(record)) => records.push(record),
            Ok(None) => break,
            Err(e) => return Err(e),
            }
        }
        Ok(records)
    }
}

pub fn recover(path : &str) -> std::io::Result<()>{
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;

    file.seek(SeekFrom::Start(FILE_HEADER_SIZE as u64))?;

    loop {
        let safe_point = file.seek(SeekFrom::Current(0))?;

        let mut length = [0u8; 8];
        match file.read_exact(&mut length){
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break Ok(()),
            Err(e) => return Err(e),
        }
        
        let length = u64::from_be_bytes(length);

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
    }
}