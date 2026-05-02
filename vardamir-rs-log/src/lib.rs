#![allow(dead_code)]
#![allow(unused_imports)]

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
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

    pub fn write_file_header(&mut self) -> std::io::Result<()> {
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
}
