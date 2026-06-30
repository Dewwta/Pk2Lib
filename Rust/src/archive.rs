use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::blowfish::Blowfish;

pub const SRO_PASSWORD: &[u8] = b"169841";

const JOYMAX_SALT: [u8; 10] = [
    0x03, 0xF8, 0xE4, 0x44, 0x88, 0x99, 0x3F, 0x64, 0xFE, 0x35,
];

const HEADER_SIZE: usize = 256;
const ENTRY_SIZE: usize = 128;
const ENTRIES_PER_BLOCK: usize = 20;
const BLOCK_SIZE: usize = ENTRY_SIZE * ENTRIES_PER_BLOCK; // 2560

#[derive(Debug)]
pub enum Pk2Error {
    Io(std::io::Error),
    NotOpen,
    NotWritable,
    NotFound,
    BadFormat(&'static str),
}

impl From<std::io::Error> for Pk2Error {
    fn from(e: std::io::Error) -> Self {
        Pk2Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Pk2Error>;

#[derive(Clone, Copy, PartialEq)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum EntryType {
    Empty,
    Folder,
    File,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub etype: EntryType,
    pub name: String,
    pub position: i64,
    pub size: u32,
    pub next_chain: i64,
}

pub struct Pk2Archive {
    file: Option<File>,
    bf: Blowfish,
    encrypted: bool,
    writable: bool,
}

impl Default for Pk2Archive {
    fn default() -> Self {
        Pk2Archive {
            file: None,
            bf: Blowfish::new(),
            encrypted: false,
            writable: false,
        }
    }
}

impl Pk2Archive {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_open(&self) -> bool {
        self.file.is_some()
    }
    pub fn is_writable(&self) -> bool {
        self.writable
    }
    
    pub fn make_silkroad_key() -> [u8; 8] {
        let mut key = [0u8; 8];
        // The C++ produces a 6-byte effective key. Per your reader:
        // key[i] = password[i] ^ salt[i], non-standard 10-byte salt.
        for i in 0..6 {
            let p = SRO_PASSWORD.get(i).copied().unwrap_or(0);
            key[i] = p ^ JOYMAX_SALT[i];
        }
        key
    }

    pub fn open(&mut self, path: &Path, mode: OpenMode) -> Result<()> {
        let writable = mode == OpenMode::ReadWrite;
        let file = OpenOptions::new()
            .read(true)
            .write(writable)
            .open(path)?;
        self.file = Some(file);
        self.writable = writable;
        self.init_key();
        self.read_header()?;
        Ok(())
    }

    fn init_key(&mut self) {
        let key = Self::make_silkroad_key();
        self.bf.set_key(&key[..6]);
    }

    fn read_header(&mut self) -> Result<()> {
        let f = self.file.as_mut().ok_or(Pk2Error::NotOpen)?;
        f.seek(SeekFrom::Start(0))?;
        let mut hdr = [0u8; HEADER_SIZE];
        f.read_exact(&mut hdr)?;
        // encryption flag at offset 30 (name[30]) + version[4] = byte 34
        self.encrypted = hdr[34] == 1;
        Ok(())
    }

    //block I/O 

    fn read_block(&mut self, offset: i64) -> Result<[Entry; ENTRIES_PER_BLOCK]> {
        let f = self.file.as_mut().ok_or(Pk2Error::NotOpen)?;
        f.seek(SeekFrom::Start(offset as u64))?;
        let mut raw = vec![0u8; BLOCK_SIZE];
        f.read_exact(&mut raw)?;
        if self.encrypted {
            self.bf.decrypt_ecb(&mut raw);
        }
        Ok(Self::parse_block(&raw))
    }

    fn parse_block(raw: &[u8]) -> [Entry; ENTRIES_PER_BLOCK] {
        std::array::from_fn(|i| {
            let off = i * ENTRY_SIZE;
            let e = &raw[off..off + ENTRY_SIZE];
            let etype = match e[0] {
                1 => EntryType::Folder,
                2 => EntryType::File,
                _ => EntryType::Empty,
            };
            // name[81] starts at byte 1
            let name_bytes = &e[1..1 + 81];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(81);
            let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
            // position: i64 at offset 1 + 81 + (3 * 8) = 106
            let position = i64::from_le_bytes(e[106..114].try_into().unwrap());
            // size: u32 at 114
            let size = u32::from_le_bytes(e[114..118].try_into().unwrap());
            // nextChain: i64 at 118
            let next_chain = i64::from_le_bytes(e[118..126].try_into().unwrap());
            Entry { etype, name, position, size, next_chain }
        })
    }

    // public read

    pub fn read_file(&mut self, archive_path: &str) -> Result<Vec<u8>> {
        let entry = self.find_entry(archive_path)?;
        if entry.etype != EntryType::File {
            return Err(Pk2Error::NotFound);
        }
        let f = self.file.as_mut().ok_or(Pk2Error::NotOpen)?;
        f.seek(SeekFrom::Start(entry.position as u64))?;
        let mut out = vec![0u8; entry.size as usize];
        f.read_exact(&mut out)?;
        Ok(out)
    }

    pub fn exists(&mut self, archive_path: &str) -> bool {
        self.find_entry(archive_path).is_ok()
    }

    /// list immediate children
    pub fn list(&mut self, folder_path: &str) -> Result<Vec<Entry>> {
        let block_off = self.folder_block_offset(folder_path)?;
        let mut out = Vec::new();
        self.walk_folder(block_off, |e| {
            if e.etype != EntryType::Empty && e.name != "." && e.name != ".." {
                out.push(e.clone());
            }
        })?;
        Ok(out)
    }

    // traversal

    fn walk_folder<F: FnMut(&Entry)>(&mut self, mut block_off: i64, mut visit: F) -> Result<()> {
        loop {
            let block = self.read_block(block_off)?;
            for e in &block {
                visit(e);
            }
            // chain continues via entries[19].next_chain
            let next = block[ENTRIES_PER_BLOCK - 1].next_chain;
            if next == 0 {
                break;
            }
            block_off = next;
        }
        Ok(())
    }

    fn folder_block_offset(&mut self, folder_path: &str) -> Result<i64> {
        // Root folder's first block sits right after the 256-byte header.
        let norm = Self::normalize(folder_path);
        if norm.is_empty() {
            return Ok(HEADER_SIZE as i64);
        }
        // Nested: resolve the folder entry and use its content-block offset.
        let e = self.find_entry(folder_path)?;
        if e.etype != EntryType::Folder {
            return Err(Pk2Error::NotFound);
        }
        Ok(e.position)
    }

    fn find_entry(&mut self, archive_path: &str) -> Result<Entry> {
        let parts = Self::split_path(&Self::normalize(archive_path));
        if parts.is_empty() {
            return Err(Pk2Error::NotFound);
        }
        let mut block_off = HEADER_SIZE as i64;
        for (depth, part) in parts.iter().enumerate() {
            let last = depth == parts.len() - 1;
            let mut found: Option<Entry> = None;
            self.walk_folder(block_off, |e| {
                if e.etype != EntryType::Empty && e.name.eq_ignore_ascii_case(part) {
                    found = Some(e.clone());
                }
            })?;
            match found {
                Some(e) if last => return Ok(e),
                Some(e) if e.etype == EntryType::Folder => block_off = e.position,
                _ => return Err(Pk2Error::NotFound),
            }
        }
        Err(Pk2Error::NotFound)
    }

    // path stuff

    fn normalize(path: &str) -> String {
        path.replace('/', "\\").trim_matches('\\').to_lowercase()
    }

    fn split_path(normalized: &str) -> Vec<String> {
        if normalized.is_empty() {
            return Vec::new();
        }
        normalized.split('\\').map(|s| s.to_string()).collect()
    }
}