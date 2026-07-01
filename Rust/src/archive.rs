use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::blowfish::Blowfish;

pub const SRO_PASSWORD: &[u8] = b"169841";

const JOYMAX_SALT: [u8; 10] = [
    0x03, 0xF8, 0xE4, 0x44, 0x88, 0x99, 0x3F, 0x64, 0xFE, 0x35,
];

const HEADER_NAME: &[u8] = b"JoyMax File Manager!\n";
const HEADER_VERIFY: &[u8; 16] = b"Joymax Pak File\0";

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
    pub access_time: u64,
    pub create_time: u64,
    pub modify_time: u64,
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

// Windows FILETIME: 100ns ticks since 1601-01-01. Purely informational metadata,
// nothing in the format depends on it being exact.
fn now_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (dur.as_secs() + EPOCH_DIFF_SECS) * 10_000_000 + (dur.subsec_nanos() as u64) / 100
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

    /// Create a brand-new, empty, encrypted archive. Overwrites any existing file.
    pub fn create(&mut self, path: &Path) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        self.file = Some(file);
        self.writable = true;
        self.encrypted = true;
        self.init_key();

        let mut hdr = [0u8; HEADER_SIZE];
        hdr[..HEADER_NAME.len()].copy_from_slice(HEADER_NAME);
        hdr[30] = 1; // version[0]
        hdr[34] = 1; // encryption flag
        let mut verify = *HEADER_VERIFY;
        self.bf.encrypt_ecb(&mut verify);
        hdr[35..35 + 16].copy_from_slice(&verify);

        {
            let f = self.file.as_mut().ok_or(Pk2Error::NotOpen)?;
            f.seek(SeekFrom::Start(0))?;
            f.write_all(&hdr)?;
        }

        let root = [0u8; BLOCK_SIZE];
        self.write_block(HEADER_SIZE as i64, &root)?;
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

    fn read_block_raw(&mut self, offset: i64) -> Result<[u8; BLOCK_SIZE]> {
        let f = self.file.as_mut().ok_or(Pk2Error::NotOpen)?;
        f.seek(SeekFrom::Start(offset as u64))?;
        let mut raw = [0u8; BLOCK_SIZE];
        f.read_exact(&mut raw)?;
        if self.encrypted {
            self.bf.decrypt_ecb(&mut raw);
        }
        Ok(raw)
    }

    fn read_block(&mut self, offset: i64) -> Result<[Entry; ENTRIES_PER_BLOCK]> {
        let raw = self.read_block_raw(offset)?;
        Ok(Self::parse_block(&raw))
    }

    fn write_block(&mut self, offset: i64, raw: &[u8; BLOCK_SIZE]) -> Result<()> {
        if !self.writable {
            return Err(Pk2Error::NotWritable);
        }
        let mut enc = *raw;
        if self.encrypted {
            self.bf.encrypt_ecb(&mut enc);
        }
        let f = self.file.as_mut().ok_or(Pk2Error::NotOpen)?;
        f.seek(SeekFrom::Start(offset as u64))?;
        f.write_all(&enc)?;
        Ok(())
    }

    /// Appends a zeroed block at EOF and returns its offset.
    fn alloc_block(&mut self) -> Result<i64> {
        if !self.writable {
            return Err(Pk2Error::NotWritable);
        }
        let offset = {
            let f = self.file.as_mut().ok_or(Pk2Error::NotOpen)?;
            f.seek(SeekFrom::End(0))? as i64
        };
        let empty = [0u8; BLOCK_SIZE];
        self.write_block(offset, &empty)?;
        Ok(offset)
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
            let access_time = u64::from_le_bytes(e[82..90].try_into().unwrap());
            let create_time = u64::from_le_bytes(e[90..98].try_into().unwrap());
            let modify_time = u64::from_le_bytes(e[98..106].try_into().unwrap());
            // position: i64 at offset 1 + 81 + (3 * 8) = 106
            let position = i64::from_le_bytes(e[106..114].try_into().unwrap());
            // size: u32 at 114
            let size = u32::from_le_bytes(e[114..118].try_into().unwrap());
            // nextChain: i64 at 118
            let next_chain = i64::from_le_bytes(e[118..126].try_into().unwrap());
            Entry {
                etype,
                name,
                access_time,
                create_time,
                modify_time,
                position,
                size,
                next_chain,
            }
        })
    }

    /// Writes a full 128-byte entry into a raw block buffer at `slot`, zeroing the rest.
    fn write_entry_raw(
        raw: &mut [u8; BLOCK_SIZE],
        slot: usize,
        etype: u8,
        name: &str,
        access: u64,
        create: u64,
        modify: u64,
        position: i64,
        size: u32,
        next_chain: i64,
    ) {
        let off = slot * ENTRY_SIZE;
        let e = &mut raw[off..off + ENTRY_SIZE];
        e.fill(0);
        e[0] = etype;
        let name_bytes = name.as_bytes();
        let n = name_bytes.len().min(80); // 81-byte field, leave room for the NUL terminator
        e[1..1 + n].copy_from_slice(&name_bytes[..n]);
        e[82..90].copy_from_slice(&access.to_le_bytes());
        e[90..98].copy_from_slice(&create.to_le_bytes());
        e[98..106].copy_from_slice(&modify.to_le_bytes());
        e[106..114].copy_from_slice(&position.to_le_bytes());
        e[114..118].copy_from_slice(&size.to_le_bytes());
        e[118..126].copy_from_slice(&next_chain.to_le_bytes());
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
        let block_off = self.folder_block(&Self::split_path(&Self::normalize(folder_path)), false)?;
        let mut out = Vec::new();
        self.walk_folder(block_off, |e, _off, _slot| {
            if e.etype != EntryType::Empty && e.name != "." && e.name != ".." {
                out.push(e.clone());
            }
        })?;
        Ok(out)
    }

    // public write

    /// Write (or overwrite) a file. Intermediate folders are created as needed.
    /// Old file data is orphaned in the archive (no compaction).
    pub fn write_file(&mut self, archive_path: &str, data: &[u8]) -> Result<()> {
        if !self.writable {
            return Err(Pk2Error::NotWritable);
        }
        let norm = Self::normalize(archive_path);
        let mut parts = Self::split_path(&norm);
        let filename = parts.pop().ok_or(Pk2Error::NotFound)?;

        let parent_block = self.folder_block(&parts, true)?;

        // Append the payload to EOF before touching any directory entries.
        let data_offset = if !data.is_empty() {
            let f = self.file.as_mut().ok_or(Pk2Error::NotOpen)?;
            let off = f.seek(SeekFrom::End(0))?;
            f.write_all(data)?;
            off as i64
        } else {
            0
        };

        let mut existing: Option<(i64, usize, Entry)> = None;
        self.walk_folder(parent_block, |e, boff, slot| {
            if e.etype != EntryType::Empty && e.name.eq_ignore_ascii_case(&filename) {
                existing = Some((boff, slot, e.clone()));
            }
        })?;

        let now = now_filetime();
        match existing {
            Some((boff, slot, old)) => {
                let mut raw = self.read_block_raw(boff)?;
                let position = if !data.is_empty() { data_offset } else { old.position };
                // Slot 19 doubles as the block-chain pointer; preserve it.
                let next_chain = if slot == ENTRIES_PER_BLOCK - 1 { old.next_chain } else { 0 };
                Self::write_entry_raw(
                    &mut raw, slot, 2, &filename,
                    old.access_time, old.create_time, now,
                    position, data.len() as u32, next_chain,
                );
                self.write_block(boff, &raw)?;
            }
            None => {
                self.add_entry(parent_block, 2, &filename, data_offset, data.len() as u32)?;
            }
        }
        Ok(())
    }

    /// Create a folder hierarchy; silently succeeds if folders already exist.
    pub fn make_folder(&mut self, folder_path: &str) -> Result<()> {
        if !self.writable {
            return Err(Pk2Error::NotWritable);
        }
        let parts = Self::split_path(&Self::normalize(folder_path));
        if parts.is_empty() {
            return Ok(()); // root always exists
        }
        self.folder_block(&parts, true)?;
        Ok(())
    }

    /// Zero the type field of an entry so it appears deleted.
    /// Does NOT recursively delete folder contents — empty the folder first.
    pub fn delete(&mut self, archive_path: &str) -> Result<()> {
        if !self.writable {
            return Err(Pk2Error::NotWritable);
        }
        let (_, block_off, slot) = self.find_entry_loc(archive_path)?;
        let mut raw = self.read_block_raw(block_off)?;
        raw[slot * ENTRY_SIZE] = 0;
        self.write_block(block_off, &raw)
    }

    // Finds a free slot in the block chain starting at `first_block`, allocating
    // and linking a new block at the tail if every existing block is full.
    fn find_or_alloc_slot(&mut self, first_block: i64) -> Result<(i64, usize, [u8; BLOCK_SIZE])> {
        let mut last_off;
        let mut cur = first_block;
        loop {
            let raw = self.read_block_raw(cur)?;
            for slot in 0..ENTRIES_PER_BLOCK {
                if raw[slot * ENTRY_SIZE] == 0 {
                    return Ok((cur, slot, raw));
                }
            }
            last_off = cur;
            let off = (ENTRIES_PER_BLOCK - 1) * ENTRY_SIZE + 118;
            let next = i64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
            if next == 0 {
                break;
            }
            cur = next;
        }

        let new_off = self.alloc_block()?;
        let mut last_raw = self.read_block_raw(last_off)?;
        let off = (ENTRIES_PER_BLOCK - 1) * ENTRY_SIZE + 118;
        last_raw[off..off + 8].copy_from_slice(&new_off.to_le_bytes());
        self.write_block(last_off, &last_raw)?;

        Ok((new_off, 0, [0u8; BLOCK_SIZE]))
    }

    // Places a new entry into the first free slot of `parent_block`'s chain.
    fn add_entry(&mut self, parent_block: i64, etype: u8, name: &str, position: i64, size: u32) -> Result<()> {
        let (block_off, slot, mut raw) = self.find_or_alloc_slot(parent_block)?;
        let off = slot * ENTRY_SIZE + 118;
        let next_chain = if slot == ENTRIES_PER_BLOCK - 1 {
            i64::from_le_bytes(raw[off..off + 8].try_into().unwrap())
        } else {
            0
        };
        let now = now_filetime();
        Self::write_entry_raw(&mut raw, slot, etype, name, now, now, now, position, size, next_chain);
        self.write_block(block_off, &raw)
    }

    // traversal

    fn walk_folder<F: FnMut(&Entry, i64, usize)>(&mut self, mut block_off: i64, mut visit: F) -> Result<()> {
        loop {
            let block = self.read_block(block_off)?;
            for (i, e) in block.iter().enumerate() {
                visit(e, block_off, i);
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

    // Resolves (and optionally creates) the content-block offset for a folder
    // given its already-normalized, already-split path components.
    fn folder_block(&mut self, parts: &[String], create_if_missing: bool) -> Result<i64> {
        let mut cur = HEADER_SIZE as i64;
        for part in parts {
            let mut found: Option<Entry> = None;
            self.walk_folder(cur, |e, _off, _slot| {
                if e.etype != EntryType::Empty && e.name.eq_ignore_ascii_case(part) {
                    found = Some(e.clone());
                }
            })?;
            match found {
                Some(e) if e.etype == EntryType::Folder => cur = e.position,
                Some(_) => return Err(Pk2Error::BadFormat("path component is a file")),
                None => {
                    if !create_if_missing || !self.writable {
                        return Err(Pk2Error::NotFound);
                    }
                    let content_block = self.alloc_block()?;
                    self.add_entry(cur, 1, part, content_block, 0)?;
                    cur = content_block;
                }
            }
        }
        Ok(cur)
    }

    fn find_entry_loc(&mut self, archive_path: &str) -> Result<(Entry, i64, usize)> {
        let parts = Self::split_path(&Self::normalize(archive_path));
        if parts.is_empty() {
            return Err(Pk2Error::NotFound);
        }
        let mut block_off = HEADER_SIZE as i64;
        for (depth, part) in parts.iter().enumerate() {
            let last = depth == parts.len() - 1;
            let mut found: Option<(Entry, i64, usize)> = None;
            self.walk_folder(block_off, |e, boff, slot| {
                if e.etype != EntryType::Empty && e.name.eq_ignore_ascii_case(part) {
                    found = Some((e.clone(), boff, slot));
                }
            })?;
            match found {
                Some((e, boff, slot)) if last => return Ok((e, boff, slot)),
                Some((e, _, _)) if e.etype == EntryType::Folder => block_off = e.position,
                _ => return Err(Pk2Error::NotFound),
            }
        }
        Err(Pk2Error::NotFound)
    }

    fn find_entry(&mut self, archive_path: &str) -> Result<Entry> {
        self.find_entry_loc(archive_path).map(|(e, _, _)| e)
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
