#include <Pk2Lib/Pk2Archive.h>

#include <algorithm>
#include <cctype>
#include <cstring>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

void Pk2Archive::MakeSilkroadKey(uint8_t outKey[8])
{
    static const char    kPassword[] = "169841";
    static const uint8_t kSalt[10]   = { 0x03,0xF8,0xE4,0x44,0x88,0x99,0x3F,0x64,0xFE,0x35 };
    constexpr size_t     plainLen    = 6;

    std::memset(outKey, 0, 8);
    for (size_t i = 0; i < plainLen; ++i)
        outKey[i] = uint8_t(kPassword[i]) ^ kSalt[i];
}

std::string Pk2Archive::EntryName(const Entry& e)
{
    size_t n = 0;
    while (n < sizeof(e.name) && e.name[n] != '\0') ++n;
    return std::string(e.name, n);
}

std::string Pk2Archive::Normalize(const std::string& path)
{
    std::string s = path;
    for (char& c : s) {
        if (c == '/') c = '\\';
        c = (char)std::tolower((unsigned char)c);
    }
    size_t start = 0;
    while (start < s.size() && s[start] == '\\') ++start;
    while (!s.empty() && s.back() == '\\') s.pop_back();
    return s.substr(start);
}

std::vector<std::string> Pk2Archive::SplitPath(const std::string& normalized)
{
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos < normalized.size()) {
        size_t sep = normalized.find('\\', pos);
        if (sep == std::string::npos) { parts.push_back(normalized.substr(pos)); break; }
        if (sep > pos) parts.push_back(normalized.substr(pos, sep - pos));
        pos = sep + 1;
    }
    return parts;
}

uint64_t Pk2Archive::Now()
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (uint64_t(ft.dwHighDateTime) << 32) | uint64_t(ft.dwLowDateTime);
#else
    return 0;
#endif
}

// Open / Create / Close

bool Pk2Archive::Open(const std::wstring& path, OpenMode mode)
{
    static_assert(sizeof(Header) == 256,  "PK2 Header must be 256 bytes");
    static_assert(sizeof(Entry)  == 128,  "PK2 Entry must be 128 bytes");
    static_assert(sizeof(Block)  == 2560, "PK2 Block must be 2560 bytes");

    Close();

#ifdef _WIN32
    const wchar_t* modeStr = (mode == OpenMode::ReadWrite) ? L"r+b" : L"rb";
    if (_wfopen_s(&m_file, path.c_str(), modeStr) != 0 || !m_file) return false;
#else
    std::string narrow(path.begin(), path.end());
    m_file = std::fopen(narrow.c_str(), (mode == OpenMode::ReadWrite) ? "r+b" : "rb");
    if (!m_file) return false;
#endif

    Header hdr{};
    if (std::fread(&hdr, 1, sizeof(hdr), m_file) != sizeof(hdr)) { Close(); return false; }

    m_encrypted = (hdr.encryption != 0);
    m_writable  = (mode == OpenMode::ReadWrite);

    if (m_encrypted) {
        uint8_t key[8];
        MakeSilkroadKey(key);
        m_bf.SetKey(key, 6);
    }
    return true;
}

bool Pk2Archive::Create(const std::wstring& path)
{
    Close();

    uint8_t key[8];
    MakeSilkroadKey(key);
    m_bf.SetKey(key, 6);
    m_encrypted = true;
    m_writable  = true;

#ifdef _WIN32
    if (_wfopen_s(&m_file, path.c_str(), L"w+b") != 0 || !m_file) {
        m_encrypted = m_writable = false;
        return false;
    }
#else
    std::string narrow(path.begin(), path.end());
    m_file = std::fopen(narrow.c_str(), "w+b");
    if (!m_file) { m_encrypted = m_writable = false; return false; }
#endif

    Header hdr{};
    static const char kName[]   = "JoyMax File Manager!\n";
    static const char kVerify[] = "Joymax Pak File\0";  // 16 bytes including NUL
    std::memcpy(hdr.name,      kName,   sizeof(kName) - 1);
    hdr.version[0] = 1;
    hdr.encryption = 1;
    std::memcpy(hdr.verifySig, kVerify, 16);
    m_bf.EncryptEcb(hdr.verifySig, 16);

    if (std::fwrite(&hdr, 1, sizeof(hdr), m_file) != sizeof(hdr)) { Close(); return false; }

    // Write empty root block
    Block root{};
    if (!WriteBlock(256, root)) { Close(); return false; }
    std::fflush(m_file);
    return true;
}

void Pk2Archive::Close()
{
    if (m_file) { std::fclose(m_file); m_file = nullptr; }
    m_encrypted = false;
    m_writable  = false;
}

// Block I/O

bool Pk2Archive::ReadBlock(int64_t offset, Block& block)
{
    if (!m_file) return false;
#ifdef _WIN32
    if (_fseeki64(m_file, offset, SEEK_SET) != 0) return false;
#else
    if (fseeko(m_file, (off_t)offset, SEEK_SET) != 0) return false;
#endif
    if (std::fread(&block, 1, sizeof(Block), m_file) != sizeof(Block)) return false;
    if (m_encrypted)
        m_bf.DecryptEcb(reinterpret_cast<uint8_t*>(&block), sizeof(Block));
    return true;
}

bool Pk2Archive::WriteBlock(int64_t offset, const Block& block)
{
    if (!m_file || !m_writable) return false;
    Block enc = block;
    if (m_encrypted)
        m_bf.EncryptEcb(reinterpret_cast<uint8_t*>(&enc), sizeof(Block));
#ifdef _WIN32
    if (_fseeki64(m_file, offset, SEEK_SET) != 0) return false;
#else
    if (fseeko(m_file, (off_t)offset, SEEK_SET) != 0) return false;
#endif
    return std::fwrite(&enc, 1, sizeof(Block), m_file) == sizeof(Block);
}

int64_t Pk2Archive::AllocBlock()
{
    if (!m_file || !m_writable) return -1;
#ifdef _WIN32
    if (_fseeki64(m_file, 0, SEEK_END) != 0) return -1;
    int64_t offset = _ftelli64(m_file);
#else
    if (fseeko(m_file, 0, SEEK_END) != 0) return -1;
    int64_t offset = (int64_t)ftello(m_file);
#endif
    if (offset < 0) return -1;
    Block empty{};
    if (!WriteBlock(offset, empty)) return -1;
    return offset;
}

// Directory traversal

// Template definition lives here (with all instantiation points in this TU).
// fn(entry, name, blockOffset, slotIndex) → true stops the walk early.
template <typename Fn>
bool Pk2Archive::WalkFolder(int64_t blockOffset, Fn fn)
{
    int64_t cur = blockOffset;
    while (cur != 0) {
        Block blk;
        if (!ReadBlock(cur, blk)) return false;
        for (int i = 0; i < 20; ++i) {
            const Entry& e = blk.entries[i];
            if (e.type == 0) continue;
            std::string nm = EntryName(e);
            if (nm == "." || nm == "..") continue;
            if (fn(e, nm, cur, i)) return true;
        }
        cur = blk.entries[19].nextChain;
    }
    return false;
}

bool Pk2Archive::FindOrAllocSlot(int64_t firstBlock,
                                  int64_t& outBlock, int& outSlot, Block& outBlockData)
{
    if (firstBlock < 256) return false;

    int64_t lastOff = firstBlock;
    int64_t cur     = firstBlock;

    while (cur != 0) {
        Block blk;
        if (!ReadBlock(cur, blk)) return false;
        for (int i = 0; i < 20; ++i) {
            if (blk.entries[i].type == 0) {
                outBlock     = cur;
                outSlot      = i;
                outBlockData = blk;
                return true;
            }
        }
        lastOff = cur;
        cur     = blk.entries[19].nextChain;
    }

    // All slots full — allocate a new block and link it at the chain tail.
    int64_t newOff = AllocBlock();
    if (newOff < 0) return false;

    Block lastBlk;
    if (!ReadBlock(lastOff, lastBlk)) return false;
    lastBlk.entries[19].nextChain = newOff;
    if (!WriteBlock(lastOff, lastBlk)) return false;

    Block newBlk{};
    outBlock     = newOff;
    outSlot      = 0;
    outBlockData = newBlk;
    return true;
}

int64_t Pk2Archive::FolderBlock(const std::vector<std::string>& parts, bool createIfMissing)
{
    int64_t cur = 256;  // root block is always right after the 256-byte header
    for (const std::string& wantName : parts) {
        Entry   found{};
        int64_t foundBlock = -1;
        int     foundSlot  = -1;
        bool got = WalkFolder(cur, [&](const Entry& e, const std::string& nm,
                                       int64_t bOff, int sIdx) {
            std::string lower = nm;
            for (char& c : lower) c = (char)std::tolower((unsigned char)c);
            if (lower == wantName) { found = e; foundBlock = bOff; foundSlot = sIdx; return true; }
            return false;
        });

        if (!got) {
            if (!createIfMissing || !m_writable) return -1;

            // Allocate the content block for the new folder.
            int64_t contentBlock = AllocBlock();
            if (contentBlock < 0) return -1;

            // Place the new folder entry in the current directory.
            int64_t slotBlock; int slotIdx; Block slotData;
            if (!FindOrAllocSlot(cur, slotBlock, slotIdx, slotData)) return -1;

            Entry& newE = slotData.entries[slotIdx];
            std::memset(&newE, 0, sizeof(newE));
            newE.type = 1;
            std::strncpy(newE.name, wantName.c_str(), sizeof(newE.name) - 1);
            newE.position   = contentBlock;
            newE.accessTime = newE.createTime = newE.modifyTime = Now();

            if (!WriteBlock(slotBlock, slotData)) return -1;
            cur = contentBlock;
        }
        else {
            if (found.type != 1) return -1;  // path component is a file, not a folder
            cur = found.position;
        }
    }
    return cur;
}

bool Pk2Archive::FindEntry(const std::string& archivePath, Entry& out,
                            int64_t* outBlock, int* outSlot)
{
    std::string norm = Normalize(archivePath);
    if (norm.empty()) return false;
    auto parts = SplitPath(norm);
    if (parts.empty()) return false;

    int64_t cur = 256;
    for (size_t pi = 0; pi < parts.size(); ++pi) {
        const std::string& want   = parts[pi];
        const bool         isLast = (pi + 1 == parts.size());

        Entry   found{};
        int64_t foundBlock = -1;
        int     foundSlot  = -1;

        bool got = WalkFolder(cur, [&](const Entry& e, const std::string& nm,
                                       int64_t bOff, int sIdx) {
            std::string lower = nm;
            for (char& c : lower) c = (char)std::tolower((unsigned char)c);
            if (lower == want) { found = e; foundBlock = bOff; foundSlot = sIdx; return true; }
            return false;
        });

        if (!got) return false;

        if (isLast) {
            out = found;
            if (outBlock) *outBlock = foundBlock;
            if (outSlot)  *outSlot  = foundSlot;
            return true;
        }

        if (found.type != 1) return false;  // expected folder
        cur = found.position;
    }
    return false;
}

// Public read API

bool Pk2Archive::Exists(const std::string& archivePath)
{
    Entry e{};
    return FindEntry(archivePath, e);
}

bool Pk2Archive::ReadFile(const std::string& archivePath, std::vector<uint8_t>& out)
{
    Entry e{};
    if (!FindEntry(archivePath, e)) return false;
    if (e.type != 2) return false;

    out.resize(e.size);
    if (e.size == 0) return true;

#ifdef _WIN32
    if (_fseeki64(m_file, e.position, SEEK_SET) != 0) return false;
#else
    if (fseeko(m_file, (off_t)e.position, SEEK_SET) != 0) return false;
#endif
    return std::fread(out.data(), 1, e.size, m_file) == e.size;
}

std::vector<std::string> Pk2Archive::List(const std::string& folderPath)
{
    std::vector<std::string> names;

    int64_t startBlock;
    std::string norm = Normalize(folderPath);
    if (norm.empty()) {
        startBlock = 256;
    }
    else {
        Entry e{};
        if (!FindEntry(folderPath, e) || e.type != 1) return names;
        startBlock = e.position;
    }

    WalkFolder(startBlock, [&](const Entry&, const std::string& nm, int64_t, int) {
        names.push_back(nm);
        return false;
    });
    return names;
}

// Public write API

bool Pk2Archive::MakeFolder(const std::string& folderPath)
{
    if (!m_writable) return false;
    std::string norm = Normalize(folderPath);
    if (norm.empty()) return true;  // root always exists
    auto parts = SplitPath(norm);
    if (parts.empty()) return true;
    return FolderBlock(parts, true) >= 0;
}

bool Pk2Archive::WriteFile(const std::string& archivePath, const std::vector<uint8_t>& data)
{
    return data.empty()
        ? WriteFile(archivePath, nullptr, 0)
        : WriteFile(archivePath, data.data(), (uint32_t)data.size());
}

bool Pk2Archive::WriteFile(const std::string& archivePath,
                            const uint8_t* data, uint32_t size)
{
    if (!m_writable) return false;

    std::string norm = Normalize(archivePath);
    if (norm.empty()) return false;
    auto parts = SplitPath(norm);
    if (parts.empty()) return false;

    // Split into parent folder path + filename.
    const std::string filename = parts.back();
    parts.pop_back();

    // Ensure the full parent folder hierarchy exists.
    int64_t parentBlock = FolderBlock(parts, true);
    if (parentBlock < 0) return false;

    // Append file payload to EOF before touching any directory entries.
    // Old file data is orphaned (no compaction — acceptable for a launcher/editor).
    int64_t dataOffset = 0;
    if (size > 0) {
#ifdef _WIN32
        if (_fseeki64(m_file, 0, SEEK_END) != 0) return false;
        dataOffset = _ftelli64(m_file);
#else
        if (fseeko(m_file, 0, SEEK_END) != 0) return false;
        dataOffset = (int64_t)ftello(m_file);
#endif
        if (dataOffset < 0) return false;
        if (std::fwrite(data, 1, size, m_file) != size) return false;
    }

    // Check whether a file with this name already exists in the parent folder.
    Entry   existing{};
    int64_t existingBlock = -1;
    int     existingSlot  = -1;
    bool exists = WalkFolder(parentBlock,
        [&](const Entry& e, const std::string& nm, int64_t bOff, int sIdx) {
            std::string lower = nm;
            for (char& c : lower) c = (char)std::tolower((unsigned char)c);
            if (lower == filename) {
                existing = e; existingBlock = bOff; existingSlot = sIdx;
                return true;
            }
            return false;
        });

    const uint64_t now = Now();

    if (exists) {
        Block blk;
        if (!ReadBlock(existingBlock, blk)) return false;
        Entry& e     = blk.entries[existingSlot];
        e.position   = (size > 0) ? dataOffset : existing.position;
        e.size       = size;
        e.modifyTime = now;
        e.accessTime = now;
        if (!WriteBlock(existingBlock, blk)) return false;
    }
    else {
        int64_t slotBlock; int slotIdx; Block slotData;
        if (!FindOrAllocSlot(parentBlock, slotBlock, slotIdx, slotData)) return false;

        Entry& e = slotData.entries[slotIdx];
        std::memset(&e, 0, sizeof(e));
        e.type       = 2;
        std::strncpy(e.name, filename.c_str(), sizeof(e.name) - 1);
        e.position   = (size > 0) ? dataOffset : 0;
        e.size       = size;
        e.accessTime = e.createTime = e.modifyTime = now;
        if (!WriteBlock(slotBlock, slotData)) return false;
    }

    std::fflush(m_file);
    return true;
}

bool Pk2Archive::Delete(const std::string& archivePath)
{
    if (!m_writable) return false;

    Entry   e{};
    int64_t blockOff = -1;
    int     slot     = -1;
    if (!FindEntry(archivePath, e, &blockOff, &slot)) return false;

    Block blk;
    if (!ReadBlock(blockOff, blk)) return false;
    blk.entries[slot].type = 0;
    if (!WriteBlock(blockOff, blk)) return false;

    std::fflush(m_file);
    return true;
}
