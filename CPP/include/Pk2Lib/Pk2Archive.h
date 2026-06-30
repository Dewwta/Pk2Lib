#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include "Blowfish.h"

// DLL export/import/static macro
#if defined(PK2_LIB_STATIC)
#  define PK2_API
#elif defined(PK2_LIB_EXPORTS)
#  define PK2_API __declspec(dllexport)
#elif defined(_WIN32)
#  define PK2_API __declspec(dllimport)
#else
#  define PK2_API
#endif

// PK2 archive reader / writer.
//
// Read-only usage:
//   Pk2Archive pk2;
//   pk2.Open(L"media.pk2");
//   std::vector<uint8_t> data;
//   pk2.ReadFile("icon\\item\\sword.ddj", data);
//
// Write usage:
//   Pk2Archive pk2;
//   pk2.Open(L"media.pk2", Pk2Archive::OpenMode::ReadWrite);
//   pk2.WriteFile("newdir\\file.bin", ptr, size);
//   pk2.MakeFolder("newdir\\sub");
//   pk2.Delete("newdir\\old.bin");
class PK2_API Pk2Archive
{
public:
    enum class OpenMode { ReadOnly, ReadWrite };

    Pk2Archive()  = default;
    ~Pk2Archive() { Close(); }

    Pk2Archive(const Pk2Archive&)            = delete;
    Pk2Archive& operator=(const Pk2Archive&) = delete;

    // Open an existing PK2 archive.
    // Pass ReadWrite to use any of the write operations below.
    bool Open(const std::wstring& path, OpenMode mode = OpenMode::ReadOnly);

    // Create a brand-new, empty, encrypted PK2 archive.
    // Overwrites the file if it already exists.
    bool Create(const std::wstring& path);

    void Close();
    bool IsOpen()     const { return m_file != nullptr; }
    bool IsWritable() const { return m_writable; }

    // Reading

    // Read an entire file from the archive by its in-archive path.
    // 'out' is resized to the file size. Returns false if not found.
    bool ReadFile(const std::string& archivePath, std::vector<uint8_t>& out);

    // True if a file or folder exists at the given path.
    bool Exists(const std::string& archivePath);

    // List immediate children (files and folders) of a folder.
    // Pass "" or omit for the root. Returns names only.
    std::vector<std::string> List(const std::string& folderPath = "");

    // Writing

    // Write (or overwrite) a file. Intermediate folders are created as needed.
    // Old file data is orphaned in the archive (no compaction).
    bool WriteFile(const std::string& archivePath, const uint8_t* data, uint32_t size);
    bool WriteFile(const std::string& archivePath, const std::vector<uint8_t>& data);

    // Zero the type field of an entry so it appears deleted.
    // Does NOT recursively delete folder contents — empty the folder first.
    bool Delete(const std::string& archivePath);

    // Create a folder hierarchy; silently succeeds if folders already exist.
    bool MakeFolder(const std::string& folderPath);

    // Standard SRO Blowfish key: password "169841" XOR'd with JoyMax salt.
    // Result placed in outKey[0..5]; outKey[6..7] zeroed.
    static void MakeSilkroadKey(uint8_t outKey[8]);

private:
    // ── On-disk layout (sizes fixed by the PK2 format) ───────────────────────
#pragma pack(push, 1)
    struct Header {
        char    name[30];       // "JoyMax File Manager!\n" + padding
        uint8_t version[4];
        uint8_t encryption;    // 1 = entries are Blowfish-encrypted
        uint8_t verifySig[16]; // encrypted "Joymax Pak File\0"
        uint8_t reserved[205];
    };                         // 256 bytes total

    struct Entry {
        uint8_t  type;         // 0 = empty slot, 1 = folder, 2 = file
        char     name[81];
        uint64_t accessTime;
        uint64_t createTime;
        uint64_t modifyTime;
        int64_t  position;     // file: byte offset of payload; folder: first block offset
        uint32_t size;         // file: payload bytes; folder: 0
        int64_t  nextChain;    // entries[19] only: next chained block offset (0 = none)
        uint8_t  padding[2];
    };                         // 128 bytes total
#pragma pack(pop)

    struct Block { Entry entries[20]; }; // 2560 bytes

    // Block I/O
    bool    ReadBlock (int64_t offset, Block& block);
    bool    WriteBlock(int64_t offset, const Block& block); // encrypts a copy before writing
    int64_t AllocBlock();                                   // appends a zeroed block at EOF

    // Directory traversal
    template <typename Fn>
    bool WalkFolder(int64_t blockOffset, Fn fn);

    // Resolve an archive path to its Entry.
    bool FindEntry(const std::string& archivePath, Entry& out,
                   int64_t* outBlock = nullptr, int* outSlot = nullptr);

    // Return the first-block offset of the folder described by normalized 'parts'.
    int64_t FolderBlock(const std::vector<std::string>& parts, bool createIfMissing);

    // Find an empty slot (type == 0) in the block chain beginning at firstBlock.
    // If all slots are taken a new block is allocated and linked at the chain tail.
    bool FindOrAllocSlot(int64_t firstBlock,
                         int64_t& outBlock, int& outSlot, Block& outBlockData);

    static std::string              Normalize(const std::string& path);
    static std::string              EntryName(const Entry& e);
    static std::vector<std::string> SplitPath(const std::string& normalized);
    static uint64_t                 Now();

    // State
    FILE*    m_file      = nullptr;
    Blowfish m_bf;
    bool     m_encrypted = false;
    bool     m_writable  = false;
};
