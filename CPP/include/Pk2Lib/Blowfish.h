#pragma once
#include <cstdint>
#include <cstddef>

class Blowfish
{
public:
    Blowfish() = default;

    void SetKey(const uint8_t* key, size_t keyLen);

    // ECB decrypt of 'len' bytes. 'len' must be a multiple of 8.
    // Trailing bytes that don't fill an 8-byte block are left untouched.
    void DecryptEcb(uint8_t* data, size_t len) const;

    // ECB encrypt.
    void EncryptEcb(uint8_t* data, size_t len) const;

private:
    void     EncryptBlock(uint32_t& xl, uint32_t& xr) const;
    void     DecryptBlock(uint32_t& xl, uint32_t& xr) const;
    uint32_t F(uint32_t x) const;

    uint32_t P[18];
    uint32_t S[4][256];
};
