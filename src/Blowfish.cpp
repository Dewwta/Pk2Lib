#include <Pk2Lib/Blowfish.h>

static const uint32_t ORIG_P[18] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0,
    0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B
};

#include "BlowfishSBoxes.inc"  // defines ORIG_S[4][256]

static inline uint32_t read_le(const uint8_t* p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

uint32_t Blowfish::F(uint32_t x) const
{
    uint8_t a = uint8_t(x >> 24);
    uint8_t b = uint8_t(x >> 16);
    uint8_t c = uint8_t(x >> 8);
    uint8_t d = uint8_t(x);
    uint32_t y = S[0][a] + S[1][b];
    y ^= S[2][c];
    y += S[3][d];
    return y;
}

void Blowfish::EncryptBlock(uint32_t& xl, uint32_t& xr) const
{
    for (int i = 0; i < 16; i += 2) {
        xl ^= P[i];
        xr ^= F(xl);
        xr ^= P[i + 1];
        xl ^= F(xr);
    }
    xl ^= P[16];
    xr ^= P[17];
    uint32_t t = xl; xl = xr; xr = t;
}

void Blowfish::DecryptBlock(uint32_t& xl, uint32_t& xr) const
{
    for (int i = 16; i > 0; i -= 2) {
        xl ^= P[i + 1];
        xr ^= F(xl);
        xr ^= P[i];
        xl ^= F(xr);
    }
    xl ^= P[1];
    xr ^= P[0];
    uint32_t t = xl; xl = xr; xr = t;
}

void Blowfish::SetKey(const uint8_t* key, size_t keyLen)
{
    for (int i = 0; i < 18; ++i) P[i] = ORIG_P[i];
    for (int i = 0; i < 4;  ++i)
        for (int j = 0; j < 256; ++j) S[i][j] = ORIG_S[i][j];

    if (keyLen == 0) return;

    size_t k = 0;
    for (int i = 0; i < 18; ++i) {
        uint32_t data = 0;
        for (int j = 0; j < 4; ++j) {
            data = (data << 8) | key[k];
            k = (k + 1) % keyLen;
        }
        P[i] ^= data;
    }

    uint32_t l = 0, r = 0;
    for (int i = 0; i < 18; i += 2) {
        EncryptBlock(l, r);
        P[i] = l; P[i + 1] = r;
    }
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 256; j += 2) {
            EncryptBlock(l, r);
            S[i][j] = l; S[i][j + 1] = r;
        }
    }
}

void Blowfish::DecryptEcb(uint8_t* data, size_t len) const
{
    size_t blocks = len / 8;
    for (size_t b = 0; b < blocks; ++b) {
        uint8_t* p = data + b * 8;
        uint32_t xl = read_le(p);
        uint32_t xr = read_le(p + 4);
        DecryptBlock(xl, xr);
        p[0] = uint8_t(xl);       p[1] = uint8_t(xl >> 8);
        p[2] = uint8_t(xl >> 16); p[3] = uint8_t(xl >> 24);
        p[4] = uint8_t(xr);       p[5] = uint8_t(xr >> 8);
        p[6] = uint8_t(xr >> 16); p[7] = uint8_t(xr >> 24);
    }
}

void Blowfish::EncryptEcb(uint8_t* data, size_t len) const
{
    size_t blocks = len / 8;
    for (size_t b = 0; b < blocks; ++b) {
        uint8_t* p = data + b * 8;
        uint32_t xl = read_le(p);
        uint32_t xr = read_le(p + 4);
        EncryptBlock(xl, xr);
        p[0] = uint8_t(xl);       p[1] = uint8_t(xl >> 8);
        p[2] = uint8_t(xl >> 16); p[3] = uint8_t(xl >> 24);
        p[4] = uint8_t(xr);       p[5] = uint8_t(xr >> 8);
        p[6] = uint8_t(xr >> 16); p[7] = uint8_t(xr >> 24);
    }
}
