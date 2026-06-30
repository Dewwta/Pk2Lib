// blowfish.rs — EXACT port of the user's Blowfish.cpp.
// Little-endian block words; 2-step unrolled Feistel matching the C++ variant.

use crate::sboxes::{ORIG_P, ORIG_S};

pub struct Blowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Default for Blowfish {
    fn default() -> Self {
        Blowfish { p: [0; 18], s: [[0; 256]; 4] }
    }
}

#[inline]
fn read_le(p: &[u8]) -> u32 {
    u32::from_le_bytes([p[0], p[1], p[2], p[3]])
}

impl Blowfish {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn f(&self, x: u32) -> u32 {
        let a = (x >> 24) as u8 as usize;
        let b = (x >> 16) as u8 as usize;
        let c = (x >> 8) as u8 as usize;
        let d = x as u8 as usize;
        let mut y = self.s[0][a].wrapping_add(self.s[1][b]);
        y ^= self.s[2][c];
        y = y.wrapping_add(self.s[3][d]);
        y
    }

    // Mirrors C++ EncryptBlock exactly.
    fn encrypt_block(&self, xl: &mut u32, xr: &mut u32) {
        let mut l = *xl;
        let mut r = *xr;
        let mut i = 0;
        while i < 16 {
            l ^= self.p[i];
            r ^= self.f(l);
            r ^= self.p[i + 1];
            l ^= self.f(r);
            i += 2;
        }
        l ^= self.p[16];
        r ^= self.p[17];
        std::mem::swap(&mut l, &mut r);
        *xl = l;
        *xr = r;
    }

    // Mirrors C++ DecryptBlock exactly.
    fn decrypt_block(&self, xl: &mut u32, xr: &mut u32) {
        let mut l = *xl;
        let mut r = *xr;
        let mut i = 16;
        while i > 0 {
            l ^= self.p[i + 1];
            r ^= self.f(l);
            r ^= self.p[i];
            l ^= self.f(r);
            i -= 2;
        }
        l ^= self.p[1];
        r ^= self.p[0];
        std::mem::swap(&mut l, &mut r);
        *xl = l;
        *xr = r;
    }

    pub fn set_key(&mut self, key: &[u8]) {
        self.p = ORIG_P;
        self.s = ORIG_S;

        let keylen = key.len();
        if keylen == 0 {
            return;
        }

        let mut k = 0usize;
        for i in 0..18 {
            let mut data: u32 = 0;
            for _ in 0..4 {
                data = (data << 8) | key[k] as u32;
                k = (k + 1) % keylen;
            }
            self.p[i] ^= data;
        }

        let mut l: u32 = 0;
        let mut r: u32 = 0;
        for i in (0..18).step_by(2) {
            self.encrypt_block(&mut l, &mut r);
            self.p[i] = l;
            self.p[i + 1] = r;
        }
        for i in 0..4 {
            for j in (0..256).step_by(2) {
                self.encrypt_block(&mut l, &mut r);
                self.s[i][j] = l;
                self.s[i][j + 1] = r;
            }
        }
    }

    /// ECB decrypt in place, little-endian words. `len` floor to /8.
    pub fn decrypt_ecb(&self, data: &mut [u8]) {
        let blocks = data.len() / 8;
        for b in 0..blocks {
            let off = b * 8;
            let mut xl = read_le(&data[off..off + 4]);
            let mut xr = read_le(&data[off + 4..off + 8]);
            self.decrypt_block(&mut xl, &mut xr);
            data[off..off + 4].copy_from_slice(&xl.to_le_bytes());
            data[off + 4..off + 8].copy_from_slice(&xr.to_le_bytes());
        }
    }

    /// ECB encrypt in place, little-endian words.
    pub fn encrypt_ecb(&self, data: &mut [u8]) {
        let blocks = data.len() / 8;
        for b in 0..blocks {
            let off = b * 8;
            let mut xl = read_le(&data[off..off + 4]);
            let mut xr = read_le(&data[off + 4..off + 8]);
            self.encrypt_block(&mut xl, &mut xr);
            data[off..off + 4].copy_from_slice(&xl.to_le_bytes());
            data[off + 4..off + 8].copy_from_slice(&xr.to_le_bytes());
        }
    }
}