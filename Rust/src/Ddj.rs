// ddj.rs — decode a Silkroad .ddj into RGBA8 pixels.
//
// DDJ layout: 20-byte JoyMax header ("JMXVDDJ " + version), then a standard
// DDS file. We strip the header and parse the DDS ourselves: read the
// DDS_PIXELFORMAT block and dispatch on FourCC (for DXT) or on the RGB/alpha
// bitmasks (for uncompressed formats). This mirrors how Pfim/your C#
// converter identifies formats and is more robust than relying on a crate's
// enum mapping, which doesn't always resolve mask-defined 16-bit formats.
//
// DXT block formats are decompressed with `texture2ddecoder`.

pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>, // width*height*4, row-major, R,G,B,A
}

#[derive(Debug)]
pub enum DdjError {
    TooSmall,
    NotDds,
    Unsupported(String),
    Decode(String),
}

const DDJ_HEADER_LEN: usize = 20;
const DDS_MAGIC: &[u8; 4] = b"DDS ";

// Offsets within the DDS data (dds_bytes), measured from the 4-byte magic.
// DDS_HEADER follows the magic; dwHeight sits at byte 12 from DDS start,
// dwWidth at 16, and DDS_PIXELFORMAT at 76. Payload begins at 128.
const OFF_HEIGHT: usize = 12;
const OFF_WIDTH: usize = 16;
const OFF_PF: usize = 76; // DDS_PIXELFORMAT starts here, 32 bytes
const DDS_FULL_HEADER: usize = 128; // where payload begins

// DDS_PIXELFORMAT field offsets (relative to OFF_PF).
const PF_FLAGS: usize = 4;
const PF_FOURCC: usize = 8;
const PF_RGBBITCOUNT: usize = 12;
const PF_RMASK: usize = 16;
const PF_GMASK: usize = 20;
const PF_BMASK: usize = 24;
const PF_AMASK: usize = 28;

// DDPF flags
const DDPF_ALPHAPIXELS: u32 = 0x1;
const DDPF_FOURCC: u32 = 0x4;
const DDPF_RGB: u32 = 0x40;

#[inline]
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

pub fn decode_ddj(bytes: &[u8]) -> Result<DecodedImage, DdjError> {
    if bytes.len() <= DDJ_HEADER_LEN + DDS_FULL_HEADER {
        return Err(DdjError::TooSmall);
    }
    let dds = &bytes[DDJ_HEADER_LEN..];
    if &dds[0..4] != DDS_MAGIC {
        return Err(DdjError::NotDds);
    }

    let width = rd_u32(dds, OFF_WIDTH);
    let height = rd_u32(dds, OFF_HEIGHT);

    let pf = &dds[OFF_PF..OFF_PF + 32];
    let flags = rd_u32(pf, PF_FLAGS);
    let fourcc = &pf[PF_FOURCC..PF_FOURCC + 4];
    let bitcount = rd_u32(pf, PF_RGBBITCOUNT);
    let rmask = rd_u32(pf, PF_RMASK);
    let gmask = rd_u32(pf, PF_GMASK);
    let bmask = rd_u32(pf, PF_BMASK);
    let amask = rd_u32(pf, PF_AMASK);

    let payload = &dds[DDS_FULL_HEADER..];

    // ---- FourCC (block-compressed) path ----
    if flags & DDPF_FOURCC != 0 {
        let mut out_argb = vec![0u32; (width * height) as usize];
        match fourcc {
            b"DXT1" => texture2ddecoder::decode_bc1(payload, width as usize, height as usize, &mut out_argb)
                .map_err(|e| DdjError::Decode(format!("{e:?}")))?,
            b"DXT3" => texture2ddecoder::decode_bc2(payload, width as usize, height as usize, &mut out_argb)
                .map_err(|e| DdjError::Decode(format!("{e:?}")))?,
            b"DXT5" => texture2ddecoder::decode_bc3(payload, width as usize, height as usize, &mut out_argb)
                .map_err(|e| DdjError::Decode(format!("{e:?}")))?,
            other => {
                let tag: String = other.iter().map(|&c| c as char).collect();
                return Err(DdjError::Unsupported(format!("FourCC '{tag}'")));
            }
        }
        return Ok(argb_u32_to_rgba(&out_argb, width, height));
    }

    // ---- Uncompressed RGB path: dispatch on bitcount + masks ----
    if flags & DDPF_RGB != 0 {
        let has_alpha = flags & DDPF_ALPHAPIXELS != 0;
        let stride = row_stride(payload.len(), height, width as usize * (bitcount as usize / 8));

        match bitcount {
            32 => return Ok(unpack_32(payload, width, height, stride, rmask, gmask, bmask, amask, has_alpha)),
            24 => return Ok(unpack_24(payload, width, height, stride, rmask, gmask, bmask)),
            16 => return Ok(unpack_16(payload, width, height, stride, rmask, gmask, bmask, amask, has_alpha)),
            other => return Err(DdjError::Unsupported(format!("{other}bpp RGB"))),
        }
    }

    Err(DdjError::Unsupported(format!(
        "flags=0x{flags:08X} bpp={bitcount}"
    )))
}

fn argb_u32_to_rgba(argb: &[u32], width: u32, height: u32) -> DecodedImage {
    let mut rgba = Vec::with_capacity(argb.len() * 4);
    for &px in argb {
        let a = ((px >> 24) & 0xFF) as u8;
        let r = ((px >> 16) & 0xFF) as u8;
        let g = ((px >> 8) & 0xFF) as u8;
        let b = (px & 0xFF) as u8;
        rgba.extend_from_slice(&[r, g, b, a]);
    }
    DecodedImage { width, height, rgba }
}

fn row_stride(data_len: usize, height: u32, packed_row: usize) -> usize {
    if height == 0 {
        return packed_row;
    }
    (data_len / height as usize).max(packed_row)
}

// Generic mask helpers: extract a channel given its mask, scale to 8-bit.
#[inline]
fn extract(value: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let bits = (mask >> shift).count_ones();
    let raw = (value & mask) >> shift;
    // scale `bits`-wide value to 8 bits
    if bits >= 8 {
        (raw >> (bits - 8)) as u8
    } else {
        let max = (1u32 << bits) - 1;
        ((raw * 255 + max / 2) / max) as u8
    }
}

fn unpack_32(
    data: &[u8], width: u32, height: u32, stride: usize,
    rmask: u32, gmask: u32, bmask: u32, amask: u32, has_alpha: bool,
) -> DecodedImage {
    let w = width as usize;
    let h = height as usize;
    let packed = w * 4;
    let mut rgba = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        let row = &data[y * stride..y * stride + packed];
        for px in row.chunks_exact(4) {
            let v = u32::from_le_bytes([px[0], px[1], px[2], px[3]]);
            let r = extract(v, rmask);
            let g = extract(v, gmask);
            let b = extract(v, bmask);
            let a = if has_alpha && amask != 0 { extract(v, amask) } else { 0xFF };
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }
    DecodedImage { width, height, rgba }
}

fn unpack_24(
    data: &[u8], width: u32, height: u32, stride: usize,
    rmask: u32, gmask: u32, bmask: u32,
) -> DecodedImage {
    let w = width as usize;
    let h = height as usize;
    let packed = w * 3;
    let mut rgba = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        let row = &data[y * stride..y * stride + packed];
        for px in row.chunks_exact(3) {
            let v = u32::from_le_bytes([px[0], px[1], px[2], 0]);
            let r = extract(v, rmask);
            let g = extract(v, gmask);
            let b = extract(v, bmask);
            rgba.extend_from_slice(&[r, g, b, 0xFF]);
        }
    }
    DecodedImage { width, height, rgba }
}

fn unpack_16(
    data: &[u8], width: u32, height: u32, stride: usize,
    rmask: u32, gmask: u32, bmask: u32, amask: u32, has_alpha: bool,
) -> DecodedImage {
    let w = width as usize;
    let h = height as usize;
    let packed = w * 2;
    let mut rgba = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        let row = &data[y * stride..y * stride + packed];
        for px in row.chunks_exact(2) {
            let v = u16::from_le_bytes([px[0], px[1]]) as u32;
            let r = extract(v, rmask);
            let g = extract(v, gmask);
            let b = extract(v, bmask);
            let a = if has_alpha && amask != 0 { extract(v, amask) } else { 0xFF };
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }
    DecodedImage { width, height, rgba }
}