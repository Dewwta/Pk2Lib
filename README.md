# Pk2Lib

Reads (and writes, on the C++ side) JoyMax PK2 archives, the package format used by Silkroad Online to store its game data. Handles the Blowfish-encrypted directory blocks and entry table, and can also decode the DDJ textures (DDS wrapped in a JoyMax header) used for item/skill icons into raw RGBA pixels.

Two implementations, same format, written independently:

- `CPP/` — read/write, static or DLL.
- `Rust/` — read-only archive access plus DDJ -> RGBA decoding (DXT1/3/5 and uncompressed 16/24/32bpp).

## C++

```cpp
#include "Pk2Lib/Pk2Archive.h"

Pk2Archive pk2;
pk2.Open(L"media.pk2");

std::vector<uint8_t> data;
pk2.ReadFile("icon\\item\\sword.ddj", data);

for (auto& name : pk2.List("icon\\item"))
    printf("%s\n", name.c_str());
```

## Rust

```rust
use Pk2Lib::{Pk2Archive, OpenMode};
use Pk2Lib::Ddj;

let mut pk2 = Pk2Archive::new();
pk2.open(Path::new("media.pk2"), OpenMode::ReadOnly)?;

let bytes = pk2.read_file("icon\\item\\sword.ddj")?;
let img = Ddj::decode_ddj(&bytes)?;
// img.width, img.height, img.rgba
```

Both use the standard Silkroad key (password `169841` xor'd with the JoyMax salt) by default.
