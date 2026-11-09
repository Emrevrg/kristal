# Kristal (formerly Sıkıştır)

Lossless file and folder compression that picks the best method per file type and verifies every archive bit-for-bit.

## Quick start
```python
from sikistir5 import pack, unpack
pack("my_folder", "my_folder.krs")
unpack("my_folder.krs", "restored")
```

## Measured (compression ratio, higher is better, all bit-exact)
| Data | Kristal | xz -9e |
|---|---|---|
| Source code | **4.982** | 4.589 |
| Plain text | **7.197** | 6.514 |
| JPEG | **1.163** | 1.003 |
| PNG | **1.373** | 1.004 |
| Icons | **8.929** | 8.894 |
| Documents | **1.244** | 1.234 |
| Model weights (with IRIS) | **1.501** | 1.428 |

Each archive is the smaller of two verified routes: content-defined chunking with per-type coders (lossless JPEG/PNG recompression, precomp), or a deterministic tar with the best of xz, zstd, brotli and PPMd. bf16 model files go through the IRIS layer.

License: MIT. Measured on one week of NVIDIA H100 time provided by portvMind (vMind) Public Cloud.