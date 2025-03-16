<h1 align="center">sum :heavy_check_mark:</h1>

<p align="center">
  <a href="https://go.dev"><img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/70sh1/sum"></a>
  <a href="https://goreportcard.com/report/github.com/70sh1/sum"><img alt="Go code report card" src="https://goreportcard.com/badge/github.com/70sh1/sum"></a>
  <a href="https://github.com/70sh1/sum/blob/main/LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green"></a>
</p>

_sum_ is a minimal and concurrent CLI file hashing tool.

### Flags
`-m` - specify hash function.

Currently supported:
| `sha256`  | default                       |
| --------- | ----------------------------- |
| `sha512`  | -                             |
| `sha1`    | -                             |
| `blake2b` | -                             |
| `blake3`  | modern & fast                 |
| `xxh3`    | non-cryptographic & very fast |
| `md5`     | -                             |

`-u` - calculate union hash (sum of multiple files combined).

### Examples
```bash
sum data.txt
# aa3ec16e6acc809d8b2818662276256abfd2f1b441cb51574933f3d4bd115d11 data.txt

sum -m blake3 data.txt
# c7a4b65f79934d742ea07a9e85b3bbb1ab9ad9f42033d8a0698495d0f564c804 data.txt

sum -m md5 data.txt file2.png bin.exe
# 764569e58f53ea8b6404f6fa7fc0247f data.txt
# 79695d7d0054d14d68b513ed997f7946 file2.png
# 65e3dd724be2affbda44084e213ea63a bin.exe

sum -m xxh3 -u data.txt file2.png bin.exe
# cef94edd97ad53f0 (3 files)
```

## Installation
Prebuilt binaries are available for **Windows, Linux, and macOS (both x86 and ARM)**: download the latest release from the [releases](https://github.com/70sh1/eddy/releases) page for the desired OS.

---

If you have [Go](https://go.dev/dl/) installed, the simplest way to get _sum_ is to run:
```shell
go install github.com/70sh1/sum@latest
```
> If you are on Linux and using this method, make sure that go bin path is added to your PATH environment variable: e.g. `export PATH=$PATH:$HOME/go/bin`

## Acknowledgements
[zeebo/blake3](https://github.com/zeebo/blake3) - blake3 implementation.

[zeebo/xxh3](https://github.com/zeebo/xxh3) - xxh3 implementation.

