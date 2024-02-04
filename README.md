# passwordfile
C++ library to read/write key-value pairs from/to AES-256-CBC encrypted files.
It is using OpenSSL under the hood. The key-value pairs are organized in tables
within an hierarchical structure. The data can be compressed with gzip before
applying the encryption.

## Build instructions
The passwordfile library depends on c++utilities and is built in the same way.
It also depends on OpenSSL and zlib.

## Copyright notice and license
Copyright © 2015-2024 Marius Kittler

All code is licensed under [GPL-2-or-later](LICENSE).
