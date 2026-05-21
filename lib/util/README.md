# util/ -- Shared Utilities

A small grab-bag library for cross-cutting helpers that don't earn a
dedicated module of their own.

## API

```c
#include "zeroize.h"

void zeroize(volatile void *mem, size_t len);
```

`zeroize()` writes zero bytes over `len` bytes starting at `mem`.  The
`volatile` qualifier on the pointer is load-bearing: it prevents the
compiler from eliminating the writes as dead stores when the memory is
about to be freed or to leave scope.  Use it any time a buffer that held
key material, a CSR private key, an SCEP challenge password, or an
NVS-decrypted credential blob is about to be released.

`len == 0` is a safe no-op.  `mem == NULL` with `len == 0` is also safe;
calling with `mem == NULL` and `len > 0` is undefined behaviour, same as
`memset`.

## Callers

| Caller | Why |
|---|---|
| `main/scep_enroll.c` | Wipes the heap-allocated RSA private-key DER, CSR DER, self-signed cert DER, PKCS#7 request, and issued cert DER before `heap_caps_free` |
| `main/host_key.c` | Wipes the wolfSSH host key DER buffer in error paths (also via the local `ForceZero` macro alias that expands to `zeroize`) |
| `lib/cred_store/cred_store.c` | Wipes the in-memory decrypted credential blob before returning it to the heap |

## Tests

`test/native/test_util/test_util.c` covers:

- `test_zeroize_clears_buffer` -- full buffer overwrite check
- `test_zeroize_zero_len_is_noop` -- zero-length call leaves bytes intact
- `test_zeroize_single_byte` -- one-byte clear

The function is platform-agnostic and compiles unchanged on both the
ESP32-S3 target and the native host.
