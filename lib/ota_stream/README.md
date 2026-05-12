# ota_stream — Streaming Read Accumulator for OTA Image Transfer

`ota_stream_read_all` reads an unknown-length byte stream into a single
contiguous buffer that grows geometrically until the stream closes.  The
function starts with a 4 KiB allocation on the first non-zero read and doubles
capacity on each subsequent grow, capping the final size at the caller-supplied
`max_bytes` limit.  Reads are issued directly into the tail of the live buffer
with no intermediate scratch copy, so a single wolfSSH chunk of any size lands
without an extra `memcpy` and without an artificially small per-call ceiling.
The loop terminates when `read_fn` returns a negative value (terminal
EOF/error) or when `max_zero_retries` consecutive transient zero-returns
accumulate without any intervening progress.

The read callback has the signature `int (*)(void *ctx, uint8_t *buf, size_t
cap)` and mirrors the `wolfSSH_stream_read` convention: positive means bytes
read, zero means transient (WS_WANT_READ), negative means terminal.  In
production `main/ota_session.c` supplies `wolfssh_read_adapter`, a thin
wrapper that translates `WS_WANT_READ` to 0 (with a 10 ms `vTaskDelay`) and
any other non-positive result to -1.  The `max_zero_retries` budget
(60 000 in production, roughly 10 minutes of idle) replaces the original
open-ended retry loop with a finite patience window.

The result is one of four values: `OTA_STREAM_OK`, `OTA_STREAM_ERR_EMPTY`
(stream closed before any bytes were stored), `OTA_STREAM_ERR_OOM` (allocator
returned NULL), or `OTA_STREAM_ERR_TOOBIG` (a successful read would push the
total past `max_bytes`).  On every error path the partial buffer is freed via
`free_fn` before returning, and `*out_buf` is set to NULL so the caller never
sees a stale pointer.  On success the caller owns `*out_buf` and must release
it with the matching `free_fn`.

The allocator hooks (`alloc_fn`, `realloc_fn`, `free_fn`) decouple buffer
placement from the accumulator logic.  Production code passes `psram_alloc`,
`psram_realloc`, and `psram_free` — thin wrappers around `heap_caps_malloc`,
`heap_caps_realloc`, and `heap_caps_free` with `MALLOC_CAP_SPIRAM` — so the
multi-megabyte OTA image lands in the ESP32-S3's 8 MB PSRAM rather than
internal SRAM.  Native unit tests inject counter-based mock hooks to force OOM
on the Nth allocator call and assert that the partial buffer is released
exactly once; passing NULL for all three falls back to `calloc`/`realloc`/
`free`.  The library has no ESP-IDF or wolfSSH includes and builds identically
for the firmware and the host Unity test suite.

## API

```c
ota_stream_result_t ota_stream_read_all(
    ota_stream_read_fn    read_fn,       /* data source */
    void                 *ctx,           /* forwarded to read_fn */
    size_t                max_bytes,     /* hard cap; triggers ERR_TOOBIG */
    unsigned              max_zero_retries,
    ota_stream_alloc_fn   alloc_fn,      /* NULL → calloc */
    ota_stream_realloc_fn realloc_fn,    /* NULL → realloc */
    ota_stream_free_fn    free_fn,       /* NULL → free */
    uint8_t             **out_buf,       /* set on OK; NULL on error */
    size_t               *out_len);      /* set on OK; 0 on error */
```

## Tests

7 cases in `test/native/test_ota_stream/`.  Covers geometric buffer growth
with payload-integrity verification, transient zero-return retry behaviour,
OOM injection with partial-buffer-release assertion, immediate-EOF empty
stream, `max_bytes` exceeded, a single small read that fits the initial
allocation without a realloc, and zero-retry budget exhaustion.
