# lib/udp_log -- UDP log mirror with coalescing + sequence numbers

Mirrors every `ESP_LOG*` line to a UDP datagram while keeping UART0 output
intact. Useful on the Zero, which lacks the CH340 UART bridge, or in any
situation where reading the UART console is inconvenient.

## Configuration

Add to `config.h` (both required to enable the feature):

```c
#define UDP_LOG_HOST  "10.57.16.10"   /* destination IPv4 address */
#define UDP_LOG_PORT  5514            /* destination UDP port    */
```

When either macro is absent, no UDP code is compiled or linked.

### Optional tunables

All have `#ifndef` fallbacks; override only if defaults don't fit:

| Macro | Default | What |
|---|---|---|
| `UDP_LOG_LINE_MAX` | `256` | Per-line scratch buffer; one ESP_LOG line longer than this is truncated |
| `UDP_LOG_DGRAM_MAX` | `1300` | Accumulator size. Stays under a typical 1500-byte path MTU after the 28-byte IPv4+UDP header |
| `UDP_LOG_FLUSH_TIMEOUT_MS` | `50` | If the accumulator has content and has been idle this long, the flush task emits a datagram |
| `UDP_LOG_POLL_MS` | `25` | Flush task tick. Lower = more responsive, higher = less wake cost |
| `UDP_LOG_FLUSH_STACK` | `4096` | Flush task stack (holds the ~1.3 KB wire-stitch buffer plus FreeRTOS overhead) |
| `UDP_LOG_FLUSH_PRIO` | `3` | Flush task priority. Keep low so it never preempts real work |

## API

```c
esp_err_t udp_log_init(void);   /* installs the hook + starts flush task */
void      udp_log_deinit(void); /* uninstalls; idempotent */
```

`udp_log_init()` is called automatically from `main/wifi.c` right after the
first `IP_EVENT_STA_GOT_IP` (or after the static-IP `STA_CONNECTED` path)
when both macros are defined.

## Capturing on the receiver

```
nc -ul 5514
```

Any UDP listener works. On macOS you may need `nc -u -l 5514`.

## Wire format

Each datagram starts with a sequence header `#<seq>\n` and then contains
one or more concatenated `ESP_LOG*` lines (themselves newline-terminated):

```
#0
I (1234) wifi: line one
I (1235) wifi: line two
I (1240) ssh_server: line three
```

The sequence number is a monotonically increasing `uint32_t`. Gaps on the
receiver mean datagrams were lost in transit (Wi-Fi flap, kernel TX queue
overflow, etc.) -- you can scroll the UART log for the missing window. The
sequence increments even when no socket is available, so a gap from
pre-Wi-Fi/Wi-Fi-down windows is also visible to the receiver as soon as
the next datagram arrives.

## Why coalescing?

Per-line `sendto()` bursts at boot hit the kernel's UDP send-rate ceiling
(particularly on lwIP), dropping ~50% of log lines on the wire. By packing
multiple lines into one near-MTU datagram, the per-packet overhead is
amortised and the receiver sees the full log even under boot bursts.

## Flush triggers

A datagram is emitted when either:

1. **Overflow** -- the next ESP_LOG line would push the accumulator past
   `UDP_LOG_DGRAM_MAX`. The hook flushes inline, then appends the new
   line to a fresh accumulator. Bursts > 1300 bytes become multiple
   sequentially numbered datagrams, back-to-back.
2. **Idle** -- the accumulator has content and has been idle for
   `UDP_LOG_FLUSH_TIMEOUT_MS`. The background flush task drains it.

A degenerate case: a single ESP_LOG line larger than `UDP_LOG_DGRAM_MAX`
is truncated and sent standalone. This is extremely rare in practice;
`UDP_LOG_LINE_MAX` already caps lines at 256 bytes before they reach the
accumulator.

## ANSI escape sequences

ESP-IDF colours log output with ANSI escape codes (e.g. `\e[0;32m` for
green INFO lines). These are forwarded verbatim. Most terminals and
`cat` render them correctly. To strip them:

```
nc -ul 5514 | sed 's/\x1B\[[0-9;]*m//g'
```

## What gets sent and what doesn't

- Log lines produced **before** `udp_log_init()` is called (everything
  that happens before Wi-Fi GOT_IP) are **never sent via UDP**. They
  appear only on UART0.
- After `udp_log_init()` every `ESP_LOG*` call appears on both UART and
  -- once coalesced into a datagram -- UDP.
- If Wi-Fi drops, `sendto()` fails silently. The accumulator is dropped
  and the sequence number still advances so the next received datagram
  signals a gap.

## Implementation notes

- The UDP socket is created lazily on the first log call after init.
- `sendto()` is non-blocking (`O_NONBLOCK`). The socket never stalls a
  log callsite.
- A single mutex (`s_acc_mutex`) guards the accumulator. The hook
  acquires it with `xSemaphoreTake(mutex, 0)` (trylock) and drops the
  current line on contention rather than ever blocking.
- The flush task is a low-priority FreeRTOS task that wakes every
  `UDP_LOG_POLL_MS`, takes the lock, and flushes if the idle timeout
  has elapsed.
- The wire-stitch buffer (~1316 bytes) is a single static. It's only
  touched while the accumulator mutex is held, so a static is safe.
- No dynamic allocation on the log hot path; lazy socket allocation
  happens once.

## Tests

`test/native/test_udp_log/test_udp_log.c` covers two layers:

- Line-formatting / UART chain / fd-not-ready guard (8 cases)
- Accumulator / overflow / idle flush / sequence numbers /
  fd-unavailable seq bump / oversize-line standalone (8 cases)

The harness mirrors the production logic inline so the tests run on
the host without ESP-IDF or FreeRTOS.
