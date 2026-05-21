# lib/udp_log -- UDP log mirror

Mirrors every `ESP_LOG*` line to a UDP datagram while keeping UART0 output
intact. Useful on the Zero, which lacks the CH340 UART bridge, or in any
situation where reading the UART console is inconvenient.

## Configuration

Add to `config.h` (both macros are required to enable the feature):

```c
#define UDP_LOG_HOST  "10.57.16.10"   /* destination IPv4 address */
#define UDP_LOG_PORT  5514             /* destination UDP port */
```

When either macro is absent, no UDP code is compiled or linked.

## API

```c
esp_err_t udp_log_init(void);   /* install vprintf hook; call once after Wi-Fi GOT_IP */
void      udp_log_deinit(void); /* uninstall; idempotent */
```

`udp_log_init()` is called automatically from `main/wifi.c` right after the
first `IP_EVENT_STA_GOT_IP` event when both macros are defined.

## Capturing on the receiver

```
nc -ul 5514
```

Any UDP listener works. On macOS you may need `nc -u -l 5514`.

## ANSI escape sequences

ESP-IDF colours log output with ANSI escape codes (e.g. `\e[0;32m` for
green INFO lines). These are forwarded verbatim in the UDP datagram. Most
terminals and `cat` render them correctly. To strip them:

```
nc -ul 5514 | sed 's/\x1B\[[0-9;]*m//g'
```

## What gets sent and what doesn't

- Log lines produced **before** `udp_log_init()` is called (i.e. everything
  that happens before Wi-Fi GOT_IP) are **never sent via UDP**. They appear
  only on UART0. This is expected -- the network is not yet available.
- After `udp_log_init()` every `ESP_LOG*` call produces both a UART line and
  a UDP datagram.
- If Wi-Fi drops, `sendto()` fails silently. The UART path is unaffected.

## Implementation notes

- The UDP socket is created lazily on the first log call after init; this
  avoids ordering issues with lwIP socket initialization.
- `sendto()` is non-blocking. Datagrams are dropped (never buffered) if the
  network is congested or unavailable.
- No dynamic allocation per log line -- the format buffer is on the stack.
- No mutex is taken inside the vprintf hook to avoid blocking ISR contexts.
  Lazy socket creation uses `xSemaphoreTake(mutex, 0)` (trylock) and skips
  if the lock is held.
