# DNS Hammer

A covert communication channel that encodes data into DNS cache timing differences.

The sender caches specific subdomains on a shared recursive DNS resolver. The receiver measures query response times to distinguish cached (fast) from uncached (slow) lookups, reconstructing the original message bit by bit.

No custom server infrastructure is needed. Both parties only need access to the same public DNS resolver (e.g. 8.8.8.8).

---

## How it works

1. The message is converted to binary (8 bits per byte).
2. For each bit position, a subdomain like `<bit_index>.<domain>` is used.
3. A `0` bit is represented by caching that subdomain (two rapid queries warm the cache).
4. A `1` bit is left uncached (no query is made).
5. The receiver queries every subdomain and measures response time:
   - Fast response = cached = bit `0`
   - Slow response = uncached = bit `1`
6. A calibration step using known cached (`c0.`) and uncached (`c1.`) subdomains determines the threshold.
7. The sender runs a keepalive loop to prevent cache entries from expiring before the receiver reads them.

---

## Quick start (copy - paste - enter)

```sh
apt update -y && apt install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/dnshammer && cd dnshammer && v -enable-globals -prod dnsh.v -o dnsh && ln -sf $(pwd)/dnsh $PREFIX/bin/dnsh && dnsh
```

---

## Requirements

- V compiler (vlang.io)
- Linux / macOS / Termux (uses POSIX sockets)
- Both sender and receiver must use the same recursive DNS resolver

---

## Build

```
v -enable-globals -o dnsh dnsh.v
```

---

## Usage

```
dnsh [--dns SERVER] [--workers N] <send|rec> [domain] [msg|bytes]
```

### Send a message

```
./dnsh send example.com "Hello"
```

With a specific DNS server and 8 parallel workers:

```
./dnsh --dns 8.8.8.8 --workers 8 send example.com "Hello"
```

The sender will:
- Encode and cache the message
- Print the number of cached subdomains
- Enter a keepalive loop that periodically refreshes the cache

Keep the sender running until the receiver has finished reading.

### Receive a message

```
./dnsh rec example.com 5
```

With a specific DNS server:

```
./dnsh --dns 8.8.8.8 rec example.com 5
```

The byte count argument must match the length of the sent message. The receiver will:
- Calibrate by measuring cached vs uncached response times
- Read each bit sequentially and reconstruct the bytes
- Print each byte and the final decoded message

---

## Options

| Flag | Description |
|------|-------------|
| `--dns SERVER` | Use a specific DNS resolver IP instead of the system default |
| `--workers N` | Number of parallel threads for sending (default: 4). Only affects send mode. Receive is always sequential to preserve timing accuracy. |
| `--window TIME` | The time of changing the domain to refresh everything cached (default: 100s). |

---

## Example session

Terminal 1 (sender):

```
$ ./dnsh --dns 8.8.8.8 send x88mes11.com "Hi"
[*] dns server: 8.8.8.8
[tx] "Hi" -> 2 bytes / 16 bits
[tx] sending with 4 workers...
[tx] cached 9 subdomains
[tx] keepalive running... (ctrl+c to stop)

  [keepalive #1] 9 entries refreshed
  [keepalive #2] 9 entries refreshed
```

Terminal 2 (receiver, different network):

```
$ ./dnsh --dns 8.8.8.8 rec x88mes11.com 2
[*] dns server: 8.8.8.8
[rx] reading 2 bytes...

[rx] calibrating...
[rx] fast:1ms slow:24ms gap:23ms thr:12ms

  byte #0  [1, 23, 1, 24, 1, 25, 1, 25]ms  ->  "H"
  byte #1  [1, 22, 1, 24, 1, 25, 25, 1]ms  ->  "i"

[rx] "Hi"
```

---

## Limitations

- Throughput is low (a few bytes per session is practical).
- DNS cache TTL varies by resolver. The keepalive loop compensates, but long delays between send and receive may cause errors.
- Some resolvers may not cache wildcard subdomains or may apply rate limiting.
- The receiver must know the exact message length in advance.
- Reading is sequential by design. Parallel reads break timing measurements.

---

## Domain setup

You need a domain with a wildcard DNS record pointing to any IP address:

```
*.x88mes11.com  A  1.2.3.4
```

The actual IP does not matter. The channel only relies on cache timing, not the resolved address.

---

## License
![License](https://img.shields.io/badge/License-MIT-blue.svg)