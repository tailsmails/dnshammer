# DNS Hammer

A covert communication channel that encodes data into DNS cache timing differences.

The sender caches specific subdomains on a shared recursive DNS resolver. The receiver measures query response times to distinguish cached (fast) from uncached (slow) lookups, reconstructing the original message bit by bit.

No custom server infrastructure is needed. Both parties only need access to the same public DNS resolver (e.g. 8.8.8.8).

---

## How it works

DNS Hammer uses a multi-phase synchronization protocol to reliably tunnel data:

1.  **Phased Cycles:** Communication is divided into cycles consisting of three phases:
    -   **T1 (Sender):** The sender caches bits (0 = cached, 1 = uncached). It performs two passes (Initial + Keep-alive) for maximum reliability.
    -   **T2 (Receiver):** The receiver measures query response times to reconstruct the message.
    -   **TK (Sync):** Both parties exchange status signals (READY, START, SUCCESS, ERROR) to manage flow control.
2.  **Bi-Directional Handshake:** The receiver starts by signaling `READY`. The sender acknowledges with `START` only when it detects the receiver is listening.
3.  **Chunked Transmission:** Messages are split into configurable chunks. Each chunk is indexed and includes a validation hash to detect and correct transmission errors.
4.  **Fuzzy Matching:** Magic byte sequences (`EEEE` for chunk end, `AAAA` for message end) use fuzzy logic to remain recognizable even with network timing noise.
5.  **Automatic Fallback:** The tool automatically uses root-level raw sockets for precise timing if available, gracefully falling back to standard UDP sockets if not.

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
dnsh [--dns SERVER] [--workers N] [--window SEC] [--hs-window SEC] [--chunk-size N] <send|rec> [domain] [msg]
```

### Send a message

```
./dnsh send example.com "Hello"
```

With a specific DNS server and 16 parallel workers:

```
./dnsh --dns 8.8.8.8 --workers 16 send example.com "Hello"
```

The sender will:
- Calibrate and wait for the receiver's `READY` signal.
- Transmit the message in indexed chunks with hash verification.
- Perform a termination handshake to ensure the receiver has fully captured the data.

### Receive a message

```
./dnsh rec example.com
```

The receiver will:
- Calibrate and signal `READY` to the sender.
- Automatically detect the message length and reconstruction boundary via magic bytes.
- Verify per-chunk and end-to-end hashes for perfect data integrity.

---

## Options

| Flag | Description |
|------|-------------|
| `--dns SERVER` | Use a specific DNS resolver IP. |
| `--workers N` | Number of parallel threads for sending (default: 16). |
| `--window SEC` | Duration of the main data phases (default: 100s). |
| `--hs-window SEC` | Duration of the fast startup handshake cycles (default: 10s). |
| `--chunk-size N` | Number of bytes to send per cycle (default: 5). |

---

## Example session

Terminal 1 (sender):

```
$ ./dnsh --dns 8.8.8.8 send target.com "Hi"
[*] calibrating...
[*] calibrated threshold: 74545µs
[tx] "Hi" -> "hi" (2 chars)
[tx] Hash: FF
[tx] Waiting for receiver READY signal (0111)...
[tx] Receiver is READY. Acknowledging and starting.
[tx] Sending chunk #0 [0..3]
[tx] Receiver status: 0100
[tx] Termination confirmed. Done.
```

Terminal 2 (receiver):

```
$ ./dnsh --dns 8.8.8.8 rec target.com
[*] calibrating...
[*] calibrated threshold: 96832µs
[rx] Sending READY (0111) and waiting for START (1100)...
[rx] START detected. Entering reading loop.
[rx] Cycle start, reading chunk...
[rx] Chunk #0 valid (terminator: AAAA, hash OK)
[rx] Final message: "hi"
[rx] Hash verified successfully.
[rx] Entering termination handshake...
```

---

## Limitations

- Throughput is low (a few bytes per session is practical).
- DNS cache TTL varies by resolver. The phased protocol compensates, but long delays between phases may cause errors.
- Some resolvers may not cache wildcard subdomains or may apply rate limiting.
- Reading is sequential by design to preserve timing accuracy.

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
