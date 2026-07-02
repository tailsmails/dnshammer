# DNS Hammer

A robust, highly resilient DNS cache-based covert communication channel written in V.

**DNS Hammer** encodes and transmits data through transient DNS cache latency differences. Instead of using static signatures, it generates pseudorandom, passphrase-derived subdomains that change dynamically in every time-window. This makes the channel virtually invisible to signature-based firewalls, DPI, and traffic analysis.

No custom DNS server infrastructure or domain registration is strictly required for testing. Both parties only need access to a shared recursive DNS resolver (e.g., `8.8.8.8` or a local resolver).

---

## Technical Architecture & How It Works

This upgraded version implements state-of-the-art DSP and networking protocol techniques to combat network jitter, latency spikes, and caching anomalies:

1. **Passphrase-Derived Dynamic Subdomains (PSK):** 
   Instead of using predictable subdomains like `d0.<domain>`, both parties provide a pre-shared passphrase (`--pass`). The program derives a highly secure 32-byte cryptographic seed from this passphrase using the memory-hard **Argon2id** algorithm (using a static 16-byte salt). This seed is then combined with the current time-window (`cts`), the target bit index, and query variant (0, 1, or 2), and hashed using **SHA3-512**. This generates highly stable, 8-character pseudorandom labels (e.g., `a7x2m9b1.domain.com`) mimicking standard tracking or CDN traffic.

2. **12-bit Micro-Framing (ARQ Protocol):**
   To maximize the probability of successful packet delivery under heavy network noise, data is sent in lightweight, dynamically sized frames (typically 12 bits when using `--chunk-size 1`):
   * **2-bit Rolling Index:** (0 to 3 modulo 4) provides sliding-window sequence control, preventing missing frames or duplicate packets.
   * **3-bit Salted Checksum:** A custom XOR-folded checksum salted with `^ 5` to break the "all-zeros" false-positive trap.
   * **Variable Payload:** (`g_chunk_size` bits) carries the actual data.
   * **2-bit Terminator:** `0b01` for standard chunk continuation, and `0b10` for End of Message (EOM). **The receiver no longer needs to know the message length in advance.**

3. **Parallel Bit Reading:**
   The receiver spawns parallel worker threads (`spawn`) to query and measure the latency of all frame bits simultaneously. This reduces chunk read times from seconds to milliseconds, completely preventing time-window phase slips and timing drifts.

4. **Dynamic Thresholding with LPF + Slew Rate Limiter (SRL):**
   To withstand severe network spikes, both sides run dynamic calibration during every cycle. It uses an **80/20 Low-Pass Filter (LPF)** combined with a **15ms Slew Rate Limiter (SRL)** to prevent sudden latency spikes from inflating the threshold and corrupting the readings.

5. **Decoupled Handshake:**
   The handshake cycle is cleanly split into two halves (Phase 2 first-half for reading, second-half for writing) to avoid timing collisions during startup synchronization.

---

## Quick Start (Copy - Paste - Enter)

```sh
apt update -y && apt install -y git clang make && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/dnshammer && cd dnshammer && v -enable-globals -prod dnsh.v -o dnsh && ln -sf $(pwd)/dnsh $PREFIX/bin/dnsh && dnsh
```

---

## Requirements

- V compiler (`vlang.io`)
- Linux / macOS / Termux
- Both sender and receiver must point to the same recursive DNS resolver

---

## Build

```bash
v -enable-globals -o dnsh dnsh.v
```

---

## Usage

```bash
dnsh [--dns SERVER] [--pass PASSPHRASE] [--chunk-size BITS] [--window TIME] <send|rec> [domain] [msg]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--dns SERVER` | Use a specific DNS resolver IP instead of the system default | System default |
| `--pass STRING` | Pre-shared passphrase used to cryptographically generate subdomains | `default_secure_passphrase` |
| `--chunk-size N` | Size of the payload chunk in bits (recommended: 1 or 5) | `5` |
| `--window SEC` | Timing cycle duration of changing the dynamic subdomains | `100s` (recommended: `20s`) |
| `--workers N` | Number of parallel threads for sending | `16` |

### 1. Send a Message

```bash
./dnsh --dns 8.8.8.8 --window 20 --chunk-size 1 --pass "MySecurePassword123!" send duckduckgooo.com "hello"
```

The sender will:
- Calibrate the local DNS lookup speed.
- Enter a decoupled handshake loop waiting for the receiver to signal `READY`.
- Begin transmission of the 12-bit micro-frames sequentially using a Stop-and-Wait ARQ loop.

### 2. Receive a Message

```bash
./dnsh --dns 8.8.8.8 --window 20 --chunk-size 1 --pass "MySecurePassword123!" rec duckduckgooo.com
```

The receiver will:
- Run a 5-attempt startup calibration to prevent inverted thresholds (`Slow < Fast`).
- Signal `READY` and wait for the sender to ACK.
- Concurrently read the frame bits using parallel threads in each cycle.
- Dynamically adapt its threshold using LPF+SRL and output the reconstructed bytes once the EOM terminator is received.

---

## Example Session

### Terminal 1 (Sender):

```text
$ ./dnsh --dns 194.225.152.10 --chunk-size 1 --window 20 --pass "SecretKey!" send duckduckgooo.com "a"
[*] dns server: 194.225.152.10
[*] calibrating...
[*] calibrated threshold: 99999µs (Fast: 49247, Slow: 150751, Gap: 101504µs)
[*] Security key derived successfully from password.
[tx] "a" -> "a" (1 chars)
[tx] Message CRC-8 Hash: 20
[tx] 3 total wire bytes (incl. Hash)
[tx] chunk size: 1 bits
[tx] Waiting for receiver READY signal (0001)...
[tx] Dynamic threshold updated (LPF+SRL): 114999µs (Fast: 94828, Slow: 337423)
[tx] Receiver is READY. Acknowledging and starting.
[tx] Sending START acknowledgement (3 cycles)...
[tx] Handshake complete.
[tx] Sending chunk #0 (RollIdx: 0) bits [0..1]
[tx] Receiver status: 1110
[tx] Sending chunk #1 (RollIdx: 1) bits [1..2]
```

### Terminal 2 (Receiver, different network):

```text
$ ./dnsh --dns 194.225.152.10 --chunk-size 1 --window 20 --pass "SecretKey!" rec duckduckgooo.com
[*] dns server: 194.225.152.10
[*] calibrating...
[*] calibrated threshold: 113554µs (Fast: 62996, Slow: 164113, Gap: 101117µs)
[*] Security key derived successfully from password.
[rx] Sending READY (0001) and waiting for START (0010)...
[rx] START detected. Entering reading loop.
[rx] Dynamic threshold updated (LPF+SRL): 116662µs (Fast: 48783, Slow: 209414)
[rx] Cycle start, reading chunk...
[rx] Chunk verified! RollIdx: 0, Term: 01 (hash OK)
[rx] First chunk accepted.
[rx] Cycle start, reading chunk...
[rx] Chunk verified! RollIdx: 1, Term: 01 (hash OK)
[rx] Chunk accepted.
```

---

## Domain Setup

For optimal real-world performance, configure a domain with a wildcard DNS record pointing to any arbitrary IP address:

```text
*.duckduckgooo.com  A  1.2.3.4
```

The actual target IP does not matter. The communication medium relies purely on cache residency and query resolution timing, not the IP address in the DNS response.

---

## License

![License](https://img.shields.io/badge/License-MIT-blue.svg)
