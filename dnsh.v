module main

import os
import time
import rand

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

fn C.gethostbyname(name &u8) voidptr
fn C.socket(domain int, @type int, protocol int) int
fn C.close(fd int) int
fn C.connect(fd int, addr voidptr, addrlen u32) int
fn C.send(fd int, buf voidptr, len usize, flags int) isize
fn C.recv(fd int, buf voidptr, len usize, flags int) isize
fn C.setsockopt(fd int, level int, optname int, optval voidptr, optlen u32) int
fn C.htons(v u16) u16
fn C.inet_pton(af int, src &u8, dst voidptr) int

struct C.sockaddr_in {
mut:
	sin_family u16
	sin_port   u16
	sin_addr   C.in_addr
}

struct C.in_addr {
mut:
	s_addr u32
}

struct SockTimeout {
mut:
	sec  i64
	usec i64
}

__global window = 100
__global g_dns = ''
__global g_workers = 4

fn get_ts() i64 {
	return time.now().unix() / window
}

fn char_idx(ch u8) int {
	if ch == ` ` {
		return 0
	}
	return int(ch - `a`) + 1
}

fn huffman_encode(msg string) ([]u8, string) {
	codes := [u32(0), 5, 60, 25, 22, 1, 56, 57, 21, 7, 125, 124, 23, 26, 8, 6, 59, 254, 20,
		9, 4, 24, 61, 27, 126, 58, 255]
	lens := [u8(3), 4, 6, 5, 5, 3, 6, 6, 5, 4, 7, 7, 5, 5, 4, 4, 6, 8, 5, 4, 4, 5, 6, 5,
		7, 6, 8]

	mut filtered := []u8{}
	for ch in msg.bytes() {
		mut c := ch
		if c >= `A` && c <= `Z` {
			c += 32
		}
		if (c >= `a` && c <= `z`) || c == ` ` {
			filtered << c
		}
	}

	mut bits := []u8{}
	for c in filtered {
		idx := char_idx(c)
		code := codes[idx]
		length := int(lens[idx])
		for b in 0 .. length {
			bits << u8((code >> u32(length - 1 - b)) & 1)
		}
	}

	mut result := []u8{}
	result << u8(filtered.len)
	mut i := 0
	for i < bits.len {
		mut bv := u8(0)
		for b in 0 .. 8 {
			bv = bv << 1
			if i + b < bits.len {
				bv |= bits[i + b]
			}
		}
		result << bv
		i += 8
	}
	return result, filtered.bytestr()
}

fn huffman_decode(data []u8) string {
	if data.len < 2 {
		return ''
	}
	nchars := int(data[0])
	syms := [u8(` `), `e`, `t`, `a`, `o`, `i`, `n`, `s`, `r`, `h`, `d`, `l`, `u`, `c`, `m`,
		`w`, `f`, `g`, `y`, `p`, `b`, `v`, `k`, `j`, `x`, `q`, `z`]
	fc := [0, 0, 0, 0, 4, 20, 56, 124, 254]
	fo := [0, 0, 0, 0, 2, 8, 16, 22, 25]
	cn := [0, 0, 0, 2, 6, 8, 6, 3, 2]

	mut bits := []u8{}
	for i in 1 .. data.len {
		for b in 0 .. 8 {
			bits << (data[i] >> u8(7 - b)) & 1
		}
	}

	mut result := []u8{}
	mut pos := 0
	for _ in 0 .. nchars {
		mut code := 0
		mut found := false
		for l in 1 .. 9 {
			if pos >= bits.len {
				break
			}
			code = (code << 1) | int(bits[pos])
			pos++
			if l >= 3 && code >= fc[l] && code - fc[l] < cn[l] {
				result << syms[fo[l] + code - fc[l]]
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return result.bytestr()
}

fn build_dns_query(host string) []u8 {
	mut pkt := []u8{cap: 128}
	pkt << u8(0xAA)
	pkt << u8(0xBB)
	pkt << u8(0x01)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x01)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x00)
	for label in host.split('.') {
		pkt << u8(label.len)
		pkt << label.bytes()
	}
	pkt << u8(0x00)
	pkt << u8(0x00)
	pkt << u8(0x01)
	pkt << u8(0x00)
	pkt << u8(0x01)
	return pkt
}

fn resolve_custom(host string) !i64 {
	sw := time.new_stopwatch()
	fd := C.socket(C.AF_INET, C.SOCK_DGRAM, 0)
	if fd < 0 {
		return error('socket failed')
	}
	tv := SockTimeout{sec: 5, usec: 0}
	C.setsockopt(fd, C.SOL_SOCKET, C.SO_RCVTIMEO, &tv, sizeof(tv))
	mut sa := C.sockaddr_in{}
	sa.sin_family = u16(C.AF_INET)
	sa.sin_port = C.htons(53)
	C.inet_pton(C.AF_INET, g_dns.str, &sa.sin_addr)
	if C.connect(fd, &sa, sizeof(sa)) < 0 {
		C.close(fd)
		return error('connect failed')
	}
	pkt := build_dns_query(host)
	C.send(fd, pkt.data, usize(pkt.len), 0)
	mut buf := []u8{len: 512}
	n := C.recv(fd, buf.data, usize(512), 0)
	C.close(fd)
	if n < 0 {
		return error('timeout')
	}
	elapsed := sw.elapsed().milliseconds()
	if elapsed > 5000 {
		return error('timeout')
	}
	return elapsed
}

fn resolve(host string) !i64 {
	if g_dns.len > 0 {
		return resolve_custom(host)
	}
	sw := time.new_stopwatch()
	_ := C.gethostbyname(host.str)
	elapsed := sw.elapsed().milliseconds()
	if elapsed > 5000 {
		return error('timeout')
	}
	return elapsed
}

fn resolve_safe(host string) i64 {
	for attempt in 0 .. 5 {
		t := resolve(host) or {
			time.sleep((500 + attempt * 1000) * time.millisecond)
			continue
		}
		return t
	}
	return -1
}

@[noreturn]
fn die(s string) {
	eprintln('[!] ${s}')
	exit(1)
}

fn send_byte(base string, byte_idx int, ch u8) {
	ts := get_ts()
	for bit in 0 .. 8 {
		idx := byte_idx * 8 + bit
		b := u8((ch >> (7 - bit)) & 1)
		if b == 0 {
			for _ in 0 .. 5 {
				resolve('${idx}${ts}${base}') or {}
				resolve('v${idx}${ts}${base}') or {}
				resolve('w${idx}${ts}${base}') or {}
			}
		}
	}
}

fn send_mode(base string, msg string) {
	resolve('c0.${base}') or { die('network down') }
	time.sleep(50 * time.millisecond)
	resolve('c0.${base}') or {}

	data, filtered := huffman_encode(msg)

	println('[tx] "${msg}" -> "${filtered}" (${filtered.len} chars)')
	println('[tx] ${data.len} wire bytes (huffman)')
	if g_dns == "" { println('[tx] receiver cmd:  dnsh rec ${base} ${data.len}') }
	else { println('[tx] receiver cmd:  dnsh --dns ${g_dns} rec ${base} ${data.len}') }
	println('[tx] sending with ${g_workers} workers...')

	mut pos := 0
	for pos < data.len {
		mut end := pos + g_workers
		if end > data.len {
			end = data.len
		}
		mut threads := []thread{}
		for i in pos .. end {
			threads << spawn send_byte(base, i, data[i])
		}
		threads.wait()
		time.sleep(100 * time.millisecond)
		pos = end
	}

	resolve('c0.${base}') or {}

	mut zeros := 0
	for ch in data {
		for bit in 0 .. 8 {
			if ((ch >> (7 - bit)) & 1) == 0 {
				zeros++
			}
		}
	}

	println('[tx] cached ${zeros} subdomains')
	println('[tx] keepalive running... (ctrl+c to stop)\n')
	
	mut round := 0
	for {
		ts := get_ts()
		round++
		mut refreshed := 0
		for i in 0 .. data.len {
			ch := data[i]
			for bit in 0 .. 8 {
				idx := i * 8 + bit
				if ((ch >> (7 - bit)) & 1) == 0 {
					resolve('${idx}${ts}${base}') or {}
					time.sleep(100 * time.millisecond)
					resolve('v${idx}${ts}${base}') or {}
					time.sleep(100 * time.millisecond)
					resolve('w${idx}${ts}${base}') or {}
					time.sleep(100 * time.millisecond)
					refreshed++
				}
			}
		}
		resolve('c0.${base}') or {}
		println('  [keepalive #${round}] ${refreshed} entries refreshed')
		time.sleep(5 * time.second)
	}
}

fn rec_mode(base string, nbytes int) {
	println('[rx] reading ${nbytes} wire bytes (huffman)...\n')
	println('[rx] calibrating...')

	mut fast_arr := []i64{}
	mut slow_arr := []i64{}

	for _ in 0 .. 7 {
		f := resolve_safe('c0.${base}')
		if f >= 0 {
			fast_arr << f
		}
		time.sleep(100 * time.millisecond)
	}
	for _ in 0 .. 7 {
		s := resolve_safe('u${rand.intn(99999) or { 0 }}.${base}')
		if s >= 0 {
			slow_arr << s
		}
		time.sleep(100 * time.millisecond)
	}

	if fast_arr.len < 3 || slow_arr.len < 3 {
		die('calibration failed')
	}

	fast_arr.sort()
	slow_arr.sort()
	fast_med := fast_arr[fast_arr.len / 2]
	slow_med := slow_arr[slow_arr.len / 2]
	gap := slow_med - fast_med

	if gap < 10 {
		die('gap ${gap}ms too small (fast:${fast_med} slow:${slow_med}) - sender running?')
	}

	mut thr := (fast_med + slow_med) / 2
	if thr < 10 {
		thr = 10
	}

	println('[rx] fast:${fast_med}ms slow:${slow_med}ms gap:${gap}ms thr:${thr}ms\n')

	mut out := []u8{}
	mut bit_idx := 0

	for i in 0 .. nbytes {
		mut ch := u8(0)
		mut ts := []i64{}
		tsd := get_ts()
		
		for _ in 0 .. 8 {
			time.sleep(100 * time.millisecond)
			t1 := resolve_safe('${bit_idx}${tsd}${base}')
			time.sleep(200 * time.millisecond)
			t2 := resolve_safe('v${bit_idx}${tsd}${base}')
			time.sleep(300 * time.millisecond)
			t3 := resolve_safe('w${bit_idx}${tsd}${base}')

			mut t := t1
			if t2 >= 0 && (t < 0 || t2 < t) {
				t = t2
			}
			if t3 >= 0 && (t < 0 || t3 < t) {
				t = t3
			}
			if t < 0 {
				die('bit ${bit_idx} failed')
			}

			ts << t
			ch = (ch << 1) | (if t <= thr { u8(0) } else { u8(1) })
			bit_idx++
		}

		out << ch
		if ch.hex() == "ff" {
			bit_idx += nbytes
			unsafe { i = 0 }
		}
		println('  byte #${i}  ${ts}ms  ->  0x${ch.hex()}')
	}

	decoded := huffman_decode(out)
	println('\n[rx] "${decoded}"')
}

fn main() {
	mut args := []string{}
	mut i := 1
	for i < os.args.len {
		if os.args[i] == '--dns' && i + 1 < os.args.len {
			g_dns = os.args[i + 1]
			i += 2
		} else if os.args[i] == '--workers' && i + 1 < os.args.len {
			g_workers = os.args[i + 1].int()
			if g_workers < 1 {
				g_workers = 1
			}
			i += 2
    } else if os.args[i] == '--window' && i + 1 < os.args.len {
			window = os.args[i + 1].int()
			i += 2
		} else {
			args << os.args[i]
			i += 1
		}
	}

	if g_dns.len > 0 {
		println('[*] dns server: ${g_dns}')
	}

	if args.len < 1 {
		eprintln('dnsh [--dns SERVER] [--workers N] [--window SEC] <send|rec> [domain] [msg|bytes]')
		eprintln('  dnsh --dns 8.8.8.8 send x.com "hello world"')
		eprintln('  dnsh --dns 8.8.8.8 rec  x.com 7')
		exit(1)
	}
	match args[0] {
		'send' {
			d := if args.len > 1 { args[1] } else { 'x.com' }
			m := if args.len > 2 { args[2] } else { 'hi' }
			send_mode(d, m)
		}
		'rec' {
			d := if args.len > 1 { args[1] } else { 'x.com' }
			n := if args.len > 2 { args[2].int() } else { 3 }
			rec_mode(d, n)
		}
		else {
			die('send or rec')
		}
	}
}