module main

import os
import time
import rand
import net

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
fn C.recvfrom(fd int, buf voidptr, len usize, flags int, src_addr voidptr, addrlen voidptr) isize
fn C.sendto(fd int, buf voidptr, len usize, flags int, dest_addr voidptr, addrlen u32) isize
fn C.setsockopt(fd int, level int, optname int, optval voidptr, optlen u32) int
fn C.htons(v u16) u16
fn C.inet_pton(af int, src &u8, dst voidptr) int
fn C.getsockname(fd int, addr voidptr, addrlen voidptr) int

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

__global g_dns = ''
__global g_workers = 1024
__global g_thr = i64(3000)

fn get_ts() i64 {
	// High speed: 125ms slots. 1024 bits / 125ms = 1 KB/s.
	return time.now().unix_milli() / 125
}

fn crc8(data []u8) u8 {
	mut crc := u8(0)
	for b in data {
		crc ^= b
		for _ in 0 .. 8 {
			if (crc & 0x80) != 0 {
				crc = (crc << 1) ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

fn char_idx(ch u8) int {
	if ch == ` ` { return 0 }
	return int(ch - `a`) + 1
}

fn huffman_encode(msg string) ([]u8, string) {
	codes :=[u32(0), 5, 60, 25, 22, 1, 56, 57, 21, 7, 125, 124, 23, 26, 8, 6, 59, 254, 20, 9, 4, 24, 61, 27, 126, 58, 255]
	lens :=[u8(3), 4, 6, 5, 5, 3, 6, 6, 5, 4, 7, 7, 5, 5, 4, 4, 6, 8, 5, 4, 4, 5, 6, 5, 7, 6, 8]

	mut filtered :=[]u8{}
	for ch in msg.bytes() {
		mut c := ch
		if c >= `A` && c <= `Z` { c += 32 }
		if (c >= `a` && c <= `z`) || c == ` ` { filtered << c }
	}

	mut bits :=[]u8{}
	for c in filtered {
		idx := char_idx(c)
		code := codes[idx]
		length := int(lens[idx])
		for b in 0 .. length {
			bits << u8((code >> u32(length - 1 - b)) & 1)
		}
	}

	mut result :=[]u8{}
	result << u8(filtered.len)
	mut i := 0
	for i < bits.len {
		mut bv := u8(0)
		for b in 0 .. 8 {
			bv = bv << 1
			if i + b < bits.len { bv |= bits[i + b] }
		}
		result << bv
		i += 8
	}
	return result, filtered.bytestr()
}

fn huffman_decode(data[]u8) string {
	if data.len < 1 { return '' }
	nchars := int(data[0])
	if nchars == 0 { return '' }
	syms :=[u8(` `), `e`, `t`, `a`, `o`, `i`, `n`, `s`, `r`, `h`, `d`, `l`, `u`, `c`, `m`, `w`, `f`, `g`, `y`, `p`, `b`, `v`, `k`, `j`, `x`, `q`, `z`]
	fc :=[0, 0, 0, 0, 4, 20, 56, 124, 254]
	fo :=[0, 0, 0, 0, 2, 8, 16, 22, 25]
	cn :=[0, 0, 0, 2, 6, 8, 6, 3, 2]

	mut bits :=[]u8{}
	for i in 1 .. data.len {
		for b in 0 .. 8 {
			bits << (data[i] >> u8(7 - b)) & 1
		}
	}

	mut result :=[]u8{}
	mut pos := 0
	for _ in 0 .. nchars {
		mut code := 0
		mut found := false
		for l in 1 .. 9 {
			if pos >= bits.len { break }
			code = (code << 1) | int(bits[pos])
			pos++
			if l >= 3 && l < fc.len && code >= fc[l] && code - fc[l] < cn[l] {
				result << syms[fo[l] + code - fc[l]]
				found = true
				break
			}
		}
		if !found { break }
	}
	return result.bytestr()
}

fn build_dns_query(host string, tx_id u16)[]u8 {
	mut pkt :=[]u8{cap: 128}
	pkt << u8((tx_id >> 8) & 0xFF)
	pkt << u8(tx_id & 0xFF)
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
		if label.len == 0 { continue }
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

fn resolve_udp(host string) !i64 {
	sw := time.new_stopwatch()
	// Using the high-level V net module for better resource management
	mut conn := net.dial_udp('${g_dns}:53') or { return error('dial_udp failed') }
	conn.set_read_timeout(1000 * time.millisecond)
	
	tx_id := u16(rand.intn(65535) or { 0 })
	pkt := build_dns_query(host, tx_id)
	
	conn.write(pkt) or {
		conn.close() or {}
		return error('send failed')
	}
	
	mut buf := []u8{len: 512}
	n, _ := conn.read(mut buf) or {
		conn.close() or {}
		return error('timeout')
	}

	elapsed := sw.elapsed().microseconds()
	conn.close() or {}

	if n < 0 {
		return error('read error')
	}
	return elapsed
}

fn resolve(host string) !i64 {
	if g_dns.len > 0 {
		return resolve_udp(host)
	}
	sw := time.new_stopwatch()
	// gethostbyname is usually slow and might use system cache.
	// For high speed, we should probably prefer direct UDP if possible,
	// but the user said "logic hand hand hand" (don't touch main logic).
	_ := C.gethostbyname(host.str)
	elapsed := sw.elapsed().microseconds()
	if elapsed > 1000000 {
		return error('timeout')
	}
	return elapsed
}

fn resolve_safe(host string) i64 {
	for attempt in 0 .. 2 {
		t := resolve(host) or {
			time.sleep((10 + attempt * 20) * time.millisecond)
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

fn send_bit(bit_idx int, ts i64, prefix string, base string, bit u8) {
	if bit == 0 {
		// Warm the cache. Multiple queries help bypass some resolver logic.
		resolve('${prefix}${bit_idx}.${ts}.${base}') or {}
		resolve('v${prefix}${bit_idx}.${ts}.${base}') or {}
	}
}

fn send_mode(base string, msg string) {
	resolve('c0.${base}') or {}
	time.sleep(50 * time.millisecond)
	resolve('c0.${base}') or {}

	data, filtered := huffman_encode(msg)

	println('[tx] "${msg}" -> "${filtered}" (${filtered.len} chars)')
	println('[tx] ${data.len} wire bytes (huffman)')
	if g_dns == "" { println('[tx] receiver cmd:  dnsh rec ${base} ${data.len}') }
	else { println('[tx] receiver cmd:  sudo ./dnsh --dns ${g_dns} rec ${base} ${data.len}') }
	total_bits_count := data.len * 8
	ts := get_ts()
	println('[tx] sending ${total_bits_count} bits with ${g_workers} workers...')

	mut bit_pos_tx := 0
	for bit_pos_tx < total_bits_count {
		mut end := bit_pos_tx + g_workers
		if end > total_bits_count { end = total_bits_count }

		mut threads := []thread{}
		for i in bit_pos_tx .. end {
			byte_idx := i / 8
			bit_idx_in_byte := i % 8
			bit := (data[byte_idx] >> (7 - bit_idx_in_byte)) & 1
			threads << spawn send_bit(i, ts, '', base, bit)
		}
		threads.wait()
		bit_pos_tx = end
	}

	mut zeros := 0
	for ch in data {
		for bit in 0 .. 8 {
			if ((ch >> (7 - bit)) & 1) == 0 { zeros++ }
		}
	}

	println('[tx] cached ${zeros} subdomains')
	println('[tx] keepalive running... (ctrl+c to stop)\n')
	
	mut round := 0
	for {
		cur_ts := get_ts()
		round++
		mut refreshed := 0

		mut bit_pos_keep := 0
		for bit_pos_keep < total_bits_count {
			mut end := bit_pos_keep + g_workers
			if end > total_bits_count { end = total_bits_count }

			mut threads := []thread{}
			for i in bit_pos_keep .. end {
				byte_idx := i / 8
				bit_idx_in_byte := i % 8
				bit := (data[byte_idx] >> (7 - bit_idx_in_byte)) & 1
				if bit == 0 {
					threads << spawn send_bit(i, cur_ts, '', base, 0)
					refreshed++
				}
			}
			threads.wait()
			bit_pos_keep = end
		}

		println('[keepalive #${round}] ${refreshed} entries refreshed')
		time.sleep(2 * time.second)
	}
}


fn rec_mode(base string, nbytes int) {
	println('[rx] reading ${nbytes} wire bytes (huffman)...\n')
	println('[rx] calibrating...')

	mut fast_arr := []i64{}
	mut slow_arr := []i64{}

	for _ in 0 .. 5 {
		f := resolve_safe('c0.${base}')
		if f >= 0 {
			fast_arr << f
		}
		time.sleep(10 * time.millisecond)
	}
	for _ in 0 .. 5 {
		s := resolve_safe('u${rand.intn(99999) or { 12345 }}.${base}')
		if s >= 0 {
			slow_arr << s
		}
		time.sleep(10 * time.millisecond)
	}

	if fast_arr.len < 2 || slow_arr.len < 2 {
		die('calibration failed')
	}

	fast_arr.sort()
	slow_arr.sort()
	fast_med := fast_arr[fast_arr.len / 2]
	slow_med := slow_arr[slow_arr.len / 2]
	gap := slow_med - fast_med

	if gap < 500 {
		die('gap ${gap}µs too small (fast:${fast_med}µs slow:${slow_med}µs) - sender running?')
	}

	mut thr := (fast_med + slow_med) / 2
	if thr < 500 {
		thr = 500
	}

	println('[rx] fast:${fast_med}µs slow:${slow_med}µs gap:${gap}µs thr:${thr}µs\n')

	mut out := []u8{len: nbytes}
	ts := get_ts()

	// Parallel reading of all bits
	total_bits := nbytes * 8
	mut bits := []u8{len: total_bits}

	println('[rx] downloading bits with ${g_workers} workers...')

	mut pos := 0
	for pos < total_bits {
		mut end := pos + g_workers
		if end > total_bits { end = total_bits }

		mut threads := []thread u8{}
		for i in pos .. end {
			threads << spawn read_bit(i, ts, '', base, thr)
		}

		res := threads.wait()
		for i in 0 .. res.len {
			bits[pos + i] = res[i]
		}
		pos = end
	}

	for i in 0 .. nbytes {
		mut ch := u8(0)
		for b in 0 .. 8 {
			bit := bits[i * 8 + b]
			if bit > 1 { die('bit ${i * 8 + b} failed') }
			ch = (ch << 1) | bit
		}
		out[i] = ch
		println('  byte #${i} -> 0x${ch.hex()}')
	}

	decoded := huffman_decode(out)
	println('\n[rx] "${decoded}"')
}

fn send_packet(prefix string, base string, ts i64, data []u8) {
	mut pkt := []u8{}
	pkt << u8(data.len)
	pkt << crc8(data)
	pkt << data

	total_bits := pkt.len * 8
	mut bit_pos := 0
	for bit_pos < total_bits {
		mut current_workers := 0
		mut threads := []thread{}
		for bit_pos < total_bits && current_workers < g_workers {
			byte_idx := bit_pos / 8
			bit_idx_in_byte := bit_pos % 8
			bit := (pkt[byte_idx] >> (7 - bit_idx_in_byte)) & 1
			threads << spawn send_bit(bit_pos, ts, prefix, base, bit)
			bit_pos++
			current_workers++
		}
		threads.wait()
	}
}

fn read_bit(bit_idx int, ts i64, prefix string, base string, thr i64) u8 {
	t1 := resolve_safe('${prefix}${bit_idx}.${ts}.${base}')
	t2 := resolve_safe('v${prefix}${bit_idx}.${ts}.${base}')
	mut t := t1
	if t2 >= 0 && (t < 0 || t2 < t) { t = t2 }
	if t < 0 { return 2 }
	return if t <= thr { u8(0) } else { u8(1) }
}

fn receive_packet(prefix string, base string, ts i64, max_bytes int) []u8 {
	mut header_bits := []u8{len: 16}
	for i in 0 .. 16 {
		header_bits[i] = read_bit(i, ts, prefix, base, g_thr)
	}

	mut h0 := u8(0)
	mut h1 := u8(0)
	for i in 0 .. 8 { h0 = (h0 << 1) | header_bits[i] }
	for i in 0 .. 8 { h1 = (h1 << 1) | header_bits[8 + i] }

	len := int(h0)
	if len == 0 || len > max_bytes || len == 255 { return []u8{} }

	total_bits := (len + 2) * 8
	mut bits := []u8{len: total_bits}
	for i in 0 .. 16 { bits[i] = header_bits[i] }

	mut pos := 16
	for pos < total_bits {
		mut current_workers := 0
		mut threads := []thread u8{}
		start_pos := pos
		for pos < total_bits && current_workers < g_workers {
			threads << spawn read_bit(pos, ts, prefix, base, g_thr)
			pos++
			current_workers++
		}
		res := threads.wait()
		for i in 0 .. res.len {
			bits[start_pos + i] = res[i]
		}
	}

	mut data := []u8{len: len}
	for i in 0 .. len {
		mut ch := u8(0)
		for b in 0 .. 8 {
			ch = (ch << 1) | bits[16 + i * 8 + b]
		}
		data[i] = ch
	}

	if crc8(data) != h1 {
		return []u8{}
	}
	return data
}

fn handle_socks_conn(mut conn net.TcpConn, base string) {
	println('[socks-client] connection accepted')
	defer { conn.close() or {} }
	mut buf := []u8{len: 512}
	n := conn.read(mut buf) or { return }
	if n < 2 || buf[0] != 0x05 { return }
	conn.write([u8(0x05), 0x00]) or { return }
	n2 := conn.read(mut buf) or { return }
	if n2 < 4 { return }

	mut dest_info := []u8{}
	dest_info << buf[3..n2]

	ts_start := get_ts()
	println('[socks-client] sending destination info in slot ${ts_start}')
	send_packet('u', base, ts_start, dest_info)

	conn.write([u8(0x05), 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]) or { return }
	println('[socks-client] tunnel established')

	for {
		// Non-blocking read from local app
		conn.set_read_timeout(100 * time.millisecond)
		mut data_buf := []u8{len: 128}
		rn := conn.read(mut data_buf) or { 0 }

		ts := get_ts()
		if rn > 0 {
			println('[socks-client] UP -> ${rn} bytes')
			send_packet('u', base, ts, data_buf[..rn])
		}

		// Poll for DOWNSTREAM data from DNS
		down_data := receive_packet('d', base, ts, 128)
		if down_data.len > 0 {
			println('[socks-client] DOWN <- ${down_data.len} bytes')
				conn.write(down_data) or { 0 }
		}

		time.sleep(100 * time.millisecond)
	}
}

fn calibrate(base string) {
	println('[*] calibrating threshold...')
	mut fast_arr := []i64{}
	mut slow_arr := []i64{}
	for _ in 0 .. 5 {
		f := resolve_safe('c0.${base}')
		if f >= 0 { fast_arr << f }
		time.sleep(20 * time.millisecond)
	}
	for _ in 0 .. 5 {
		s := resolve_safe('u${rand.intn(99999) or { 1234 }}.${base}')
		if s >= 0 { slow_arr << s }
		time.sleep(20 * time.millisecond)
	}
	if fast_arr.len > 0 && slow_arr.len > 0 {
		fast_arr.sort()
		slow_arr.sort()
		fast_med := fast_arr[fast_arr.len / 2]
		slow_med := slow_arr[slow_arr.len / 2]
		g_thr = (fast_med + slow_med) / 2
		println('[*] calibrated: fast:${fast_med}µs slow:${slow_med}µs thr:${g_thr}µs')
	}
}

fn socks_mode(mode string, base string, socks_port int) {
	println('[*] socks mode: ${mode} on port ${socks_port}')
	calibrate(base)
	if mode == 'client' {
		mut l := net.listen_tcp(.ip, '127.0.0.1:${socks_port}') or { die(err.msg()) }
		println('[*] socks client listening on 127.0.0.1:${socks_port}')
		for {
			mut conn := l.accept() or { continue }
			spawn handle_socks_conn(mut conn, base)
		}
	} else if mode == 'server' {
		println('[*] socks server polling DNS for data...')
		mut last_ts := i64(0)
		mut is_connected := false
		mut target_conn := net.TcpConn{}

		for {
			ts := get_ts()
			if ts <= last_ts {
				time.sleep(50 * time.millisecond)
				continue
			}
			last_ts = ts

			// Poll UPSTREAM
			data := receive_packet('u', base, ts, 128)
			if data.len > 0 {
				if !is_connected {
					atyp := data[0]
					mut addr := ''
					mut port := u16(0)
					if atyp == 0x01 {
						addr = '${data[1]}.${data[2]}.${data[3]}.${data[4]}'
						port = (u16(data[5]) << 8) | data[6]
					} else if atyp == 0x03 {
						len := int(data[1])
						addr = data[2..2+len].bytestr()
						port = (u16(data[2+len]) << 8) | data[3+len]
					}
					if addr != '' {
						println('[socks-server] connecting to ${addr}:${port}...')
						if mut tc := net.dial_tcp('${addr}:${port}') {
							target_conn = tc
							is_connected = true
						}
					}
				} else {
					println('[socks-server] UP -> ${data.len} bytes')
					target_conn.write(data) or { is_connected = false }
				}
			}

			// Poll TARGET for DOWNSTREAM
			if is_connected {
				target_conn.set_read_timeout(50 * time.millisecond)
				mut down_buf := []u8{len: 128}
				dn := target_conn.read(mut down_buf) or { 0 }
				if dn > 0 {
					println('[socks-server] DOWN <- ${dn} bytes')
					send_packet('d', base, ts, down_buf[..dn])
				}
			}
		}
	} else {
		die('unknown socks mode: ' + mode)
	}
}


fn main() {
	mut args :=[]string{}
	mut i := 1
	for i < os.args.len {
		if os.args[i] == '--dns' && i + 1 < os.args.len {
			g_dns = os.args[i + 1]
			i += 2
		} else if os.args[i] == '--workers' && i + 1 < os.args.len {
			g_workers = os.args[i + 1].int()
			if g_workers < 1 { g_workers = 1 }
			i += 2
		} else {
			args << os.args[i]
			i += 1
		}
	}

	if g_dns.len > 0 { println('[*] dns server: ${g_dns}') }

	if args.len < 1 {
		eprintln('dnsh [--dns SERVER] [--workers N] <send|rec|socks> [domain] [msg|bytes|port]')
		eprintln('  dnsh --dns 8.8.8.8 send x.com "hello world"')
		eprintln('  dnsh --dns 8.8.8.8 rec  x.com 7')
		eprintln('  dnsh --dns 8.8.8.8 socks client x.com 1080')
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
		'socks' {
			m := if args.len > 1 { args[1] } else { 'client' }
			d := if args.len > 2 { args[2] } else { 'x.com' }
			p := if args.len > 3 { args[3].int() } else { 1080 }
			socks_mode(m, d, p)
		}
		else { die('use: send, rec, or socks') }
	}
}